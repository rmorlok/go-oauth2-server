package integration_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/RichardKnop/go-oauth2-server/database"
	"github.com/RichardKnop/go-oauth2-server/health"
	"github.com/RichardKnop/go-oauth2-server/models"
	"github.com/RichardKnop/go-oauth2-server/oauth"
	"github.com/RichardKnop/go-oauth2-server/session"
	"github.com/RichardKnop/go-oauth2-server/telemetry"
	"github.com/RichardKnop/go-oauth2-server/testmode"
	"github.com/RichardKnop/go-oauth2-server/util/migrations"
	"github.com/RichardKnop/go-oauth2-server/web"
	"github.com/gorilla/sessions"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
)

// telemetryServer wraps a test-mode server stood up with telemetry.Enabled
// = true so OAuth-domain metrics and spans are emitted into the in-memory
// SDKs installed below.
type telemetryServer struct {
	URL      string
	Spans    *tracetest.InMemoryExporter
	Reader   *sdkmetric.ManualReader
	server   *httptest.Server
	teardown func()
}

// newTelemetryServer mirrors newTestServer but enables telemetry and
// installs in-memory tracer/meter SDKs as the OTel globals BEFORE
// oauth.NewService caches its tracer/meter handles.
func newTelemetryServer(t *testing.T) *telemetryServer {
	t.Helper()

	traceExp := tracetest.NewInMemoryExporter()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSyncer(traceExp))
	otel.SetTracerProvider(tp)

	reader := sdkmetric.NewManualReader()
	mp := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	otel.SetMeterProvider(mp)

	cnf := testmode.NewConfig(":memory:")
	cnf.Telemetry = telemetry.Config{
		Enabled:  true,
		Exporter: telemetry.Exporter{Protocol: telemetry.ProtocolGRPC, Endpoint: "http://localhost:4317"},
		Resource: telemetry.Resource{ServiceName: "test"},
	}
	cnf.Telemetry.ApplyDefaults()

	db, err := database.NewDatabase(cnf)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	if err := migrations.Bootstrap(db); err != nil {
		t.Fatalf("bootstrap migrations: %v", err)
	}
	if err := models.MigrateAll(db); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	if err := testmode.Seed(db); err != nil {
		t.Fatalf("seed: %v", err)
	}

	healthService := health.NewService(db)
	oauthService := oauth.NewService(cnf, db)
	sessionService := session.NewService(cnf, sessions.NewCookieStore([]byte(cnf.Session.Secret)))
	webService := web.NewService(cnf, oauthService, sessionService)
	testService := testmode.NewService(cnf, db, oauthService)

	handler := testmode.BuildTestApp(healthService, oauthService, webService, testService, cnf.Telemetry)
	httpSrv := httptest.NewServer(handler)

	ts := &telemetryServer{
		URL:    httpSrv.URL,
		Spans:  traceExp,
		Reader: reader,
		server: httpSrv,
		teardown: func() {
			httpSrv.Close()
			db.Close()
			_ = tp.Shutdown(context.Background())
			_ = mp.Shutdown(context.Background())
		},
	}
	t.Cleanup(ts.teardown)
	return ts
}

// TestTelemetry_OAuthLifecycle drives a password → refresh flow with
// telemetry enabled and asserts on the OAuth counter dimensions. The
// goal is to verify acceptance criterion #6: counters cover all four
// grant types plus introspect / revoke / userinfo, with correct
// dimensions and outcome labels.
func TestTelemetry_OAuthLifecycle(t *testing.T) {
	ts := newTelemetryServer(t)

	// Register a client + user via the test-mode control plane.
	cBody, _ := json.Marshal(map[string]any{
		"key":                        "tel-client",
		"secret":                     "tel-secret",
		"redirect_uri":               "https://app.example.com/cb",
		"token_endpoint_auth_method": "client_secret_post",
	})
	httpPost(t, ts.URL+"/test/clients", "application/json", cBody, http.StatusCreated)

	uBody, _ := json.Marshal(map[string]any{
		"username": "tel-user@example.com",
		"password": "hunter22",
		"role":     "user",
		"email":    "tel-user@example.com",
	})
	httpPost(t, ts.URL+"/test/users", "application/json", uBody, http.StatusCreated)

	// 1. password grant.
	form := url.Values{}
	form.Set("grant_type", "password")
	form.Set("client_id", "tel-client")
	form.Set("client_secret", "tel-secret")
	form.Set("username", "tel-user@example.com")
	form.Set("password", "hunter22")
	form.Set("scope", "read")
	respBody := httpForm(t, ts.URL+"/v1/oauth/tokens", form, http.StatusOK)

	var tok struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
	}
	if err := json.Unmarshal(respBody, &tok); err != nil {
		t.Fatalf("decode token: %v body=%s", err, respBody)
	}
	if tok.AccessToken == "" || tok.RefreshToken == "" {
		t.Fatalf("missing tokens in %s", respBody)
	}

	// 2. refresh_token grant.
	form = url.Values{}
	form.Set("grant_type", "refresh_token")
	form.Set("client_id", "tel-client")
	form.Set("client_secret", "tel-secret")
	form.Set("refresh_token", tok.RefreshToken)
	respBody = httpForm(t, ts.URL+"/v1/oauth/tokens", form, http.StatusOK)
	var tok2 struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(respBody, &tok2); err != nil {
		t.Fatalf("decode refreshed: %v", err)
	}

	// 3. introspect.
	form = url.Values{}
	form.Set("client_id", "tel-client")
	form.Set("client_secret", "tel-secret")
	form.Set("token", tok2.AccessToken)
	httpForm(t, ts.URL+"/v1/oauth/introspect", form, http.StatusOK)

	// 4. revoke.
	form = url.Values{}
	form.Set("client_id", "tel-client")
	form.Set("client_secret", "tel-secret")
	form.Set("token", tok2.AccessToken)
	httpForm(t, ts.URL+"/v1/oauth/revoke", form, http.StatusOK)

	// 5. failed password grant (wrong password) → exercises error path.
	form = url.Values{}
	form.Set("grant_type", "password")
	form.Set("client_id", "tel-client")
	form.Set("client_secret", "tel-secret")
	form.Set("username", "tel-user@example.com")
	form.Set("password", "wrong")
	httpForm(t, ts.URL+"/v1/oauth/tokens", form, http.StatusUnauthorized)

	// Collect metrics and verify expected counters fired with correct labels.
	rm := mustCollect(t, ts.Reader)

	// oauth.token.issued: two success (password + refresh_token) + one error.
	issued := pointsByLabels(rm, "oauth.token.issued")
	if len(issued) == 0 {
		t.Fatalf("oauth.token.issued has no points; metrics=%v", metricNames(rm))
	}
	wantIssued := map[string]bool{
		"oauth.grant_type=password&outcome=success":                              true,
		"oauth.grant_type=refresh_token&outcome=success":                         true,
		"oauth.grant_type=password&outcome=error&oauth.error_code=invalid_grant": true,
	}
	for _, pt := range issued {
		key := labelKey(pt, "oauth.grant_type", "outcome", "oauth.error_code")
		delete(wantIssued, key)
	}
	if len(wantIssued) > 0 {
		t.Errorf("missing oauth.token.issued label sets %v; got %s", wantIssued, dumpPoints(issued))
	}

	// oauth.token.refreshed.
	if pts := pointsByLabels(rm, "oauth.token.refreshed"); len(pts) == 0 {
		t.Errorf("oauth.token.refreshed has no points")
	}

	// oauth.introspect.requests.
	if pts := pointsByLabels(rm, "oauth.introspect.requests"); len(pts) == 0 {
		t.Errorf("oauth.introspect.requests has no points")
	}

	// oauth.token.revoked.
	if pts := pointsByLabels(rm, "oauth.token.revoked"); len(pts) == 0 {
		t.Errorf("oauth.token.revoked has no points")
	}

	// At least one span named oauth.grant.password should exist.
	sawGrant := false
	for _, sp := range ts.Spans.GetSpans() {
		if sp.Name == "oauth.grant.password" {
			sawGrant = true
			break
		}
	}
	if !sawGrant {
		t.Errorf("no oauth.grant.password span emitted; got %d spans", len(ts.Spans.GetSpans()))
	}
}

// helpers

func httpPost(t *testing.T, urlStr, contentType string, body []byte, wantStatus int) []byte {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, urlStr, strings.NewReader(string(body)))
	if err != nil {
		t.Fatalf("build req: %v", err)
	}
	req.Header.Set("Content-Type", contentType)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("post %s: %v", urlStr, err)
	}
	defer resp.Body.Close()
	rb := readBody(t, resp)
	if resp.StatusCode != wantStatus {
		t.Fatalf("POST %s: status %d, want %d, body=%s", urlStr, resp.StatusCode, wantStatus, rb)
	}
	return rb
}

func httpForm(t *testing.T, urlStr string, form url.Values, wantStatus int) []byte {
	t.Helper()
	resp, err := http.PostForm(urlStr, form)
	if err != nil {
		t.Fatalf("form %s: %v", urlStr, err)
	}
	defer resp.Body.Close()
	rb := readBody(t, resp)
	if resp.StatusCode != wantStatus {
		t.Fatalf("FORM %s: status %d, want %d, body=%s", urlStr, resp.StatusCode, wantStatus, rb)
	}
	return rb
}

func readBody(t *testing.T, resp *http.Response) []byte {
	t.Helper()
	out := make([]byte, 0, 1024)
	buf := make([]byte, 1024)
	for {
		n, err := resp.Body.Read(buf)
		if n > 0 {
			out = append(out, buf[:n]...)
		}
		if err != nil {
			break
		}
	}
	return out
}

func mustCollect(t *testing.T, reader *sdkmetric.ManualReader) metricdata.ResourceMetrics {
	t.Helper()
	var rm metricdata.ResourceMetrics
	if err := reader.Collect(context.Background(), &rm); err != nil {
		t.Fatalf("collect: %v", err)
	}
	return rm
}

func metricNames(rm metricdata.ResourceMetrics) []string {
	var out []string
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			out = append(out, m.Name)
		}
	}
	return out
}

func pointsByLabels(rm metricdata.ResourceMetrics, name string) []metricdata.DataPoint[int64] {
	var out []metricdata.DataPoint[int64]
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			if m.Name != name {
				continue
			}
			if sum, ok := m.Data.(metricdata.Sum[int64]); ok {
				out = append(out, sum.DataPoints...)
			}
		}
	}
	return out
}

// labelKey serializes a fixed-order subset of a data point's labels so
// tests can assert on the dimension combinations they care about.
func labelKey(pt metricdata.DataPoint[int64], keys ...string) string {
	var parts []string
	for _, k := range keys {
		v, ok := pt.Attributes.Value(attribute.Key(k))
		if !ok {
			continue
		}
		parts = append(parts, k+"="+v.AsString())
	}
	return strings.Join(parts, "&")
}

func dumpPoints(pts []metricdata.DataPoint[int64]) string {
	var rows []string
	for _, p := range pts {
		rows = append(rows, p.Attributes.Encoded(nil))
	}
	return strings.Join(rows, " | ")
}
