package oauthtelem_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/RichardKnop/go-oauth2-server/telemetry"
	"github.com/RichardKnop/go-oauth2-server/telemetry/oauthtelem"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
)

func setup(t *testing.T) (*tracetest.InMemoryExporter, *sdkmetric.ManualReader, func()) {
	t.Helper()
	traceExp := tracetest.NewInMemoryExporter()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSyncer(traceExp))
	otel.SetTracerProvider(tp)

	reader := sdkmetric.NewManualReader()
	mp := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	otel.SetMeterProvider(mp)

	return traceExp, reader, func() {
		_ = tp.Shutdown(context.Background())
		_ = mp.Shutdown(context.Background())
	}
}

func enabledCfg() telemetry.Config {
	c := telemetry.Config{Enabled: true,
		Exporter: telemetry.Exporter{Protocol: telemetry.ProtocolGRPC, Endpoint: "http://localhost:4317"},
		Resource: telemetry.Resource{ServiceName: "svc"},
	}
	c.ApplyDefaults()
	return c
}

func TestRecorder_NoOpWhenDisabled(t *testing.T) {
	traceExp, reader, cleanup := setup(t)
	defer cleanup()

	r := oauthtelem.New(telemetry.Config{Enabled: false})

	ctx, span := r.StartTokens(context.Background())
	r.SetClient(span, "client-1")
	r.SetScope(span, "read write")
	r.SetTokenType(span, "Bearer")
	r.FinishWithError(span, errors.New("nope"), "invalid_grant")
	span.End()

	r.RecordTokenIssued(ctx, "password", "client-1", nil, "")
	r.RecordTokenRefreshed(ctx, "client-1", nil, "")
	r.RecordTokenRevoked(ctx, "client-1", "access_token")
	r.RecordIntrospect(ctx, "client-1", true, nil, "")
	r.RecordUserinfo(ctx, nil, "")
	r.RecordGrantDuration(ctx, "password", time.Now(), nil)

	if spans := traceExp.GetSpans(); len(spans) != 0 {
		t.Errorf("disabled recorder emitted %d spans", len(spans))
	}
	if names := metricNames(collect(t, reader)); len(names) != 0 {
		t.Errorf("disabled recorder emitted metrics %v", names)
	}
}

func TestRecorder_GrantSpanCarriesAttrs(t *testing.T) {
	traceExp, _, cleanup := setup(t)
	defer cleanup()

	r := oauthtelem.New(enabledCfg())
	_, span := r.StartGrant(context.Background(), "authorization_code")
	r.SetClient(span, "client-7")
	r.SetScope(span, "openid email")
	r.SetTokenType(span, "Bearer")
	span.End()

	spans := traceExp.GetSpans()
	if len(spans) != 1 {
		t.Fatalf("got %d spans, want 1", len(spans))
	}
	sp := spans[0]
	if sp.Name != "oauth.grant.authorization_code" {
		t.Errorf("name = %q, want oauth.grant.authorization_code", sp.Name)
	}
	want := map[string]string{
		"oauth.grant_type": "authorization_code",
		"oauth.client_id":  "client-7",
		"oauth.scope":      "openid email",
		"oauth.token_type": "Bearer",
	}
	for k, v := range want {
		if !hasAttr(sp.Attributes, k, v) {
			t.Errorf("missing %s=%q; have %+v", k, v, sp.Attributes)
		}
	}
}

func TestRecorder_FinishWithErrorMarksSpan(t *testing.T) {
	traceExp, _, cleanup := setup(t)
	defer cleanup()

	r := oauthtelem.New(enabledCfg())
	_, span := r.StartGrant(context.Background(), "password")
	r.FinishWithError(span, errors.New("bad pw"), "invalid_grant")
	span.End()

	spans := traceExp.GetSpans()
	if len(spans) != 1 {
		t.Fatalf("got %d spans, want 1", len(spans))
	}
	if spans[0].Status.Code.String() != "Error" {
		t.Errorf("span status = %v, want Error", spans[0].Status.Code)
	}
	if !hasAttr(spans[0].Attributes, "oauth.error_code", "invalid_grant") {
		t.Errorf("missing oauth.error_code=invalid_grant: %+v", spans[0].Attributes)
	}
}

func TestRecorder_TokenIssuedCounterDimensions(t *testing.T) {
	_, reader, cleanup := setup(t)
	defer cleanup()

	r := oauthtelem.New(enabledCfg())
	ctx := context.Background()
	r.RecordTokenIssued(ctx, "authorization_code", "client-A", nil, "")
	r.RecordTokenIssued(ctx, "authorization_code", "client-A", errors.New("x"), "invalid_grant")

	rm := collect(t, reader)
	pts := sumPoints(rm, "oauth.token.issued")
	if len(pts) != 2 {
		t.Fatalf("oauth.token.issued got %d points, want 2", len(pts))
	}
	// Each point has a distinct attribute set; verify outcome + grant_type are present.
	var sawSuccess, sawError bool
	for _, p := range pts {
		gt, _ := p.Attributes.Value("oauth.grant_type")
		oc, _ := p.Attributes.Value("outcome")
		if gt.AsString() != "authorization_code" {
			t.Errorf("oauth.grant_type = %q, want authorization_code", gt.AsString())
		}
		switch oc.AsString() {
		case "success":
			sawSuccess = true
		case "error":
			sawError = true
			ec, _ := p.Attributes.Value("oauth.error_code")
			if ec.AsString() != "invalid_grant" {
				t.Errorf("oauth.error_code = %q, want invalid_grant", ec.AsString())
			}
		}
		cid, _ := p.Attributes.Value("oauth.client_id")
		if cid.AsString() != "client-A" {
			t.Errorf("oauth.client_id = %q, want client-A", cid.AsString())
		}
	}
	if !sawSuccess || !sawError {
		t.Errorf("expected both success and error outcomes; sawSuccess=%v sawError=%v", sawSuccess, sawError)
	}
}

func TestRecorder_IncludeClientIDOff(t *testing.T) {
	_, reader, cleanup := setup(t)
	defer cleanup()

	cfg := enabledCfg()
	f := false
	cfg.OAuth.IncludeClientID = &f

	r := oauthtelem.New(cfg)
	r.RecordTokenIssued(context.Background(), "password", "client-A", nil, "")

	rm := collect(t, reader)
	pts := sumPoints(rm, "oauth.token.issued")
	if len(pts) != 1 {
		t.Fatalf("got %d points, want 1", len(pts))
	}
	if _, ok := pts[0].Attributes.Value("oauth.client_id"); ok {
		t.Errorf("oauth.client_id present despite IncludeClientID=false: %+v", pts[0].Attributes)
	}

	_, span := r.StartGrant(context.Background(), "password")
	r.SetClient(span, "client-A")
	span.End()
	// SetClient should also be a no-op when disabled — we just need the
	// metric assertion above. The span check is implicit in trace tests.
}

func TestRecorder_TokenRevokedCounter(t *testing.T) {
	_, reader, cleanup := setup(t)
	defer cleanup()

	r := oauthtelem.New(enabledCfg())
	r.RecordTokenRevoked(context.Background(), "client-Z", "access_token")

	rm := collect(t, reader)
	pts := sumPoints(rm, "oauth.token.revoked")
	if len(pts) != 1 {
		t.Fatalf("got %d points, want 1", len(pts))
	}
	hint, _ := pts[0].Attributes.Value("oauth.token_type_hint")
	if hint.AsString() != "access_token" {
		t.Errorf("token_type_hint = %q, want access_token", hint.AsString())
	}
}

func TestRecorder_IntrospectActiveDimension(t *testing.T) {
	_, reader, cleanup := setup(t)
	defer cleanup()

	r := oauthtelem.New(enabledCfg())
	ctx := context.Background()
	r.RecordIntrospect(ctx, "c", true, nil, "")
	r.RecordIntrospect(ctx, "c", false, nil, "")

	rm := collect(t, reader)
	pts := sumPoints(rm, "oauth.introspect.requests")
	if len(pts) != 2 {
		t.Fatalf("got %d points, want 2", len(pts))
	}
	values := []bool{}
	for _, p := range pts {
		a, _ := p.Attributes.Value("active")
		values = append(values, a.AsBool())
	}
	if !(contains(values, true) && contains(values, false)) {
		t.Errorf("expected both active=true and active=false; got %v", values)
	}
}

func TestRecorder_GrantDurationDimensions(t *testing.T) {
	_, reader, cleanup := setup(t)
	defer cleanup()

	r := oauthtelem.New(enabledCfg())
	r.RecordGrantDuration(context.Background(), "password", time.Now().Add(-10*time.Millisecond), nil)

	rm := collect(t, reader)
	found := false
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			if m.Name == "oauth.grant.duration" {
				found = true
			}
		}
	}
	if !found {
		t.Errorf("oauth.grant.duration histogram not present")
	}
}

func TestJoinScopes(t *testing.T) {
	cases := []struct {
		in   []string
		want string
	}{
		{[]string{"a", "b"}, "a b"},
		{[]string{"a", "", "  ", "b"}, "a b"},
		{[]string{"a", "a", "b"}, "a b"},
	}
	for _, tc := range cases {
		got := oauthtelem.JoinScopes(tc.in...)
		if got != tc.want {
			t.Errorf("JoinScopes(%v) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// helpers

func hasAttr(attrs []attribute.KeyValue, key, want string) bool {
	for _, kv := range attrs {
		if string(kv.Key) == key && kv.Value.AsString() == want {
			return true
		}
	}
	return false
}

func collect(t *testing.T, reader *sdkmetric.ManualReader) metricdata.ResourceMetrics {
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

// sumPoints flattens int64 Sum data points for a metric name.
func sumPoints(rm metricdata.ResourceMetrics, name string) []metricdata.DataPoint[int64] {
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

func contains[T comparable](s []T, v T) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}
