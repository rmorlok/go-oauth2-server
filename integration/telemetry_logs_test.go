package integration_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/RichardKnop/go-oauth2-server/database"
	"github.com/RichardKnop/go-oauth2-server/health"
	"github.com/RichardKnop/go-oauth2-server/log"
	"github.com/RichardKnop/go-oauth2-server/models"
	"github.com/RichardKnop/go-oauth2-server/oauth"
	"github.com/RichardKnop/go-oauth2-server/session"
	"github.com/RichardKnop/go-oauth2-server/telemetry"
	"github.com/RichardKnop/go-oauth2-server/testmode"
	"github.com/RichardKnop/go-oauth2-server/util/migrations"
	"github.com/RichardKnop/go-oauth2-server/web"
	"github.com/gorilla/sessions"
	"go.opentelemetry.io/otel"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
)

// TestTelemetry_LogsCarryTraceID stands up a telemetry-enabled test
// server with logs configured to write JSON to a buffer, drives a single
// request through it, and verifies that:
//
//  1. The HTTP server span is emitted by the middleware.
//  2. The negroni URL logger writes a JSON log record carrying the same
//     trace_id as the server span.
//
// This exercises the end-to-end correlation path: incoming request →
// httptelem middleware opens a span → handler chain invokes the URL
// logger → log.FromContext picks up the request's context → traceHandler
// stamps trace_id / span_id onto the slog record.
func TestTelemetry_LogsCarryTraceID(t *testing.T) {
	// Install in-memory trace SDK as the OTel global BEFORE building the
	// server so the http middleware caches a handle to it.
	traceExp := tracetest.NewInMemoryExporter()
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithSyncer(traceExp),
		sdktrace.WithSampler(sdktrace.AlwaysSample()),
	)
	otel.SetTracerProvider(tp)
	t.Cleanup(func() { _ = tp.Shutdown(context.Background()) })

	logBuf := newSafeBuffer()
	trueP := true
	log.Init(log.Options{
		Level:               "debug",
		Format:              log.FormatJSON,
		Output:              logBuf,
		IncludeTraceContext: &trueP,
	})
	t.Cleanup(func() { log.Init(log.Options{}) })

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
	t.Cleanup(func() { db.Close() })
	if err := migrations.Bootstrap(db); err != nil {
		t.Fatalf("bootstrap: %v", err)
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
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)

	// Reset trace state from anything migrations/seed emitted before the
	// test request, so the assertion is on the request's own span.
	traceExp.Reset()

	// Register a client via the test-mode control plane. This is a real
	// POST route, so mux middlewares (httptelem + URL logger) run.
	body := strings.NewReader(`{"key":"telcorr","redirect_uri":"https://app.example.com/cb"}`)
	resp, err := http.Post(srv.URL+"/test/clients", "application/json", body)
	if err != nil {
		t.Fatalf("POST clients: %v", err)
	}
	resp.Body.Close()

	// Find the HTTP server span — that's the trace root we expect our
	// "request started" / "request finished" records to carry.
	spans := traceExp.GetSpans()
	if len(spans) == 0 {
		t.Fatalf("no spans emitted for POST /test/clients")
	}
	var wantTraceID string
	for _, s := range spans {
		if s.Name == "/test/clients" {
			wantTraceID = s.SpanContext.TraceID().String()
			break
		}
	}
	if wantTraceID == "" {
		t.Fatalf("did not find /test/clients HTTP span; got %d spans", len(spans))
	}

	output := logBuf.String()
	if output == "" {
		t.Fatalf("no log output captured")
	}
	var sawCorrelated bool
	for _, line := range strings.Split(strings.TrimRight(output, "\n"), "\n") {
		if line == "" {
			continue
		}
		var rec map[string]any
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			// Non-JSON lines slip in from gorm's console output; skip them.
			continue
		}
		if rec["trace_id"] == wantTraceID {
			sawCorrelated = true
			if _, ok := rec["span_id"]; !ok {
				t.Errorf("log record with trace_id is missing span_id: %v", rec)
			}
			break
		}
	}
	if !sawCorrelated {
		t.Errorf("no log record carried trace_id=%s; want at least one. Output:\n%s",
			wantTraceID, output)
	}
}

// safeBuffer wraps a bytes.Buffer with a mutex so the slog handler (which
// writes from request goroutines) can race with the test goroutine that
// reads it.
type safeBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func newSafeBuffer() *safeBuffer { return &safeBuffer{} }

func (b *safeBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *safeBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}
