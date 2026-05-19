package httptelem

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/RichardKnop/go-oauth2-server/telemetry"
	"github.com/gorilla/mux"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/propagation"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	tracesdk "go.opentelemetry.io/otel/trace"
)

// setup installs in-memory trace + metric SDKs as the OTel globals so the
// middleware emits into something this test can inspect, and returns the
// recorder + reader along with a cleanup func.
func setup(t *testing.T) (*tracetest.InMemoryExporter, *sdkmetric.ManualReader, func()) {
	t.Helper()
	traceExp := tracetest.NewInMemoryExporter()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSyncer(traceExp))
	otel.SetTracerProvider(tp)

	reader := sdkmetric.NewManualReader()
	mp := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	otel.SetMeterProvider(mp)

	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{},
		propagation.Baggage{},
	))

	return traceExp, reader, func() {
		_ = tp.Shutdown(context.Background())
		_ = mp.Shutdown(context.Background())
	}
}

// buildRouter wires the middleware against the supplied config and returns
// a mux router with two routes: a parametric /things/{id} that respects
// the provided handler, and /v1/health for exclusion tests.
func buildRouter(cfg telemetry.Config, handler http.HandlerFunc) *mux.Router {
	r := mux.NewRouter()
	r.Use(Middleware(cfg))
	r.HandleFunc("/things/{id}", handler).Methods("GET")
	r.HandleFunc("/v1/health", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}).Methods("GET")
	r.HandleFunc("/test/clients", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}).Methods("GET")
	return r
}

func enabledCfg() telemetry.Config {
	c := telemetry.Config{Enabled: true,
		Exporter: telemetry.Exporter{Protocol: telemetry.ProtocolGRPC, Endpoint: "http://localhost:4317"},
		Resource: telemetry.Resource{ServiceName: "svc"},
	}
	c.ApplyDefaults()
	return c
}

func TestMiddleware_EmitsSpanWithRouteTemplate(t *testing.T) {
	traceExp, reader, cleanup := setup(t)
	defer cleanup()

	router := buildRouter(enabledCfg(), func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/things/42", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	spans := traceExp.GetSpans()
	if len(spans) != 1 {
		t.Fatalf("got %d spans, want 1: %+v", len(spans), spans)
	}
	span := spans[0]
	if span.Name != "/things/{id}" {
		t.Errorf("span name = %q, want %q", span.Name, "/things/{id}")
	}
	if span.SpanKind != tracesdk.SpanKindServer {
		t.Errorf("span kind = %v, want Server", span.SpanKind)
	}
	if !hasAttr(span.Attributes, "http.route", "/things/{id}") {
		t.Errorf("missing http.route attribute: %+v", span.Attributes)
	}
	if !hasAttr(span.Attributes, "http.request.method", "GET") {
		t.Errorf("missing http.request.method attribute: %+v", span.Attributes)
	}
	if !hasAttr(span.Attributes, "url.path", "/things/42") {
		t.Errorf("missing url.path attribute: %+v", span.Attributes)
	}
	if !hasIntAttr(span.Attributes, "http.response.status_code", 200) {
		t.Errorf("missing http.response.status_code=200: %+v", span.Attributes)
	}

	// Metrics: duration histogram + requests counter + active=0.
	got := collect(t, reader)
	if !metricSeen(got, "http.server.request.duration") {
		t.Errorf("missing http.server.request.duration in: %v", metricNames(got))
	}
	if !metricSeen(got, "http.server.requests") {
		t.Errorf("missing http.server.requests in: %v", metricNames(got))
	}
	if !metricSeen(got, "http.server.active_requests") {
		t.Errorf("missing http.server.active_requests in: %v", metricNames(got))
	}
}

func TestMiddleware_5xxMarksSpanError(t *testing.T) {
	traceExp, _, cleanup := setup(t)
	defer cleanup()

	router := buildRouter(enabledCfg(), func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})

	req := httptest.NewRequest(http.MethodGet, "/things/abc", nil)
	router.ServeHTTP(httptest.NewRecorder(), req)

	spans := traceExp.GetSpans()
	if len(spans) != 1 {
		t.Fatalf("got %d spans, want 1", len(spans))
	}
	if spans[0].Status.Code.String() != "Error" {
		t.Errorf("span status code = %v, want Error", spans[0].Status.Code)
	}
	if !hasIntAttr(spans[0].Attributes, "http.response.status_code", 500) {
		t.Errorf("status_code attr missing/wrong: %+v", spans[0].Attributes)
	}
}

func TestMiddleware_PanicRecordedAndRepanicked(t *testing.T) {
	traceExp, _, cleanup := setup(t)
	defer cleanup()

	router := buildRouter(enabledCfg(), func(http.ResponseWriter, *http.Request) {
		panic(errors.New("boom"))
	})

	req := httptest.NewRequest(http.MethodGet, "/things/x", nil)

	defer func() {
		if r := recover(); r == nil {
			t.Fatalf("expected re-panic, got none")
		}

		spans := traceExp.GetSpans()
		if len(spans) != 1 {
			t.Fatalf("got %d spans, want 1", len(spans))
		}
		if spans[0].Status.Code.String() != "Error" {
			t.Errorf("span status code = %v, want Error", spans[0].Status.Code)
		}
		// RecordError adds an "exception" event.
		foundException := false
		for _, ev := range spans[0].Events {
			if ev.Name == "exception" {
				foundException = true
				break
			}
		}
		if !foundException {
			t.Errorf("no exception event recorded: %+v", spans[0].Events)
		}
	}()

	router.ServeHTTP(httptest.NewRecorder(), req)
}

func TestMiddleware_ExcludedPathEmitsNothing(t *testing.T) {
	traceExp, reader, cleanup := setup(t)
	defer cleanup()

	router := buildRouter(enabledCfg(), func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/v1/health", nil)
	router.ServeHTTP(httptest.NewRecorder(), req)

	if spans := traceExp.GetSpans(); len(spans) != 0 {
		t.Errorf("got %d spans for excluded path, want 0", len(spans))
	}
	got := collect(t, reader)
	if metricSeen(got, "http.server.request.duration") {
		t.Errorf("duration histogram should be absent for excluded path; metrics: %v", metricNames(got))
	}
}

func TestMiddleware_TestPathIsNotExcluded(t *testing.T) {
	traceExp, _, cleanup := setup(t)
	defer cleanup()

	router := buildRouter(enabledCfg(), func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/test/clients", nil)
	router.ServeHTTP(httptest.NewRecorder(), req)

	spans := traceExp.GetSpans()
	if len(spans) != 1 {
		t.Fatalf("got %d spans for /test/clients, want 1 (load tests need this visible)", len(spans))
	}
	if spans[0].Name != "/test/clients" {
		t.Errorf("span name = %q, want %q", spans[0].Name, "/test/clients")
	}
}

func TestMiddleware_HonorsIncomingTraceparent(t *testing.T) {
	traceExp, _, cleanup := setup(t)
	defer cleanup()

	router := buildRouter(enabledCfg(), func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/things/foo", nil)
	// 32-hex trace-id, 16-hex span-id, sampled.
	wantTraceID := "0123456789abcdef0123456789abcdef"
	req.Header.Set("traceparent", "00-"+wantTraceID+"-fedcba9876543210-01")

	router.ServeHTTP(httptest.NewRecorder(), req)

	spans := traceExp.GetSpans()
	if len(spans) != 1 {
		t.Fatalf("got %d spans, want 1", len(spans))
	}
	gotTraceID := spans[0].SpanContext.TraceID().String()
	if gotTraceID != wantTraceID {
		t.Errorf("trace id = %q, want %q (incoming traceparent not honored)", gotTraceID, wantTraceID)
	}
	if !spans[0].Parent.IsValid() {
		t.Errorf("parent span context is invalid; want valid from incoming traceparent")
	}
}

func TestMiddleware_DisabledIsPassThrough(t *testing.T) {
	traceExp, reader, cleanup := setup(t)
	defer cleanup()

	cfg := telemetry.Config{Enabled: false}
	router := mux.NewRouter()
	router.Use(Middleware(cfg))
	router.HandleFunc("/x", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	router.ServeHTTP(httptest.NewRecorder(), req)

	if spans := traceExp.GetSpans(); len(spans) != 0 {
		t.Errorf("disabled middleware emitted %d spans", len(spans))
	}
	if names := metricNames(collect(t, reader)); len(names) != 0 {
		t.Errorf("disabled middleware emitted metrics: %v", names)
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

func hasIntAttr(attrs []attribute.KeyValue, key string, want int64) bool {
	for _, kv := range attrs {
		if string(kv.Key) == key && kv.Value.AsInt64() == want {
			return true
		}
	}
	return false
}

func collect(t *testing.T, reader *sdkmetric.ManualReader) metricdata.ResourceMetrics {
	t.Helper()
	var rm metricdata.ResourceMetrics
	if err := reader.Collect(context.Background(), &rm); err != nil {
		t.Fatalf("metric collect: %v", err)
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

func metricSeen(rm metricdata.ResourceMetrics, name string) bool {
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			if m.Name == name {
				return true
			}
		}
	}
	return false
}
