// Package httptelem provides OpenTelemetry instrumentation for inbound HTTP
// traffic served by gorilla/mux behind negroni.
//
// The exported Middleware is a mux.MiddlewareFunc, attached via
// router.Use(...). Running inside the mux chain means the matched route
// template is available via mux.CurrentRoute(r), which keeps span and
// metric cardinality bounded (path parameters don't blow out the
// dimension set).
//
// When telemetry is disabled (cfg.Enabled == false), Middleware returns
// the next handler unchanged so the request path is identical to the
// pre-telemetry baseline.
package httptelem

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/RichardKnop/go-oauth2-server/telemetry"
	"github.com/gorilla/mux"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/propagation"
	semconv "go.opentelemetry.io/otel/semconv/v1.40.0"
	"go.opentelemetry.io/otel/trace"
)

// ScopeName identifies the instrumentation library in emitted telemetry.
const ScopeName = "github.com/RichardKnop/go-oauth2-server/telemetry/httptelem"

// Middleware returns a mux.MiddlewareFunc that records a server span and
// HTTP RED metrics for every non-excluded inbound request.
//
// Span name is the mux route template (e.g. "/v1/oauth/tokens"). 5xx
// responses mark the span as Error. Panics are recorded as exception
// events on the span and re-panicked so the negroni Recovery middleware
// still emits the 500 response.
//
// Metrics:
//
//	http.server.request.duration  histogram (ms)
//	http.server.requests          counter
//	http.server.active_requests   up/down counter
//
// duration/requests carry method, route, and response status; the
// active_requests gauge omits status since the request is still in flight.
func Middleware(cfg telemetry.Config) mux.MiddlewareFunc {
	if !cfg.Enabled {
		return func(next http.Handler) http.Handler { return next }
	}

	tracer := otel.Tracer(ScopeName)
	meter := otel.Meter(ScopeName)
	duration, _ := meter.Float64Histogram(
		"http.server.request.duration",
		metric.WithUnit("ms"),
		metric.WithDescription("Duration of inbound HTTP server requests."),
	)
	requests, _ := meter.Int64Counter(
		"http.server.requests",
		metric.WithDescription("Count of inbound HTTP server requests."),
	)
	active, _ := meter.Int64UpDownCounter(
		"http.server.active_requests",
		metric.WithDescription("Number of in-flight inbound HTTP server requests."),
	)
	propagator := otel.GetTextMapPropagator()

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if cfg.IsExcluded(r.URL.Path) {
				next.ServeHTTP(w, r)
				return
			}

			ctx := propagator.Extract(r.Context(), propagation.HeaderCarrier(r.Header))

			route := routeTemplate(r)
			spanName := route
			if spanName == "" {
				spanName = r.Method
			}

			scheme := r.URL.Scheme
			if scheme == "" {
				if r.TLS != nil {
					scheme = "https"
				} else {
					scheme = "http"
				}
			}

			startAttrs := []attribute.KeyValue{
				semconv.HTTPRequestMethodKey.String(r.Method),
				semconv.URLPath(r.URL.Path),
				semconv.URLScheme(scheme),
			}
			if route != "" {
				startAttrs = append(startAttrs, semconv.HTTPRoute(route))
			}

			ctx, span := tracer.Start(ctx, spanName,
				trace.WithSpanKind(trace.SpanKindServer),
				trace.WithAttributes(startAttrs...),
			)
			defer span.End()

			activeAttrs := metric.WithAttributes(
				semconv.HTTPRequestMethodKey.String(r.Method),
				semconv.HTTPRoute(route),
			)
			active.Add(ctx, 1, activeAttrs)
			start := time.Now()

			rw := &statusRecorder{ResponseWriter: w, status: http.StatusOK}

			defer func() {
				active.Add(ctx, -1, activeAttrs)

				if rec := recover(); rec != nil {
					span.RecordError(panicErr(rec))
					span.SetStatus(codes.Error, "handler panicked")
					recordEnd(ctx, duration, requests, start, r.Method, route, http.StatusInternalServerError)
					panic(rec)
				}

				recordEnd(ctx, duration, requests, start, r.Method, route, rw.status)
				span.SetAttributes(semconv.HTTPResponseStatusCode(rw.status))
				if rw.status >= 500 {
					span.SetStatus(codes.Error, http.StatusText(rw.status))
				}
			}()

			next.ServeHTTP(rw, r.WithContext(ctx))
		})
	}
}

func recordEnd(
	ctx context.Context,
	duration metric.Float64Histogram,
	requests metric.Int64Counter,
	start time.Time,
	method, route string,
	status int,
) {
	elapsedMs := float64(time.Since(start)) / float64(time.Millisecond)
	attrs := metric.WithAttributes(
		semconv.HTTPRequestMethodKey.String(method),
		semconv.HTTPRoute(route),
		semconv.HTTPResponseStatusCode(status),
	)
	duration.Record(ctx, elapsedMs, attrs)
	requests.Add(ctx, 1, attrs)
}

func routeTemplate(r *http.Request) string {
	if cr := mux.CurrentRoute(r); cr != nil {
		if t, err := cr.GetPathTemplate(); err == nil {
			return t
		}
	}
	return ""
}

func panicErr(v any) error {
	if e, ok := v.(error); ok {
		return e
	}
	return fmt.Errorf("panic: %v", v)
}

type statusRecorder struct {
	http.ResponseWriter
	status      int
	wroteHeader bool
}

func (s *statusRecorder) WriteHeader(code int) {
	if !s.wroteHeader {
		s.status = code
		s.wroteHeader = true
	}
	s.ResponseWriter.WriteHeader(code)
}

func (s *statusRecorder) Write(b []byte) (int, error) {
	if !s.wroteHeader {
		s.wroteHeader = true
	}
	return s.ResponseWriter.Write(b)
}

// Flush forwards to the wrapped writer when it supports flushing so SSE
// and similar streaming handlers continue to work through the wrapper.
func (s *statusRecorder) Flush() {
	if f, ok := s.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}
