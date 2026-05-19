package log

import (
	"context"
	"errors"
	"log/slog"

	"go.opentelemetry.io/otel/trace"
)

// traceHandler is a slog.Handler middleware that attaches trace_id and
// span_id from the active span in record.Context to every record.
//
// When there is no active span (or the span context is not valid), the
// handler passes the record through unchanged. The check is one method
// call on trace.SpanFromContext + one IsValid() — cheap enough that this
// middleware can stay on universally when telemetry is enabled.
type traceHandler struct{ inner slog.Handler }

// newTraceHandler returns the trace-correlation middleware. Passing nil
// is a programming error and will panic on first use.
func newTraceHandler(inner slog.Handler) slog.Handler {
	return traceHandler{inner: inner}
}

func (h traceHandler) Enabled(ctx context.Context, l slog.Level) bool {
	return h.inner.Enabled(ctx, l)
}

func (h traceHandler) Handle(ctx context.Context, r slog.Record) error {
	if ctx != nil {
		sc := trace.SpanContextFromContext(ctx)
		if sc.IsValid() {
			r.AddAttrs(
				slog.String("trace_id", sc.TraceID().String()),
				slog.String("span_id", sc.SpanID().String()),
			)
		}
	}
	return h.inner.Handle(ctx, r)
}

func (h traceHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return traceHandler{inner: h.inner.WithAttrs(attrs)}
}

func (h traceHandler) WithGroup(name string) slog.Handler {
	return traceHandler{inner: h.inner.WithGroup(name)}
}

// teeHandler fans every record out to multiple inner handlers. Used to
// keep stdout/console output alongside an OTLP-bound bridge handler so
// operators still see logs via `docker logs` etc. while observability
// shipping is additive.
type teeHandler struct{ handlers []slog.Handler }

// newTeeHandler returns a slog.Handler that delivers each record to each
// inner handler. With zero or one handler it returns a sensible
// short-circuit: nil if empty, the single handler if there's one.
func newTeeHandler(handlers ...slog.Handler) slog.Handler {
	switch len(handlers) {
	case 0:
		return discardHandler{}
	case 1:
		return handlers[0]
	default:
		return teeHandler{handlers: handlers}
	}
}

func (t teeHandler) Enabled(ctx context.Context, l slog.Level) bool {
	for _, h := range t.handlers {
		if h.Enabled(ctx, l) {
			return true
		}
	}
	return false
}

func (t teeHandler) Handle(ctx context.Context, r slog.Record) error {
	var errs []error
	for _, h := range t.handlers {
		if !h.Enabled(ctx, r.Level) {
			continue
		}
		if err := h.Handle(ctx, r.Clone()); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func (t teeHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	out := make([]slog.Handler, len(t.handlers))
	for i, h := range t.handlers {
		out[i] = h.WithAttrs(attrs)
	}
	return teeHandler{handlers: out}
}

func (t teeHandler) WithGroup(name string) slog.Handler {
	out := make([]slog.Handler, len(t.handlers))
	for i, h := range t.handlers {
		out[i] = h.WithGroup(name)
	}
	return teeHandler{handlers: out}
}

// discardHandler is a slog.Handler that drops every record. Returned by
// newTeeHandler when no inner handlers are supplied.
type discardHandler struct{}

func (discardHandler) Enabled(context.Context, slog.Level) bool  { return false }
func (discardHandler) Handle(context.Context, slog.Record) error { return nil }
func (discardHandler) WithAttrs([]slog.Attr) slog.Handler        { return discardHandler{} }
func (discardHandler) WithGroup(string) slog.Handler             { return discardHandler{} }
