package log

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"

	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/trace"
)

// jsonRec parses the latest JSON line written to buf and returns it.
func jsonRec(t *testing.T, buf *bytes.Buffer) map[string]any {
	t.Helper()
	lines := strings.Split(strings.TrimRight(buf.String(), "\n"), "\n")
	if len(lines) == 0 || lines[0] == "" {
		t.Fatalf("no log lines written: %q", buf.String())
	}
	var rec map[string]any
	if err := json.Unmarshal([]byte(lines[len(lines)-1]), &rec); err != nil {
		t.Fatalf("decode last line: %v: %q", err, lines[len(lines)-1])
	}
	return rec
}

// startedSpanContext returns a real (and valid) span context produced by
// a sampled in-memory tracer provider, so the trace handler sees IsValid()
// returning true.
func startedSpanContext(t *testing.T) (context.Context, trace.SpanContext) {
	t.Helper()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSampler(sdktrace.AlwaysSample()))
	t.Cleanup(func() { _ = tp.Shutdown(context.Background()) })
	ctx, span := tp.Tracer("test").Start(context.Background(), "test-span")
	t.Cleanup(func() { span.End() })
	return ctx, span.SpanContext()
}

func TestTraceHandler_AttachesTraceAndSpanID(t *testing.T) {
	var buf bytes.Buffer
	h := newTraceHandler(slog.NewJSONHandler(&buf, nil))
	logger := slog.New(h)

	ctx, sc := startedSpanContext(t)
	logger.InfoContext(ctx, "hello")

	rec := jsonRec(t, &buf)
	if rec["trace_id"] != sc.TraceID().String() {
		t.Errorf("trace_id = %v, want %s", rec["trace_id"], sc.TraceID())
	}
	if rec["span_id"] != sc.SpanID().String() {
		t.Errorf("span_id = %v, want %s", rec["span_id"], sc.SpanID())
	}
}

func TestTraceHandler_NoSpanContextStaysClean(t *testing.T) {
	var buf bytes.Buffer
	h := newTraceHandler(slog.NewJSONHandler(&buf, nil))
	logger := slog.New(h)

	logger.Info("hello")

	rec := jsonRec(t, &buf)
	if _, ok := rec["trace_id"]; ok {
		t.Errorf("trace_id leaked into record without active span: %v", rec)
	}
	if _, ok := rec["span_id"]; ok {
		t.Errorf("span_id leaked into record without active span: %v", rec)
	}
}

func TestTeeHandler_FansOutToAll(t *testing.T) {
	var b1, b2 bytes.Buffer
	h := newTeeHandler(
		slog.NewJSONHandler(&b1, nil),
		slog.NewJSONHandler(&b2, nil),
	)
	slog.New(h).Info("hello", "k", "v")

	for i, b := range []*bytes.Buffer{&b1, &b2} {
		if !strings.Contains(b.String(), "hello") || !strings.Contains(b.String(), `"k":"v"`) {
			t.Errorf("buffer %d missing expected content: %q", i, b.String())
		}
	}
}

func TestTeeHandler_SkipsHandlersThatDisableLevel(t *testing.T) {
	var b1, b2 bytes.Buffer
	high := slog.NewJSONHandler(&b1, &slog.HandlerOptions{Level: slog.LevelError})
	low := slog.NewJSONHandler(&b2, &slog.HandlerOptions{Level: slog.LevelDebug})
	logger := slog.New(newTeeHandler(high, low))

	logger.Info("hello")

	if b1.Len() != 0 {
		t.Errorf("high-threshold buffer received info record: %q", b1.String())
	}
	if !strings.Contains(b2.String(), "hello") {
		t.Errorf("low-threshold buffer missed record: %q", b2.String())
	}
}

func TestTeeHandler_ShortCircuitsForSingleAndEmpty(t *testing.T) {
	if _, ok := newTeeHandler().(discardHandler); !ok {
		t.Errorf("empty newTeeHandler should return discardHandler")
	}
	leaf := slog.NewJSONHandler(&bytes.Buffer{}, nil)
	if got := newTeeHandler(leaf); got != leaf {
		t.Errorf("single-element newTeeHandler should return the leaf directly")
	}
}

func TestTraceHandler_WithAttrsAndGroupPropagate(t *testing.T) {
	var buf bytes.Buffer
	h := newTraceHandler(slog.NewJSONHandler(&buf, nil))
	logger := slog.New(h).With("svc", "x").WithGroup("g")
	ctx, _ := startedSpanContext(t)
	logger.InfoContext(ctx, "hello", "k", "v")

	rec := jsonRec(t, &buf)
	if rec["svc"] != "x" {
		t.Errorf("svc attribute lost: %v", rec)
	}
	g, ok := rec["g"].(map[string]any)
	if !ok {
		t.Fatalf("group missing: %v", rec)
	}
	if g["k"] != "v" {
		t.Errorf("group attribute lost: %v", g)
	}
	// slog routes record-time AddAttrs through the active group, so
	// trace_id / span_id appear inside g when a group is open.
	if _, ok := g["trace_id"]; !ok {
		if _, ok := rec["trace_id"]; !ok {
			t.Errorf("trace_id missing after With/WithGroup: %v", rec)
		}
	}
}
