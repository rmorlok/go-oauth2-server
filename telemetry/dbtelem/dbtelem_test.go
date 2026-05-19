package dbtelem_test

import (
	"context"
	"strings"
	"testing"

	"github.com/RichardKnop/go-oauth2-server/telemetry"
	"github.com/RichardKnop/go-oauth2-server/telemetry/dbtelem"

	_ "github.com/mattn/go-sqlite3"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
)

// setup installs in-memory trace + metric SDKs as OTel globals so the
// dbtelem wrapper emits into something this test can inspect.
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

func TestOpen_EnabledEmitsSpansWithDBSystem(t *testing.T) {
	traceExp, _, cleanup := setup(t)
	defer cleanup()

	db, err := dbtelem.Open(enabledCfg(), "sqlite3", ":memory:", "sqlite")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer db.Close()

	if _, err := db.ExecContext(context.Background(), "CREATE TABLE t (id INTEGER PRIMARY KEY, name TEXT)"); err != nil {
		t.Fatalf("create: %v", err)
	}
	if _, err := db.ExecContext(context.Background(), "INSERT INTO t (name) VALUES ('a')"); err != nil {
		t.Fatalf("insert: %v", err)
	}

	spans := traceExp.GetSpans()
	if len(spans) == 0 {
		t.Fatalf("got 0 spans, want at least 1")
	}

	// At least one span carries db.system=sqlite. We also expect db.statement
	// to be present (default capture-without-bind-values behaviour).
	var sawDBSystem, sawStatement bool
	for _, sp := range spans {
		for _, a := range sp.Attributes {
			switch string(a.Key) {
			case "db.system.name", "db.system":
				if a.Value.AsString() == "sqlite" {
					sawDBSystem = true
				}
			case "db.statement", "db.query.text":
				if strings.Contains(a.Value.AsString(), "INSERT") || strings.Contains(a.Value.AsString(), "CREATE") {
					sawStatement = true
				}
			}
		}
	}
	if !sawDBSystem {
		t.Errorf("no span carried db.system=sqlite; spans=%+v", spans)
	}
	if !sawStatement {
		t.Errorf("expected db.statement to be captured by default; spans=%+v", spans)
	}
}

func TestOpen_FailingQueryRecordsErrorOnSpan(t *testing.T) {
	traceExp, _, cleanup := setup(t)
	defer cleanup()

	db, err := dbtelem.Open(enabledCfg(), "sqlite3", ":memory:", "sqlite")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer db.Close()

	// Reference a table that doesn't exist so the driver returns an error.
	_, _ = db.ExecContext(context.Background(), "SELECT * FROM nope_does_not_exist")

	sawError := false
	for _, sp := range traceExp.GetSpans() {
		if sp.Status.Code.String() == "Error" {
			sawError = true
			break
		}
		for _, ev := range sp.Events {
			if ev.Name == "exception" {
				sawError = true
				break
			}
		}
	}
	if !sawError {
		t.Errorf("expected at least one span to record the query error; spans=%+v", traceExp.GetSpans())
	}
}

func TestOpen_DisableStatementOmitsQuery(t *testing.T) {
	traceExp, _, cleanup := setup(t)
	defer cleanup()

	cfg := enabledCfg()
	cfg.Database.DisableStatement = true

	db, err := dbtelem.Open(cfg, "sqlite3", ":memory:", "sqlite")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer db.Close()

	if _, err := db.ExecContext(context.Background(), "CREATE TABLE t (id INTEGER PRIMARY KEY)"); err != nil {
		t.Fatalf("create: %v", err)
	}

	for _, sp := range traceExp.GetSpans() {
		for _, a := range sp.Attributes {
			if string(a.Key) == "db.statement" || string(a.Key) == "db.query.text" {
				t.Errorf("DisableStatement=true: span %q still has %s=%q", sp.Name, a.Key, a.Value.AsString())
			}
		}
	}
}

func TestOpen_DisabledReturnsPlainDB(t *testing.T) {
	traceExp, reader, cleanup := setup(t)
	defer cleanup()

	cfg := telemetry.Config{Enabled: false}

	db, err := dbtelem.Open(cfg, "sqlite3", ":memory:", "sqlite")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer db.Close()

	if _, err := db.ExecContext(context.Background(), "CREATE TABLE t (id INTEGER PRIMARY KEY)"); err != nil {
		t.Fatalf("create: %v", err)
	}

	if spans := traceExp.GetSpans(); len(spans) != 0 {
		t.Errorf("disabled telemetry emitted %d spans, want 0", len(spans))
	}
	if names := metricNames(collect(t, reader)); len(names) != 0 {
		t.Errorf("disabled telemetry emitted metrics %v, want none", names)
	}
}

func TestRegisterPoolMetrics_EmitsConnectionGauges(t *testing.T) {
	_, reader, cleanup := setup(t)
	defer cleanup()

	db, err := dbtelem.Open(enabledCfg(), "sqlite3", ":memory:", "sqlite")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer db.Close()

	if err := dbtelem.RegisterPoolMetrics(enabledCfg(), db, "sqlite", attribute.String("pool", "primary")); err != nil {
		t.Fatalf("RegisterPoolMetrics: %v", err)
	}

	// Force the pool to materialize at least one connection so the gauges
	// have something to report.
	if err := db.PingContext(context.Background()); err != nil {
		t.Fatalf("ping: %v", err)
	}

	// XSAM/otelsql emits pool metrics under db.sql.connection.* names
	// rather than the semconv db.client.connections.* names. Verify that
	// at least the core "open" and "max_open" gauges are present.
	rm := collect(t, reader)
	want := []string{"db.sql.connection.open", "db.sql.connection.max_open"}
	for _, name := range want {
		if !metricSeen(rm, name) {
			t.Errorf("missing %q in pool metrics: %v", name, metricNames(rm))
		}
	}
}

func TestRegisterPoolMetrics_DisabledIsNoOp(t *testing.T) {
	_, reader, cleanup := setup(t)
	defer cleanup()

	cfg := telemetry.Config{Enabled: false}
	db, err := dbtelem.Open(cfg, "sqlite3", ":memory:", "sqlite")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer db.Close()

	if err := dbtelem.RegisterPoolMetrics(cfg, db, "sqlite"); err != nil {
		t.Errorf("RegisterPoolMetrics(disabled) returned %v, want nil", err)
	}
	if err := db.PingContext(context.Background()); err != nil {
		t.Fatalf("ping: %v", err)
	}

	if names := metricNames(collect(t, reader)); len(names) != 0 {
		t.Errorf("disabled pool metrics emitted %v, want none", names)
	}
}

// helpers

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
	for _, n := range metricNames(rm) {
		if n == name {
			return true
		}
	}
	return false
}
