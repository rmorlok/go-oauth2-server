package telemetry

import (
	"context"
	"testing"
	"time"
)

func TestNoOp_FieldsAreNonNilAndShutdownNoErr(t *testing.T) {
	p := NoOp()
	if p.TracerProvider == nil || p.MeterProvider == nil || p.LoggerProvider == nil {
		t.Fatalf("NoOp() returned nil provider field: %+v", p)
	}
	if err := p.Shutdown(context.Background()); err != nil {
		t.Errorf("NoOp().Shutdown returned %v, want nil", err)
	}
}

func TestInit_DisabledReturnsNoOp(t *testing.T) {
	p, err := Init(context.Background(), Config{Enabled: false})
	if err != nil {
		t.Fatalf("Init(disabled) error = %v, want nil", err)
	}
	if p.TracerProvider == nil || p.MeterProvider == nil || p.LoggerProvider == nil {
		t.Fatalf("Init(disabled) returned nil provider field: %+v", p)
	}
	if err := p.Shutdown(context.Background()); err != nil {
		t.Errorf("Shutdown returned %v, want nil", err)
	}
}

func TestInit_InvalidConfigReturnsError(t *testing.T) {
	cfg := Config{
		Enabled:  true,
		Exporter: Exporter{Protocol: "wat", Endpoint: "http://x:4317"},
		Resource: Resource{ServiceName: "svc"},
	}
	_, err := Init(context.Background(), cfg)
	if err == nil {
		t.Fatalf("Init with bad protocol = nil error, want validation error")
	}
}

func TestInit_AllSignalsDisabledReturnsNoOpButValid(t *testing.T) {
	f := false
	cfg := Config{
		Enabled:  true,
		Exporter: Exporter{Protocol: ProtocolGRPC, Endpoint: "http://localhost:4317", Insecure: true},
		Resource: Resource{ServiceName: "svc"},
		Signals:  Signals{Traces: &f, Metrics: &f, Logs: &f},
		Shutdown: Shutdown{Timeout: 250 * time.Millisecond},
	}
	p, err := Init(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Init = %v, want nil", err)
	}
	if p.TracerProvider == nil || p.MeterProvider == nil || p.LoggerProvider == nil {
		t.Fatalf("Init returned nil provider field: %+v", p)
	}
	if err := p.Shutdown(context.Background()); err != nil {
		t.Errorf("Shutdown returned %v, want nil", err)
	}
}

func TestInit_ShutdownRespectsConfigTimeout(t *testing.T) {
	f := false
	cfg := Config{
		Enabled:  true,
		Exporter: Exporter{Protocol: ProtocolGRPC, Endpoint: "http://localhost:4317", Insecure: true},
		Resource: Resource{ServiceName: "svc"},
		Signals:  Signals{Traces: &f, Metrics: &f, Logs: &f},
		Shutdown: Shutdown{Timeout: 25 * time.Millisecond},
	}
	p, err := Init(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Init = %v, want nil", err)
	}
	// Shutdown should return quickly because we disabled all signals.
	start := time.Now()
	if err := p.Shutdown(context.Background()); err != nil {
		t.Errorf("Shutdown returned %v, want nil", err)
	}
	if elapsed := time.Since(start); elapsed > 250*time.Millisecond {
		t.Errorf("Shutdown took %v, expected near-instant", elapsed)
	}
}

func TestServiceInstanceID_PrefersHostnameEnv(t *testing.T) {
	t.Setenv("HOSTNAME", "test-host-7")
	if got, want := serviceInstanceID(), "test-host-7"; got != want {
		t.Errorf("serviceInstanceID() = %q, want %q", got, want)
	}
}

func TestIsOn(t *testing.T) {
	tr, fa := true, false
	if !isOn(nil) {
		t.Errorf("isOn(nil) = false, want true (nil means default-on)")
	}
	if !isOn(&tr) {
		t.Errorf("isOn(&true) = false, want true")
	}
	if isOn(&fa) {
		t.Errorf("isOn(&false) = true, want false")
	}
}
