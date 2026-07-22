package config

import (
	"testing"

	"github.com/RichardKnop/go-oauth2-server/telemetry"
)

func TestTelemetryOptionsApplyTo(t *testing.T) {
	cfg := &Config{}

	TelemetryOptions{
		Enabled:     true,
		Endpoint:    "otel-collector:4317",
		Protocol:    telemetry.ProtocolHTTP,
		ServiceName: "go-oauth2-server-test",
		Insecure:    true,
	}.ApplyTo(cfg)

	if !cfg.Telemetry.Enabled {
		t.Fatalf("expected telemetry enabled")
	}
	if cfg.Telemetry.Exporter.Endpoint != "otel-collector:4317" {
		t.Fatalf("unexpected endpoint %q", cfg.Telemetry.Exporter.Endpoint)
	}
	if cfg.Telemetry.Exporter.Protocol != telemetry.ProtocolHTTP {
		t.Fatalf("unexpected protocol %q", cfg.Telemetry.Exporter.Protocol)
	}
	if cfg.Telemetry.Resource.ServiceName != "go-oauth2-server-test" {
		t.Fatalf("unexpected service name %q", cfg.Telemetry.Resource.ServiceName)
	}
	if !cfg.Telemetry.Exporter.Insecure {
		t.Fatalf("expected insecure transport")
	}
}

func TestTelemetryOptionsZeroLeavesConfigUnchanged(t *testing.T) {
	cfg := &Config{}
	cfg.Telemetry.Enabled = true
	cfg.Telemetry.Exporter.Endpoint = "configured:4317"

	TelemetryOptions{}.ApplyTo(cfg)

	if !cfg.Telemetry.Enabled {
		t.Fatalf("zero options should not disable telemetry")
	}
	if cfg.Telemetry.Exporter.Endpoint != "configured:4317" {
		t.Fatalf("zero options changed endpoint to %q", cfg.Telemetry.Exporter.Endpoint)
	}
}
