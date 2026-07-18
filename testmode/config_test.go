package testmode

import (
	"testing"

	"github.com/RichardKnop/go-oauth2-server/telemetry"
)

func TestNewConfigDefaultsLoadMode(t *testing.T) {
	cnf := NewConfig(":memory:")
	if !cnf.TestMode {
		t.Fatalf("expected test mode enabled")
	}
	if cnf.Oauth.SyntheticRefreshTokenPrefix != defaultSyntheticRefreshTokenPrefix {
		t.Fatalf("unexpected synthetic refresh prefix %q", cnf.Oauth.SyntheticRefreshTokenPrefix)
	}
	if cnf.Oauth.SyntheticRefreshScope != defaultSyntheticRefreshScope {
		t.Fatalf("unexpected synthetic refresh scope %q", cnf.Oauth.SyntheticRefreshScope)
	}
	if cnf.Telemetry.Enabled {
		t.Fatalf("telemetry should remain default-off without explicit opt-in")
	}
}

func TestNewConfigWithTelemetryOptions(t *testing.T) {
	cnf := NewConfigWithOptions(":memory:", ConfigOptions{
		TelemetryEnabled:     true,
		TelemetryEndpoint:    "otel-collector:4317",
		TelemetryProtocol:    telemetry.ProtocolHTTP,
		TelemetryServiceName: "go-oauth2-server-load",
		TelemetryInsecure:    true,
	})

	if !cnf.Telemetry.Enabled {
		t.Fatalf("expected telemetry enabled")
	}
	if cnf.Telemetry.Exporter.Endpoint != "otel-collector:4317" {
		t.Fatalf("unexpected telemetry endpoint %q", cnf.Telemetry.Exporter.Endpoint)
	}
	if cnf.Telemetry.Exporter.Protocol != telemetry.ProtocolHTTP {
		t.Fatalf("expected explicit http/protobuf protocol, got %q", cnf.Telemetry.Exporter.Protocol)
	}
	if cnf.Telemetry.Resource.ServiceName != "go-oauth2-server-load" {
		t.Fatalf("unexpected service name %q", cnf.Telemetry.Resource.ServiceName)
	}
	if !cnf.Telemetry.Exporter.Insecure {
		t.Fatalf("expected insecure OTLP transport")
	}
}
