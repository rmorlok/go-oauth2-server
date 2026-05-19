package telemetry

import (
	"testing"
	"time"
)

func TestApplyDefaults_FillsDefaultsWhenUnset(t *testing.T) {
	t.Setenv("OTEL_SERVICE_NAME", "")
	t.Setenv("OTEL_RESOURCE_ATTRIBUTES", "")
	t.Setenv("OTEL_EXPORTER_OTLP_PROTOCOL", "")
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "")
	t.Setenv("OTEL_EXPORTER_OTLP_HEADERS", "")

	c := Config{}
	c.ApplyDefaults()

	if got, want := c.Resource.ServiceName, DefaultServiceName; got != want {
		t.Errorf("Resource.ServiceName = %q, want %q", got, want)
	}
	if got, want := c.Exporter.Protocol, ProtocolGRPC; got != want {
		t.Errorf("Exporter.Protocol = %q, want %q", got, want)
	}
	if got, want := c.Exporter.Endpoint, DefaultGRPCEndpoint; got != want {
		t.Errorf("Exporter.Endpoint = %q, want %q", got, want)
	}
	if c.Sampling.Ratio == nil || *c.Sampling.Ratio != DefaultSamplingRatio {
		t.Errorf("Sampling.Ratio = %v, want %v", c.Sampling.Ratio, DefaultSamplingRatio)
	}
	if c.Signals.Traces == nil || !*c.Signals.Traces {
		t.Errorf("Signals.Traces = %v, want true", c.Signals.Traces)
	}
	if c.Signals.Metrics == nil || !*c.Signals.Metrics {
		t.Errorf("Signals.Metrics = %v, want true", c.Signals.Metrics)
	}
	if c.Signals.Logs == nil || !*c.Signals.Logs {
		t.Errorf("Signals.Logs = %v, want true", c.Signals.Logs)
	}
	if c.Shutdown.Timeout != DefaultShutdownTimeout {
		t.Errorf("Shutdown.Timeout = %v, want %v", c.Shutdown.Timeout, DefaultShutdownTimeout)
	}
	if len(c.HTTP.ExcludedPaths) != 1 || c.HTTP.ExcludedPaths[0] != DefaultExcludedPath {
		t.Errorf("HTTP.ExcludedPaths = %v, want [%q]", c.HTTP.ExcludedPaths, DefaultExcludedPath)
	}
}

func TestApplyDefaults_HTTPProtocolPicksHTTPEndpoint(t *testing.T) {
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "")

	c := Config{Exporter: Exporter{Protocol: ProtocolHTTP}}
	c.ApplyDefaults()

	if got, want := c.Exporter.Endpoint, DefaultHTTPEndpoint; got != want {
		t.Errorf("Exporter.Endpoint = %q, want %q", got, want)
	}
}

func TestApplyDefaults_EnvFillsGaps(t *testing.T) {
	t.Setenv("OTEL_SERVICE_NAME", "env-service")
	t.Setenv("OTEL_EXPORTER_OTLP_PROTOCOL", ProtocolHTTP)
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://collector:4318")
	t.Setenv("OTEL_EXPORTER_OTLP_HEADERS", "x-team=auth,x-tier=core")
	t.Setenv("OTEL_RESOURCE_ATTRIBUTES", "deployment.environment=staging,region=us-east-1")

	c := Config{}
	c.ApplyDefaults()

	if got, want := c.Resource.ServiceName, "env-service"; got != want {
		t.Errorf("Resource.ServiceName = %q, want %q", got, want)
	}
	if got, want := c.Exporter.Protocol, ProtocolHTTP; got != want {
		t.Errorf("Exporter.Protocol = %q, want %q", got, want)
	}
	if got, want := c.Exporter.Endpoint, "http://collector:4318"; got != want {
		t.Errorf("Exporter.Endpoint = %q, want %q", got, want)
	}
	if got, want := c.Exporter.Headers["x-team"], "auth"; got != want {
		t.Errorf("Exporter.Headers[x-team] = %q, want %q", got, want)
	}
	if got, want := c.Exporter.Headers["x-tier"], "core"; got != want {
		t.Errorf("Exporter.Headers[x-tier] = %q, want %q", got, want)
	}
	if got, want := c.Resource.Attributes["deployment.environment"], "staging"; got != want {
		t.Errorf("Resource.Attributes[deployment.environment] = %q, want %q", got, want)
	}
	if got, want := c.Resource.Attributes["region"], "us-east-1"; got != want {
		t.Errorf("Resource.Attributes[region] = %q, want %q", got, want)
	}
}

func TestApplyDefaults_ConfigBeatsEnv(t *testing.T) {
	t.Setenv("OTEL_SERVICE_NAME", "env-service")
	t.Setenv("OTEL_EXPORTER_OTLP_PROTOCOL", ProtocolHTTP)
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://env-collector:4318")
	t.Setenv("OTEL_EXPORTER_OTLP_HEADERS", "x-team=env-team")
	t.Setenv("OTEL_RESOURCE_ATTRIBUTES", "region=env-region")

	c := Config{
		Exporter: Exporter{
			Protocol: ProtocolGRPC,
			Endpoint: "http://config-collector:4317",
			Headers:  map[string]string{"x-team": "config-team"},
		},
		Resource: Resource{
			ServiceName: "config-service",
			Attributes:  map[string]string{"region": "config-region"},
		},
	}
	c.ApplyDefaults()

	if got, want := c.Resource.ServiceName, "config-service"; got != want {
		t.Errorf("Resource.ServiceName = %q, want %q", got, want)
	}
	if got, want := c.Exporter.Protocol, ProtocolGRPC; got != want {
		t.Errorf("Exporter.Protocol = %q, want %q", got, want)
	}
	if got, want := c.Exporter.Endpoint, "http://config-collector:4317"; got != want {
		t.Errorf("Exporter.Endpoint = %q, want %q", got, want)
	}
	if got, want := c.Exporter.Headers["x-team"], "config-team"; got != want {
		t.Errorf("Exporter.Headers[x-team] = %q, want %q", got, want)
	}
	if got, want := c.Resource.Attributes["region"], "config-region"; got != want {
		t.Errorf("Resource.Attributes[region] = %q, want %q", got, want)
	}
}

func TestApplyDefaults_ZeroRatioIsHonored(t *testing.T) {
	zero := 0.0
	c := Config{Sampling: Sampling{Ratio: &zero}}
	c.ApplyDefaults()

	if c.Sampling.Ratio == nil || *c.Sampling.Ratio != 0.0 {
		t.Errorf("Sampling.Ratio = %v, want 0.0", c.Sampling.Ratio)
	}
}

func TestApplyDefaults_ExplicitFalseSignalsAreHonored(t *testing.T) {
	f := false
	c := Config{Signals: Signals{Traces: &f, Metrics: &f, Logs: &f}}
	c.ApplyDefaults()

	if c.Signals.Traces == nil || *c.Signals.Traces {
		t.Errorf("Signals.Traces = %v, want false", c.Signals.Traces)
	}
	if c.Signals.Metrics == nil || *c.Signals.Metrics {
		t.Errorf("Signals.Metrics = %v, want false", c.Signals.Metrics)
	}
	if c.Signals.Logs == nil || *c.Signals.Logs {
		t.Errorf("Signals.Logs = %v, want false", c.Signals.Logs)
	}
}

func TestValidate_DisabledIsAlwaysValid(t *testing.T) {
	c := Config{Enabled: false}
	if err := c.Validate(); err != nil {
		t.Errorf("Validate() on disabled config returned error: %v", err)
	}
}

func TestValidate_EnabledRequiresProtocolAndEndpoint(t *testing.T) {
	cases := []struct {
		name string
		c    Config
		want string
	}{
		{
			name: "missing protocol",
			c: Config{
				Enabled:  true,
				Resource: Resource{ServiceName: "svc"},
				Exporter: Exporter{Endpoint: "http://x:4317"},
			},
			want: "exporter.protocol",
		},
		{
			name: "bad protocol",
			c: Config{
				Enabled:  true,
				Resource: Resource{ServiceName: "svc"},
				Exporter: Exporter{Protocol: "udp", Endpoint: "http://x:4317"},
			},
			want: "exporter.protocol",
		},
		{
			name: "missing endpoint",
			c: Config{
				Enabled:  true,
				Resource: Resource{ServiceName: "svc"},
				Exporter: Exporter{Protocol: ProtocolGRPC},
			},
			want: "exporter.endpoint",
		},
		{
			name: "missing service name",
			c: Config{
				Enabled:  true,
				Exporter: Exporter{Protocol: ProtocolGRPC, Endpoint: "http://x:4317"},
			},
			want: "resource.service_name",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.c.Validate()
			if err == nil {
				t.Fatalf("Validate() = nil, want error containing %q", tc.want)
			}
			if !contains(err.Error(), tc.want) {
				t.Errorf("Validate() error = %q, want substring %q", err.Error(), tc.want)
			}
		})
	}
}

func TestValidate_RatioOutOfRange(t *testing.T) {
	neg, big := -0.1, 1.1
	for _, r := range []float64{neg, big} {
		c := Config{
			Enabled:  true,
			Exporter: Exporter{Protocol: ProtocolGRPC, Endpoint: "http://x:4317"},
			Resource: Resource{ServiceName: "svc"},
			Sampling: Sampling{Ratio: &r},
		}
		err := c.Validate()
		if err == nil {
			t.Errorf("Validate() with ratio=%g = nil, want error", r)
		}
	}
}

func TestValidate_RatioBoundariesAccepted(t *testing.T) {
	for _, r := range []float64{0.0, 0.5, 1.0} {
		ratio := r
		c := Config{
			Enabled:  true,
			Exporter: Exporter{Protocol: ProtocolGRPC, Endpoint: "http://x:4317"},
			Resource: Resource{ServiceName: "svc"},
			Sampling: Sampling{Ratio: &ratio},
		}
		if err := c.Validate(); err != nil {
			t.Errorf("Validate() with ratio=%g returned %v, want nil", r, err)
		}
	}
}

func TestIsExcluded(t *testing.T) {
	c := Config{HTTP: HTTP{ExcludedPaths: []string{"/v1/health", "/internal/*"}}}
	cases := []struct {
		path string
		want bool
	}{
		{"/v1/health", true},
		{"/v1/health/", false}, // exact-match pattern, trailing slash not matched
		{"/v1/oauth/token", false},
		{"/internal/", true},
		{"/internal/whatever/here", true},
		{"/test/clients", false}, // /test/* deliberately not excluded by default
	}
	for _, tc := range cases {
		if got := c.IsExcluded(tc.path); got != tc.want {
			t.Errorf("IsExcluded(%q) = %v, want %v", tc.path, got, tc.want)
		}
	}
}

func TestApplyShutdownDefaults_KeepsNonZero(t *testing.T) {
	c := Config{Shutdown: Shutdown{Timeout: 42 * time.Second}}
	c.ApplyDefaults()
	if c.Shutdown.Timeout != 42*time.Second {
		t.Errorf("Shutdown.Timeout = %v, want 42s", c.Shutdown.Timeout)
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || indexOf(s, substr) >= 0)
}

func indexOf(s, substr string) int {
	for i := 0; i+len(substr) <= len(s); i++ {
		if s[i:i+len(substr)] == substr {
			return i
		}
	}
	return -1
}
