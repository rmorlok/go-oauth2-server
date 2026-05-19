package telemetry

import (
	"fmt"
	"os"
	"strings"
	"time"
)

const (
	ProtocolGRPC = "grpc"
	ProtocolHTTP = "http/protobuf"

	DefaultServiceName     = "go-oauth2-server"
	DefaultGRPCEndpoint    = "http://localhost:4317"
	DefaultHTTPEndpoint    = "http://localhost:4318"
	DefaultSamplingRatio   = 1.0
	DefaultShutdownTimeout = 5 * time.Second

	// DefaultExcludedPath is the only path excluded from telemetry by default.
	// Test-mode paths under /test/* are deliberately NOT excluded — load
	// tests against the test-mode harness should see those endpoints.
	DefaultExcludedPath = "/v1/health"
)

// Config is the top-level telemetry configuration block. It is embedded in
// config.Config and serialized as JSON when stored in etcd/consul.
//
// When Enabled is false (or this block is absent from the config entirely),
// Init returns no-op providers and never opens a network connection.
type Config struct {
	Enabled  bool     `json:"enabled"`
	Exporter Exporter `json:"exporter"`
	Resource Resource `json:"resource"`
	Sampling Sampling `json:"sampling"`
	Signals  Signals  `json:"signals"`
	HTTP     HTTP     `json:"http"`
	Database Database `json:"database,omitempty"`
	OAuth    OAuth    `json:"oauth,omitempty"`
	Shutdown Shutdown `json:"shutdown"`
}

// OAuth holds telemetry settings specific to the OAuth lifecycle.
// IncludeClientID controls whether the oauth.client_id label appears on
// counters; deployments with very high client cardinality can disable it.
// A nil pointer means "use default" (true).
type OAuth struct {
	IncludeClientID *bool `json:"include_client_id,omitempty"`
}

// Database holds telemetry settings specific to database/sql instrumentation.
type Database struct {
	// DisableStatement omits db.statement from emitted spans entirely.
	// Useful for deployments where even parameterized SQL is considered
	// sensitive. Bind values are never captured regardless of this setting.
	DisableStatement bool `json:"disable_statement,omitempty"`
}

// Exporter describes the OTLP exporter configuration. Empty fields are
// resolved against standard OTEL_EXPORTER_OTLP_* environment variables and
// then sensible defaults.
type Exporter struct {
	Protocol string            `json:"protocol"` // "grpc" | "http/protobuf"
	Endpoint string            `json:"endpoint"`
	Headers  map[string]string `json:"headers"`
	Insecure bool              `json:"insecure"`
}

// Resource describes resource-level attributes attached to every signal.
type Resource struct {
	ServiceName string            `json:"service_name"`
	Attributes  map[string]string `json:"attributes"`
}

// Sampling controls head-based trace sampling. A nil Ratio means "use
// default" (1.0, sample everything). 0.0 explicitly drops everything.
type Sampling struct {
	Ratio *float64 `json:"ratio,omitempty"`
}

// Signals toggles individual signal pipelines. A nil pointer means "use
// default" (enabled). Setting any to false skips that signal's provider
// entirely — the OTel global for that signal remains the no-op default.
type Signals struct {
	Traces  *bool `json:"traces,omitempty"`
	Metrics *bool `json:"metrics,omitempty"`
	Logs    *bool `json:"logs,omitempty"`
}

// HTTP holds telemetry settings specific to inbound HTTP traffic.
// ExcludedPaths supports a trailing "*" wildcard (e.g., "/test/*").
type HTTP struct {
	ExcludedPaths []string `json:"excluded_paths,omitempty"`
}

// Shutdown configures clean shutdown behavior.
type Shutdown struct {
	Timeout time.Duration `json:"timeout,omitempty"`
}

// ApplyDefaults fills unset fields with sensible defaults, honoring
// standard OTEL_* environment variables. Values already present in c
// take precedence; env variables fill gaps; defaults fill what env
// doesn't supply.
func (c *Config) ApplyDefaults() {
	c.applyResourceDefaults()
	c.applyExporterDefaults()
	c.applySamplingDefaults()
	c.applySignalDefaults()
	c.applyHTTPDefaults()
	c.applyOAuthDefaults()
	c.applyShutdownDefaults()
}

func (c *Config) applyOAuthDefaults() {
	if c.OAuth.IncludeClientID == nil {
		v := true
		c.OAuth.IncludeClientID = &v
	}
}

func (c *Config) applyResourceDefaults() {
	if c.Resource.ServiceName == "" {
		if v := os.Getenv("OTEL_SERVICE_NAME"); v != "" {
			c.Resource.ServiceName = v
		} else {
			c.Resource.ServiceName = DefaultServiceName
		}
	}
	if c.Resource.Attributes == nil {
		c.Resource.Attributes = map[string]string{}
	}
	// OTEL_RESOURCE_ATTRIBUTES — comma-separated key=value pairs.
	// Config-provided keys win over env to preserve YAML-over-env precedence.
	if v := os.Getenv("OTEL_RESOURCE_ATTRIBUTES"); v != "" {
		for _, pair := range strings.Split(v, ",") {
			kv := strings.SplitN(strings.TrimSpace(pair), "=", 2)
			if len(kv) != 2 {
				continue
			}
			k, val := strings.TrimSpace(kv[0]), strings.TrimSpace(kv[1])
			if k == "" {
				continue
			}
			if _, exists := c.Resource.Attributes[k]; !exists {
				c.Resource.Attributes[k] = val
			}
		}
	}
}

func (c *Config) applyExporterDefaults() {
	if c.Exporter.Protocol == "" {
		if v := os.Getenv("OTEL_EXPORTER_OTLP_PROTOCOL"); v != "" {
			c.Exporter.Protocol = v
		} else {
			c.Exporter.Protocol = ProtocolGRPC
		}
	}
	if c.Exporter.Endpoint == "" {
		if v := os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT"); v != "" {
			c.Exporter.Endpoint = v
		} else if c.Exporter.Protocol == ProtocolHTTP {
			c.Exporter.Endpoint = DefaultHTTPEndpoint
		} else {
			c.Exporter.Endpoint = DefaultGRPCEndpoint
		}
	}
	if c.Exporter.Headers == nil {
		c.Exporter.Headers = map[string]string{}
	}
	if v := os.Getenv("OTEL_EXPORTER_OTLP_HEADERS"); v != "" {
		for _, pair := range strings.Split(v, ",") {
			kv := strings.SplitN(strings.TrimSpace(pair), "=", 2)
			if len(kv) != 2 {
				continue
			}
			k, val := strings.TrimSpace(kv[0]), strings.TrimSpace(kv[1])
			if k == "" {
				continue
			}
			if _, exists := c.Exporter.Headers[k]; !exists {
				c.Exporter.Headers[k] = val
			}
		}
	}
}

func (c *Config) applySamplingDefaults() {
	if c.Sampling.Ratio == nil {
		r := DefaultSamplingRatio
		c.Sampling.Ratio = &r
	}
}

func (c *Config) applySignalDefaults() {
	if c.Signals.Traces == nil {
		v := true
		c.Signals.Traces = &v
	}
	if c.Signals.Metrics == nil {
		v := true
		c.Signals.Metrics = &v
	}
	if c.Signals.Logs == nil {
		v := true
		c.Signals.Logs = &v
	}
}

func (c *Config) applyHTTPDefaults() {
	if c.HTTP.ExcludedPaths == nil {
		c.HTTP.ExcludedPaths = []string{DefaultExcludedPath}
	}
}

func (c *Config) applyShutdownDefaults() {
	if c.Shutdown.Timeout == 0 {
		c.Shutdown.Timeout = DefaultShutdownTimeout
	}
}

// Validate checks the resolved configuration for sanity. Only called when
// Enabled is true; a disabled block is always valid (it's a no-op).
func (c *Config) Validate() error {
	if !c.Enabled {
		return nil
	}
	switch c.Exporter.Protocol {
	case ProtocolGRPC, ProtocolHTTP:
	case "":
		return fmt.Errorf("telemetry: exporter.protocol is required when enabled")
	default:
		return fmt.Errorf("telemetry: exporter.protocol must be %q or %q, got %q",
			ProtocolGRPC, ProtocolHTTP, c.Exporter.Protocol)
	}
	if c.Exporter.Endpoint == "" {
		return fmt.Errorf("telemetry: exporter.endpoint is required when enabled")
	}
	if c.Sampling.Ratio != nil {
		r := *c.Sampling.Ratio
		if r < 0 || r > 1 {
			return fmt.Errorf("telemetry: sampling.ratio must be in [0.0, 1.0], got %g", r)
		}
	}
	if c.Resource.ServiceName == "" {
		return fmt.Errorf("telemetry: resource.service_name is required when enabled")
	}
	return nil
}

// IsExcluded reports whether path matches any configured exclusion pattern.
// Patterns either match exactly or, with a trailing "*", match as a prefix
// (e.g., "/test/*" matches "/test/clients").
func (c *Config) IsExcluded(path string) bool {
	for _, p := range c.HTTP.ExcludedPaths {
		if matchPath(p, path) {
			return true
		}
	}
	return false
}

func matchPath(pattern, path string) bool {
	if strings.HasSuffix(pattern, "/*") {
		prefix := strings.TrimSuffix(pattern, "*")
		return strings.HasPrefix(path, prefix)
	}
	return pattern == path
}
