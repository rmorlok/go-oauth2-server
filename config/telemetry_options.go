package config

// TelemetryOptions are CLI/env overrides for OpenTelemetry export settings.
// Zero values leave the loaded config unchanged.
type TelemetryOptions struct {
	Enabled     bool
	Endpoint    string
	Protocol    string
	ServiceName string
	Insecure    bool
}

// ApplyTo overlays explicitly supplied telemetry options onto cfg.
func (opts TelemetryOptions) ApplyTo(cfg *Config) {
	if opts.Enabled {
		cfg.Telemetry.Enabled = true
	}
	if opts.Endpoint != "" {
		cfg.Telemetry.Exporter.Endpoint = opts.Endpoint
	}
	if opts.Protocol != "" {
		cfg.Telemetry.Exporter.Protocol = opts.Protocol
	}
	if opts.ServiceName != "" {
		cfg.Telemetry.Resource.ServiceName = opts.ServiceName
	}
	if opts.Insecure {
		cfg.Telemetry.Exporter.Insecure = true
	}
}
