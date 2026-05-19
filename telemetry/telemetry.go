// Package telemetry bootstraps the OpenTelemetry SDK for go-oauth2-server.
//
// When telemetry is disabled (Config.Enabled == false), Init returns no-op
// providers and never touches the OTel globals or opens a network
// connection. This is the default state for existing deployments — they
// see zero behavioral change on upgrade until they opt in.
//
// When enabled, Init constructs trace, meter, and logger providers backed
// by OTLP exporters (gRPC or HTTP), sets them as OTel globals so any
// downstream library calling otel.Tracer / otel.Meter / global.GetLoggerProvider
// picks them up, and returns a Providers struct whose Shutdown closure
// flushes and stops every exporter within the configured timeout.
package telemetry

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/google/uuid"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlplog/otlploggrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlplog/otlploghttp"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetricgrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetrichttp"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	otellog "go.opentelemetry.io/otel/log"
	logglobal "go.opentelemetry.io/otel/log/global"
	lognoop "go.opentelemetry.io/otel/log/noop"
	"go.opentelemetry.io/otel/metric"
	metricnoop "go.opentelemetry.io/otel/metric/noop"
	"go.opentelemetry.io/otel/propagation"
	sdklog "go.opentelemetry.io/otel/sdk/log"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.40.0"
	"go.opentelemetry.io/otel/trace"
	tracenoop "go.opentelemetry.io/otel/trace/noop"
)

// ServiceVersion is the build-time version stamped into the resource. It
// defaults to "dev" and can be overridden via -ldflags at build time.
var ServiceVersion = "dev"

// Providers exposes the active telemetry signal providers. When telemetry
// is disabled, every field is a no-op implementation and Shutdown is a
// no-op. When enabled, each field is either a real SDK provider (if the
// signal is on) or a no-op (if that signal was individually disabled).
type Providers struct {
	TracerProvider trace.TracerProvider
	MeterProvider  metric.MeterProvider
	LoggerProvider otellog.LoggerProvider
	Shutdown       func(ctx context.Context) error
}

// NoOp returns a Providers whose every field is a no-op. Useful when
// telemetry is disabled or when tests want a deterministic, side-effect
// free set of providers.
func NoOp() *Providers {
	return &Providers{
		TracerProvider: tracenoop.NewTracerProvider(),
		MeterProvider:  metricnoop.NewMeterProvider(),
		LoggerProvider: lognoop.NewLoggerProvider(),
		Shutdown:       func(context.Context) error { return nil },
	}
}

// Init bootstraps the SDK from cfg. ApplyDefaults and Validate are called
// internally; callers should pass the raw config straight in.
//
// On success, the OTel globals are set so any code reaching for
// otel.GetTracerProvider() / otel.GetMeterProvider() / logglobal.GetLoggerProvider()
// picks up the configured providers. The W3C TraceContext + Baggage
// propagator pair is installed as the global text-map propagator so
// incoming traceparent headers are honored.
//
// When cfg.Enabled is false, Init returns a NoOp Providers and does not
// touch the OTel globals.
func Init(ctx context.Context, cfg Config) (*Providers, error) {
	cfg.ApplyDefaults()
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	if !cfg.Enabled {
		return NoOp(), nil
	}

	res, err := buildResource(ctx, cfg.Resource)
	if err != nil {
		return nil, fmt.Errorf("telemetry: build resource: %w", err)
	}

	providers := &Providers{
		TracerProvider: tracenoop.NewTracerProvider(),
		MeterProvider:  metricnoop.NewMeterProvider(),
		LoggerProvider: lognoop.NewLoggerProvider(),
	}
	var shutdowns []func(context.Context) error

	if isOn(cfg.Signals.Traces) {
		tp, tShutdown, err := buildTracerProvider(ctx, cfg, res)
		if err != nil {
			runShutdowns(ctx, shutdowns)
			return nil, fmt.Errorf("telemetry: build tracer provider: %w", err)
		}
		shutdowns = append(shutdowns, tShutdown)
		providers.TracerProvider = tp
		otel.SetTracerProvider(tp)
	}

	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{},
		propagation.Baggage{},
	))

	if isOn(cfg.Signals.Metrics) {
		mp, mShutdown, err := buildMeterProvider(ctx, cfg, res)
		if err != nil {
			runShutdowns(ctx, shutdowns)
			return nil, fmt.Errorf("telemetry: build meter provider: %w", err)
		}
		shutdowns = append(shutdowns, mShutdown)
		providers.MeterProvider = mp
		otel.SetMeterProvider(mp)
	}

	if isOn(cfg.Signals.Logs) {
		lp, lShutdown, err := buildLoggerProvider(ctx, cfg, res)
		if err != nil {
			runShutdowns(ctx, shutdowns)
			return nil, fmt.Errorf("telemetry: build logger provider: %w", err)
		}
		shutdowns = append(shutdowns, lShutdown)
		providers.LoggerProvider = lp
		logglobal.SetLoggerProvider(lp)
	}

	shutdownTimeout := cfg.Shutdown.Timeout
	providers.Shutdown = func(ctx context.Context) error {
		sctx, cancel := context.WithTimeout(ctx, shutdownTimeout)
		defer cancel()
		return runShutdowns(sctx, shutdowns)
	}
	return providers, nil
}

func isOn(b *bool) bool {
	return b == nil || *b
}

func buildResource(ctx context.Context, rc Resource) (*resource.Resource, error) {
	attrs := []attribute.KeyValue{
		semconv.ServiceName(rc.ServiceName),
		semconv.ServiceVersion(ServiceVersion),
		semconv.ServiceInstanceID(serviceInstanceID()),
	}
	for k, v := range rc.Attributes {
		attrs = append(attrs, attribute.String(k, v))
	}
	// resource.New merges options in order; later options override earlier
	// ones on key conflict. WithFromEnv loads OTEL_RESOURCE_ATTRIBUTES;
	// WithAttributes is applied after so explicit config keys win.
	return resource.New(ctx,
		resource.WithHost(),
		resource.WithOSType(),
		resource.WithProcessRuntimeName(),
		resource.WithProcessRuntimeVersion(),
		resource.WithProcessRuntimeDescription(),
		resource.WithFromEnv(),
		resource.WithAttributes(attrs...),
	)
}

func serviceInstanceID() string {
	if id := os.Getenv("HOSTNAME"); id != "" {
		return id
	}
	if id, err := os.Hostname(); err == nil && id != "" {
		return id
	}
	return uuid.NewString()
}

func buildTracerProvider(ctx context.Context, cfg Config, res *resource.Resource) (*sdktrace.TracerProvider, func(context.Context) error, error) {
	exporter, err := buildTraceExporter(ctx, cfg.Exporter)
	if err != nil {
		return nil, nil, err
	}
	ratio := DefaultSamplingRatio
	if cfg.Sampling.Ratio != nil {
		ratio = *cfg.Sampling.Ratio
	}
	sampler := sdktrace.ParentBased(sdktrace.TraceIDRatioBased(ratio))
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exporter),
		sdktrace.WithResource(res),
		sdktrace.WithSampler(sampler),
	)
	return tp, tp.Shutdown, nil
}

func buildTraceExporter(ctx context.Context, exp Exporter) (sdktrace.SpanExporter, error) {
	switch exp.Protocol {
	case ProtocolGRPC:
		opts := []otlptracegrpc.Option{otlptracegrpc.WithEndpointURL(exp.Endpoint)}
		if len(exp.Headers) > 0 {
			opts = append(opts, otlptracegrpc.WithHeaders(exp.Headers))
		}
		if exp.Insecure {
			opts = append(opts, otlptracegrpc.WithInsecure())
		}
		return otlptrace.New(ctx, otlptracegrpc.NewClient(opts...))
	case ProtocolHTTP:
		opts := []otlptracehttp.Option{otlptracehttp.WithEndpointURL(exp.Endpoint)}
		if len(exp.Headers) > 0 {
			opts = append(opts, otlptracehttp.WithHeaders(exp.Headers))
		}
		if exp.Insecure {
			opts = append(opts, otlptracehttp.WithInsecure())
		}
		return otlptrace.New(ctx, otlptracehttp.NewClient(opts...))
	default:
		return nil, fmt.Errorf("telemetry: unsupported exporter protocol %q", exp.Protocol)
	}
}

func buildMeterProvider(ctx context.Context, cfg Config, res *resource.Resource) (*sdkmetric.MeterProvider, func(context.Context) error, error) {
	exporter, err := buildMetricExporter(ctx, cfg.Exporter)
	if err != nil {
		return nil, nil, err
	}
	mp := sdkmetric.NewMeterProvider(
		sdkmetric.WithResource(res),
		sdkmetric.WithReader(sdkmetric.NewPeriodicReader(exporter)),
	)
	return mp, mp.Shutdown, nil
}

func buildMetricExporter(ctx context.Context, exp Exporter) (sdkmetric.Exporter, error) {
	switch exp.Protocol {
	case ProtocolGRPC:
		opts := []otlpmetricgrpc.Option{otlpmetricgrpc.WithEndpointURL(exp.Endpoint)}
		if len(exp.Headers) > 0 {
			opts = append(opts, otlpmetricgrpc.WithHeaders(exp.Headers))
		}
		if exp.Insecure {
			opts = append(opts, otlpmetricgrpc.WithInsecure())
		}
		return otlpmetricgrpc.New(ctx, opts...)
	case ProtocolHTTP:
		opts := []otlpmetrichttp.Option{otlpmetrichttp.WithEndpointURL(exp.Endpoint)}
		if len(exp.Headers) > 0 {
			opts = append(opts, otlpmetrichttp.WithHeaders(exp.Headers))
		}
		if exp.Insecure {
			opts = append(opts, otlpmetrichttp.WithInsecure())
		}
		return otlpmetrichttp.New(ctx, opts...)
	default:
		return nil, fmt.Errorf("telemetry: unsupported exporter protocol %q", exp.Protocol)
	}
}

func buildLoggerProvider(ctx context.Context, cfg Config, res *resource.Resource) (*sdklog.LoggerProvider, func(context.Context) error, error) {
	exporter, err := buildLogExporter(ctx, cfg.Exporter)
	if err != nil {
		return nil, nil, err
	}
	lp := sdklog.NewLoggerProvider(
		sdklog.WithResource(res),
		sdklog.WithProcessor(sdklog.NewBatchProcessor(exporter)),
	)
	return lp, lp.Shutdown, nil
}

func buildLogExporter(ctx context.Context, exp Exporter) (sdklog.Exporter, error) {
	switch exp.Protocol {
	case ProtocolGRPC:
		opts := []otlploggrpc.Option{otlploggrpc.WithEndpointURL(exp.Endpoint)}
		if len(exp.Headers) > 0 {
			opts = append(opts, otlploggrpc.WithHeaders(exp.Headers))
		}
		if exp.Insecure {
			opts = append(opts, otlploggrpc.WithInsecure())
		}
		return otlploggrpc.New(ctx, opts...)
	case ProtocolHTTP:
		opts := []otlploghttp.Option{otlploghttp.WithEndpointURL(exp.Endpoint)}
		if len(exp.Headers) > 0 {
			opts = append(opts, otlploghttp.WithHeaders(exp.Headers))
		}
		if exp.Insecure {
			opts = append(opts, otlploghttp.WithInsecure())
		}
		return otlploghttp.New(ctx, opts...)
	default:
		return nil, fmt.Errorf("telemetry: unsupported exporter protocol %q", exp.Protocol)
	}
}

// runShutdowns invokes every shutdown function with the same context and
// returns the combined error. All shutdowns run even if one fails, so the
// caller gets a complete picture of which signals flushed and which didn't.
func runShutdowns(ctx context.Context, shutdowns []func(context.Context) error) error {
	var errs []error
	for _, fn := range shutdowns {
		if err := fn(ctx); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}
