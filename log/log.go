// Package log is the application's structured logging entry point.
//
// It wraps log/slog with two small affordances:
//
//   - A package-level default logger constructed lazily from environment
//     variables (LOG_LEVEL, LOG_FORMAT) so any code that imports this
//     package can log immediately, without a setup step.
//   - Init(Options) lets the binary entry point apply config-driven
//     settings (level, format, output, dev flag) once, after config has
//     loaded. Init is idempotent — calling it again replaces the handler.
//
// All call sites use the slog.Logger returned by Default(); never grab
// slog.Default() directly, since this package configures its own logger
// rather than mutating the slog default.
package log

import (
	"context"
	"io"
	"log/slog"
	"os"
	"strings"
	"sync"
)

// Format identifies the output encoder for the slog handler.
type Format string

const (
	// FormatText emits human-readable key=value lines via slog.TextHandler.
	FormatText Format = "text"
	// FormatJSON emits one JSON object per record via slog.JSONHandler.
	FormatJSON Format = "json"
)

// Options configures the package logger. Zero values resolve to sensible
// defaults: Level=info, Format=text in dev / json in prod, Output=stderr.
type Options struct {
	// Level controls minimum severity. Accepts "debug", "info", "warn",
	// "error" (case-insensitive). Empty falls back to LOG_LEVEL env, then
	// info / debug-in-dev.
	Level string

	// Format selects "text" or "json". Empty falls back to LOG_FORMAT env,
	// then "text" if IsDevelopment else "json".
	Format Format

	// IsDevelopment toggles dev-friendly defaults (text format + debug
	// level when nothing else is specified).
	IsDevelopment bool

	// Output is where records are written. nil means os.Stderr.
	Output io.Writer

	// AddSource adds source file + line info to each record. Defaults to
	// IsDevelopment so prod logs stay compact.
	AddSource bool
}

var (
	mu     sync.RWMutex
	logger *slog.Logger = buildLogger(Options{})
)

// Default returns the package logger. Always non-nil.
//
// Use this in preference to slog.Default(); we configure our own logger
// rather than mutating slog's global so libraries pulling slog.Default()
// for trace correlation see a clean baseline.
func Default() *slog.Logger {
	mu.RLock()
	defer mu.RUnlock()
	return logger
}

// Init replaces the package logger with one built from opts. Idempotent
// and safe to call concurrently.
func Init(opts Options) {
	l := buildLogger(opts)
	mu.Lock()
	logger = l
	mu.Unlock()
}

// Set installs a fully built logger. Useful in tests; production code
// should prefer Init.
func Set(l *slog.Logger) {
	if l == nil {
		l = buildLogger(Options{})
	}
	mu.Lock()
	logger = l
	mu.Unlock()
}

// With returns a logger with additional attributes pre-attached.
func With(args ...any) *slog.Logger {
	return Default().With(args...)
}

// FromContext returns the logger attached to ctx by ContextWith, or the
// package default if none is attached. Always non-nil.
func FromContext(ctx context.Context) *slog.Logger {
	if ctx == nil {
		return Default()
	}
	if v := ctx.Value(loggerCtxKey{}); v != nil {
		if l, ok := v.(*slog.Logger); ok && l != nil {
			return l
		}
	}
	return Default()
}

// ContextWith returns a child context carrying l. Handlers can attach a
// per-request logger (e.g. one already enriched with request_id) and
// downstream code retrieves it via FromContext.
func ContextWith(ctx context.Context, l *slog.Logger) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithValue(ctx, loggerCtxKey{}, l)
}

// Debug / Info / Warn / Error are thin pass-throughs to the package
// logger so call sites can stay terse: log.Info("...", "key", val).
func Debug(msg string, args ...any) { Default().Debug(msg, args...) }
func Info(msg string, args ...any)  { Default().Info(msg, args...) }
func Warn(msg string, args ...any)  { Default().Warn(msg, args...) }
func Error(msg string, args ...any) { Default().Error(msg, args...) }

// Fatal logs at error level then calls os.Exit(1). Preferred for
// startup-time fatal errors only; do not use inside request handlers.
func Fatal(msg string, args ...any) {
	Default().Error(msg, args...)
	os.Exit(1)
}

type loggerCtxKey struct{}

func buildLogger(o Options) *slog.Logger {
	level := resolveLevel(o)
	format := resolveFormat(o)
	out := o.Output
	if out == nil {
		out = os.Stderr
	}
	addSource := o.AddSource || o.IsDevelopment

	handlerOpts := &slog.HandlerOptions{Level: level, AddSource: addSource}

	var h slog.Handler
	switch format {
	case FormatJSON:
		h = slog.NewJSONHandler(out, handlerOpts)
	default:
		h = slog.NewTextHandler(out, handlerOpts)
	}
	return slog.New(h)
}

func resolveLevel(o Options) slog.Level {
	v := strings.TrimSpace(o.Level)
	if v == "" {
		v = os.Getenv("LOG_LEVEL")
	}
	switch strings.ToLower(v) {
	case "debug":
		return slog.LevelDebug
	case "info":
		return slog.LevelInfo
	case "warn", "warning":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	}
	if o.IsDevelopment {
		return slog.LevelDebug
	}
	return slog.LevelInfo
}

func resolveFormat(o Options) Format {
	v := strings.TrimSpace(string(o.Format))
	if v == "" {
		v = strings.TrimSpace(os.Getenv("LOG_FORMAT"))
	}
	switch strings.ToLower(v) {
	case "json":
		return FormatJSON
	case "text", "console":
		return FormatText
	}
	if o.IsDevelopment {
		return FormatText
	}
	return FormatJSON
}
