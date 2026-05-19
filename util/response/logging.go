package response

import (
	stdlog "log"
	"net/http"
	"os"
	"time"

	"github.com/RichardKnop/go-oauth2-server/log"
	"github.com/urfave/negroni"
)

// Logger is a middleware handler that logs the request as it goes in and
// the response as it goes out. It keeps the embedded *stdlog.Logger field
// for backwards compatibility with callers that constructed it directly;
// the actual log records go through the package slog logger.
type Logger struct {
	*stdlog.Logger
}

// NewURLLogger returns a new Logger instance.
func NewURLLogger() *Logger {
	return &Logger{stdlog.New(os.Stdout, "[negroni] ", 0)}
}

func (l *Logger) ServeHTTP(rw http.ResponseWriter, r *http.Request, next http.HandlerFunc) {
	start := time.Now()
	ip := r.RemoteAddr
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		ip = xff
	}

	logger := log.FromContext(r.Context())
	logger.Info("request started", "method", r.Method, "path", r.URL.Path, "client_ip", ip)

	next(rw, r)

	res := rw.(negroni.ResponseWriter)
	status := res.Status()
	args := []any{
		"method", r.Method,
		"path", r.URL.Path,
		"status", status,
		"duration_ms", float64(time.Since(start)) / float64(time.Millisecond),
	}
	switch {
	case status < 400:
		logger.Info("request finished", args...)
	case status < 500:
		logger.Warn("request finished", args...)
	default:
		logger.Error("request finished", args...)
	}
}
