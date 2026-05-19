package response

import (
	stdlog "log"
	"net/http"
	"os"
	"time"

	"github.com/RichardKnop/go-oauth2-server/log"
	"github.com/gorilla/mux"
)

// Logger is the legacy negroni-style URL access logger. It is kept for
// backwards-compatibility; new code should use NewURLLoggerMiddleware
// (a mux middleware) so the log record can pick up the OTel span from
// r.Context() and inherit trace_id / span_id.
type Logger struct {
	*stdlog.Logger
}

// NewURLLogger returns a Logger configured for use as a negroni middleware.
func NewURLLogger() *Logger {
	return &Logger{stdlog.New(os.Stdout, "[negroni] ", 0)}
}

func (l *Logger) ServeHTTP(rw http.ResponseWriter, r *http.Request, next http.HandlerFunc) {
	sr := &statusWriter{ResponseWriter: rw, status: http.StatusOK}
	logRequest(sr, r, next.ServeHTTP)
}

// URLLoggerMiddleware returns a mux.MiddlewareFunc that emits structured
// "request started" / "request finished" records via the package slog
// logger.
//
// Mount via router.Use(...) AFTER any tracing middleware so r.Context()
// carries the active span and the slog handler can stamp trace_id /
// span_id onto each record.
func URLLoggerMiddleware() mux.MiddlewareFunc {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			sr := &statusWriter{ResponseWriter: w, status: http.StatusOK}
			logRequest(sr, r, next.ServeHTTP)
		})
	}
}

func logRequest(w *statusWriter, r *http.Request, next http.HandlerFunc) {
	start := time.Now()
	ip := r.RemoteAddr
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		ip = xff
	}

	logger := log.FromContext(r.Context())
	logger.InfoContext(r.Context(), "request started",
		"method", r.Method, "path", r.URL.Path, "client_ip", ip)

	next(w, r)

	status := w.status
	args := []any{
		"method", r.Method,
		"path", r.URL.Path,
		"status", status,
		"duration_ms", float64(time.Since(start)) / float64(time.Millisecond),
	}
	switch {
	case status < 400:
		logger.InfoContext(r.Context(), "request finished", args...)
	case status < 500:
		logger.WarnContext(r.Context(), "request finished", args...)
	default:
		logger.ErrorContext(r.Context(), "request finished", args...)
	}
}

// statusWriter wraps an http.ResponseWriter to capture the status code so
// the URL logger can include it on the "request finished" record.
type statusWriter struct {
	http.ResponseWriter
	status      int
	wroteHeader bool
}

func (s *statusWriter) WriteHeader(code int) {
	if !s.wroteHeader {
		s.status = code
		s.wroteHeader = true
	}
	s.ResponseWriter.WriteHeader(code)
}

func (s *statusWriter) Write(b []byte) (int, error) {
	if !s.wroteHeader {
		s.wroteHeader = true
	}
	return s.ResponseWriter.Write(b)
}
