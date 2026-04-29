package testmode

import (
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// DefaultRecorderCapacity is the maximum number of requests retained.
const DefaultRecorderCapacity = 1000

// RecordedRequest is a sanitized snapshot of a request that hit a recorded
// endpoint. Secrets are redacted; the Authorization header preserves the
// scheme so tests can assert on auth method without leaking credentials.
type RecordedRequest struct {
	Timestamp time.Time           `json:"timestamp"`
	Method    string              `json:"method"`
	Path      string              `json:"path"`
	Endpoint  string              `json:"endpoint"`
	ClientID  string              `json:"client_id,omitempty"`
	Headers   map[string]string   `json:"headers"`
	Query     map[string][]string `json:"query,omitempty"`
	Form      map[string][]string `json:"form,omitempty"`
}

// Recorder is a bounded, thread-safe ring buffer of RecordedRequest.
type Recorder struct {
	mu       sync.Mutex
	cap      int
	entries  []RecordedRequest
	inserted int
}

// NewRecorder constructs a Recorder with the given capacity. Capacity <= 0
// uses DefaultRecorderCapacity.
func NewRecorder(capacity int) *Recorder {
	if capacity <= 0 {
		capacity = DefaultRecorderCapacity
	}
	return &Recorder{cap: capacity, entries: make([]RecordedRequest, 0, capacity)}
}

// Record appends an entry, dropping the oldest when at capacity.
func (r *Recorder) Record(entry RecordedRequest) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.inserted++
	if len(r.entries) < r.cap {
		r.entries = append(r.entries, entry)
		return
	}
	// Shift left and append.
	copy(r.entries, r.entries[1:])
	r.entries[len(r.entries)-1] = entry
}

// Snapshot returns a copy of recorded entries, optionally filtered.
type SnapshotFilter struct {
	Endpoint string
	ClientID string
	Since    time.Time
}

// Snapshot returns matching entries in chronological order.
func (r *Recorder) Snapshot(f SnapshotFilter) []RecordedRequest {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]RecordedRequest, 0, len(r.entries))
	for _, e := range r.entries {
		if f.Endpoint != "" && e.Endpoint != f.Endpoint {
			continue
		}
		if f.ClientID != "" && e.ClientID != f.ClientID {
			continue
		}
		if !f.Since.IsZero() && e.Timestamp.Before(f.Since) {
			continue
		}
		out = append(out, e)
	}
	return out
}

// Reset clears all recorded entries (test helper).
func (r *Recorder) Reset() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.entries = r.entries[:0]
	r.inserted = 0
}

// classifyEndpoint maps a request path (and form for token/refresh) to an
// endpoint label. Returns the empty string for paths that should not be
// recorded.
func classifyEndpoint(path string, form url.Values) string {
	switch {
	case path == "/v1/oauth/tokens":
		if form.Get("grant_type") == "refresh_token" {
			return "refresh"
		}
		return "token"
	case path == "/v1/oauth/introspect":
		return "introspect"
	case path == "/v1/oauth/revoke":
		return "revoke"
	case path == "/v1/oauth/userinfo":
		return "userinfo"
	case path == "/test/resource" || strings.HasPrefix(path, "/test/resource/"):
		return "resource"
	default:
		return ""
	}
}

// redactedFormFields are stripped from recorded requests. Authorization
// header values are also redacted (scheme preserved) by sanitizeHeaders.
var redactedFormFields = map[string]struct{}{
	"client_secret": {},
	"password":      {},
	"code_verifier": {},
	"refresh_token": {},
}

// sanitizeHeaders copies headers, redacts Authorization values to keep just
// the scheme, and drops cookies.
func sanitizeHeaders(h http.Header) map[string]string {
	out := make(map[string]string, len(h))
	for name, values := range h {
		canonical := http.CanonicalHeaderKey(name)
		switch canonical {
		case "Cookie", "Set-Cookie":
			continue
		case "Authorization":
			if len(values) == 0 {
				continue
			}
			parts := strings.SplitN(values[0], " ", 2)
			if len(parts) == 2 && parts[1] != "" {
				out[canonical] = parts[0] + " <redacted>"
			} else {
				out[canonical] = "<redacted>"
			}
		default:
			out[canonical] = strings.Join(values, ", ")
		}
	}
	return out
}

// sanitizeForm copies form values and redacts known credential fields.
func sanitizeForm(form url.Values) map[string][]string {
	if len(form) == 0 {
		return nil
	}
	out := make(map[string][]string, len(form))
	for k, v := range form {
		if _, redact := redactedFormFields[strings.ToLower(k)]; redact {
			out[k] = []string{"<redacted>"}
			continue
		}
		out[k] = append([]string(nil), v...)
	}
	return out
}

// extractClientID pulls a client identifier from Basic auth or form fields,
// preferring Basic auth (the spec authenticates clients there).
func extractClientID(r *http.Request, form url.Values) string {
	if user, _, ok := r.BasicAuth(); ok && user != "" {
		return user
	}
	return form.Get("client_id")
}

// recorderMiddleware is a negroni-compatible middleware that records every
// request whose path classifyEndpoint recognizes.
type recorderMiddleware struct {
	rec *Recorder
}

func (m *recorderMiddleware) ServeHTTP(w http.ResponseWriter, r *http.Request, next http.HandlerFunc) {
	// Parsing the form here is safe: ParseForm caches r.PostForm/r.Form, so
	// downstream handlers calling it again are no-ops. ParseForm only reads
	// the body for application/x-www-form-urlencoded requests, which is
	// what the OAuth endpoints use.
	_ = r.ParseForm()

	endpoint := classifyEndpoint(r.URL.Path, r.PostForm)
	if endpoint == "" {
		next(w, r)
		return
	}

	entry := RecordedRequest{
		Timestamp: time.Now().UTC(),
		Method:    r.Method,
		Path:      r.URL.Path,
		Endpoint:  endpoint,
		ClientID:  extractClientID(r, r.PostForm),
		Headers:   sanitizeHeaders(r.Header),
		Query:     map[string][]string(r.URL.Query()),
		Form:      sanitizeForm(r.PostForm),
	}
	m.rec.Record(entry)
	next(w, r)
}
