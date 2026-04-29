package testmode

import (
	"bytes"
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/RichardKnop/go-oauth2-server/log"
	"github.com/RichardKnop/go-oauth2-server/oauth"
)

// scriptMiddleware applies queued Actions to incoming requests bound for
// recordable OAuth endpoints.
type scriptMiddleware struct {
	queue *ScriptQueue
}

func (m *scriptMiddleware) ServeHTTP(w http.ResponseWriter, r *http.Request, next http.HandlerFunc) {
	_ = r.ParseForm()
	endpoint := classifyEndpoint(r.URL.Path, r.PostForm)
	if endpoint == "" {
		next(w, r)
		return
	}

	clientID := extractClientID(r, r.PostForm)
	action, ok := m.queue.Pop(clientID, endpoint)
	if !ok {
		next(w, r)
		return
	}
	action = resolveTemplate(action)

	if action.DelayMS > 0 {
		time.Sleep(time.Duration(action.DelayMS) * time.Millisecond)
	}

	if action.DropConnection {
		hj, ok := w.(http.Hijacker)
		if !ok {
			log.ERROR.Print("testmode: drop_connection requested but writer is not a Hijacker")
			http.Error(w, "drop_connection unsupported on this writer", http.StatusInternalServerError)
			return
		}
		conn, _, err := hj.Hijack()
		if err != nil {
			log.ERROR.Printf("testmode: hijack failed: %v", err)
			return
		}
		_ = conn.Close()
		return
	}

	// Pass-through actions: stamp PKCE-skip onto the request context if
	// requested, then run the real handler (possibly with scope rewrite).
	if action.Status == 0 {
		if action.SkipPKCECheck {
			r = r.WithContext(oauth.WithSkipPKCE(r.Context()))
		}
		if action.ScopeOverride != nil {
			applyScopeOverride(w, r, next, *action.ScopeOverride)
			return
		}
		if action.Body == "" {
			next(w, r)
			return
		}
		// fall through to full-replacement path below — body without
		// status implies a 200 with that body.
	}

	// Full replacement.
	for k, v := range action.Headers {
		w.Header().Set(k, v)
	}
	if w.Header().Get("Content-Type") == "" {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
	}
	if w.Header().Get("Content-Length") == "" {
		w.Header().Set("Content-Length", strconv.Itoa(len(action.Body)))
	}
	status := action.Status
	if status == 0 {
		status = http.StatusOK
	}
	w.WriteHeader(status)
	_, _ = w.Write([]byte(action.Body))
}

// applyScopeOverride runs next() against a buffering writer, then rewrites
// the JSON body's `scope` field. An empty override removes the field.
func applyScopeOverride(w http.ResponseWriter, r *http.Request, next http.HandlerFunc, override string) {
	bw := &bufferingWriter{header: http.Header{}, body: &bytes.Buffer{}}
	next(bw, r)

	// Try to parse the body as JSON object and rewrite `scope`.
	var obj map[string]any
	if err := json.Unmarshal(bw.body.Bytes(), &obj); err == nil {
		if override == "" {
			delete(obj, "scope")
		} else {
			obj["scope"] = override
		}
		newBody, _ := json.Marshal(obj)
		// Copy headers but override Content-Length.
		for k, vs := range bw.header {
			for _, v := range vs {
				w.Header().Add(k, v)
			}
		}
		w.Header().Set("Content-Length", strconv.Itoa(len(newBody)))
		status := bw.status
		if status == 0 {
			status = http.StatusOK
		}
		w.WriteHeader(status)
		_, _ = w.Write(newBody)
		return
	}

	// Body wasn't JSON — pass through verbatim.
	for k, vs := range bw.header {
		for _, v := range vs {
			w.Header().Add(k, v)
		}
	}
	status := bw.status
	if status == 0 {
		status = http.StatusOK
	}
	w.WriteHeader(status)
	_, _ = w.Write(bw.body.Bytes())
}

// bufferingWriter captures status, headers, and body so a middleware can
// post-process the downstream handler's response.
type bufferingWriter struct {
	header      http.Header
	status      int
	body        *bytes.Buffer
	wroteHeader bool
}

func (b *bufferingWriter) Header() http.Header { return b.header }

func (b *bufferingWriter) WriteHeader(code int) {
	if b.wroteHeader {
		return
	}
	b.status = code
	b.wroteHeader = true
}

func (b *bufferingWriter) Write(p []byte) (int, error) {
	if !b.wroteHeader {
		b.WriteHeader(http.StatusOK)
	}
	return b.body.Write(p)
}
