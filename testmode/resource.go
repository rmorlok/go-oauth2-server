package testmode

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"

	"github.com/RichardKnop/go-oauth2-server/util/response"
)

// resourcePolicies holds registered scope requirements keyed by exact path
// (e.g. "/test/resource/admin"). Tests register entries via
// POST /test/resource-policy.
type resourcePolicies struct {
	mu    sync.RWMutex
	rules map[string]string // path -> required scope (space-separated)
}

func newResourcePolicies() *resourcePolicies {
	return &resourcePolicies{rules: make(map[string]string)}
}

func (p *resourcePolicies) set(path, scope string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.rules[path] = scope
}

func (p *resourcePolicies) get(path string) (string, bool) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	s, ok := p.rules[path]
	return s, ok
}

func (p *resourcePolicies) clear() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.rules = make(map[string]string)
}

// resourceHandler implements ANY /test/resource/{path}. The script
// middleware runs first, so by the time we get here any queued action has
// either replaced the response or fallen through.
//
// Auth: Bearer token in Authorization header. Token must be a valid
// (unexpired, unrevoked) access token. Returns 401 invalid_token otherwise.
//
// Scope: if a policy is registered for this path, every required scope
// must be present in the token's scopes. Mismatch returns 403
// insufficient_scope.
//
// Default body: 200 with {sub, client_id, scope, path}. The recorder
// captures the inbound request automatically.
func (s *Service) resourceHandler(w http.ResponseWriter, r *http.Request) {
	auth := r.Header.Get("Authorization")
	if auth == "" {
		writeBearerError(w, http.StatusUnauthorized, "invalid_token", "missing Authorization header", "")
		return
	}
	parts := strings.SplitN(auth, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") || parts[1] == "" {
		writeBearerError(w, http.StatusUnauthorized, "invalid_token", "Authorization header must be 'Bearer <token>'", "")
		return
	}

	accessToken, err := s.oauthService.Authenticate(parts[1])
	if err != nil {
		writeBearerError(w, http.StatusUnauthorized, "invalid_token", err.Error(), "")
		return
	}

	if required, ok := s.resourcePolicies.get(r.URL.Path); ok {
		if !hasAllScopes(accessToken.Scope, required) {
			writeBearerError(w, http.StatusForbidden, "insufficient_scope", "token does not have required scope(s)", required)
			return
		}
	}

	body := map[string]any{
		"sub":       accessToken.UserID.String,
		"client_id": accessToken.ClientID.String,
		"scope":     accessToken.Scope,
		"path":      r.URL.Path,
	}
	if r.Method != http.MethodGet && r.Method != "" {
		body["method"] = r.Method
	}
	response.WriteJSON(w, body, http.StatusOK)
}

// resourcePolicyRequest is the body of POST /test/resource-policy.
type resourcePolicyRequest struct {
	Path          string `json:"path"`
	RequiredScope string `json:"required_scope"`
}

// resourcePolicyHandler implements POST /test/resource-policy.
func (s *Service) resourcePolicyHandler(w http.ResponseWriter, r *http.Request) {
	var req resourcePolicyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		response.Error(w, "invalid JSON body: "+err.Error(), http.StatusBadRequest)
		return
	}
	if req.Path == "" {
		response.Error(w, "path is required", http.StatusBadRequest)
		return
	}
	if !strings.HasPrefix(req.Path, "/test/resource/") {
		response.Error(w, "path must start with /test/resource/", http.StatusBadRequest)
		return
	}
	s.resourcePolicies.set(req.Path, req.RequiredScope)
	response.NoContent(w)
}

// hasAllScopes reports whether every space-separated scope in `required`
// is also present in `granted`.
func hasAllScopes(granted, required string) bool {
	if required == "" {
		return true
	}
	grantedSet := make(map[string]struct{})
	for _, s := range strings.Fields(granted) {
		grantedSet[s] = struct{}{}
	}
	for _, want := range strings.Fields(required) {
		if _, ok := grantedSet[want]; !ok {
			return false
		}
	}
	return true
}

// writeBearerError writes an RFC 6750 §3 WWW-Authenticate response.
func writeBearerError(w http.ResponseWriter, status int, code, description, scope string) {
	parts := []string{`realm="test"`}
	if code != "" {
		parts = append(parts, fmt.Sprintf(`error="%s"`, code))
	}
	if description != "" {
		parts = append(parts, fmt.Sprintf(`error_description="%s"`, sanitizeHeaderValue(description)))
	}
	if scope != "" {
		parts = append(parts, fmt.Sprintf(`scope="%s"`, scope))
	}
	w.Header().Set("WWW-Authenticate", "Bearer "+strings.Join(parts, ", "))
	response.Error(w, code, status)
}

// sanitizeHeaderValue strips characters that would break the
// WWW-Authenticate quoted-string. Test-mode only; cheap and safe.
func sanitizeHeaderValue(s string) string {
	r := strings.NewReplacer(`"`, `'`, "\r", " ", "\n", " ")
	return r.Replace(s)
}
