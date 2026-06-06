package testmode

import (
	"encoding/json"
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

// apiKeyResourcePolicies holds test-mode API key requirements keyed by exact
// path (e.g. "/test/api-key-resource/demo"). Tests register entries via
// POST /test/api-key-resource-policy.
type apiKeyResourcePolicies struct {
	mu    sync.RWMutex
	rules map[string]apiKeyResourcePolicy // path -> expected key + placement
}

type apiKeyResourcePolicy struct {
	Path       string `json:"path"`
	Key        string `json:"key"`
	Placement  string `json:"placement,omitempty"`
	HeaderName string `json:"header_name,omitempty"`
	Prefix     string `json:"prefix,omitempty"`
}

func newResourcePolicies() *resourcePolicies {
	return &resourcePolicies{rules: make(map[string]string)}
}

func newAPIKeyResourcePolicies() *apiKeyResourcePolicies {
	return &apiKeyResourcePolicies{rules: make(map[string]apiKeyResourcePolicy)}
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

func (p *apiKeyResourcePolicies) set(policy apiKeyResourcePolicy) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.rules[policy.Path] = policy
}

func (p *apiKeyResourcePolicies) get(path string) (apiKeyResourcePolicy, bool) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	policy, ok := p.rules[path]
	return policy, ok
}

func (p *apiKeyResourcePolicies) clear() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.rules = make(map[string]apiKeyResourcePolicy)
}

// resourceHandler implements ANY /test/resource/{path} in test mode.
// Delegates to oauth.ServeSampleResource for bearer auth + body, with
// the per-path scope policy registered via /test/resource-policy.
//
// The script middleware runs first, so any queued action has already
// either replaced the response or fallen through by the time we get
// here. The recorder captures the inbound request automatically.
func (s *Service) resourceHandler(w http.ResponseWriter, r *http.Request) {
	s.oauthService.ServeSampleResource(w, r, "test", s.resourcePolicies.get)
}

func (s *Service) apiKeyResourceHandler(w http.ResponseWriter, r *http.Request) {
	policy, ok := s.apiKeyResourcePolicies.get(r.URL.Path)
	if !ok {
		policy = apiKeyResourcePolicy{
			Path:       r.URL.Path,
			Key:        "demo-api-key",
			Placement:  "bearer",
			HeaderName: "Authorization",
			Prefix:     "Bearer ",
		}
	}

	if !apiKeyResourceAuthorized(r, policy) {
		w.Header().Set("WWW-Authenticate", `Bearer realm="test-api-key", error="invalid_token"`)
		response.Error(w, "invalid or missing API key", http.StatusUnauthorized)
		return
	}

	response.WriteJSON(w, map[string]any{
		"path":       r.URL.Path,
		"auth":       "api-key",
		"placement":  normalizedAPIKeyPlacement(policy),
		"headerName": policy.HeaderName,
	}, http.StatusOK)
}

func apiKeyResourceAuthorized(r *http.Request, policy apiKeyResourcePolicy) bool {
	switch normalizedAPIKeyPlacement(policy) {
	case "header":
		headerName := policy.HeaderName
		if headerName == "" {
			headerName = "X-API-Key"
		}
		prefix := policy.Prefix
		return r.Header.Get(headerName) == prefix+policy.Key
	default:
		return r.Header.Get("Authorization") == "Bearer "+policy.Key
	}
}

func normalizedAPIKeyPlacement(policy apiKeyResourcePolicy) string {
	if policy.Placement == "" {
		return "bearer"
	}
	return strings.ToLower(policy.Placement)
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

// apiKeyResourcePolicyHandler implements POST /test/api-key-resource-policy.
func (s *Service) apiKeyResourcePolicyHandler(w http.ResponseWriter, r *http.Request) {
	var req apiKeyResourcePolicy
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		response.Error(w, "invalid JSON body: "+err.Error(), http.StatusBadRequest)
		return
	}
	if req.Path == "" {
		response.Error(w, "path is required", http.StatusBadRequest)
		return
	}
	if !strings.HasPrefix(req.Path, "/test/api-key-resource/") {
		response.Error(w, "path must start with /test/api-key-resource/", http.StatusBadRequest)
		return
	}
	if req.Key == "" {
		response.Error(w, "key is required", http.StatusBadRequest)
		return
	}
	switch normalizedAPIKeyPlacement(req) {
	case "bearer":
		req.Placement = "bearer"
	case "header":
		req.Placement = "header"
		if req.HeaderName == "" {
			response.Error(w, "header_name is required for header placement", http.StatusBadRequest)
			return
		}
	default:
		response.Error(w, "placement must be bearer or header", http.StatusBadRequest)
		return
	}
	s.apiKeyResourcePolicies.set(req)
	response.NoContent(w)
}
