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

