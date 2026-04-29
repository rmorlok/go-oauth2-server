package testmode

import (
	"encoding/json"
	"net/http"

	"github.com/RichardKnop/go-oauth2-server/util/response"
)

type enqueueScriptRequest struct {
	ClientID string   `json:"client_id"`
	Endpoint string   `json:"endpoint"`
	Actions  []Action `json:"actions"`
}

var validScriptEndpoints = map[string]struct{}{
	"token":      {},
	"refresh":    {},
	"revoke":     {},
	"resource":   {},
	"introspect": {},
	"userinfo":   {},
}

// enqueueScript implements POST /test/scripts.
func (s *Service) enqueueScript(w http.ResponseWriter, r *http.Request) {
	var req enqueueScriptRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		response.Error(w, "invalid JSON body: "+err.Error(), http.StatusBadRequest)
		return
	}
	if req.Endpoint == "" {
		response.Error(w, "endpoint is required", http.StatusBadRequest)
		return
	}
	if _, ok := validScriptEndpoints[req.Endpoint]; !ok {
		response.Error(w, "unknown endpoint: "+req.Endpoint, http.StatusBadRequest)
		return
	}
	if len(req.Actions) == 0 {
		response.Error(w, "at least one action is required", http.StatusBadRequest)
		return
	}
	for _, a := range req.Actions {
		if a.BodyTemplate != "" {
			if _, ok := templateAction(a.BodyTemplate); !ok {
				response.Error(w, "unknown body_template: "+a.BodyTemplate, http.StatusBadRequest)
				return
			}
		}
	}

	s.queue.Enqueue(req.ClientID, req.Endpoint, req.Actions)
	response.NoContent(w)
}

// listScripts implements GET /test/scripts.
func (s *Service) listScripts(w http.ResponseWriter, r *http.Request) {
	response.WriteJSON(w, s.queue.Snapshot(), http.StatusOK)
}

// clearScripts implements DELETE /test/scripts.
func (s *Service) clearScripts(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	s.queue.Clear(q.Get("client_id"), q.Get("endpoint"))
	response.NoContent(w)
}
