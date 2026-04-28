package testmode

import (
	"encoding/json"
	"net/http"

	"github.com/RichardKnop/go-oauth2-server/util/response"
)

type rotatePolicyRequest struct {
	Rotation *bool `json:"rotation"`
}

type rotatePolicyResponse struct {
	Rotation bool `json:"rotation"`
}

// rotatePolicy implements POST /test/refresh-tokens/rotate-policy. It mutates
// the in-memory config so subsequent refresh-token grants either rotate or
// reuse the existing refresh token. This is test-mode only.
func (s *Service) rotatePolicy(w http.ResponseWriter, r *http.Request) {
	var req rotatePolicyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		response.Error(w, "invalid JSON body: "+err.Error(), http.StatusBadRequest)
		return
	}
	if req.Rotation == nil {
		response.Error(w, "rotation field is required", http.StatusBadRequest)
		return
	}
	s.cnf.Oauth.RefreshTokenRotation = *req.Rotation
	response.WriteJSON(w, rotatePolicyResponse{Rotation: *req.Rotation}, http.StatusOK)
}
