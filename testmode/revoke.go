package testmode

import (
	"encoding/json"
	"net/http"

	"github.com/RichardKnop/go-oauth2-server/util/response"
)

type adminRevokeRequest struct {
	Token    string `json:"token,omitempty"`
	UserID   string `json:"user_id,omitempty"`
	ClientID string `json:"client_id,omitempty"`
}

type adminRevokeResponse struct {
	Found         bool  `json:"found,omitempty"`
	RefreshTokens int64 `json:"refresh_tokens_revoked,omitempty"`
	AccessTokens  int64 `json:"access_tokens_revoked,omitempty"`
}

// adminRevoke implements POST /test/revoke. It exists so a test harness can
// simulate provider-side revocation without going through the production
// /v1/oauth/revoke handler (no client auth, no ownership checks).
//
// Exactly one of token / user_id / client_id must be set.
func (s *Service) adminRevoke(w http.ResponseWriter, r *http.Request) {
	var req adminRevokeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		response.Error(w, "invalid JSON body: "+err.Error(), http.StatusBadRequest)
		return
	}

	set := 0
	if req.Token != "" {
		set++
	}
	if req.UserID != "" {
		set++
	}
	if req.ClientID != "" {
		set++
	}
	if set != 1 {
		response.Error(w, "exactly one of token, user_id, client_id must be set", http.StatusBadRequest)
		return
	}

	switch {
	case req.Token != "":
		found, err := s.oauthService.AdminRevokeByToken(req.Token)
		if err != nil {
			response.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		response.WriteJSON(w, adminRevokeResponse{Found: found}, http.StatusOK)
	case req.UserID != "":
		rt, at, err := s.oauthService.AdminRevokeByUser(req.UserID)
		if err != nil {
			response.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		response.WriteJSON(w, adminRevokeResponse{RefreshTokens: rt, AccessTokens: at}, http.StatusOK)
	case req.ClientID != "":
		// Client lookup: caller passes the client ID (UUID). For convenience
		// we also accept the client key (the public identifier used for
		// OAuth) and resolve it.
		resolved, err := s.resolveClientID(req.ClientID)
		if err != nil {
			response.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		rt, at, err := s.oauthService.AdminRevokeByClient(resolved)
		if err != nil {
			response.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		response.WriteJSON(w, adminRevokeResponse{RefreshTokens: rt, AccessTokens: at}, http.StatusOK)
	}
}

// resolveClientID accepts either a database ID (UUID) or the client's
// public Key and returns the database ID.
func (s *Service) resolveClientID(idOrKey string) (string, error) {
	client, err := s.oauthService.FindClientByClientID(idOrKey)
	if err == nil {
		return client.ID, nil
	}
	// Not a key — assume it's already an ID.
	return idOrKey, nil
}
