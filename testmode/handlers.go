package testmode

import (
	"encoding/json"
	"net/http"

	"github.com/RichardKnop/go-oauth2-server/log"
	"github.com/RichardKnop/go-oauth2-server/oauth/roles"
	"github.com/RichardKnop/go-oauth2-server/util/response"
)

type createClientRequest struct {
	Key         string `json:"key"`
	Secret      string `json:"secret"`
	RedirectURI string `json:"redirect_uri"`

	// Accepted but not yet enforced; reserved for PR-3 / PR-8.
	Scope                   string `json:"scope,omitempty"`
	TokenEndpointAuthMethod string `json:"token_endpoint_auth_method,omitempty"`
}

type clientResponse struct {
	ID          string `json:"id"`
	Key         string `json:"key"`
	RedirectURI string `json:"redirect_uri,omitempty"`
}

func (s *Service) createClient(w http.ResponseWriter, r *http.Request) {
	var req createClientRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		response.Error(w, "invalid JSON body: "+err.Error(), http.StatusBadRequest)
		return
	}
	if req.Key == "" {
		response.Error(w, "key is required", http.StatusBadRequest)
		return
	}
	if req.Scope != "" || req.TokenEndpointAuthMethod != "" {
		log.INFO.Printf("testmode: /test/clients received scope=%q token_endpoint_auth_method=%q "+
			"(accepted but not yet enforced; see PR-3, PR-8)",
			req.Scope, req.TokenEndpointAuthMethod)
	}

	client, err := s.oauthService.CreateClient(req.Key, req.Secret, req.RedirectURI)
	if err != nil {
		response.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	response.WriteJSON(w, clientResponse{
		ID:          client.ID,
		Key:         client.Key,
		RedirectURI: client.RedirectURI.String,
	}, http.StatusCreated)
}

type createUserRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Role     string `json:"role"`
}

type userResponse struct {
	ID       string `json:"id"`
	Username string `json:"username"`
	Role     string `json:"role"`
}

func (s *Service) createUser(w http.ResponseWriter, r *http.Request) {
	var req createUserRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		response.Error(w, "invalid JSON body: "+err.Error(), http.StatusBadRequest)
		return
	}
	if req.Username == "" {
		response.Error(w, "username is required", http.StatusBadRequest)
		return
	}
	role := req.Role
	if role == "" {
		role = roles.User
	}

	user, err := s.oauthService.CreateUser(role, req.Username, req.Password)
	if err != nil {
		response.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	response.WriteJSON(w, userResponse{
		ID:       user.ID,
		Username: user.Username,
		Role:     user.RoleID.String,
	}, http.StatusCreated)
}

func (s *Service) health(w http.ResponseWriter, r *http.Request) {
	response.WriteJSON(w, map[string]string{
		"status": "ok",
		"mode":   "test",
	}, http.StatusOK)
}
