package testmode

import (
	"encoding/json"
	"net/http"

	"github.com/RichardKnop/go-oauth2-server/log"
	"github.com/RichardKnop/go-oauth2-server/oauth/roles"
	"github.com/RichardKnop/go-oauth2-server/util"
	"github.com/RichardKnop/go-oauth2-server/util/response"
)

type createClientRequest struct {
	Key         string `json:"key"`
	Secret      string `json:"secret"`
	RedirectURI string `json:"redirect_uri"`

	// Accepted but not yet enforced; reserved for PR-3.
	Scope string `json:"scope,omitempty"`

	TokenEndpointAuthMethod string `json:"token_endpoint_auth_method,omitempty"`
	RequirePKCE             bool   `json:"require_pkce,omitempty"`
}

type clientResponse struct {
	ID                      string `json:"id"`
	Key                     string `json:"key"`
	RedirectURI             string `json:"redirect_uri,omitempty"`
	TokenEndpointAuthMethod string `json:"token_endpoint_auth_method,omitempty"`
	RequirePKCE             bool   `json:"require_pkce,omitempty"`
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
	if req.Scope != "" {
		log.INFO.Printf("testmode: /test/clients received scope=%q (accepted but not yet enforced; see PR-3)",
			req.Scope)
	}

	client, err := s.oauthService.CreateClient(req.Key, req.Secret, req.RedirectURI, req.TokenEndpointAuthMethod, req.RequirePKCE)
	if err != nil {
		response.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	response.WriteJSON(w, clientResponse{
		ID:                      client.ID,
		Key:                     client.Key,
		RedirectURI:             client.RedirectURI.String,
		TokenEndpointAuthMethod: client.TokenEndpointAuthMethod,
		RequirePKCE:             client.RequirePKCE,
	}, http.StatusCreated)
}

type createUserRequest struct {
	Username    string `json:"username"`
	Password    string `json:"password"`
	Role        string `json:"role"`
	Email       string `json:"email,omitempty"`
	DisplayName string `json:"display_name,omitempty"`
	Sub         string `json:"sub,omitempty"`
}

type userResponse struct {
	ID          string `json:"id"`
	Username    string `json:"username"`
	Role        string `json:"role"`
	Email       string `json:"email,omitempty"`
	DisplayName string `json:"display_name,omitempty"`
	Sub         string `json:"sub,omitempty"`
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

	// Apply identity attributes if any were supplied at creation time.
	updates := map[string]interface{}{}
	if req.Email != "" {
		updates["email"] = util.StringOrNull(req.Email)
	}
	if req.DisplayName != "" {
		updates["display_name"] = util.StringOrNull(req.DisplayName)
	}
	if req.Sub != "" {
		updates["sub_override"] = util.StringOrNull(req.Sub)
	}
	if len(updates) > 0 {
		if err := s.db.Model(user).Updates(updates).Error; err != nil {
			response.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		s.db.Where("id = ?", user.ID).First(user)
	}

	resp := userResponse{
		ID:       user.ID,
		Username: user.Username,
		Role:     user.RoleID.String,
	}
	if user.Email.Valid {
		resp.Email = user.Email.String
	}
	if user.DisplayName.Valid {
		resp.DisplayName = user.DisplayName.String
	}
	if user.SubOverride.Valid {
		resp.Sub = user.SubOverride.String
	}
	response.WriteJSON(w, resp, http.StatusCreated)
}

func (s *Service) health(w http.ResponseWriter, r *http.Request) {
	response.WriteJSON(w, map[string]string{
		"status": "ok",
		"mode":   "test",
	}, http.StatusOK)
}
