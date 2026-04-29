package testmode

import (
	"encoding/json"
	"net/http"

	"github.com/RichardKnop/go-oauth2-server/models"
	"github.com/RichardKnop/go-oauth2-server/util"
	"github.com/RichardKnop/go-oauth2-server/util/response"
	"github.com/gorilla/mux"
)

type identityRequest struct {
	Sub         *string `json:"sub,omitempty"`
	Email       *string `json:"email,omitempty"`
	DisplayName *string `json:"display_name,omitempty"`
}

type identityResponse struct {
	ID          string `json:"id"`
	Username    string `json:"username"`
	Email       string `json:"email,omitempty"`
	DisplayName string `json:"display_name,omitempty"`
	Sub         string `json:"sub,omitempty"`
}

// updateIdentity implements POST /test/users/{id}/identity. Only fields
// present in the request body are updated; missing fields are left alone.
// Pass an explicit empty string to clear a field.
func (s *Service) updateIdentity(w http.ResponseWriter, r *http.Request) {
	userID := mux.Vars(r)["id"]
	if userID == "" {
		response.Error(w, "user id required", http.StatusBadRequest)
		return
	}

	var req identityRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		response.Error(w, "invalid JSON body: "+err.Error(), http.StatusBadRequest)
		return
	}

	user := new(models.OauthUser)
	if s.db.Where("id = ?", userID).First(user).RecordNotFound() {
		response.Error(w, "user not found", http.StatusNotFound)
		return
	}

	updates := map[string]interface{}{}
	if req.Email != nil {
		updates["email"] = util.StringOrNull(*req.Email)
	}
	if req.DisplayName != nil {
		updates["display_name"] = util.StringOrNull(*req.DisplayName)
	}
	if req.Sub != nil {
		updates["sub_override"] = util.StringOrNull(*req.Sub)
	}
	if len(updates) > 0 {
		if err := s.db.Model(user).Updates(updates).Error; err != nil {
			response.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}

	// Re-read so the response reflects what was actually persisted.
	s.db.Where("id = ?", userID).First(user)
	response.WriteJSON(w, marshalIdentity(user), http.StatusOK)
}

type swapSubjectRequest struct {
	NewSub string `json:"new_sub"`
}

// swapSubject implements POST /test/users/{id}/swap-subject. Stronger
// variant of identity update that only touches sub_override. Empty string
// clears the override (userinfo falls back to the user's UUID).
func (s *Service) swapSubject(w http.ResponseWriter, r *http.Request) {
	userID := mux.Vars(r)["id"]
	if userID == "" {
		response.Error(w, "user id required", http.StatusBadRequest)
		return
	}

	var req swapSubjectRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		response.Error(w, "invalid JSON body: "+err.Error(), http.StatusBadRequest)
		return
	}

	user := new(models.OauthUser)
	if s.db.Where("id = ?", userID).First(user).RecordNotFound() {
		response.Error(w, "user not found", http.StatusNotFound)
		return
	}

	if err := s.db.Model(user).Update("sub_override", util.StringOrNull(req.NewSub)).Error; err != nil {
		response.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	s.db.Where("id = ?", userID).First(user)
	response.WriteJSON(w, marshalIdentity(user), http.StatusOK)
}

func marshalIdentity(user *models.OauthUser) identityResponse {
	resp := identityResponse{
		ID:       user.ID,
		Username: user.Username,
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
	return resp
}
