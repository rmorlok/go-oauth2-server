package oauth

import (
	"errors"
	"net/http"

	"github.com/RichardKnop/go-oauth2-server/models"
	"github.com/RichardKnop/go-oauth2-server/util/response"
)

// userinfoRequiredScopes are the scopes that satisfy /v1/oauth/userinfo.
// Tokens that do not have at least one of these in their granted scope
// receive 403 insufficient_scope.
const userinfoRequiredScopes = "profile email"

// UserinfoResponse is the JSON returned by /v1/oauth/userinfo. Empty
// fields are omitted so callers can distinguish "not set" from "empty
// string".
type UserinfoResponse struct {
	Sub               string `json:"sub"`
	Email             string `json:"email,omitempty"`
	PreferredUsername string `json:"preferred_username,omitempty"`
	Name              string `json:"name,omitempty"`
}

// userinfoHandler handles GET (and POST) /v1/oauth/userinfo. Per RFC 7662
// §2.1 the endpoint is bearer-authenticated; the access token must have
// at least one of the userinfoRequiredScopes.
func (s *Service) userinfoHandler(w http.ResponseWriter, r *http.Request) {
	ctx, span := s.telem.StartUserinfo(r.Context())
	defer span.End()

	token, errDesc := ExtractBearerToken(r)
	if errDesc != "" {
		err := errors.New(errDesc)
		s.telem.FinishWithError(span, err, "invalid_token")
		s.telem.RecordUserinfo(ctx, err, "invalid_token")
		WriteBearerError(w, http.StatusUnauthorized, "invalid_token", errDesc, "", "")
		return
	}

	accessToken, err := s.Authenticate(token)
	if err != nil {
		s.telem.FinishWithError(span, err, "invalid_token")
		s.telem.RecordUserinfo(ctx, err, "invalid_token")
		WriteBearerError(w, http.StatusUnauthorized, "invalid_token", err.Error(), "", "")
		return
	}

	if !HasAnyScope(accessToken.Scope, userinfoRequiredScopes) {
		err := errors.New("insufficient_scope")
		s.telem.FinishWithError(span, err, "insufficient_scope")
		s.telem.RecordUserinfo(ctx, err, "insufficient_scope")
		WriteBearerError(w, http.StatusForbidden, "insufficient_scope",
			"token does not include profile or email scope", "", userinfoRequiredScopes)
		return
	}

	if !accessToken.UserID.Valid {
		err := errors.New("insufficient_scope")
		s.telem.FinishWithError(span, err, "insufficient_scope")
		s.telem.RecordUserinfo(ctx, err, "insufficient_scope")
		WriteBearerError(w, http.StatusForbidden, "insufficient_scope",
			"token is not associated with a user", "", "")
		return
	}

	user := new(models.OauthUser)
	if s.db.Where("id = ?", accessToken.UserID.String).First(user).RecordNotFound() {
		err := errors.New("invalid_token")
		s.telem.FinishWithError(span, err, "invalid_token")
		s.telem.RecordUserinfo(ctx, err, "invalid_token")
		WriteBearerError(w, http.StatusUnauthorized, "invalid_token", "user not found", "", "")
		return
	}

	resp := UserinfoResponse{
		Sub:               user.ID,
		PreferredUsername: user.Username,
	}
	if user.SubOverride.Valid && user.SubOverride.String != "" {
		resp.Sub = user.SubOverride.String
	}
	if user.Email.Valid {
		resp.Email = user.Email.String
	}
	if user.DisplayName.Valid {
		resp.Name = user.DisplayName.String
	}
	s.telem.RecordUserinfo(ctx, nil, "")
	response.WriteJSON(w, resp, http.StatusOK)
}
