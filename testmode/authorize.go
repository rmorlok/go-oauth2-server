package testmode

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"time"

	"github.com/RichardKnop/go-oauth2-server/models"
	"github.com/RichardKnop/go-oauth2-server/oauth"
	"github.com/RichardKnop/go-oauth2-server/util/response"
)

// parseSince accepts RFC3339 or a Unix-second integer string for ergonomic
// cli/script use.
func parseSince(s string) (time.Time, error) {
	if t, err := time.Parse(time.RFC3339Nano, s); err == nil {
		return t, nil
	}
	return time.Parse(time.RFC3339, s)
}

type authorizeRequest struct {
	ClientID            string `json:"client_id"`
	UserID              string `json:"user_id"`
	Username            string `json:"username,omitempty"`
	RedirectURI         string `json:"redirect_uri"`
	Scope               string `json:"scope"`
	State               string `json:"state"`
	Decision            string `json:"decision"`
	GrantedScope        string `json:"granted_scope,omitempty"`
	CodeChallenge       string `json:"code_challenge,omitempty"`
	CodeChallengeMethod string `json:"code_challenge_method,omitempty"`
}

type authorizeResponse struct {
	RedirectURL string `json:"redirect_url"`
}

// authorize implements POST /test/authorize. It bypasses the HTML/session
// flow and produces the redirect URL the proxy would have followed after
// the user clicked approve or deny.
func (s *Service) authorize(w http.ResponseWriter, r *http.Request) {
	var req authorizeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		response.Error(w, "invalid JSON body: "+err.Error(), http.StatusBadRequest)
		return
	}
	if req.ClientID == "" {
		response.Error(w, "client_id is required", http.StatusBadRequest)
		return
	}
	if req.Decision != "approve" && req.Decision != "deny" {
		response.Error(w, `decision must be "approve" or "deny"`, http.StatusBadRequest)
		return
	}

	client, err := s.oauthService.FindClientByClientID(req.ClientID)
	if err != nil {
		response.Error(w, "client not found: "+req.ClientID, http.StatusNotFound)
		return
	}

	// Resolve redirect_uri: fall back to the client's registered URI
	// when the request omits it (mirrors /web/authorize behavior). When
	// both are present, they must match.
	redirectURI := req.RedirectURI
	if redirectURI == "" {
		if !client.RedirectURI.Valid || client.RedirectURI.String == "" {
			response.Error(w, "redirect_uri is required (client has no registered URI)", http.StatusBadRequest)
			return
		}
		redirectURI = client.RedirectURI.String
	} else if client.RedirectURI.Valid && client.RedirectURI.String != "" && client.RedirectURI.String != redirectURI {
		response.Error(w, "redirect_uri does not match registered URI", http.StatusBadRequest)
		return
	}

	redirectURL, err := url.Parse(redirectURI)
	if err != nil {
		response.Error(w, "invalid redirect_uri: "+err.Error(), http.StatusBadRequest)
		return
	}

	// Deny: short-circuit with error redirect; no user lookup required.
	if req.Decision == "deny" {
		q := redirectURL.Query()
		q.Set("error", "access_denied")
		if req.State != "" {
			q.Set("state", req.State)
		}
		redirectURL.RawQuery = q.Encode()
		response.WriteJSON(w, authorizeResponse{RedirectURL: redirectURL.String()}, http.StatusOK)
		return
	}

	user, err := s.findUser(req.UserID, req.Username)
	if err != nil {
		response.Error(w, err.Error(), http.StatusNotFound)
		return
	}

	scopeForCode := req.GrantedScope
	if scopeForCode == "" {
		scopeForCode = req.Scope
	}
	resolvedScope, err := s.oauthService.GetScope(scopeForCode)
	if err != nil {
		response.Error(w, "invalid scope: "+scopeForCode, http.StatusBadRequest)
		return
	}

	authCode, err := s.oauthService.GrantAuthorizationCode(
		client,
		user,
		s.cnf.Oauth.AuthCodeLifetime,
		redirectURI,
		resolvedScope,
		req.CodeChallenge,
		req.CodeChallengeMethod,
	)
	if err != nil {
		// PKCE input errors are user errors → 400; everything else → 500.
		switch err {
		case oauth.ErrPKCEInvalidRequest, oauth.ErrPKCEMethodUnsupported, oauth.ErrClientRequiresPKCE:
			response.Error(w, err.Error(), http.StatusBadRequest)
		default:
			response.Error(w, "granting authorization code: "+err.Error(), http.StatusInternalServerError)
		}
		return
	}

	q := redirectURL.Query()
	q.Set("code", authCode.Code)
	if req.State != "" {
		q.Set("state", req.State)
	}
	redirectURL.RawQuery = q.Encode()
	response.WriteJSON(w, authorizeResponse{RedirectURL: redirectURL.String()}, http.StatusOK)
}

// findUser resolves a user by UUID or username. user_id is preferred per
// the spec; username is accepted as a convenience for tests that don't
// want to track UUIDs.
func (s *Service) findUser(userID, username string) (*models.OauthUser, error) {
	if userID == "" && username == "" {
		return nil, errors.New("user_id or username is required")
	}
	if userID != "" {
		var user models.OauthUser
		notFound := s.db.Where("id = ?", userID).First(&user).RecordNotFound()
		if notFound {
			return nil, errors.New("user not found: " + userID)
		}
		return &user, nil
	}
	user, err := s.oauthService.FindUserByUsername(username)
	if err != nil {
		if errors.Is(err, oauth.ErrUserNotFound) {
			return nil, errors.New("user not found: " + username)
		}
		return nil, err
	}
	return user, nil
}

// requestsHandler implements GET /test/requests.
func (s *Service) requestsHandler(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	filter := SnapshotFilter{
		Endpoint: q.Get("endpoint"),
		ClientID: q.Get("client_id"),
	}
	if since := q.Get("since"); since != "" {
		t, err := parseSince(since)
		if err != nil {
			response.Error(w, "invalid since: "+err.Error(), http.StatusBadRequest)
			return
		}
		filter.Since = t
	}
	response.WriteJSON(w, s.recorder.Snapshot(filter), http.StatusOK)
}
