package oauth

import (
	"errors"
	"net/http"

	"github.com/RichardKnop/go-oauth2-server/models"
	"github.com/RichardKnop/go-oauth2-server/util/response"
)

var (
	// ErrInvalidGrantType ...
	ErrInvalidGrantType = errors.New("Invalid grant type")
	// ErrInvalidClientIDOrSecret ...
	ErrInvalidClientIDOrSecret = errors.New("Invalid client ID or secret")
)

// tokensHandler handles all OAuth 2.0 grant types
// (POST /v1/oauth/tokens)
func (s *Service) tokensHandler(w http.ResponseWriter, r *http.Request) {
	ctx, span := s.telem.StartTokens(r.Context())
	defer span.End()
	r = r.WithContext(ctx)

	// Parse the form so r.Form becomes available
	if err := r.ParseForm(); err != nil {
		s.telem.FinishWithError(span, err, "invalid_request")
		response.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Map of grant types against handler functions
	grantTypes := map[string]func(r *http.Request, client *models.OauthClient) (*AccessTokenResponse, error){
		"authorization_code": s.authorizationCodeGrant,
		"password":           s.passwordGrant,
		"client_credentials": s.clientCredentialsGrant,
		"refresh_token":      s.refreshTokenGrant,
	}

	// Check the grant type
	grantType := r.Form.Get("grant_type")
	span.SetAttributes(grantTypeAttr(grantType))
	grantHandler, ok := grantTypes[grantType]
	if !ok {
		s.telem.FinishWithError(span, ErrInvalidGrantType, "unsupported_grant_type")
		s.telem.RecordTokenIssued(ctx, grantType, "", ErrInvalidGrantType, "unsupported_grant_type")
		response.Error(w, ErrInvalidGrantType.Error(), http.StatusBadRequest)
		return
	}

	// Client auth (per-client method: basic, post, or none)
	client, err := s.authenticateClient(r)
	if err != nil {
		s.telem.FinishWithError(span, err, "invalid_client")
		s.telem.RecordTokenIssued(ctx, grantType, "", err, "invalid_client")
		response.UnauthorizedError(w, err.Error())
		return
	}
	s.telem.SetClient(span, client.Key)

	// Grant processing
	resp, err := grantHandler(r, client)
	if err != nil {
		errCode := oauthErrorCode(err)
		s.telem.FinishWithError(span, err, errCode)
		s.telem.RecordTokenIssued(ctx, grantType, client.Key, err, errCode)
		response.Error(w, err.Error(), getErrStatusCode(err))
		return
	}

	s.telem.SetScope(span, resp.Scope)
	s.telem.SetTokenType(span, resp.TokenType)
	s.telem.RecordTokenIssued(ctx, grantType, client.Key, nil, "")
	if grantType == "refresh_token" {
		s.telem.RecordTokenRefreshed(ctx, client.Key, nil, "")
	}

	// Write response to json
	response.WriteJSON(w, resp, 200)
}

// introspectHandler handles OAuth 2.0 introspect request
// (POST /v1/oauth/introspect)
func (s *Service) introspectHandler(w http.ResponseWriter, r *http.Request) {
	ctx, span := s.telem.StartIntrospect(r.Context())
	defer span.End()
	r = r.WithContext(ctx)

	if err := r.ParseForm(); err != nil {
		s.telem.FinishWithError(span, err, "invalid_request")
		s.telem.RecordIntrospect(ctx, "", false, err, "invalid_request")
		response.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	// Client auth (per-client method: basic, post, or none)
	client, err := s.authenticateClient(r)
	if err != nil {
		s.telem.FinishWithError(span, err, "invalid_client")
		s.telem.RecordIntrospect(ctx, "", false, err, "invalid_client")
		response.UnauthorizedError(w, err.Error())
		return
	}
	s.telem.SetClient(span, client.Key)

	// Introspect the token
	resp, err := s.introspectToken(r, client)
	if err != nil {
		errCode := oauthErrorCode(err)
		s.telem.FinishWithError(span, err, errCode)
		s.telem.RecordIntrospect(ctx, client.Key, false, err, errCode)
		response.Error(w, err.Error(), getErrStatusCode(err))
		return
	}

	s.telem.SetScope(span, resp.Scope)
	s.telem.RecordIntrospect(ctx, client.Key, resp.Active, nil, "")

	// Write response to json
	response.WriteJSON(w, resp, 200)
}
