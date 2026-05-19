package oauth

import (
	"net/http"
	"time"

	"github.com/RichardKnop/go-oauth2-server/models"
	"github.com/RichardKnop/go-oauth2-server/oauth/tokentypes"
)

func (s *Service) clientCredentialsGrant(r *http.Request, client *models.OauthClient) (resp *AccessTokenResponse, err error) {
	ctx, span := s.telem.StartGrant(r.Context(), "client_credentials")
	defer span.End()
	s.telem.SetClient(span, client.Key)
	start := time.Now()
	defer func() {
		s.telem.RecordGrantDuration(ctx, "client_credentials", start, err)
		if err != nil {
			s.telem.FinishWithError(span, err, oauthErrorCode(err))
		} else if resp != nil {
			s.telem.SetScope(span, resp.Scope)
		}
	}()
	// Get the scope string
	scope, err := s.GetScope(r.Form.Get("scope"))
	if err != nil {
		return nil, err
	}

	// Create a new access token
	accessToken, err := s.GrantAccessToken(
		client,
		nil,                             // empty user
		s.cnf.Oauth.AccessTokenLifetime, // expires in
		scope,
	)
	if err != nil {
		return nil, err
	}

	// Create response
	accessTokenResponse, err := NewAccessTokenResponse(
		accessToken,
		nil, // refresh token
		s.cnf.Oauth.AccessTokenLifetime,
		tokentypes.Bearer,
	)
	if err != nil {
		return nil, err
	}

	return accessTokenResponse, nil
}
