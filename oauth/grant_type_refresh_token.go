package oauth

import (
	"net/http"

	"github.com/RichardKnop/go-oauth2-server/models"
	"github.com/RichardKnop/go-oauth2-server/oauth/tokentypes"
)

func (s *Service) refreshTokenGrant(r *http.Request, client *models.OauthClient) (*AccessTokenResponse, error) {
	// Fetch the refresh token
	theRefreshToken, err := s.GetValidRefreshToken(r.Form.Get("refresh_token"), client)
	if err != nil {
		return nil, err
	}

	// Get the scope
	scope, err := s.getRefreshTokenScope(theRefreshToken, r.Form.Get("scope"))
	if err != nil {
		return nil, err
	}

	var (
		accessToken  *models.OauthAccessToken
		refreshToken *models.OauthRefreshToken
	)
	if s.cnf.Oauth.RefreshTokenRotation {
		accessToken, refreshToken, err = s.rotateRefreshToken(theRefreshToken, scope)
	} else {
		// Legacy non-rotation path: reuses the existing refresh token.
		accessToken, refreshToken, err = s.Login(
			theRefreshToken.Client,
			theRefreshToken.User,
			scope,
		)
	}
	if err != nil {
		return nil, err
	}

	// Create response
	accessTokenResponse, err := NewAccessTokenResponse(
		accessToken,
		refreshToken,
		s.cnf.Oauth.AccessTokenLifetime,
		tokentypes.Bearer,
	)
	if err != nil {
		return nil, err
	}

	return accessTokenResponse, nil
}
