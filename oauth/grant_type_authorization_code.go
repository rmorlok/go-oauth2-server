package oauth

import (
	"errors"
	"net/http"
	"time"

	"github.com/RichardKnop/go-oauth2-server/models"
	"github.com/RichardKnop/go-oauth2-server/oauth/tokentypes"
)

var (
	// ErrInvalidRedirectURI ...
	ErrInvalidRedirectURI = errors.New("Invalid redirect URI")
)

func (s *Service) authorizationCodeGrant(r *http.Request, client *models.OauthClient) (resp *AccessTokenResponse, err error) {
	ctx, span := s.telem.StartGrant(r.Context(), "authorization_code")
	defer span.End()
	s.telem.SetClient(span, client.Key)
	start := time.Now()
	defer func() {
		s.telem.RecordGrantDuration(ctx, "authorization_code", start, err)
		if err != nil {
			s.telem.FinishWithError(span, err, oauthErrorCode(err))
		} else if resp != nil {
			s.telem.SetScope(span, resp.Scope)
		}
	}()
	// Fetch the authorization code
	authorizationCode, err := s.getValidAuthorizationCode(
		r.Form.Get("code"),
		r.Form.Get("redirect_uri"),
		client,
	)
	if err != nil {
		return nil, err
	}

	// PKCE verification (RFC 7636). The skip path is reserved for the
	// test-mode script middleware's skip_pkce_check action.
	if !skipPKCE(r.Context()) {
		if err := verifyPKCE(authorizationCode, r.Form.Get("code_verifier"), client); err != nil {
			return nil, err
		}
	}

	// Log in the user
	accessToken, refreshToken, err := s.Login(
		authorizationCode.Client,
		authorizationCode.User,
		authorizationCode.Scope,
	)
	if err != nil {
		return nil, err
	}

	// Delete the authorization code
	s.db.Unscoped().Delete(&authorizationCode)

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
