package oauth

import (
	"errors"
	"net/http"

	"github.com/RichardKnop/go-oauth2-server/models"
	"github.com/RichardKnop/go-oauth2-server/util/password"
)

// Token-endpoint client authentication methods (RFC 7591 §2).
const (
	AuthMethodSecretBasic = "client_secret_basic"
	AuthMethodSecretPost  = "client_secret_post"
	AuthMethodNone        = "none"
)

// ValidAuthMethod reports whether m is one of the supported method names.
// Empty string is also valid and is treated as the default
// (client_secret_basic).
func ValidAuthMethod(m string) bool {
	switch m {
	case "", AuthMethodSecretBasic, AuthMethodSecretPost, AuthMethodNone:
		return true
	}
	return false
}

// ErrClientRequiresPKCE is returned when GrantAuthorizationCode is called
// for a client that requires PKCE (either token_endpoint_auth_method=none
// or require_pkce=true) but the request omits code_challenge.
var ErrClientRequiresPKCE = errors.New("client requires PKCE: code_challenge is mandatory")

// authenticateClient resolves and authenticates the client for token,
// introspect, and revoke endpoints, applying the per-client
// token_endpoint_auth_method:
//
//   - client_secret_basic: HTTP Basic; reject form client_id/client_secret
//   - client_secret_post:  form client_id+client_secret; reject Basic
//   - none:                form client_id only; reject Basic and form secret.
//                          PKCE on the authorization_code grant is enforced
//                          at GrantAuthorizationCode time.
//
// Mismatches return ErrInvalidClientIDOrSecret which the handler maps to
// 401. Empty TokenEndpointAuthMethod on the client record is treated as
// client_secret_basic for backwards compatibility.
func (s *Service) authenticateClient(r *http.Request) (*models.OauthClient, error) {
	basicID, basicSecret, hasBasic := r.BasicAuth()
	formID := r.Form.Get("client_id")
	formSecret := r.Form.Get("client_secret")

	var clientID string
	switch {
	case hasBasic && basicID != "":
		clientID = basicID
	case formID != "":
		clientID = formID
	default:
		return nil, ErrInvalidClientIDOrSecret
	}

	client, err := s.FindClientByClientID(clientID)
	if err != nil {
		return nil, ErrInvalidClientIDOrSecret
	}

	method := client.TokenEndpointAuthMethod
	if method == "" {
		method = AuthMethodSecretBasic
	}

	switch method {
	case AuthMethodSecretBasic:
		if !hasBasic {
			return nil, ErrInvalidClientIDOrSecret
		}
		if formID != "" || formSecret != "" {
			return nil, ErrInvalidClientIDOrSecret
		}
		if password.VerifyPassword(client.Secret, basicSecret) != nil {
			return nil, ErrInvalidClientIDOrSecret
		}
	case AuthMethodSecretPost:
		if hasBasic {
			return nil, ErrInvalidClientIDOrSecret
		}
		if formID == "" || formSecret == "" {
			return nil, ErrInvalidClientIDOrSecret
		}
		if password.VerifyPassword(client.Secret, formSecret) != nil {
			return nil, ErrInvalidClientIDOrSecret
		}
	case AuthMethodNone:
		if hasBasic {
			return nil, ErrInvalidClientIDOrSecret
		}
		if formSecret != "" {
			return nil, ErrInvalidClientIDOrSecret
		}
		if formID == "" {
			return nil, ErrInvalidClientIDOrSecret
		}
		// PKCE enforcement is at the authorize step + verifier check; no
		// extra work required here.
	default:
		return nil, ErrInvalidClientIDOrSecret
	}

	return client, nil
}
