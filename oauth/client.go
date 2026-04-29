package oauth

import (
	"errors"
	"strings"
	"time"

	"github.com/RichardKnop/go-oauth2-server/models"
	"github.com/RichardKnop/go-oauth2-server/util"
	"github.com/RichardKnop/go-oauth2-server/util/password"
	"github.com/RichardKnop/uuid"
	"github.com/jinzhu/gorm"
)

var (
	// ErrClientNotFound ...
	ErrClientNotFound = errors.New("Client not found")
	// ErrInvalidClientSecret ...
	ErrInvalidClientSecret = errors.New("Invalid client secret")
	// ErrClientIDTaken ...
	ErrClientIDTaken = errors.New("Client ID taken")
	// ErrInvalidAuthMethod is returned by CreateClient when an unknown
	// token_endpoint_auth_method is supplied.
	ErrInvalidAuthMethod = errors.New("Invalid token_endpoint_auth_method")
)

// ClientExists returns true if client exists
func (s *Service) ClientExists(clientID string) bool {
	_, err := s.FindClientByClientID(clientID)
	return err == nil
}

// FindClientByClientID looks up a client by client ID
func (s *Service) FindClientByClientID(clientID string) (*models.OauthClient, error) {
	// Client IDs are case insensitive
	client := new(models.OauthClient)
	notFound := s.db.Where("key = LOWER(?)", clientID).
		First(client).RecordNotFound()

	// Not found
	if notFound {
		return nil, ErrClientNotFound
	}

	return client, nil
}

// CreateClient saves a new client to database. tokenEndpointAuthMethod
// must be one of "client_secret_basic" (default), "client_secret_post",
// "none", or empty (treated as the default).
//
// requirePKCE forces strict PKCE for the client (mandatory code_challenge
// at authorize time, no spurious verifier accepted at the token endpoint).
// `none` clients always get strict PKCE regardless of this argument.
func (s *Service) CreateClient(clientID, secret, redirectURI, tokenEndpointAuthMethod string, requirePKCE bool) (*models.OauthClient, error) {
	return s.createClientCommon(s.db, clientID, secret, redirectURI, tokenEndpointAuthMethod, requirePKCE)
}

// CreateClientTx saves a new client to database using injected db object.
func (s *Service) CreateClientTx(tx *gorm.DB, clientID, secret, redirectURI, tokenEndpointAuthMethod string, requirePKCE bool) (*models.OauthClient, error) {
	return s.createClientCommon(tx, clientID, secret, redirectURI, tokenEndpointAuthMethod, requirePKCE)
}

// AuthClient authenticates client
func (s *Service) AuthClient(clientID, secret string) (*models.OauthClient, error) {
	// Fetch the client
	client, err := s.FindClientByClientID(clientID)
	if err != nil {
		return nil, ErrClientNotFound
	}

	// Verify the secret
	if password.VerifyPassword(client.Secret, secret) != nil {
		return nil, ErrInvalidClientSecret
	}

	return client, nil
}

func (s *Service) createClientCommon(db *gorm.DB, clientID, secret, redirectURI, tokenEndpointAuthMethod string, requirePKCE bool) (*models.OauthClient, error) {
	// Check client ID
	if s.ClientExists(clientID) {
		return nil, ErrClientIDTaken
	}

	if !ValidAuthMethod(tokenEndpointAuthMethod) {
		return nil, ErrInvalidAuthMethod
	}
	method := tokenEndpointAuthMethod
	if method == "" {
		method = AuthMethodSecretBasic
	}

	// `none` clients have no secret; for the other methods we hash whatever
	// secret was provided (empty string is allowed but won't authenticate).
	var secretHash []byte
	if method != AuthMethodNone {
		var err error
		secretHash, err = password.HashPassword(secret)
		if err != nil {
			return nil, err
		}
	}

	// Public clients always require PKCE.
	if method == AuthMethodNone {
		requirePKCE = true
	}

	client := &models.OauthClient{
		MyGormModel: models.MyGormModel{
			ID:        uuid.New(),
			CreatedAt: time.Now().UTC(),
		},
		Key:                     strings.ToLower(clientID),
		Secret:                  string(secretHash),
		RedirectURI:             util.StringOrNull(redirectURI),
		TokenEndpointAuthMethod: method,
		RequirePKCE:             requirePKCE,
	}
	if err := db.Create(client).Error; err != nil {
		return nil, err
	}
	return client, nil
}
