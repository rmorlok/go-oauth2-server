package oauth

import (
	"github.com/RichardKnop/go-oauth2-server/telemetry/oauthtelem"
	"go.opentelemetry.io/otel/attribute"
)

// grantTypeAttr formats an oauth.grant_type span attribute. Used by
// tokensHandler before grant dispatch so the attribute appears even on
// the unsupported-grant error path.
func grantTypeAttr(grantType string) attribute.KeyValue {
	return attribute.String(oauthtelem.AttrGrantType, grantType)
}

// oauthErrorCode maps an internal sentinel error to the RFC 6749 / 7009 /
// 7662 error code used as the oauth.error_code telemetry attribute.
//
// Unknown errors collapse to "server_error" so the dimension stays
// bounded — callers should add new sentinels here when they want to
// distinguish a new failure mode in dashboards.
func oauthErrorCode(err error) string {
	if err == nil {
		return ""
	}
	switch err {
	case ErrInvalidClientIDOrSecret:
		return "invalid_client"
	case ErrInvalidGrantType:
		return "unsupported_grant_type"
	case ErrInvalidUsernameOrPassword,
		ErrInvalidRedirectURI,
		ErrAuthorizationCodeNotFound,
		ErrAuthorizationCodeExpired,
		ErrRefreshTokenNotFound,
		ErrRefreshTokenExpired,
		ErrRefreshTokenRevoked,
		ErrAccessTokenNotFound,
		ErrAccessTokenRevoked:
		return "invalid_grant"
	case ErrInvalidScope, ErrRequestedScopeCannotBeGreater:
		return "invalid_scope"
	case ErrTokenMissing:
		return "invalid_request"
	case ErrTokenHintInvalid, ErrUnsupportedTokenType:
		return "unsupported_token_type"
	case ErrPKCEInvalidRequest,
		ErrPKCEMethodUnsupported,
		ErrPKCEVerifierMissing,
		ErrPKCEVerifierMismatch,
		ErrPKCEVerifierUnexpected,
		ErrClientRequiresPKCE:
		return "invalid_grant"
	}
	return "server_error"
}
