package oauth

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"

	"github.com/RichardKnop/go-oauth2-server/models"
)

// PKCE methods per RFC 7636 §4.2.
const (
	PKCEMethodPlain = "plain"
	PKCEMethodS256  = "S256"
)

var (
	// ErrPKCEInvalidRequest is returned when code_challenge_method is set
	// without a code_challenge, or other malformed PKCE input.
	ErrPKCEInvalidRequest = errors.New("invalid PKCE request")
	// ErrPKCEMethodUnsupported is returned when code_challenge_method is
	// set to something other than "plain" or "S256".
	ErrPKCEMethodUnsupported = errors.New("unsupported PKCE method")
	// ErrPKCEVerifierMissing is returned when an authorization code carries
	// a stored code_challenge but the token request omits code_verifier.
	ErrPKCEVerifierMissing = errors.New("code_verifier required")
	// ErrPKCEVerifierMismatch is returned when the supplied code_verifier
	// fails the challenge check.
	ErrPKCEVerifierMismatch = errors.New("code_verifier does not match challenge")
)

// pkceSkipKey is the context key used by test-mode scripting to mark a
// single token call as PKCE-bypassed.
type pkceSkipKey struct{}

// WithSkipPKCE returns a derived context that signals the
// authorization_code grant to skip PKCE verification for this request.
// Used by the test-mode script middleware to simulate broken IdPs.
func WithSkipPKCE(ctx context.Context) context.Context {
	return context.WithValue(ctx, pkceSkipKey{}, true)
}

func skipPKCE(ctx context.Context) bool {
	v, _ := ctx.Value(pkceSkipKey{}).(bool)
	return v
}

// validateChallengeAtAuthorize is called by GrantAuthorizationCode to
// validate (challenge, method) before persistence. Empty challenge and
// empty method together is fine (no PKCE). Method without challenge is
// invalid_request. Returns the canonical method string ("plain" if the
// method was empty but a challenge was supplied).
func validateChallengeAtAuthorize(challenge, method string) (string, error) {
	if challenge == "" && method == "" {
		return "", nil
	}
	if challenge == "" && method != "" {
		return "", ErrPKCEInvalidRequest
	}
	if method == "" {
		method = PKCEMethodPlain
	}
	if method != PKCEMethodPlain && method != PKCEMethodS256 {
		return "", ErrPKCEMethodUnsupported
	}
	return method, nil
}

// verifyPKCE checks the supplied verifier against the stored challenge.
// Returns nil if the auth code has no challenge stored (no PKCE was
// requested) or if the verifier matches.
func verifyPKCE(code *models.OauthAuthorizationCode, verifier string) error {
	if !code.CodeChallenge.Valid || code.CodeChallenge.String == "" {
		// No challenge stored — RFC §4.5: spurious verifier is permitted
		// and ignored. (Strict-rejection mode would belong on a future
		// per-client setting.)
		return nil
	}
	if verifier == "" {
		return ErrPKCEVerifierMissing
	}

	method := code.CodeChallengeMethod.String
	if method == "" {
		method = PKCEMethodPlain
	}

	var computed string
	switch method {
	case PKCEMethodPlain:
		computed = verifier
	case PKCEMethodS256:
		h := sha256.Sum256([]byte(verifier))
		computed = base64.RawURLEncoding.EncodeToString(h[:])
	default:
		// Stored method shouldn't be invalid because we validate at
		// persistence, but guard anyway.
		return ErrPKCEMethodUnsupported
	}

	if computed != code.CodeChallenge.String {
		return ErrPKCEVerifierMismatch
	}
	return nil
}
