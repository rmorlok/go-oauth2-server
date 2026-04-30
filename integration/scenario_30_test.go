package integration_test

import (
	"net/http"
	"strings"
	"testing"
)

// TestScenario30_ClockSkew covers the server-side parts of the spec's
// "Clock Skew": the provider can issue a token with a very short
// lifetime, expires_in reflects the configured lifetime, and an
// already-expired token is rejected at the resource.
//
// PROXY-SIDE: applying an expiry buffer / skew tolerance / refreshing
// before nominal expiry are all proxy concerns. See
// docs/integration_test_gaps.md row "scenario-30".
//
// Spec: P2 scenario 30.
func TestScenario30_ClockSkew(t *testing.T) {
	ts := newTestServer(t)
	c := registerClient(t, ts, "scn30", "scn30-secret", "https://app.example.com/cb")
	registerUser(t, ts, "scn30@example.com", "hunter22")

	// Mutate the in-memory config so the next token is issued with a
	// 1-second access-token lifetime. Each scenario test runs against
	// its own server instance (fresh config) so this doesn't leak
	// across scenarios.
	cnf := ts.OauthService.GetConfig()
	cnf.Oauth.AccessTokenLifetime = 1

	t.Run("expires_in reflects the configured short lifetime", func(t *testing.T) {
		_, tok, body := passwordGrant(t, ts, c, "scn30@example.com", "hunter22", "read")
		if tok.AccessToken == "" {
			t.Fatalf("setup: missing access token (body=%s)", body)
		}
		if tok.ExpiresIn != 1 {
			t.Fatalf("expected expires_in=1, got %d (body=%s)", tok.ExpiresIn, body)
		}
	})

	t.Run("expired token is rejected at the resource", func(t *testing.T) {
		_, tok, _ := passwordGrant(t, ts, c, "scn30@example.com", "hunter22", "read")
		// Back-date the just-issued token so the next Authenticate call
		// rejects it as expired without forcing the test to sleep.
		expireAccessToken(t, ts, tok.AccessToken)

		status, hdr, body := callResource(t, ts, tok.AccessToken, "/test/resource/foo")
		if status != http.StatusUnauthorized {
			t.Fatalf("expected 401 expired, got %d body=%s", status, body)
		}
		// Server emits Bearer error="invalid_token" for both expired and
		// revoked; spot-check the descriptor mentions "expired" so
		// proxy tests can distinguish.
		desc := hdr.Get("WWW-Authenticate")
		if !strings.Contains(strings.ToLower(desc), "expired") {
			t.Fatalf("WWW-Authenticate should mention expired, got %q", desc)
		}
	})
}
