package integration_test

import (
	"net/http"
	"testing"
)

// TestScenario26_ProxyInitiatedDisconnect covers the spec's
// "Proxy-Initiated Disconnect" via the RFC 7009 revocation endpoint:
//
//   - revoking the refresh token cascades to the access token
//   - the endpoint silently returns 200 for unknown / wrong-client
//     tokens, but does not actually revoke them
//
// Spec: P2 scenario 26.
func TestScenario26_ProxyInitiatedDisconnect(t *testing.T) {
	ts := newTestServer(t)
	c := registerClient(t, ts, "scn26", "scn26-secret", "https://app.example.com/cb")
	other := registerClient(t, ts, "scn26-other", "other-secret", "https://app.example.com/cb")
	registerUser(t, ts, "scn26@example.com", "hunter22")

	t.Run("revoking RT via /v1/oauth/revoke disconnects the connection", func(t *testing.T) {
		_, tok, _ := passwordGrant(t, ts, c, "scn26@example.com", "hunter22", "read")
		if tok.AccessToken == "" || tok.RefreshToken == "" {
			t.Fatalf("setup: missing tokens")
		}

		if status := revokeToken(t, ts, c, tok.RefreshToken, "refresh_token"); status != http.StatusOK {
			t.Fatalf("revoke expected 200, got %d", status)
		}

		// Refresh fails.
		st, _, _ := refresh(t, ts, c, tok.RefreshToken)
		if st != http.StatusBadRequest {
			t.Fatalf("post-revoke refresh expected 400, got %d", st)
		}

		// Cascaded access token at resource is 401.
		st2, _, _ := callResource(t, ts, tok.AccessToken, "/test/resource/foo")
		if st2 != http.StatusUnauthorized {
			t.Fatalf("post-revoke resource expected 401, got %d", st2)
		}
	})

	t.Run("revoking unknown token returns 200 silently per RFC 7009", func(t *testing.T) {
		if status := revokeToken(t, ts, c, "00000000-0000-0000-0000-000000000000", ""); status != http.StatusOK {
			t.Fatalf("unknown-token revoke expected 200, got %d", status)
		}
	})

	t.Run("cross-client revoke returns 200 but does not actually revoke", func(t *testing.T) {
		// Issue a token belonging to `other`.
		_, otherTok, _ := passwordGrant(t, ts, other, "scn26@example.com", "hunter22", "read")
		if otherTok.AccessToken == "" {
			t.Fatalf("setup: missing other-client token")
		}

		// `c` (a different client) tries to revoke `other`'s access token.
		if status := revokeToken(t, ts, c, otherTok.AccessToken, "access_token"); status != http.StatusOK {
			t.Fatalf("cross-client revoke expected silent 200 per RFC 7009, got %d", status)
		}

		// `other`'s token still works at the resource — the cross-client
		// revoke was silently ignored.
		st, _, _ := callResource(t, ts, otherTok.AccessToken, "/test/resource/foo")
		if st != http.StatusOK {
			t.Fatalf("token should still be valid for owning client, got %d", st)
		}
	})
}
