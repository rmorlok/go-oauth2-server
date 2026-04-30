package integration_test

import (
	"net/http"
	"testing"
)

// TestScenario28_MultipleConnections covers the spec's "Multiple
// Connections to Same Provider":
//
//   - Same tenant can hold multiple independent client registrations
//   - Token storage / revocation are isolated per (client, user) pair
//   - Revoking one chain doesn't touch the other
//
// Spec: P2 scenario 28.
func TestScenario28_MultipleConnections(t *testing.T) {
	ts := newTestServer(t)

	cA := registerClient(t, ts, "scn28-a", "secret-a", "https://app.example.com/cb")
	cB := registerClient(t, ts, "scn28-b", "secret-b", "https://app.example.com/cb")
	registerUser(t, ts, "scn28@example.com", "hunter22")

	t.Run("same user authorizing two clients yields independent chains", func(t *testing.T) {
		_, tokA, _ := passwordGrant(t, ts, cA, "scn28@example.com", "hunter22", "read")
		_, tokB, _ := passwordGrant(t, ts, cB, "scn28@example.com", "hunter22", "read")
		if tokA.AccessToken == "" || tokB.AccessToken == "" {
			t.Fatalf("setup: expected both tokens")
		}
		if tokA.AccessToken == tokB.AccessToken {
			t.Fatalf("each client should get a distinct access token")
		}
		if tokA.RefreshToken == tokB.RefreshToken {
			t.Fatalf("each client should get a distinct refresh token")
		}

		// Both tokens work at the resource.
		if st, _, _ := callResource(t, ts, tokA.AccessToken, "/test/resource/foo"); st != http.StatusOK {
			t.Fatalf("tokenA at resource expected 200, got %d", st)
		}
		if st, _, _ := callResource(t, ts, tokB.AccessToken, "/test/resource/foo"); st != http.StatusOK {
			t.Fatalf("tokenB at resource expected 200, got %d", st)
		}

		// Revoke chain A via the admin endpoint.
		adminRevoke(t, ts, map[string]string{"token": tokA.RefreshToken})

		// chain A's access token is now invalid (cascade) ...
		if st, _, _ := callResource(t, ts, tokA.AccessToken, "/test/resource/foo"); st != http.StatusUnauthorized {
			t.Fatalf("chain A access token should be revoked, got %d", st)
		}
		// ... but chain B is untouched.
		if st, _, _ := callResource(t, ts, tokB.AccessToken, "/test/resource/foo"); st != http.StatusOK {
			t.Fatalf("chain B should be unaffected by chain A revoke, got %d", st)
		}
		// And chain B's refresh still works.
		stRefresh, refreshedB, _ := refresh(t, ts, cB, tokB.RefreshToken)
		if stRefresh != http.StatusOK {
			t.Fatalf("chain B refresh should still work, got %d", stRefresh)
		}
		if refreshedB.AccessToken == "" {
			t.Fatalf("chain B refresh should produce a new access token")
		}
	})

	t.Run("clientA cannot revoke clientB's tokens", func(t *testing.T) {
		// Fresh token for clientB.
		_, tokB, _ := passwordGrant(t, ts, cB, "scn28@example.com", "hunter22", "read")
		if tokB.AccessToken == "" {
			t.Fatalf("setup: missing tokenB")
		}

		// clientA's credentials, attempting to revoke clientB's access token.
		// RFC 7009: silent 200, no actual revocation.
		if status := revokeToken(t, ts, cA, tokB.AccessToken, "access_token"); status != http.StatusOK {
			t.Fatalf("cross-client revoke expected silent 200, got %d", status)
		}

		// clientB's token still works.
		if st, _, _ := callResource(t, ts, tokB.AccessToken, "/test/resource/foo"); st != http.StatusOK {
			t.Fatalf("tokenB should still be valid for clientB, got %d", st)
		}
	})
}
