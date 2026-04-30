package integration_test

import (
	"net/http"
	"strings"
	"testing"
)

// TestScenario11_ThirdPartyRevocation covers the spec's "User Revokes
// Access on the Third Party": after a successful flow, the provider
// admin path is used to revoke the refresh token. The cascade then
// invalidates the active access token; subsequent refresh and resource
// calls fail.
//
// Spec: P0 scenario 11.
func TestScenario11_ThirdPartyRevocation(t *testing.T) {
	ts := newTestServer(t)

	c := registerClient(t, ts, "scn11", "scn11-secret", "https://app.example.com/cb")
	registerUser(t, ts, "scn11@example.com", "hunter22",
		userOpts{Email: "scn11@example.com", DisplayName: "Scenario Eleven"})

	_, tok, body := passwordGrant(t, ts, c, "scn11@example.com", "hunter22", "profile")
	if tok.AccessToken == "" || tok.RefreshToken == "" {
		t.Fatalf("expected both tokens, body=%s", body)
	}

	// Sanity: token works at the resource and at userinfo before revocation.
	if status, _, _ := callResource(t, ts, tok.AccessToken, "/test/resource/foo"); status != http.StatusOK {
		t.Fatalf("pre-revoke resource expected 200, got %d", status)
	}
	if status, _, _ := userinfo(t, ts, tok.AccessToken); status != http.StatusOK {
		t.Fatalf("pre-revoke userinfo expected 200, got %d", status)
	}

	// Provider-side revocation: admin path bypasses client auth and
	// targets the refresh token, which cascades to the access token.
	adminRevoke(t, ts, map[string]string{"token": tok.RefreshToken})

	t.Run("refresh with revoked RT is rejected", func(t *testing.T) {
		status, _, body := refresh(t, ts, c, tok.RefreshToken)
		if status != http.StatusBadRequest {
			t.Fatalf("expected 400 invalid_grant, got %d body=%s", status, body)
		}
		if !strings.Contains(strings.ToLower(string(body)), "revoked") {
			t.Fatalf("expected error to mention revoked, got %s", body)
		}
	})

	t.Run("cascaded access token returns 401 at resource", func(t *testing.T) {
		status, hdr, body := callResource(t, ts, tok.AccessToken, "/test/resource/foo")
		if status != http.StatusUnauthorized {
			t.Fatalf("expected 401, got %d body=%s", status, body)
		}
		if !strings.Contains(hdr.Get("WWW-Authenticate"), `error="invalid_token"`) {
			t.Fatalf("expected invalid_token in WWW-Authenticate, got %q", hdr.Get("WWW-Authenticate"))
		}
	})

	t.Run("cascaded access token returns 401 at userinfo", func(t *testing.T) {
		status, _, body := userinfo(t, ts, tok.AccessToken)
		if status != http.StatusUnauthorized {
			t.Fatalf("expected 401 at userinfo, got %d body=%s", status, body)
		}
	})
}
