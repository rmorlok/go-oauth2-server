package integration_test

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/RichardKnop/go-oauth2-server/models"
)

// TestScenario04_CallbackSecurity covers the server-side parts of the
// spec's "Invalid, Missing, or Replayed State" — namely the four
// guarantees the proxy depends on:
//
//   - state is echoed back faithfully, including special characters
//   - authorization codes are single-use
//   - redirect_uri at exchange must match the value used at authorize
//   - expired authorization codes are rejected
//
// State validation across users / tenants / connections is proxy-side.
//
// Spec: P0 scenario 4.
func TestScenario04_CallbackSecurity(t *testing.T) {
	ts := newTestServer(t)

	c := registerClient(t, ts, "scn04", "scn04-secret", "https://app.example.com/cb")
	u := registerUser(t, ts, "scn04@example.com", "hunter22")

	t.Run("state is echoed faithfully", func(t *testing.T) {
		states := []string{
			"plain-state",
			"with spaces and / slashes",
			`special !@#$%^&*()_+={}[]|;':",.<>?`,
			"unicode-✓-and-emoji-🚀",
		}
		for _, want := range states {
			redirectURL := authorize(t, ts, "approve", authorizeParams{
				Client: c, User: u, Scope: "read", State: want,
			})
			parsed, err := url.Parse(redirectURL)
			if err != nil {
				t.Fatalf("parse redirect for %q: %v", want, err)
			}
			if got := parsed.Query().Get("state"); got != want {
				t.Fatalf("state mismatch: want %q got %q (url: %s)", want, got, redirectURL)
			}
		}
	})

	t.Run("authorization code is single-use", func(t *testing.T) {
		redirectURL := authorize(t, ts, "approve", authorizeParams{
			Client: c, User: u, Scope: "read",
		})
		code := extractCode(t, redirectURL)

		// First exchange succeeds.
		if status, _, body := exchangeCode(t, ts, c, code); status != http.StatusOK {
			t.Fatalf("first exchange expected 200, got %d body=%s", status, body)
		}
		// Second exchange of the same code fails.
		status, _, body := exchangeCode(t, ts, c, code)
		if status == http.StatusOK {
			t.Fatalf("second exchange of same code should fail, got 200 body=%s", body)
		}
	})

	t.Run("redirect_uri mismatch at exchange is rejected", func(t *testing.T) {
		redirectURL := authorize(t, ts, "approve", authorizeParams{
			Client: c, User: u, Scope: "read",
		})
		code := extractCode(t, redirectURL)

		// Hand-roll the exchange with a different redirect_uri than was
		// used at /test/authorize.
		form := url.Values{}
		form.Set("grant_type", "authorization_code")
		form.Set("code", code)
		form.Set("redirect_uri", "https://attacker.example.com/cb")
		req, _ := http.NewRequest("POST", ts.URL+"/v1/oauth/tokens", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.SetBasicAuth(c.Key, c.Secret)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("exchange: %v", err)
		}
		resp.Body.Close()
		if resp.StatusCode == http.StatusOK {
			t.Fatalf("redirect_uri mismatch should reject the exchange, got 200")
		}
	})

	t.Run("expired authorization code is rejected", func(t *testing.T) {
		redirectURL := authorize(t, ts, "approve", authorizeParams{
			Client: c, User: u, Scope: "read",
		})
		code := extractCode(t, redirectURL)

		// Back-date the code so the exchange's expiry check fires. The
		// auth-code lifetime is config-wide; per-scenario back-dating is
		// the cleanest way to simulate "the proxy waited too long".
		expireAuthorizationCode(t, ts, code)

		status, _, body := exchangeCode(t, ts, c, code)
		if status == http.StatusOK {
			t.Fatalf("expired code should not exchange, got 200 body=%s", body)
		}
	})
}

func expireAuthorizationCode(t *testing.T, ts *testServer, code string) {
	t.Helper()
	res := ts.DB.Model(new(models.OauthAuthorizationCode)).
		Where("code = ?", code).
		Update("expires_at", time.Now().UTC().Add(-1*time.Hour))
	if res.Error != nil {
		t.Fatalf("expire auth code: %v", res.Error)
	}
	if res.RowsAffected != 1 {
		t.Fatalf("expected to expire 1 auth code row, affected %d", res.RowsAffected)
	}
}
