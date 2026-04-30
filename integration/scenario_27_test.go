package integration_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"testing"
)

// TestScenario27_ProviderIdentityChanges covers the spec's "Provider
// Account Identity Changes": the provider can swap the `sub` returned
// by /v1/oauth/userinfo without re-issuing tokens, so a proxy can
// detect identity drift mid-session.
//
// Spec: P2 scenario 27.
func TestScenario27_ProviderIdentityChanges(t *testing.T) {
	ts := newTestServer(t)
	c := registerClient(t, ts, "scn27", "scn27-secret", "https://app.example.com/cb")
	u := registerUser(t, ts, "scn27@example.com", "hunter22",
		userOpts{Email: "scn27@example.com", DisplayName: "Scenario 27"})

	_, tok, _ := passwordGrant(t, ts, c, "scn27@example.com", "hunter22", "profile")
	if tok.AccessToken == "" {
		t.Fatalf("setup: missing access token")
	}

	t.Run("initial userinfo returns user UUID as sub", func(t *testing.T) {
		status, _, body := userinfo(t, ts, tok.AccessToken)
		if status != http.StatusOK {
			t.Fatalf("expected 200, got %d body=%s", status, body)
		}
		var ui struct{ Sub string }
		json.Unmarshal(body, &ui)
		if ui.Sub != u.ID {
			t.Fatalf("expected sub=%q, got %q", u.ID, ui.Sub)
		}
	})

	t.Run("swap-subject changes sub on the same access token", func(t *testing.T) {
		swap, _ := json.Marshal(map[string]string{"new_sub": "iss://example/users/42"})
		resp, _ := http.Post(ts.URL+"/test/users/"+u.ID+"/swap-subject", "application/json", bytes.NewReader(swap))
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("swap-subject expected 200, got %d", resp.StatusCode)
		}

		// Same access token; userinfo now reports the override.
		_, _, body := userinfo(t, ts, tok.AccessToken)
		var ui struct{ Sub string }
		json.Unmarshal(body, &ui)
		if ui.Sub != "iss://example/users/42" {
			t.Fatalf("expected swapped sub, got %q (body=%s)", ui.Sub, body)
		}
	})

	t.Run("clearing override falls back to UUID", func(t *testing.T) {
		clear, _ := json.Marshal(map[string]string{"new_sub": ""})
		resp, _ := http.Post(ts.URL+"/test/users/"+u.ID+"/swap-subject", "application/json", bytes.NewReader(clear))
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("clear expected 200, got %d", resp.StatusCode)
		}

		_, _, body := userinfo(t, ts, tok.AccessToken)
		var ui struct{ Sub string }
		json.Unmarshal(body, &ui)
		if ui.Sub != u.ID {
			t.Fatalf("expected sub to fall back to UUID, got %q (body=%s)", ui.Sub, body)
		}
	})
}
