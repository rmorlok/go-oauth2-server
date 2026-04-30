package integration_test

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"testing"
)

// TestScenario29_OpenRedirectProtection covers the server-side parts
// of the spec's "Open Redirect Protection": redirect_uri at /test/
// authorize must match the client's registered URI, and a missing
// redirect_uri falls back to the registered URI.
//
// PROXY-SIDE: validating the post-auth return URL the proxy itself
// redirects users to is not in the test provider's purview. See
// docs/integration_test_gaps.md row "scenario-29".
//
// Spec: P2 scenario 29.
func TestScenario29_OpenRedirectProtection(t *testing.T) {
	ts := newTestServer(t)
	const registered = "https://app.example.com/cb"
	c := registerClient(t, ts, "scn29", "scn29-secret", registered)
	u := registerUser(t, ts, "scn29@example.com", "hunter22")

	t.Run("redirect_uri mismatch is rejected", func(t *testing.T) {
		body, _ := json.Marshal(map[string]any{
			"client_id":    c.Key,
			"user_id":      u.ID,
			"redirect_uri": "https://attacker.example.com/cb",
			"scope":        "read",
			"decision":     "approve",
		})
		resp, err := http.Post(ts.URL+"/test/authorize", "application/json", bytes.NewReader(body))
		if err != nil {
			t.Fatalf("authorize: %v", err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("expected 400 for redirect_uri mismatch, got %d", resp.StatusCode)
		}
	})

	t.Run("missing redirect_uri falls back to registered URI", func(t *testing.T) {
		body, _ := json.Marshal(map[string]any{
			"client_id": c.Key,
			"user_id":   u.ID,
			"scope":     "read",
			"decision":  "approve",
			// redirect_uri intentionally absent
		})
		resp, err := http.Post(ts.URL+"/test/authorize", "application/json", bytes.NewReader(body))
		if err != nil {
			t.Fatalf("authorize: %v", err)
		}
		raw, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("expected 200 with fallback redirect_uri, got %d body=%s", resp.StatusCode, raw)
		}
		var r struct {
			RedirectURL string `json:"redirect_url"`
		}
		if err := json.Unmarshal(raw, &r); err != nil {
			t.Fatalf("decode: %v", err)
		}
		parsed, err := url.Parse(r.RedirectURL)
		if err != nil {
			t.Fatalf("parse redirect: %v", err)
		}
		if got := parsed.Scheme + "://" + parsed.Host + parsed.Path; got != registered {
			t.Fatalf("expected fallback to registered URI %q, got %q", registered, got)
		}
	})
}
