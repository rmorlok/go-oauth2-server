package integration_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

// TestScenario22_ProxyAPI403 covers the spec's "Proxy API Call
// Receives 403": scope-policy mismatch returns 403 with a
// WWW-Authenticate header that reports the required scope, so the
// proxy can surface a meaningful "missing permission" error.
//
// The spec's example uses `admin` as the required scope, but the test
// provider only seeds `read`, `read_write`, `profile`, and `email`. To
// avoid mutating the seed for one scenario, we use `read_write` as
// the required scope and issue the user a `read`-only token. The
// shape of the assertion is identical.
//
// Spec: P1 scenario 22.
func TestScenario22_ProxyAPI403(t *testing.T) {
	ts := newTestServer(t)
	c := registerClient(t, ts, "scn22", "scn22-secret", "https://app.example.com/cb")
	registerUser(t, ts, "scn22@example.com", "hunter22")

	const adminPath = "/test/resource/admin"

	// Register the policy: hitting adminPath requires `read_write`.
	policyBody, _ := json.Marshal(map[string]string{
		"path":           adminPath,
		"required_scope": "read_write",
	})
	resp, err := http.Post(ts.URL+"/test/resource-policy", "application/json", bytes.NewReader(policyBody))
	if err != nil {
		t.Fatalf("policy: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("policy register expected 204, got %d", resp.StatusCode)
	}

	t.Run("read-only token at admin path returns 403", func(t *testing.T) {
		_, tok, _ := passwordGrant(t, ts, c, "scn22@example.com", "hunter22", "read")
		if tok.AccessToken == "" {
			t.Fatalf("setup: missing access token")
		}

		status, hdr, body := callResource(t, ts, tok.AccessToken, adminPath)
		if status != http.StatusForbidden {
			t.Fatalf("expected 403, got %d body=%s", status, body)
		}
		got := hdr.Get("WWW-Authenticate")
		if !strings.Contains(got, `error="insufficient_scope"`) {
			t.Fatalf("expected insufficient_scope, got %q", got)
		}
		if !strings.Contains(got, `scope="read_write"`) {
			t.Fatalf("expected scope=\"read_write\" in WWW-Authenticate, got %q", got)
		}
	})

	t.Run("token with required scope passes the policy", func(t *testing.T) {
		_, tok, _ := passwordGrant(t, ts, c, "scn22@example.com", "hunter22", "read_write")
		if tok.AccessToken == "" {
			t.Fatalf("setup: missing access token")
		}

		status, _, body := callResource(t, ts, tok.AccessToken, adminPath)
		if status != http.StatusOK {
			t.Fatalf("expected 200, got %d body=%s", status, body)
		}
	})

	t.Run("non-admin path is unaffected by the admin policy", func(t *testing.T) {
		_, tok, _ := passwordGrant(t, ts, c, "scn22@example.com", "hunter22", "read")
		if tok.AccessToken == "" {
			t.Fatalf("setup: missing access token")
		}

		// /test/resource/foo has no policy; read-only token works.
		status, _, body := callResource(t, ts, tok.AccessToken, "/test/resource/foo")
		if status != http.StatusOK {
			t.Fatalf("expected 200 for un-policed path, got %d body=%s", status, body)
		}
	})
}
