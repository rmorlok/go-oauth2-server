package integration_test

import (
	"net/http"
	"strings"
	"testing"

	"github.com/RichardKnop/go-oauth2-server/testmode"
)

// TestScenario21_ProxyAPI401 covers the spec's "Proxy API Call
// Receives 401" — both natural causes (expired, revoked, malformed,
// tampered) and a scripted 401 from the resource endpoint.
//
// Spec: P1 scenario 21.
func TestScenario21_ProxyAPI401(t *testing.T) {
	ts := newTestServer(t)
	c := registerClient(t, ts, "scn21", "scn21-secret", "https://app.example.com/cb")
	registerUser(t, ts, "scn21@example.com", "hunter22")

	mintToken := func(t *testing.T) string {
		t.Helper()
		_, tok, _ := passwordGrant(t, ts, c, "scn21@example.com", "hunter22", "read")
		if tok.AccessToken == "" {
			t.Fatalf("setup: missing access token")
		}
		return tok.AccessToken
	}

	t.Run("expired token", func(t *testing.T) {
		ts.Queue.Clear("", "")
		at := mintToken(t)
		expireAccessToken(t, ts, at)
		status, hdr, _ := callResource(t, ts, at, "/test/resource/foo")
		if status != http.StatusUnauthorized {
			t.Fatalf("expected 401, got %d", status)
		}
		if !strings.Contains(hdr.Get("WWW-Authenticate"), `error="invalid_token"`) {
			t.Fatalf("expected invalid_token in WWW-Authenticate, got %q", hdr.Get("WWW-Authenticate"))
		}
	})

	t.Run("revoked token", func(t *testing.T) {
		ts.Queue.Clear("", "")
		at := mintToken(t)
		adminRevoke(t, ts, map[string]string{"token": at})
		status, hdr, _ := callResource(t, ts, at, "/test/resource/foo")
		if status != http.StatusUnauthorized {
			t.Fatalf("expected 401, got %d", status)
		}
		if !strings.Contains(hdr.Get("WWW-Authenticate"), `error="invalid_token"`) {
			t.Fatalf("expected invalid_token, got %q", hdr.Get("WWW-Authenticate"))
		}
	})

	t.Run("malformed token (wrong format)", func(t *testing.T) {
		ts.Queue.Clear("", "")
		status, hdr, _ := callResource(t, ts, "not-a-real-token-format", "/test/resource/foo")
		if status != http.StatusUnauthorized {
			t.Fatalf("expected 401, got %d", status)
		}
		if !strings.Contains(hdr.Get("WWW-Authenticate"), `error="invalid_token"`) {
			t.Fatalf("expected invalid_token, got %q", hdr.Get("WWW-Authenticate"))
		}
	})

	t.Run("tampered token (one char changed)", func(t *testing.T) {
		ts.Queue.Clear("", "")
		at := mintToken(t)
		// Flip one character in the middle of the UUID.
		i := len(at) / 2
		var b byte
		if at[i] == 'a' {
			b = 'b'
		} else {
			b = 'a'
		}
		tampered := at[:i] + string(b) + at[i+1:]
		status, _, _ := callResource(t, ts, tampered, "/test/resource/foo")
		if status != http.StatusUnauthorized {
			t.Fatalf("expected 401 for tampered token, got %d", status)
		}
	})

	t.Run("scripted 401 with custom body", func(t *testing.T) {
		ts.Queue.Clear("", "")
		at := mintToken(t)
		const body = `{"error":"invalid_token","error_description":"upstream says no"}`
		enqueueScript(t, ts, "", "resource", testmode.Action{
			Status:  http.StatusUnauthorized,
			Headers: map[string]string{"WWW-Authenticate": `Bearer error="invalid_token"`},
			Body:    body,
		})

		status, hdr, gotBody := callResource(t, ts, at, "/test/resource/foo")
		if status != http.StatusUnauthorized {
			t.Fatalf("expected scripted 401, got %d", status)
		}
		if string(gotBody) != body {
			t.Fatalf("body byte-for-byte mismatch:\nwant %q\ngot  %q", body, gotBody)
		}
		if got := hdr.Get("WWW-Authenticate"); !strings.Contains(got, `error="invalid_token"`) {
			t.Fatalf("expected scripted WWW-Authenticate, got %q", got)
		}
	})
}
