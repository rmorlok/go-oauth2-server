package integration_test

import (
	"net/http"
	"strings"
	"testing"

	"github.com/RichardKnop/go-oauth2-server/testmode"
)

// TestScenario07_RefreshFailures covers the spec's "Refresh Token
// Failure" cases — both natural (revoked RT) and scripted (invalid_grant,
// malformed JSON, success-without-access-token).
//
// Spec: P0 scenario 7.
func TestScenario07_RefreshFailures(t *testing.T) {
	ts := newTestServer(t)

	c := registerClient(t, ts, "scn07", "scn07-secret", "https://app.example.com/cb")
	registerUser(t, ts, "scn07@example.com", "hunter22")

	mintRT := func(t *testing.T) string {
		t.Helper()
		_, tok, body := passwordGrant(t, ts, c, "scn07@example.com", "hunter22", "read")
		if tok.RefreshToken == "" {
			t.Fatalf("expected refresh_token from password grant, body=%s", body)
		}
		return tok.RefreshToken
	}

	t.Run("revoked RT is rejected", func(t *testing.T) {
		ts.Queue.Clear("", "")

		rt := mintRT(t)
		// Revoke via the admin path.
		adminRevoke(t, ts, map[string]string{"token": rt})

		status, _, body := refresh(t, ts, c, rt)
		if status != http.StatusBadRequest {
			t.Fatalf("expected 400 on revoked RT, got %d body=%s", status, body)
		}
	})

	t.Run("scripted invalid_grant on refresh", func(t *testing.T) {
		ts.Queue.Clear("", "")
		enqueueScript(t, ts, "", "refresh", testmode.Action{BodyTemplate: "invalid_grant"})

		status, _, body := refresh(t, ts, c, mintRT(t))
		if status != http.StatusBadRequest {
			t.Fatalf("scripted invalid_grant expected 400, got %d body=%s", status, body)
		}
		if !strings.Contains(string(body), "invalid_grant") {
			t.Fatalf("expected canonical invalid_grant body, got %s", body)
		}
	})

	t.Run("scripted malformed_json on refresh", func(t *testing.T) {
		ts.Queue.Clear("", "")
		enqueueScript(t, ts, "", "refresh", testmode.Action{BodyTemplate: "malformed_json"})

		status, _, body := refresh(t, ts, c, mintRT(t))
		// The malformed_json template uses status 200, so the proxy gets
		// a 200 with a body that isn't valid JSON. Server-side, the
		// response should be byte-for-byte the malformed string from the
		// template.
		if status != http.StatusOK {
			t.Fatalf("malformed_json template uses 200, got %d", status)
		}
		if string(body) != "{not valid json" {
			t.Fatalf("expected malformed body byte-for-byte, got %q", body)
		}
	})

	t.Run("scripted success-without-access-token", func(t *testing.T) {
		ts.Queue.Clear("", "")
		// Custom body that mimics a successful refresh response but is
		// missing access_token. Server should pass it through verbatim;
		// it's the proxy's job to detect the missing field.
		body := `{"refresh_token":"new-rt-12345","token_type":"Bearer","expires_in":3600}`
		enqueueScript(t, ts, "", "refresh", testmode.Action{
			Status: 200,
			Body:   body,
		})

		status, _, gotBody := refresh(t, ts, c, mintRT(t))
		if status != http.StatusOK {
			t.Fatalf("expected scripted 200, got %d", status)
		}
		if string(gotBody) != body {
			t.Fatalf("expected body byte-for-byte; want %q got %q", body, gotBody)
		}
	})
}
