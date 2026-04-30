package integration_test

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/RichardKnop/go-oauth2-server/testmode"
)

// TestScenario01_StandardOAuthFlow — Phase 1 stub.
//
// Phase 1 (#27): asserts the harness boots and the basic helper chain
// works (register client + user, run /test/health, exercise the
// recorder + queue plumbing). Full PKCE + S256 + resource round-trip
// happy-path coverage lands in Phase 2 (#28).
//
// Spec: P0 scenario 1 — "Standard Successful OAuth Flow".
func TestScenario01_StandardOAuthFlow(t *testing.T) {
	ts := newTestServer(t)

	// /test/health round-trip — the simplest "the server is alive" check.
	resp, err := http.Get(ts.URL + "/test/health")
	if err != nil {
		t.Fatalf("health: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("health expected 200, got %d", resp.StatusCode)
	}
	var hb map[string]string
	json.NewDecoder(resp.Body).Decode(&hb)
	if hb["status"] != "ok" || hb["mode"] != "test" {
		t.Fatalf("unexpected health body: %v", hb)
	}

	// Helper chain: register a client + user, run a password grant, hit
	// the sample resource. Phase 2 will replace this with the full
	// authorization-code + PKCE flow.
	c := registerClient(t, ts, "scn1", "scn1-secret", "https://app.example.com/cb")
	if c.ID == "" || c.Key != "scn1" {
		t.Fatalf("unexpected registered client: %+v", c)
	}

	registerUser(t, ts, "scn1@example.com", "hunter22",
		userOpts{Email: "scn1@example.com", DisplayName: "Scenario One"})

	status, tok, body := passwordGrant(t, ts, c, "scn1@example.com", "hunter22", "read")
	if status != http.StatusOK {
		t.Fatalf("password grant expected 200, got %d body=%s", status, body)
	}
	if tok.AccessToken == "" || tok.RefreshToken == "" || tok.TokenType != "Bearer" {
		t.Fatalf("unexpected token response: %+v", tok)
	}

	rstatus, _, rbody := callResource(t, ts, tok.AccessToken, "/test/resource/health-check")
	if rstatus != http.StatusOK {
		t.Fatalf("resource expected 200, got %d body=%s", rstatus, rbody)
	}

	// Recorder picked up the token call; this proves BuildTestApp wired
	// the recorder middleware into the chain correctly.
	entries := ts.Recorder.Snapshot(testmode.SnapshotFilter{Endpoint: "token"})
	if len(entries) == 0 {
		t.Fatalf("expected recorded token request")
	}
	if got := entries[0].Headers["Authorization"]; got != "Basic <redacted>" {
		t.Fatalf("expected Basic <redacted>, got %q", got)
	}
}
