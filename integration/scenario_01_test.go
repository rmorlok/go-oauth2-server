package integration_test

import (
	"encoding/json"
	"net/http"
	"net/url"
	"testing"

	"github.com/RichardKnop/go-oauth2-server/testmode"
)

// TestScenario01_StandardOAuthFlow exercises the spec's "Standard
// Successful OAuth Flow" end-to-end: register, authorize-with-PKCE,
// exchange, call protected resource, inspect recorder.
//
// Spec: P0 scenario 1.
func TestScenario01_StandardOAuthFlow(t *testing.T) {
	ts := newTestServer(t)

	c := registerClient(t, ts, "scn01", "scn01-secret", "https://app.example.com/cb")
	u := registerUser(t, ts, "scn01@example.com", "hunter22")

	verifier, challenge := pkcePair()

	redirectURL := authorize(t, ts, "approve", authorizeParams{
		Client:              c,
		User:                u,
		Scope:               "read",
		State:               "spec-scn-01",
		CodeChallenge:       challenge,
		CodeChallengeMethod: "S256",
	})

	// Sanity-check the redirect: state echoed, code present.
	parsed, err := url.Parse(redirectURL)
	if err != nil {
		t.Fatalf("parse redirect: %v", err)
	}
	if parsed.Host != "app.example.com" || parsed.Path != "/cb" {
		t.Fatalf("unexpected redirect host/path: %s", redirectURL)
	}
	if got := parsed.Query().Get("state"); got != "spec-scn-01" {
		t.Fatalf("expected state=spec-scn-01, got %q", got)
	}

	code := extractCode(t, redirectURL)

	status, tok, body := exchangeCode(t, ts, c, code, exchangeOpts{CodeVerifier: verifier})
	if status != http.StatusOK {
		t.Fatalf("exchange expected 200, got %d body=%s", status, body)
	}
	if tok.AccessToken == "" {
		t.Fatalf("missing access_token in %s", body)
	}
	if tok.RefreshToken == "" {
		t.Fatalf("missing refresh_token in %s", body)
	}
	if tok.TokenType != "Bearer" {
		t.Fatalf("expected token_type=Bearer, got %q", tok.TokenType)
	}
	if tok.Scope != "read" {
		t.Fatalf("expected scope=read, got %q", tok.Scope)
	}
	if tok.ExpiresIn <= 0 {
		t.Fatalf("expected positive expires_in, got %d", tok.ExpiresIn)
	}

	rstatus, _, rbody := callResource(t, ts, tok.AccessToken, "/test/resource/foo")
	if rstatus != http.StatusOK {
		t.Fatalf("resource expected 200, got %d body=%s", rstatus, rbody)
	}
	var doc map[string]any
	if err := json.Unmarshal(rbody, &doc); err != nil {
		t.Fatalf("decode resource body: %v body=%s", err, rbody)
	}
	if doc["path"] != "/test/resource/foo" || doc["scope"] != "read" {
		t.Fatalf("unexpected resource body: %+v", doc)
	}

	// Recorder should show the token request with Authorization redacted.
	entries := ts.Recorder.Snapshot(testmode.SnapshotFilter{Endpoint: "token"})
	if len(entries) == 0 {
		t.Fatalf("expected recorded token request")
	}
	got := entries[0]
	if got.Headers["Authorization"] != "Basic <redacted>" {
		t.Fatalf("expected Basic <redacted>, got %q", got.Headers["Authorization"])
	}
	if got.ClientID != "scn01" {
		t.Fatalf("expected recorded client_id=scn01, got %q", got.ClientID)
	}
	if v := got.Form["code_verifier"]; len(v) != 1 || v[0] != "<redacted>" {
		t.Fatalf("expected code_verifier redacted, got %v", v)
	}
}
