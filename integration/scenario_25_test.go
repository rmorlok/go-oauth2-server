package integration_test

import (
	"net/http"
	"strings"
	"testing"
)

// TestScenario25_IncrementalAuthorization covers the spec's
// "Incremental Authorization": after a successful flow with a narrow
// scope, the same user re-authorizes the same client with a broader
// scope. The new access token has the broader scope and the original
// access token continues to work until expiry — failed upgrade does
// not destroy existing credentials.
//
// Server quirk worth noting: GetOrCreateRefreshToken finds an existing
// non-revoked RT for (client, user) and returns it as-is. So a second
// authorization for the same (client, user) pair reuses the prior RT
// rather than minting one with the broader scope. The access tokens
// are independent (one per Login call) so the broader-scope assertion
// holds at the access-token layer; we don't assert anything specific
// about the second-flow refresh token's scope.
// See docs/integration_test_gaps.md row "fresh-rt-per-auth".
//
// Spec: P2 scenario 25.
func TestScenario25_IncrementalAuthorization(t *testing.T) {
	ts := newTestServer(t)
	c := registerClient(t, ts, "scn25", "scn25-secret", "https://app.example.com/cb")
	u := registerUser(t, ts, "scn25@example.com", "hunter22")

	// First flow: scope=read.
	redirect1 := authorize(t, ts, "approve", authorizeParams{
		Client: c, User: u, Scope: "read",
	})
	code1 := extractCode(t, redirect1)
	status1, tok1, body1 := exchangeCode(t, ts, c, code1)
	if status1 != http.StatusOK {
		t.Fatalf("first exchange expected 200, got %d body=%s", status1, body1)
	}
	if tok1.Scope != "read" {
		t.Fatalf("first token expected scope=read, got %q", tok1.Scope)
	}

	// Second flow: re-authorize with the broader scope.
	redirect2 := authorize(t, ts, "approve", authorizeParams{
		Client: c, User: u, Scope: "read_write",
	})
	code2 := extractCode(t, redirect2)
	status2, tok2, body2 := exchangeCode(t, ts, c, code2)
	if status2 != http.StatusOK {
		t.Fatalf("second exchange expected 200, got %d body=%s", status2, body2)
	}
	if tok2.Scope != "read_write" {
		t.Fatalf("second token expected scope=read_write, got %q", tok2.Scope)
	}
	if tok2.AccessToken == tok1.AccessToken {
		t.Fatalf("second flow should issue a new access token, got same as first")
	}

	// Original access token still works at the resource (existing
	// credentials are not destroyed by the upgrade).
	st1, _, b1 := callResource(t, ts, tok1.AccessToken, "/test/resource/foo")
	if st1 != http.StatusOK {
		t.Fatalf("original access token should still work, got %d body=%s", st1, b1)
	}

	// New access token has the broader scope visible in the default body.
	st2, _, b2 := callResource(t, ts, tok2.AccessToken, "/test/resource/foo")
	if st2 != http.StatusOK {
		t.Fatalf("new access token should work, got %d body=%s", st2, b2)
	}
	if !strings.Contains(string(b2), `"scope":"read_write"`) {
		t.Fatalf("new resource body should report scope=read_write, got %s", b2)
	}
}
