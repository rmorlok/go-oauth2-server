package integration_test

import (
	"net/url"
	"testing"
)

// TestScenario15_CallbackBothCodeAndError covers the server's
// contribution to the spec's "Callback Contains Both Code and Error":
// the test-mode authorize endpoint can produce both shapes, so a proxy
// test harness can stitch them into a single malicious URL and verify
// the proxy rejects it.
//
// PROXY-SIDE: deciding what to do when a real callback URL contains
// both `code` and `error` is the proxy's responsibility — not the
// provider's — and is therefore not covered here. See
// docs/integration_test_gaps.md row "scenario-15".
//
// Spec: P1 scenario 15.
func TestScenario15_CallbackBothCodeAndError(t *testing.T) {
	ts := newTestServer(t)
	c := registerClient(t, ts, "scn15", "scn15-secret", "https://app.example.com/cb")
	u := registerUser(t, ts, "scn15@example.com", "hunter22")

	// Approve produces a redirect with code + state.
	approve := authorize(t, ts, "approve", authorizeParams{
		Client: c, User: u, Scope: "read", State: "scn15",
	})
	approveU, err := url.Parse(approve)
	if err != nil {
		t.Fatalf("parse approve: %v", err)
	}
	if approveU.Query().Get("code") == "" {
		t.Fatalf("approve must include code, got %s", approve)
	}
	if approveU.Query().Get("state") != "scn15" {
		t.Fatalf("approve must echo state, got %q", approveU.Query().Get("state"))
	}
	if approveU.Query().Get("error") != "" {
		t.Fatalf("approve must not include error, got %s", approve)
	}

	// Deny produces a redirect with error + state, no code.
	deny := authorize(t, ts, "deny", authorizeParams{
		Client: c, User: u, Scope: "read", State: "scn15",
	})
	denyU, err := url.Parse(deny)
	if err != nil {
		t.Fatalf("parse deny: %v", err)
	}
	if got := denyU.Query().Get("error"); got != "access_denied" {
		t.Fatalf("deny must include error=access_denied, got %q", got)
	}
	if denyU.Query().Get("state") != "scn15" {
		t.Fatalf("deny must echo state, got %q", denyU.Query().Get("state"))
	}
	if got := denyU.Query().Get("code"); got != "" {
		t.Fatalf("deny must not include code, got %q", got)
	}

	// At this point both shapes have been demonstrated; a proxy test
	// can construct the malicious URL by combining the two as a
	// crafted callback. The server's job ends here.
}
