package integration_test

import (
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/RichardKnop/go-oauth2-server/testmode"
)

// TestScenario02_UserDenial covers the spec's "User Rejects
// Authorization": deny redirect carries error=access_denied + state, no
// code, no token exchange happens server-side, and an opportunistic
// synthetic-code exchange fails.
//
// Spec: P0 scenario 2.
func TestScenario02_UserDenial(t *testing.T) {
	ts := newTestServer(t)

	c := registerClient(t, ts, "scn02", "scn02-secret", "https://app.example.com/cb")
	u := registerUser(t, ts, "scn02@example.com", "hunter22")

	const state = "scn02-state-9f1e"
	redirectURL := authorize(t, ts, "deny", authorizeParams{
		Client: c,
		User:   u,
		Scope:  "read",
		State:  state,
	})

	parsed, err := url.Parse(redirectURL)
	if err != nil {
		t.Fatalf("parse redirect: %v", err)
	}
	q := parsed.Query()
	if got := q.Get("error"); got != "access_denied" {
		t.Fatalf("expected error=access_denied, got %q (full: %s)", got, redirectURL)
	}
	if got := q.Get("state"); got != state {
		t.Fatalf("expected state=%q, got %q", state, got)
	}
	if got := q.Get("code"); got != "" {
		t.Fatalf("deny redirect must not include code, got %q", got)
	}

	// No token grant happens server-side as a consequence of the deny.
	if entries := ts.Recorder.Snapshot(testmode.SnapshotFilter{Endpoint: "token"}); len(entries) != 0 {
		t.Fatalf("expected zero recorded token grants after deny, got %d", len(entries))
	}

	// A synthetic / replayed code from a malicious client must not work.
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", "00000000-0000-4000-8000-000000000000")
	form.Set("redirect_uri", c.RedirectURI)
	req, _ := http.NewRequest("POST", ts.URL+"/v1/oauth/tokens", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(c.Key, c.Secret)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("synthetic exchange: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode == http.StatusOK {
		t.Fatalf("synthetic-code exchange should fail, got 200")
	}
}
