package integration_test

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/RichardKnop/go-oauth2-server/testmode"
)

// TestScenario03_ScopeVariations covers the spec's scope-variation
// cases: granted-narrower-than-requested, scripted scope_override
// (omit and replace), and recorded inbound scope.
//
// Spec: P0 scenario 3.
func TestScenario03_ScopeVariations(t *testing.T) {
	ts := newTestServer(t)

	c := registerClient(t, ts, "scn03", "scn03-secret", "https://app.example.com/cb")
	u := registerUser(t, ts, "scn03@example.com", "hunter22")

	t.Run("granted_scope narrows the issued scope", func(t *testing.T) {
		ts.Queue.Clear("", "")

		redirectURL := authorize(t, ts, "approve", authorizeParams{
			Client:       c,
			User:         u,
			Scope:        "read_write",
			GrantedScope: "read",
		})
		code := extractCode(t, redirectURL)

		status, tok, body := exchangeCode(t, ts, c, code)
		if status != http.StatusOK {
			t.Fatalf("exchange expected 200, got %d body=%s", status, body)
		}
		if tok.Scope != "read" {
			t.Fatalf("expected scope narrowed to 'read', got %q (full: %s)", tok.Scope, body)
		}
	})

	t.Run("script scope_override empty omits scope from response", func(t *testing.T) {
		ts.Queue.Clear("", "")
		emptyScope := ""
		enqueueScript(t, ts, "", "token", testmode.Action{ScopeOverride: &emptyScope})

		// Use password grant for simplicity.
		_, _, body := passwordGrant(t, ts, c, "scn03@example.com", "hunter22", "read")
		var generic map[string]any
		if err := json.Unmarshal(body, &generic); err != nil {
			t.Fatalf("decode token body: %v body=%s", err, body)
		}
		if _, has := generic["scope"]; has {
			t.Fatalf("expected scope omitted, got %s", body)
		}
		if _, has := generic["access_token"]; !has {
			t.Fatalf("expected access_token still present, got %s", body)
		}
	})

	t.Run("script scope_override non-empty replaces scope", func(t *testing.T) {
		ts.Queue.Clear("", "")
		newScope := "narrowed"
		enqueueScript(t, ts, "", "token", testmode.Action{ScopeOverride: &newScope})

		_, tok, body := passwordGrant(t, ts, c, "scn03@example.com", "hunter22", "read")
		if tok.Scope != "narrowed" {
			t.Fatalf("expected scope=narrowed, got %q (body=%s)", tok.Scope, body)
		}
	})

	t.Run("recorder captures the inbound requested scope", func(t *testing.T) {
		ts.Queue.Clear("", "")
		ts.Recorder.Reset()

		// Plain password grant; no scope override, recorder should see
		// the scope the client sent.
		_, _, _ = passwordGrant(t, ts, c, "scn03@example.com", "hunter22", "read_write")

		entries := ts.Recorder.Snapshot(testmode.SnapshotFilter{Endpoint: "token"})
		if len(entries) != 1 {
			t.Fatalf("expected 1 recorded token call, got %d", len(entries))
		}
		got := entries[0].Form["scope"]
		if len(got) != 1 || got[0] != "read_write" {
			t.Fatalf("expected recorded scope=[read_write], got %v", got)
		}
	})
}
