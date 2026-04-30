package integration_test

import (
	"net/http"
	"testing"

	"github.com/RichardKnop/go-oauth2-server/testmode"
)

// TestScenario08_RefreshTransientWithRetry exercises the script queue's
// fail_count + fall-through semantics: enqueue a single 503 action with
// fail_count: 2, hit refresh three times — first two fire the action,
// third falls through to the real handler and refreshes successfully.
//
// Proxy retry policy itself is out of scope; the server contribution
// is "scripted failures fire in FIFO order, then the queue empties and
// real handlers take over". Subsequent rotation invariants (PR-4) hold:
// after the third refresh, the original RT is revoked and the new RT
// works.
//
// Spec: P0 scenario 8.
func TestScenario08_RefreshTransientWithRetry(t *testing.T) {
	ts := newTestServer(t)

	c := registerClient(t, ts, "scn08", "scn08-secret", "https://app.example.com/cb")
	registerUser(t, ts, "scn08@example.com", "hunter22")

	_, tok, body := passwordGrant(t, ts, c, "scn08@example.com", "hunter22", "read")
	if tok.RefreshToken == "" {
		t.Fatalf("expected refresh_token, body=%s", body)
	}
	originalRT := tok.RefreshToken

	// Enqueue ONE action with fail_count: 2 (apply twice, then drop).
	enqueueScript(t, ts, "", "refresh", testmode.Action{
		BodyTemplate: "temporarily_unavailable_503",
		FailCount:    2,
	})

	// First two refreshes: scripted 503. The original RT is untouched
	// because the script intercepts before the real handler runs.
	for i := 1; i <= 2; i++ {
		status, _, _ := refresh(t, ts, c, originalRT)
		if status != http.StatusServiceUnavailable {
			t.Fatalf("refresh #%d expected 503, got %d", i, status)
		}
	}

	// Third refresh: queue is now empty (fail_count exhausted), real
	// handler runs, rotation produces a new RT.
	status, refreshed, rbody := refresh(t, ts, c, originalRT)
	if status != http.StatusOK {
		t.Fatalf("refresh #3 expected 200 fall-through, got %d body=%s", status, rbody)
	}
	if refreshed.RefreshToken == "" || refreshed.RefreshToken == originalRT {
		t.Fatalf("expected a new RT after fall-through, got %q (was %q)", refreshed.RefreshToken, originalRT)
	}

	// The original RT is now revoked by the rotation; replay must fail.
	statusReplay, _, _ := refresh(t, ts, c, originalRT)
	if statusReplay != http.StatusBadRequest {
		t.Fatalf("expected 400 replay-after-rotation, got %d", statusReplay)
	}
}
