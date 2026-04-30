package integration_test

import (
	"net/http"
	"strings"
	"testing"

	"github.com/RichardKnop/go-oauth2-server/testmode"
)

// TestScenario13_NoRefreshToken covers the spec's "Successful Flow
// Without Refresh Token". Some real providers omit refresh_token from
// their token response (e.g. for short-lived public-client flows). The
// proxy needs to handle that path; the server's contribution is being
// able to produce such a response on demand.
//
// Spec: P1 scenario 13.
func TestScenario13_NoRefreshToken(t *testing.T) {
	ts := newTestServer(t)
	c := registerClient(t, ts, "scn13", "scn13-secret", "https://app.example.com/cb")

	const scriptedBody = `{"access_token":"sole-access-token","token_type":"Bearer","expires_in":3600,"scope":"read"}`
	enqueueScript(t, ts, "", "token", testmode.Action{Status: 200, Body: scriptedBody})

	status, _, body := clientCredentialsGrant(t, ts, c, "read")
	if status != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", status, body)
	}
	if string(body) != scriptedBody {
		t.Fatalf("body should be byte-for-byte the scripted body. want %q got %q", scriptedBody, body)
	}
	if strings.Contains(string(body), "refresh_token") {
		t.Fatalf("body should not contain refresh_token, got %q", body)
	}

	// Recorder still picks up the request (the scripter doesn't bypass
	// the recorder, which is mounted earlier in the chain).
	entries := ts.Recorder.Snapshot(testmode.SnapshotFilter{Endpoint: "token"})
	if len(entries) != 1 {
		t.Fatalf("expected 1 recorded token request, got %d", len(entries))
	}
	if entries[0].ClientID != "scn13" {
		t.Fatalf("expected recorded client_id=scn13, got %q", entries[0].ClientID)
	}
}
