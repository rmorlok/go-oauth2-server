package integration_test

import (
	"net/http"
	"testing"

	"github.com/RichardKnop/go-oauth2-server/testmode"
)

// TestScenario23_ProxyAPI429 covers the spec's "Proxy API Call
// Receives 429": script a 429 with a Retry-After header on the
// resource endpoint, verify the proxy receives both, and confirm the
// queue empties so subsequent un-scripted calls succeed.
//
// Spec: P1 scenario 23.
func TestScenario23_ProxyAPI429(t *testing.T) {
	ts := newTestServer(t)
	c := registerClient(t, ts, "scn23", "scn23-secret", "https://app.example.com/cb")
	registerUser(t, ts, "scn23@example.com", "hunter22")

	_, tok, _ := passwordGrant(t, ts, c, "scn23@example.com", "hunter22", "read")
	if tok.AccessToken == "" {
		t.Fatalf("setup: missing access token")
	}

	enqueueScript(t, ts, "", "resource", testmode.Action{
		Status:  http.StatusTooManyRequests,
		Headers: map[string]string{"Retry-After": "30"},
		Body:    `{"error":"rate_limited"}`,
	})

	status, hdr, body := callResource(t, ts, tok.AccessToken, "/test/resource/foo")
	if status != http.StatusTooManyRequests {
		t.Fatalf("expected 429, got %d body=%s", status, body)
	}
	if got := hdr.Get("Retry-After"); got != "30" {
		t.Fatalf("expected Retry-After=30, got %q", got)
	}
	if string(body) != `{"error":"rate_limited"}` {
		t.Fatalf("body byte-for-byte mismatch, got %q", body)
	}

	// Following call (queue empty) succeeds — confirms 429 was a one-shot.
	st2, _, body2 := callResource(t, ts, tok.AccessToken, "/test/resource/foo")
	if st2 != http.StatusOK {
		t.Fatalf("follow-up after 429 expected 200, got %d body=%s", st2, body2)
	}
}
