package integration_test

import (
	"net/http"
	"strconv"
	"testing"

	"github.com/RichardKnop/go-oauth2-server/testmode"
)

// TestScenario24_ProxyAPI5xx covers the spec's "Proxy API Call
// Receives 5xx" — for each of 500, 502, 503, 504 verify the scripted
// status reaches the client byte-for-byte and a follow-up un-scripted
// call returns 200.
//
// Spec: P1 scenario 24.
func TestScenario24_ProxyAPI5xx(t *testing.T) {
	ts := newTestServer(t)
	c := registerClient(t, ts, "scn24", "scn24-secret", "https://app.example.com/cb")
	registerUser(t, ts, "scn24@example.com", "hunter22")

	_, tok, _ := passwordGrant(t, ts, c, "scn24@example.com", "hunter22", "read")
	if tok.AccessToken == "" {
		t.Fatalf("setup: missing access token")
	}

	for _, code := range []int{500, 502, 503, 504} {
		t.Run(strconv.Itoa(code), func(t *testing.T) {
			ts.Queue.Clear("", "")
			body := `{"error":"upstream_` + strconv.Itoa(code) + `"}`
			enqueueScript(t, ts, "", "resource", testmode.Action{
				Status: code,
				Body:   body,
			})

			status, _, gotBody := callResource(t, ts, tok.AccessToken, "/test/resource/foo")
			if status != code {
				t.Fatalf("expected scripted %d, got %d", code, status)
			}
			if string(gotBody) != body {
				t.Fatalf("body byte-for-byte mismatch:\nwant %q\ngot  %q", body, gotBody)
			}

			// Un-scripted follow-up returns 200 (queue empty).
			st2, _, body2 := callResource(t, ts, tok.AccessToken, "/test/resource/foo")
			if st2 != http.StatusOK {
				t.Fatalf("follow-up after %d expected 200, got %d body=%s", code, st2, body2)
			}
		})
	}
}
