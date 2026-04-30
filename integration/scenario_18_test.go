package integration_test

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/RichardKnop/go-oauth2-server/testmode"
)

// TestScenario18_ProviderTimeout scripts a delay on each recordable
// endpoint and uses a client with a short request timeout. The first
// call to each endpoint times out client-side; the action is then
// drained from the queue so a subsequent un-scripted call to the same
// endpoint succeeds.
//
// Server-side, all we're proving is that delay_ms actually delays:
// proxy retry/backoff policy is its own concern.
//
// Spec: P1 scenario 18.
func TestScenario18_ProviderTimeout(t *testing.T) {
	ts := newTestServer(t)
	c := registerClient(t, ts, "scn18", "scn18-secret", "https://app.example.com/cb")
	registerUser(t, ts, "scn18@example.com", "hunter22")

	// Mint a token + RT once for the refresh / resource / userinfo /
	// revoke calls. Use the un-throttled client.
	_, baseTok, _ := passwordGrant(t, ts, c, "scn18@example.com", "hunter22", "profile")
	if baseTok.AccessToken == "" || baseTok.RefreshToken == "" {
		t.Fatalf("setup: expected both tokens")
	}

	const (
		delayMs = 500
		timeout = 75 * time.Millisecond
	)
	slowClient := &http.Client{Timeout: timeout}

	endpoints := []struct {
		label  string
		script string // action goes on this script-queue endpoint label
		fire   func(*testing.T, *http.Client) (int, error)
		// followUp drives an un-scripted call to verify the queue drained.
		followUp func(*testing.T) int
	}{
		{
			label:  "token",
			script: "token",
			fire: func(t *testing.T, hc *http.Client) (int, error) {
				return postFormBasic(hc, ts.URL+"/v1/oauth/tokens", c.Key, c.Secret,
					url.Values{"grant_type": []string{"client_credentials"}, "scope": []string{"read"}})
			},
			followUp: func(t *testing.T) int {
				st, _, _ := clientCredentialsGrant(t, ts, c, "read")
				return st
			},
		},
		{
			label:  "refresh",
			script: "refresh",
			fire: func(t *testing.T, hc *http.Client) (int, error) {
				return postFormBasic(hc, ts.URL+"/v1/oauth/tokens", c.Key, c.Secret,
					url.Values{"grant_type": []string{"refresh_token"}, "refresh_token": []string{baseTok.RefreshToken}})
			},
			followUp: func(t *testing.T) int {
				// Use a fresh RT for the un-scripted follow-up — refresh
				// is destructive due to rotation.
				_, freshTok, _ := passwordGrant(t, ts, c, "scn18@example.com", "hunter22", "profile")
				st, _, _ := refresh(t, ts, c, freshTok.RefreshToken)
				return st
			},
		},
		{
			label:  "revoke",
			script: "revoke",
			fire: func(t *testing.T, hc *http.Client) (int, error) {
				return postFormBasic(hc, ts.URL+"/v1/oauth/revoke", c.Key, c.Secret,
					url.Values{"token": []string{"some-token"}})
			},
			followUp: func(t *testing.T) int {
				return revokeToken(t, ts, c, "some-other-token", "")
			},
		},
		{
			label:  "userinfo",
			script: "userinfo",
			fire: func(t *testing.T, hc *http.Client) (int, error) {
				req, _ := http.NewRequest("GET", ts.URL+"/v1/oauth/userinfo", nil)
				req.Header.Set("Authorization", "Bearer "+baseTok.AccessToken)
				resp, err := hc.Do(req)
				if err != nil {
					return 0, err
				}
				resp.Body.Close()
				return resp.StatusCode, nil
			},
			followUp: func(t *testing.T) int {
				st, _, _ := userinfo(t, ts, baseTok.AccessToken)
				return st
			},
		},
		{
			label:  "resource",
			script: "resource",
			fire: func(t *testing.T, hc *http.Client) (int, error) {
				req, _ := http.NewRequest("GET", ts.URL+"/test/resource/foo", nil)
				req.Header.Set("Authorization", "Bearer "+baseTok.AccessToken)
				resp, err := hc.Do(req)
				if err != nil {
					return 0, err
				}
				resp.Body.Close()
				return resp.StatusCode, nil
			},
			followUp: func(t *testing.T) int {
				st, _, _ := callResource(t, ts, baseTok.AccessToken, "/test/resource/foo")
				return st
			},
		},
	}

	for _, tc := range endpoints {
		t.Run(tc.label+" times out", func(t *testing.T) {
			ts.Queue.Clear("", "")
			enqueueScript(t, ts, "", tc.script, testmode.Action{
				DelayMS: delayMs,
				Status:  200,
				Body:    `{"never":"delivered"}`,
			})

			start := time.Now()
			_, err := tc.fire(t, slowClient)
			elapsed := time.Since(start)
			if err == nil {
				t.Fatalf("%s: expected timeout error, got nil", tc.label)
			}
			if !isTimeoutErr(err) {
				t.Fatalf("%s: expected timeout error, got %v", tc.label, err)
			}
			// Sanity: the timeout fired close to the configured client
			// timeout, not the full server delay.
			if elapsed > timeout*4 {
				t.Fatalf("%s: client took too long (%v) — expected ~%v", tc.label, elapsed, timeout)
			}
		})

		t.Run(tc.label+" un-scripted call after timeout succeeds", func(t *testing.T) {
			// The script middleware popped its action on the timed-out
			// request, so the queue is already empty by the time we get
			// here. The previous handler goroutine is still sleeping
			// in the background; it will write to the closed connection
			// and return harmlessly. We don't need to wait for it.
			st := tc.followUp(t)
			// Most endpoints return 200 on the un-scripted path. revoke
			// is silent-200 even on unknown tokens. Token / refresh /
			// userinfo / resource all return 200 here.
			if st != http.StatusOK {
				t.Fatalf("%s: un-scripted follow-up expected 200, got %d", tc.label, st)
			}
		})
	}
}

// postFormBasic posts a form with HTTP Basic auth and returns the
// status code (or the error if the request never completes).
func postFormBasic(hc *http.Client, u, user, pass string, form url.Values) (int, error) {
	req, _ := http.NewRequest("POST", u, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(user, pass)
	resp, err := hc.Do(req)
	if err != nil {
		return 0, err
	}
	resp.Body.Close()
	return resp.StatusCode, nil
}

// isTimeoutErr returns true if err looks like an http.Client timeout.
// We match on the message because the underlying cause in net/http is
// either a *url.Error wrapping a timeout, a context.DeadlineExceeded,
// or a net.Error with Timeout()==true; the message is reliably present
// in all three.
func isTimeoutErr(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "Client.Timeout") ||
		strings.Contains(msg, "context deadline exceeded") ||
		strings.Contains(msg, "i/o timeout")
}
