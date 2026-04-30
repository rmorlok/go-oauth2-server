package integration_test

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
)

// TestScenario16_MissingAuthorizationCode verifies the server-side
// contribution to the spec's "Missing Authorization Code": an exchange
// request that omits `code` (e.g. because the proxy received a callback
// with state but no code and incorrectly tried to exchange anyway)
// must not produce a token.
//
// PROXY-SIDE: detecting "the callback URL had state but no code" before
// even attempting an exchange is the proxy's job — not the provider's.
// See docs/integration_test_gaps.md row "scenario-16".
//
// Spec: P1 scenario 16.
func TestScenario16_MissingAuthorizationCode(t *testing.T) {
	ts := newTestServer(t)
	c := registerClient(t, ts, "scn16", "scn16-secret", "https://app.example.com/cb")

	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	// Intentionally no `code` field.
	form.Set("redirect_uri", c.RedirectURI)

	req, _ := http.NewRequest("POST", ts.URL+"/v1/oauth/tokens", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(c.Key, c.Secret)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("token: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode == http.StatusOK {
		t.Fatalf("exchange without code must not succeed, got 200")
	}
}
