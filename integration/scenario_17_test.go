package integration_test

import (
	"net/http"
	"strings"
	"testing"

	"github.com/RichardKnop/go-oauth2-server/testmode"
)

// TestScenario17_MalformedTokenResponses scripts a battery of malformed
// or unusual token responses and verifies the server delivers each one
// byte-for-byte. The server's contribution is "I can produce arbitrary
// bytes for the proxy to choke on"; the proxy's contribution (failing
// safely on each) lives in the AuthProxy test harness.
//
// Spec: P1 scenario 17.
func TestScenario17_MalformedTokenResponses(t *testing.T) {
	ts := newTestServer(t)
	c := registerClient(t, ts, "scn17", "scn17-secret", "https://app.example.com/cb")

	cases := []struct {
		name        string
		action      testmode.Action
		wantStatus  int
		wantBody    string            // exact string match if non-empty
		wantHeaders map[string]string // subset match if non-empty
	}{
		{
			name:       "invalid JSON",
			action:     testmode.Action{BodyTemplate: "malformed_json"},
			wantStatus: 200,
			wantBody:   `{not valid json`,
		},
		{
			name: "wrong content-type",
			action: testmode.Action{
				Status:  200,
				Headers: map[string]string{"Content-Type": "text/plain"},
				Body:    `{"access_token":"x","token_type":"Bearer","expires_in":3600}`,
			},
			wantStatus:  200,
			wantBody:    `{"access_token":"x","token_type":"Bearer","expires_in":3600}`,
			wantHeaders: map[string]string{"Content-Type": "text/plain"},
		},
		{
			name: "missing access_token",
			action: testmode.Action{
				Status: 200,
				Body:   `{"token_type":"Bearer","expires_in":3600,"scope":"read"}`,
			},
			wantStatus: 200,
			wantBody:   `{"token_type":"Bearer","expires_in":3600,"scope":"read"}`,
		},
		{
			name: "missing token_type",
			action: testmode.Action{
				Status: 200,
				Body:   `{"access_token":"x","expires_in":3600,"scope":"read"}`,
			},
			wantStatus: 200,
			wantBody:   `{"access_token":"x","expires_in":3600,"scope":"read"}`,
		},
		{
			name: "unsupported token_type (MAC)",
			action: testmode.Action{
				Status: 200,
				Body:   `{"access_token":"x","token_type":"MAC","expires_in":3600}`,
			},
			wantStatus: 200,
			wantBody:   `{"access_token":"x","token_type":"MAC","expires_in":3600}`,
		},
		{
			name: "non-integer expires_in",
			action: testmode.Action{
				Status: 200,
				Body:   `{"access_token":"x","token_type":"Bearer","expires_in":"not-a-number"}`,
			},
			wantStatus: 200,
			wantBody:   `{"access_token":"x","token_type":"Bearer","expires_in":"not-a-number"}`,
		},
		{
			name: "negative expires_in",
			action: testmode.Action{
				Status: 200,
				Body:   `{"access_token":"x","token_type":"Bearer","expires_in":-1}`,
			},
			wantStatus: 200,
			wantBody:   `{"access_token":"x","token_type":"Bearer","expires_in":-1}`,
		},
		{
			name: "extreme expires_in",
			action: testmode.Action{
				Status: 200,
				Body:   `{"access_token":"x","token_type":"Bearer","expires_in":99999999999999}`,
			},
			wantStatus: 200,
			wantBody:   `{"access_token":"x","token_type":"Bearer","expires_in":99999999999999}`,
		},
		{
			name: "duplicate fields",
			action: testmode.Action{
				Status: 200,
				Body:   `{"access_token":"first","access_token":"second","token_type":"Bearer","expires_in":3600}`,
			},
			wantStatus: 200,
			wantBody:   `{"access_token":"first","access_token":"second","token_type":"Bearer","expires_in":3600}`,
		},
		{
			name: "missing scope",
			action: testmode.Action{
				Status: 200,
				Body:   `{"access_token":"x","token_type":"Bearer","expires_in":3600}`,
			},
			wantStatus: 200,
			wantBody:   `{"access_token":"x","token_type":"Bearer","expires_in":3600}`,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ts.Queue.Clear("", "")
			enqueueScript(t, ts, "", "token", tc.action)

			status, _, body := clientCredentialsGrant(t, ts, c, "read")
			if status != tc.wantStatus {
				t.Fatalf("status: want %d got %d body=%s", tc.wantStatus, status, body)
			}
			if tc.wantBody != "" && string(body) != tc.wantBody {
				t.Fatalf("body byte-for-byte mismatch:\nwant %q\ngot  %q", tc.wantBody, body)
			}
			// Header subset check (we don't have access to the full
			// response object here, but the script delivered exact
			// headers; spot-check via a fresh request capture).
			_ = tc.wantHeaders // covered by direct request below

			if len(tc.wantHeaders) > 0 {
				ts.Queue.Clear("", "")
				enqueueScript(t, ts, "", "token", tc.action)

				req, _ := http.NewRequest("POST", ts.URL+"/v1/oauth/tokens",
					strings.NewReader("grant_type=client_credentials&scope=read"))
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				req.SetBasicAuth(c.Key, c.Secret)
				resp, err := http.DefaultClient.Do(req)
				if err != nil {
					t.Fatalf("token req: %v", err)
				}
				resp.Body.Close()
				for k, want := range tc.wantHeaders {
					if got := resp.Header.Get(k); got != want {
						t.Fatalf("header %s: want %q got %q", k, want, got)
					}
				}
			}
		})
	}
}
