package integration_test

import (
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/RichardKnop/go-oauth2-server/oauth"
)

// TestScenario19_AuthMethodCompatibility exercises all three RFC 7591
// token-endpoint auth methods end-to-end:
//
//   - client_secret_basic: HTTP Basic on the token endpoint
//   - client_secret_post:  client_id + client_secret in the form body
//   - none:                public client, PKCE-required, no secret
//
// For each, the matching auth style succeeds. For each confidential
// client, the wrong style is rejected.
//
// Spec: P1 scenario 19 (the issue groups it with happy paths).
func TestScenario19_AuthMethodCompatibility(t *testing.T) {
	ts := newTestServer(t)
	registerUser(t, ts, "scn19@example.com", "hunter22")

	t.Run("client_secret_basic happy path", func(t *testing.T) {
		c := registerClient(t, ts, "scn19-basic", "basic-secret", "https://app.example.com/cb",
			clientOpts{AuthMethod: oauth.AuthMethodSecretBasic})

		status, tok, body := passwordGrant(t, ts, c, "scn19@example.com", "hunter22", "read")
		if status != http.StatusOK {
			t.Fatalf("basic-auth grant expected 200, got %d body=%s", status, body)
		}
		if tok.AccessToken == "" {
			t.Fatalf("missing access token: %s", body)
		}
	})

	t.Run("client_secret_basic rejects post-style auth", func(t *testing.T) {
		// Same client as above; force form-style auth manually.
		form := url.Values{}
		form.Set("grant_type", "password")
		form.Set("username", "scn19@example.com")
		form.Set("password", "hunter22")
		form.Set("scope", "read")
		form.Set("client_id", "scn19-basic")
		form.Set("client_secret", "basic-secret")
		req, _ := http.NewRequest("POST", ts.URL+"/v1/oauth/tokens", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("token: %v", err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("post-style auth on basic client should fail, got %d", resp.StatusCode)
		}
	})

	t.Run("client_secret_post happy path", func(t *testing.T) {
		c := registerClient(t, ts, "scn19-post", "post-secret", "https://app.example.com/cb",
			clientOpts{AuthMethod: oauth.AuthMethodSecretPost})

		// Helpers honor c.TokenEndpointAuthMethod and put creds in the form.
		status, tok, body := passwordGrant(t, ts, c, "scn19@example.com", "hunter22", "read")
		if status != http.StatusOK {
			t.Fatalf("post-auth grant expected 200, got %d body=%s", status, body)
		}
		if tok.AccessToken == "" {
			t.Fatalf("missing access token: %s", body)
		}
	})

	t.Run("client_secret_post rejects basic-style auth", func(t *testing.T) {
		// Hit the post client with HTTP Basic.
		form := url.Values{}
		form.Set("grant_type", "password")
		form.Set("username", "scn19@example.com")
		form.Set("password", "hunter22")
		form.Set("scope", "read")
		req, _ := http.NewRequest("POST", ts.URL+"/v1/oauth/tokens", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.SetBasicAuth("scn19-post", "post-secret")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("token: %v", err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("basic auth on post client should fail, got %d", resp.StatusCode)
		}
	})

	t.Run("none (public) client + PKCE auth-code happy path", func(t *testing.T) {
		c := registerClient(t, ts, "scn19-pub", "", "https://app.example.com/cb",
			clientOpts{AuthMethod: oauth.AuthMethodNone})

		// `none` clients must use PKCE; registerClient confirmed
		// require_pkce was auto-set on creation.
		if !c.RequirePKCE {
			t.Fatalf("none client should auto-set require_pkce=true; got %+v", c)
		}

		verifier, challenge := pkcePair()
		redirectURL := authorize(t, ts, "approve", authorizeParams{
			Client:              c,
			Username:            "scn19@example.com",
			Scope:               "read",
			State:               "scn19-pkce",
			CodeChallenge:       challenge,
			CodeChallengeMethod: "S256",
		})
		code := extractCode(t, redirectURL)

		// Helpers put client_id (no secret) in the form body for none.
		status, tok, body := exchangeCode(t, ts, c, code, exchangeOpts{CodeVerifier: verifier})
		if status != http.StatusOK {
			t.Fatalf("none + PKCE exchange expected 200, got %d body=%s", status, body)
		}
		if tok.AccessToken == "" {
			t.Fatalf("missing access token: %s", body)
		}
	})

	t.Run("none client rejects basic auth at token endpoint", func(t *testing.T) {
		// Use the existing scn19-pub client with HTTP Basic.
		req, _ := http.NewRequest("POST", ts.URL+"/v1/oauth/tokens",
			strings.NewReader(url.Values{
				"grant_type": []string{"client_credentials"},
				"scope":      []string{"read"},
			}.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.SetBasicAuth("scn19-pub", "anything")
		resp, _ := http.DefaultClient.Do(req)
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("none client with basic auth should be 401, got %d body=%s", resp.StatusCode, body)
		}
	})

	t.Run("none client without PKCE is rejected at authorize", func(t *testing.T) {
		buf := []byte(`{"client_id":"scn19-pub","username":"scn19@example.com","redirect_uri":"https://app.example.com/cb","scope":"read","decision":"approve"}`)
		resp, err := http.Post(ts.URL+"/test/authorize", "application/json", strings.NewReader(string(buf)))
		if err != nil {
			t.Fatalf("authorize: %v", err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("none client without challenge should be 400, got %d", resp.StatusCode)
		}
	})
}
