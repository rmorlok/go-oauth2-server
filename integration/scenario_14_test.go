package integration_test

import (
	"net/http"
	"strings"
	"testing"

	"github.com/RichardKnop/go-oauth2-server/oauth"
)

// TestScenario14_PKCEValidation walks through every PKCE branch the
// proxy may exercise:
//
//   - S256 happy path: matching verifier → 200
//   - S256 mismatch: wrong verifier → 400
//   - missing verifier when challenge is stored → 400
//   - plain method works
//   - none-client (strict PKCE) without challenge at authorize → 400
//   - unknown method (S512) at authorize → 400
//
// Spec: P1 scenario 14.
func TestScenario14_PKCEValidation(t *testing.T) {
	ts := newTestServer(t)

	c := registerClient(t, ts, "scn14", "scn14-secret", "https://app.example.com/cb")
	registerUser(t, ts, "scn14@example.com", "hunter22")

	verifier, challenge := pkcePair()

	authWithChallenge := func(t *testing.T, method string) string {
		t.Helper()
		redirectURL := authorize(t, ts, "approve", authorizeParams{
			Client:              c,
			Username:            "scn14@example.com",
			Scope:               "read",
			CodeChallenge:       challenge,
			CodeChallengeMethod: method,
		})
		return extractCode(t, redirectURL)
	}

	t.Run("S256 happy path", func(t *testing.T) {
		code := authWithChallenge(t, "S256")
		status, tok, body := exchangeCode(t, ts, c, code, exchangeOpts{CodeVerifier: verifier})
		if status != http.StatusOK {
			t.Fatalf("expected 200, got %d body=%s", status, body)
		}
		if tok.AccessToken == "" {
			t.Fatalf("missing access token: %s", body)
		}
	})

	t.Run("S256 mismatch is rejected", func(t *testing.T) {
		code := authWithChallenge(t, "S256")
		status, _, body := exchangeCode(t, ts, c, code, exchangeOpts{CodeVerifier: "WRONG-VERIFIER"})
		if status != http.StatusBadRequest {
			t.Fatalf("expected 400, got %d body=%s", status, body)
		}
		if !strings.Contains(string(body), "code_verifier") {
			t.Fatalf("error should mention code_verifier, got %s", body)
		}
	})

	t.Run("missing verifier when challenge is stored", func(t *testing.T) {
		code := authWithChallenge(t, "S256")
		status, _, body := exchangeCode(t, ts, c, code) // no opts → no verifier
		if status != http.StatusBadRequest {
			t.Fatalf("expected 400, got %d body=%s", status, body)
		}
	})

	t.Run("plain method", func(t *testing.T) {
		// For plain, challenge == verifier.
		redirectURL := authorize(t, ts, "approve", authorizeParams{
			Client:              c,
			Username:            "scn14@example.com",
			Scope:               "read",
			CodeChallenge:       verifier,
			CodeChallengeMethod: "plain",
		})
		code := extractCode(t, redirectURL)
		status, _, body := exchangeCode(t, ts, c, code, exchangeOpts{CodeVerifier: verifier})
		if status != http.StatusOK {
			t.Fatalf("expected 200 for plain match, got %d body=%s", status, body)
		}
	})

	t.Run("none client without challenge at authorize is rejected", func(t *testing.T) {
		pub := registerClient(t, ts, "scn14-pub", "", "https://app.example.com/cb",
			clientOpts{AuthMethod: oauth.AuthMethodNone})
		if !pub.RequirePKCE {
			t.Fatalf("none clients should auto-set require_pkce, got %+v", pub)
		}

		// Hand-roll the authorize request because the helper would 200 on
		// success; a strict-PKCE no-challenge authorize should fail with 400.
		buf := strings.NewReader(`{"client_id":"scn14-pub","username":"scn14@example.com","redirect_uri":"https://app.example.com/cb","scope":"read","decision":"approve"}`)
		resp, err := http.Post(ts.URL+"/test/authorize", "application/json", buf)
		if err != nil {
			t.Fatalf("authorize: %v", err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("expected 400 for none-client without challenge, got %d", resp.StatusCode)
		}
	})

	t.Run("unknown method (S512) at authorize is rejected", func(t *testing.T) {
		buf := strings.NewReader(`{"client_id":"scn14","username":"scn14@example.com","redirect_uri":"https://app.example.com/cb","scope":"read","decision":"approve","code_challenge":"` + challenge + `","code_challenge_method":"S512"}`)
		resp, err := http.Post(ts.URL+"/test/authorize", "application/json", buf)
		if err != nil {
			t.Fatalf("authorize: %v", err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("expected 400 for unknown method, got %d", resp.StatusCode)
		}
	})

}
