package integration_test

import (
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/RichardKnop/go-oauth2-server/oauth"
	"github.com/RichardKnop/go-oauth2-server/testmode"
)

// TestScenario12_SensitiveValueRedaction proves that secrets do not
// appear in /test/requests for any of the recordable endpoints. Covers:
//
//   - Authorization: Basic <redacted>  (raw secret never recorded)
//   - Authorization: Bearer <redacted> (raw token never recorded)
//   - form fields client_secret, password, code_verifier, refresh_token
//     all redacted to <redacted>
//   - Cookie / Set-Cookie absent from recorded headers
//   - error response bodies don't echo the supplied secret
//
// Spec: P0 scenario 12.
func TestScenario12_SensitiveValueRedaction(t *testing.T) {
	ts := newTestServer(t)

	const supersecret = "super-s3cret-do-not-leak"
	const userPassword = "very-secret-password-do-not-leak"

	cBasic := registerClient(t, ts, "scn12-basic", supersecret, "https://app.example.com/cb")
	cPost := registerClient(t, ts, "scn12-post", supersecret, "https://app.example.com/cb",
		clientOpts{AuthMethod: oauth.AuthMethodSecretPost})
	registerUser(t, ts, "scn12@example.com", userPassword)

	t.Run("basic-auth client: Authorization Basic <redacted>", func(t *testing.T) {
		ts.Recorder.Reset()
		ts.Queue.Clear("", "")
		_, _, _ = clientCredentialsGrant(t, ts, cBasic, "read")
		entries := ts.Recorder.Snapshot(testmode.SnapshotFilter{Endpoint: "token"})
		if len(entries) != 1 {
			t.Fatalf("expected 1 token entry, got %d", len(entries))
		}
		assertNoLeak(t, entries[0], supersecret, "")
		if got := entries[0].Headers["Authorization"]; got != "Basic <redacted>" {
			t.Fatalf("expected Basic <redacted>, got %q", got)
		}
	})

	t.Run("post-auth client: form client_secret <redacted>", func(t *testing.T) {
		ts.Recorder.Reset()
		ts.Queue.Clear("", "")
		_, _, _ = clientCredentialsGrant(t, ts, cPost, "read")
		entries := ts.Recorder.Snapshot(testmode.SnapshotFilter{Endpoint: "token"})
		if len(entries) != 1 {
			t.Fatalf("expected 1 token entry, got %d", len(entries))
		}
		assertNoLeak(t, entries[0], supersecret, "")
		if got := entries[0].Form["client_secret"]; len(got) != 1 || got[0] != "<redacted>" {
			t.Fatalf("expected client_secret <redacted>, got %v", got)
		}
	})

	t.Run("password grant: form password <redacted>", func(t *testing.T) {
		ts.Recorder.Reset()
		ts.Queue.Clear("", "")
		_, _, _ = passwordGrant(t, ts, cBasic, "scn12@example.com", userPassword, "read")
		entries := ts.Recorder.Snapshot(testmode.SnapshotFilter{Endpoint: "token"})
		if len(entries) != 1 {
			t.Fatalf("expected 1 token entry, got %d", len(entries))
		}
		assertNoLeak(t, entries[0], supersecret, userPassword)
		if got := entries[0].Form["password"]; len(got) != 1 || got[0] != "<redacted>" {
			t.Fatalf("expected password <redacted>, got %v", got)
		}
	})

	t.Run("auth-code with PKCE: form code_verifier <redacted>", func(t *testing.T) {
		ts.Recorder.Reset()
		ts.Queue.Clear("", "")

		verifier, challenge := pkcePair()
		redirectURL := authorize(t, ts, "approve", authorizeParams{
			Client:              cBasic,
			Username:            "scn12@example.com",
			Scope:               "read",
			CodeChallenge:       challenge,
			CodeChallengeMethod: "S256",
		})
		code := extractCode(t, redirectURL)
		_, _, _ = exchangeCode(t, ts, cBasic, code, exchangeOpts{CodeVerifier: verifier})

		entries := ts.Recorder.Snapshot(testmode.SnapshotFilter{Endpoint: "token"})
		if len(entries) != 1 {
			t.Fatalf("expected 1 token entry, got %d", len(entries))
		}
		assertNoLeak(t, entries[0], supersecret, verifier)
		if got := entries[0].Form["code_verifier"]; len(got) != 1 || got[0] != "<redacted>" {
			t.Fatalf("expected code_verifier <redacted>, got %v", got)
		}
	})

	t.Run("refresh: form refresh_token <redacted>", func(t *testing.T) {
		ts.Recorder.Reset()
		ts.Queue.Clear("", "")

		_, tok, _ := passwordGrant(t, ts, cBasic, "scn12@example.com", userPassword, "read")
		_, _, _ = refresh(t, ts, cBasic, tok.RefreshToken)

		entries := ts.Recorder.Snapshot(testmode.SnapshotFilter{Endpoint: "refresh"})
		if len(entries) != 1 {
			t.Fatalf("expected 1 refresh entry, got %d (full: %+v)", len(entries),
				ts.Recorder.Snapshot(testmode.SnapshotFilter{}))
		}
		assertNoLeak(t, entries[0], supersecret, tok.RefreshToken)
		if got := entries[0].Form["refresh_token"]; len(got) != 1 || got[0] != "<redacted>" {
			t.Fatalf("expected refresh_token <redacted>, got %v", got)
		}
	})

	t.Run("resource: Authorization Bearer <redacted>", func(t *testing.T) {
		ts.Recorder.Reset()
		ts.Queue.Clear("", "")

		_, tok, _ := passwordGrant(t, ts, cBasic, "scn12@example.com", userPassword, "read")
		_, _, _ = callResource(t, ts, tok.AccessToken, "/test/resource/foo")

		entries := ts.Recorder.Snapshot(testmode.SnapshotFilter{Endpoint: "resource"})
		if len(entries) != 1 {
			t.Fatalf("expected 1 resource entry, got %d", len(entries))
		}
		assertNoLeak(t, entries[0], supersecret, tok.AccessToken)
		if got := entries[0].Headers["Authorization"]; got != "Bearer <redacted>" {
			t.Fatalf("expected Bearer <redacted>, got %q", got)
		}
	})

	t.Run("recorded headers do not include Cookie / Set-Cookie", func(t *testing.T) {
		ts.Recorder.Reset()
		ts.Queue.Clear("", "")

		// Hit a recorded endpoint with a Cookie header.
		form := url.Values{}
		form.Set("grant_type", "client_credentials")
		form.Set("scope", "read")
		req, _ := http.NewRequest("POST", ts.URL+"/v1/oauth/tokens", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Cookie", "session=do-not-leak")
		req.SetBasicAuth(cBasic.Key, cBasic.Secret)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("token: %v", err)
		}
		resp.Body.Close()

		entries := ts.Recorder.Snapshot(testmode.SnapshotFilter{Endpoint: "token"})
		if len(entries) == 0 {
			t.Fatalf("expected at least 1 token entry")
		}
		for _, e := range entries {
			if _, has := e.Headers["Cookie"]; has {
				t.Fatalf("Cookie should be stripped from recorded headers, got %v", e.Headers)
			}
			if _, has := e.Headers["Set-Cookie"]; has {
				t.Fatalf("Set-Cookie should be stripped from recorded headers, got %v", e.Headers)
			}
		}
	})

	t.Run("error response body does not echo client_secret", func(t *testing.T) {
		// Wrong-secret POST: server returns 401, body should not echo
		// the bad secret we sent.
		form := url.Values{}
		form.Set("grant_type", "client_credentials")
		form.Set("scope", "read")
		req, _ := http.NewRequest("POST", ts.URL+"/v1/oauth/tokens", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.SetBasicAuth(cBasic.Key, "WRONG-SECRET-with-marker-leak-zz")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("token: %v", err)
		}
		var buf [4096]byte
		n, _ := resp.Body.Read(buf[:])
		resp.Body.Close()
		body := string(buf[:n])
		if strings.Contains(body, "WRONG-SECRET-with-marker-leak-zz") {
			t.Fatalf("error body echoed the secret: %s", body)
		}
	})
}

// assertNoLeak fails the test if the recorded entry contains the given
// secrets anywhere in headers, query, or form values.
func assertNoLeak(t *testing.T, entry testmode.RecordedRequest, secrets ...string) {
	t.Helper()
	check := func(s string, where string) {
		for _, secret := range secrets {
			if secret == "" {
				continue
			}
			if strings.Contains(s, secret) {
				t.Fatalf("secret %q leaked in %s: %q", secret, where, s)
			}
		}
	}
	for k, v := range entry.Headers {
		check(v, "header "+k)
	}
	for k, vs := range entry.Query {
		for _, v := range vs {
			check(v, "query "+k)
		}
	}
	for k, vs := range entry.Form {
		for _, v := range vs {
			check(v, "form "+k)
		}
	}
}
