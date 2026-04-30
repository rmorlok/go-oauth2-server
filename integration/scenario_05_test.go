package integration_test

import (
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/RichardKnop/go-oauth2-server/testmode"
)

// TestScenario05_ExchangeFailures covers the spec's "Authorization Code
// Exchange Failures" — natural failure modes plus scripted bad
// responses.
//
// Spec: P0 scenario 5.
func TestScenario05_ExchangeFailures(t *testing.T) {
	ts := newTestServer(t)

	c := registerClient(t, ts, "scn05", "scn05-secret", "https://app.example.com/cb")
	u := registerUser(t, ts, "scn05@example.com", "hunter22")

	mintCode := func(t *testing.T) string {
		t.Helper()
		redirectURL := authorize(t, ts, "approve", authorizeParams{
			Client: c, User: u, Scope: "read",
		})
		return extractCode(t, redirectURL)
	}

	t.Run("bad client secret -> 401", func(t *testing.T) {
		code := mintCode(t)
		form := url.Values{}
		form.Set("grant_type", "authorization_code")
		form.Set("code", code)
		form.Set("redirect_uri", c.RedirectURI)
		req, _ := http.NewRequest("POST", ts.URL+"/v1/oauth/tokens", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.SetBasicAuth(c.Key, "WRONG-SECRET")
		resp, _ := http.DefaultClient.Do(req)
		resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("bad secret expected 401, got %d", resp.StatusCode)
		}
	})

	t.Run("redirect_uri mismatch at exchange is rejected", func(t *testing.T) {
		code := mintCode(t)
		form := url.Values{}
		form.Set("grant_type", "authorization_code")
		form.Set("code", code)
		form.Set("redirect_uri", "https://other.example.com/cb")
		req, _ := http.NewRequest("POST", ts.URL+"/v1/oauth/tokens", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.SetBasicAuth(c.Key, c.Secret)
		resp, _ := http.DefaultClient.Do(req)
		resp.Body.Close()
		if resp.StatusCode == http.StatusOK {
			t.Fatalf("redirect_uri mismatch should reject, got 200")
		}
	})

	t.Run("already-used code -> rejected on replay", func(t *testing.T) {
		code := mintCode(t)
		if status, _, _ := exchangeCode(t, ts, c, code); status != http.StatusOK {
			t.Fatalf("first exchange should succeed, got %d", status)
		}
		status, _, body := exchangeCode(t, ts, c, code)
		if status == http.StatusOK {
			t.Fatalf("replay should fail, got 200 body=%s", body)
		}
	})

	t.Run("scripted invalid_grant -> 400", func(t *testing.T) {
		ts.Queue.Clear("", "")
		enqueueScript(t, ts, "", "token", testmode.Action{BodyTemplate: "invalid_grant"})

		status, _, body := exchangeCode(t, ts, c, mintCode(t))
		if status != http.StatusBadRequest {
			t.Fatalf("scripted invalid_grant should be 400, got %d body=%s", status, body)
		}
		if !strings.Contains(string(body), "invalid_grant") {
			t.Fatalf("expected invalid_grant body, got %s", body)
		}
	})

	t.Run("scripted temporarily_unavailable_503 -> 503", func(t *testing.T) {
		ts.Queue.Clear("", "")
		enqueueScript(t, ts, "", "token", testmode.Action{BodyTemplate: "temporarily_unavailable_503"})

		status, _, _ := exchangeCode(t, ts, c, mintCode(t))
		if status != http.StatusServiceUnavailable {
			t.Fatalf("scripted 503 should be 503, got %d", status)
		}
	})

	t.Run("scripted 500 / 502 / 504 reach the client byte-for-byte", func(t *testing.T) {
		for _, code := range []int{500, 502, 504} {
			ts.Queue.Clear("", "")
			body := `{"e":"upstream"}`
			enqueueScript(t, ts, "", "token", testmode.Action{
				Status: code,
				Body:   body,
			})
			status, _, gotBody := exchangeCode(t, ts, c, mintCode(t))
			if status != code {
				t.Fatalf("scripted %d should be %d, got %d", code, code, status)
			}
			if string(gotBody) != body {
				t.Fatalf("scripted body mismatch for %d: want %q got %q", code, body, gotBody)
			}
		}
	})
}
