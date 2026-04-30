package integration_test

import (
	"net/http"
	"testing"
	"time"

	"github.com/RichardKnop/go-oauth2-server/models"
)

// TestScenario06_AccessTokenExpiryAndRefresh covers the spec's "Access
// Token Expiry and Successful Refresh".
//
// Drives the just-issued access token into the past via a direct DB
// update (the test-mode access-token lifetime is config-wide and
// scenarios shouldn't fight over it; back-dating the row is the
// scenario-local way to simulate "the proxy notices the token is
// expired").
//
// Spec: P0 scenario 6.
func TestScenario06_AccessTokenExpiryAndRefresh(t *testing.T) {
	ts := newTestServer(t)

	c := registerClient(t, ts, "scn06", "scn06-secret", "https://app.example.com/cb")
	registerUser(t, ts, "scn06@example.com", "hunter22")

	// Get a refresh-eligible token via password grant.
	status, tok, body := passwordGrant(t, ts, c, "scn06@example.com", "hunter22", "read")
	if status != http.StatusOK {
		t.Fatalf("password grant expected 200, got %d body=%s", status, body)
	}
	originalAT := tok.AccessToken
	if originalAT == "" || tok.RefreshToken == "" {
		t.Fatalf("expected both tokens, got %+v", tok)
	}

	// Sanity: the just-issued token works.
	if s, _, _ := callResource(t, ts, originalAT, "/test/resource/foo"); s != http.StatusOK {
		t.Fatalf("freshly issued token should work, got %d", s)
	}

	// Back-date the access token so Authenticate's expiry check fires on
	// the next call.
	expireAccessToken(t, ts, originalAT)

	// Resource call with the now-expired token: 401.
	if s, _, _ := callResource(t, ts, originalAT, "/test/resource/foo"); s != http.StatusUnauthorized {
		t.Fatalf("expired token should return 401, got %d", s)
	}

	// Refresh.
	rstatus, refreshed, rbody := refresh(t, ts, c, tok.RefreshToken)
	if rstatus != http.StatusOK {
		t.Fatalf("refresh expected 200, got %d body=%s", rstatus, rbody)
	}
	if refreshed.AccessToken == "" || refreshed.AccessToken == originalAT {
		t.Fatalf("expected a new access token, got %q (was %q)", refreshed.AccessToken, originalAT)
	}

	// New token works.
	if s, _, body := callResource(t, ts, refreshed.AccessToken, "/test/resource/foo"); s != http.StatusOK {
		t.Fatalf("refreshed token should work at resource, got %d body=%s", s, body)
	}
}

// expireAccessToken sets the token's expires_at to one hour in the past
// so the next Authenticate call rejects it as expired.
func expireAccessToken(t *testing.T, ts *testServer, token string) {
	t.Helper()
	res := ts.DB.Model(new(models.OauthAccessToken)).
		Where("token = ?", token).
		Update("expires_at", time.Now().UTC().Add(-1*time.Hour))
	if res.Error != nil {
		t.Fatalf("expire access token: %v", res.Error)
	}
	if res.RowsAffected != 1 {
		t.Fatalf("expected to expire 1 access token, affected %d", res.RowsAffected)
	}
}
