package integration_test

import (
	"net/http"
	"testing"

	"github.com/RichardKnop/go-oauth2-server/models"
)

// TestScenario09_RefreshRotation covers the spec's "Refresh Token
// Rotation". Test-mode defaults RefreshTokenRotation=true so a single
// refresh should produce a new refresh token, the old one should be
// rejected on replay, and the new one should chain via parent_id.
//
// Spec: P0 scenario 9.
func TestScenario09_RefreshRotation(t *testing.T) {
	ts := newTestServer(t)

	c := registerClient(t, ts, "scn09", "scn09-secret", "https://app.example.com/cb")
	registerUser(t, ts, "scn09@example.com", "hunter22")

	_, tok, body := passwordGrant(t, ts, c, "scn09@example.com", "hunter22", "read")
	if tok.RefreshToken == "" {
		t.Fatalf("expected refresh_token, body=%s", body)
	}
	originalRT := tok.RefreshToken

	// First refresh — rotation is on by default in test mode.
	status, refreshed, rbody := refresh(t, ts, c, originalRT)
	if status != http.StatusOK {
		t.Fatalf("first refresh expected 200, got %d body=%s", status, rbody)
	}
	if refreshed.RefreshToken == "" || refreshed.RefreshToken == originalRT {
		t.Fatalf("expected a new refresh token, got %q (was %q)", refreshed.RefreshToken, originalRT)
	}

	// Replay the OLD refresh token: must fail.
	status2, _, body2 := refresh(t, ts, c, originalRT)
	if status2 != http.StatusBadRequest {
		t.Fatalf("expected 400 on revoked-RT replay, got %d body=%s", status2, body2)
	}

	// New RT works.
	status3, _, body3 := refresh(t, ts, c, refreshed.RefreshToken)
	if status3 != http.StatusOK {
		t.Fatalf("new RT should work, got %d body=%s", status3, body3)
	}

	// parent_id linkage: the most recently issued (un-revoked) RT in the
	// DB should point back through parent_id to the original.
	var rows []models.OauthRefreshToken
	if err := ts.DB.Where("token = ?", refreshed.RefreshToken).Find(&rows).Error; err != nil {
		t.Fatalf("find rotated RT: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("expected 1 row for rotated RT, got %d", len(rows))
	}
	if !rows[0].ParentID.Valid || rows[0].ParentID.String == "" {
		t.Fatalf("rotated RT should have parent_id set, got %+v", rows[0].ParentID)
	}

	// And the original RT should be marked revoked, not deleted.
	var originals []models.OauthRefreshToken
	if err := ts.DB.Where("token = ?", originalRT).Find(&originals).Error; err != nil {
		t.Fatalf("find original RT: %v", err)
	}
	if len(originals) != 1 {
		t.Fatalf("expected original RT row to still exist (revoked, not deleted), got %d", len(originals))
	}
	if originals[0].RevokedAt == nil {
		t.Fatalf("original RT should have revoked_at set")
	}
}
