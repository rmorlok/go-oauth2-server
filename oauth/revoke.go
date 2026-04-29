package oauth

import (
	"errors"
	"net/http"
	"time"

	"github.com/RichardKnop/go-oauth2-server/models"
	"github.com/RichardKnop/go-oauth2-server/util/response"
)

// ErrUnsupportedTokenType is returned for an unrecognized token_type_hint.
// RFC 7009 §2.2.1.
var ErrUnsupportedTokenType = errors.New("unsupported_token_type")

// revokeHandler implements POST /v1/oauth/revoke per RFC 7009.
//
// Per §2.2 the response is always 200 unless authentication fails or the
// hint is malformed: unknown tokens, already-revoked tokens, and tokens
// belonging to a different client are all silently swallowed.
func (s *Service) revokeHandler(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		response.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	client, err := s.authenticateClient(r)
	if err != nil {
		response.UnauthorizedError(w, err.Error())
		return
	}

	token := r.Form.Get("token")
	if token == "" {
		// RFC 7009 doesn't strictly require this, but invalid_request is
		// the standard response when a required parameter is missing.
		response.Error(w, ErrTokenMissing.Error(), http.StatusBadRequest)
		return
	}

	hint := r.Form.Get("token_type_hint")
	switch hint {
	case "", AccessTokenHint, RefreshTokenHint:
		// fine
	default:
		response.Error(w, ErrUnsupportedTokenType.Error(), http.StatusBadRequest)
		return
	}

	if err := s.RevokeToken(token, hint, client); err != nil {
		// Should not happen for the normal "not-found / wrong-client"
		// paths — those return nil. A non-nil error here is a real DB or
		// internal failure.
		response.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
}

// RevokeToken applies RFC 7009 revocation semantics. It looks up the token
// (preferring `hint`'s table), checks ownership against `client`, and on a
// match marks the token revoked. Refresh-token revocation cascades to all
// non-revoked access tokens for the same (client_id, user_id) pair —
// over-revoking slightly when a single user has multiple grants for the
// same client, but correct in the common case and aligned with RFC 7009
// §2.1's SHOULD on cascading.
func (s *Service) RevokeToken(token, hint string, client *models.OauthClient) error {
	// Try the hinted table first, then fall back to the other.
	tryAccessFirst := hint != RefreshTokenHint

	if tryAccessFirst {
		if found, err := s.tryRevokeAccessToken(token, client); err != nil || found {
			return err
		}
		_, err := s.tryRevokeRefreshToken(token, client)
		return err
	}

	if found, err := s.tryRevokeRefreshToken(token, client); err != nil || found {
		return err
	}
	_, err := s.tryRevokeAccessToken(token, client)
	return err
}

func (s *Service) tryRevokeAccessToken(token string, client *models.OauthClient) (bool, error) {
	at := new(models.OauthAccessToken)
	notFound := s.db.Where("token = ?", token).First(at).RecordNotFound()
	if notFound {
		return false, nil
	}
	if at.ClientID.String != client.ID {
		// Belongs to another client — RFC 7009 §2.2: silently OK.
		return true, nil
	}
	if at.RevokedAt != nil {
		return true, nil // already revoked; nothing to do
	}
	return true, s.markAccessTokenRevoked(at)
}

func (s *Service) tryRevokeRefreshToken(token string, client *models.OauthClient) (bool, error) {
	rt := new(models.OauthRefreshToken)
	notFound := s.db.Where("token = ?", token).First(rt).RecordNotFound()
	if notFound {
		return false, nil
	}
	if rt.ClientID.String != client.ID {
		return true, nil
	}
	if rt.RevokedAt != nil {
		return true, nil
	}
	return true, s.revokeRefreshTokenWithCascade(rt)
}

func (s *Service) markAccessTokenRevoked(at *models.OauthAccessToken) error {
	now := time.Now().UTC()
	return s.db.Model(at).Update("revoked_at", now).Error
}

// revokeRefreshTokenWithCascade marks the refresh token revoked and
// cascades to every unrevoked access token for the same (client, user)
// pair, in a single transaction.
func (s *Service) revokeRefreshTokenWithCascade(rt *models.OauthRefreshToken) error {
	now := time.Now().UTC()

	tx := s.db.Begin()
	if tx.Error != nil {
		return tx.Error
	}

	if err := tx.Model(rt).Update("revoked_at", now).Error; err != nil {
		tx.Rollback()
		return err
	}

	q := tx.Model(new(models.OauthAccessToken)).
		Where("client_id = ?", rt.ClientID).
		Where("revoked_at IS NULL")
	if rt.UserID.Valid {
		q = q.Where("user_id = ?", rt.UserID.String)
	} else {
		q = q.Where("user_id IS NULL")
	}
	if err := q.Update("revoked_at", now).Error; err != nil {
		tx.Rollback()
		return err
	}

	return tx.Commit().Error
}

// AdminRevokeByToken revokes a single token regardless of which client owns
// it. Used by the test-mode /test/revoke endpoint. Returns true if a token
// was found and revoked.
func (s *Service) AdminRevokeByToken(token string) (bool, error) {
	at := new(models.OauthAccessToken)
	if !s.db.Where("token = ?", token).First(at).RecordNotFound() {
		if at.RevokedAt != nil {
			return true, nil
		}
		return true, s.markAccessTokenRevoked(at)
	}
	rt := new(models.OauthRefreshToken)
	if !s.db.Where("token = ?", token).First(rt).RecordNotFound() {
		if rt.RevokedAt != nil {
			return true, nil
		}
		return true, s.revokeRefreshTokenWithCascade(rt)
	}
	return false, nil
}

// AdminRevokeByUser revokes all unrevoked tokens for the given user. Used
// by /test/revoke. Returns the count of (refresh, access) tokens revoked.
func (s *Service) AdminRevokeByUser(userID string) (int64, int64, error) {
	now := time.Now().UTC()

	tx := s.db.Begin()
	if tx.Error != nil {
		return 0, 0, tx.Error
	}
	rRes := tx.Model(new(models.OauthRefreshToken)).
		Where("user_id = ? AND revoked_at IS NULL", userID).
		Update("revoked_at", now)
	if rRes.Error != nil {
		tx.Rollback()
		return 0, 0, rRes.Error
	}
	aRes := tx.Model(new(models.OauthAccessToken)).
		Where("user_id = ? AND revoked_at IS NULL", userID).
		Update("revoked_at", now)
	if aRes.Error != nil {
		tx.Rollback()
		return 0, 0, aRes.Error
	}
	return rRes.RowsAffected, aRes.RowsAffected, tx.Commit().Error
}

// AdminRevokeByClient revokes all unrevoked tokens for the given client.
func (s *Service) AdminRevokeByClient(clientID string) (int64, int64, error) {
	now := time.Now().UTC()

	tx := s.db.Begin()
	if tx.Error != nil {
		return 0, 0, tx.Error
	}
	rRes := tx.Model(new(models.OauthRefreshToken)).
		Where("client_id = ? AND revoked_at IS NULL", clientID).
		Update("revoked_at", now)
	if rRes.Error != nil {
		tx.Rollback()
		return 0, 0, rRes.Error
	}
	aRes := tx.Model(new(models.OauthAccessToken)).
		Where("client_id = ? AND revoked_at IS NULL", clientID).
		Update("revoked_at", now)
	if aRes.Error != nil {
		tx.Rollback()
		return 0, 0, aRes.Error
	}
	return rRes.RowsAffected, aRes.RowsAffected, tx.Commit().Error
}
