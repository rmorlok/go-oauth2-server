package oauth

import (
	"time"

	"github.com/RichardKnop/go-oauth2-server/models"
	"github.com/RichardKnop/go-oauth2-server/util"
)

// rotateRefreshToken is the rotation-on path for grant_type=refresh_token.
// It atomically marks the old token revoked and issues a new (access,
// refresh) pair linked back to it via parent_id.
//
// Concurrency: the revoke is a CAS update of the form
//
//	UPDATE oauth_refresh_tokens SET revoked_at = ?
//	 WHERE id = ? AND revoked_at IS NULL
//
// so two simultaneous refresh requests for the same token race on the same
// row: exactly one update affects 1 row, the other affects 0 and gets
// ErrRefreshTokenRevoked back.
func (s *Service) rotateRefreshToken(old *models.OauthRefreshToken, scope string) (*models.OauthAccessToken, *models.OauthRefreshToken, error) {
	if old.User != nil && !s.IsRoleAllowed(old.User.RoleID.String) {
		return nil, nil, ErrInvalidUsernameOrPassword
	}

	tx := s.db.Begin()
	if tx.Error != nil {
		return nil, nil, tx.Error
	}

	now := time.Now().UTC()
	res := tx.Model(new(models.OauthRefreshToken)).
		Where("id = ? AND revoked_at IS NULL", old.ID).
		Update("revoked_at", now)
	if res.Error != nil {
		tx.Rollback()
		return nil, nil, res.Error
	}
	if res.RowsAffected != 1 {
		tx.Rollback()
		return nil, nil, ErrRefreshTokenRevoked
	}

	// New access token. We don't reuse GrantAccessToken because that opens
	// its own transaction and would deadlock here on SQLite.
	accessToken := models.NewOauthAccessToken(
		old.Client, old.User, s.cnf.Oauth.AccessTokenLifetime, scope,
	)
	if err := tx.Create(accessToken).Error; err != nil {
		tx.Rollback()
		return nil, nil, err
	}
	accessToken.Client = old.Client
	accessToken.User = old.User

	// New refresh token, linked to the old one.
	refreshToken := models.NewOauthRefreshToken(
		old.Client, old.User, s.cnf.Oauth.RefreshTokenLifetime, scope,
	)
	refreshToken.ParentID = util.StringOrNull(old.ID)
	if err := tx.Create(refreshToken).Error; err != nil {
		tx.Rollback()
		return nil, nil, err
	}
	refreshToken.Client = old.Client
	refreshToken.User = old.User

	if err := tx.Commit().Error; err != nil {
		tx.Rollback()
		return nil, nil, err
	}
	return accessToken, refreshToken, nil
}
