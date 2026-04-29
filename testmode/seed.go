package testmode

import (
	"time"

	"github.com/RichardKnop/go-oauth2-server/models"
	"github.com/RichardKnop/go-oauth2-server/oauth/roles"
	"github.com/jinzhu/gorm"
)

// Seed inserts the minimum role and scope rows the OAuth service requires
// to issue tokens. Mirrors oauth/fixtures/{roles,scopes}.yml.
func Seed(db *gorm.DB) error {
	now := time.Now().UTC()

	defaultRoles := []models.OauthRole{
		{ID: roles.Superuser, Name: "Superuser", TimestampModel: models.TimestampModel{CreatedAt: now, UpdatedAt: now}},
		{ID: roles.User, Name: "User", TimestampModel: models.TimestampModel{CreatedAt: now, UpdatedAt: now}},
	}
	for i := range defaultRoles {
		r := defaultRoles[i]
		if err := db.FirstOrCreate(&r, models.OauthRole{ID: r.ID}).Error; err != nil {
			return err
		}
	}

	defaultScopes := []models.OauthScope{
		{MyGormModel: models.MyGormModel{ID: "1", CreatedAt: now}, Scope: "read", IsDefault: true},
		{MyGormModel: models.MyGormModel{ID: "2", CreatedAt: now}, Scope: "read_write", IsDefault: false},
		{MyGormModel: models.MyGormModel{ID: "3", CreatedAt: now}, Scope: "profile", IsDefault: false},
		{MyGormModel: models.MyGormModel{ID: "4", CreatedAt: now}, Scope: "email", IsDefault: false},
	}
	for i := range defaultScopes {
		sc := defaultScopes[i]
		if err := db.FirstOrCreate(&sc, models.OauthScope{Scope: sc.Scope}).Error; err != nil {
			return err
		}
	}

	return nil
}
