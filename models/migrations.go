package models

import (
	"fmt"

	"github.com/RichardKnop/go-oauth2-server/util/migrations"
	"github.com/jinzhu/gorm"
)

var (
	list = []migrations.MigrationStage{
		{
			Name:     "initial",
			Function: migrate0001,
		},
		{
			Name:     "refresh_token_rotation",
			Function: migrate0002,
		},
		{
			Name:     "access_token_revocation",
			Function: migrate0003,
		},
		{
			Name:     "pkce_challenge",
			Function: migrate0004,
		},
		{
			Name:     "client_auth_method",
			Function: migrate0005,
		},
	}
)

// MigrateAll executes all migrations
func MigrateAll(db *gorm.DB) error {
	return migrations.Migrate(db, list)
}

func migrate0001(db *gorm.DB, name string) error {
	//-------------
	// OAUTH models
	//-------------

	// Create tables
	if err := db.CreateTable(new(OauthClient)).Error; err != nil {
		return fmt.Errorf("Error creating oauth_clients table: %s", err)
	}
	if err := db.CreateTable(new(OauthScope)).Error; err != nil {
		return fmt.Errorf("Error creating oauth_scopes table: %s", err)
	}
	if err := db.CreateTable(new(OauthRole)).Error; err != nil {
		return fmt.Errorf("Error creating oauth_roles table: %s", err)
	}
	if err := db.CreateTable(new(OauthUser)).Error; err != nil {
		return fmt.Errorf("Error creating oauth_users table: %s", err)
	}
	if err := db.CreateTable(new(OauthRefreshToken)).Error; err != nil {
		return fmt.Errorf("Error creating oauth_refresh_tokens table: %s", err)
	}
	if err := db.CreateTable(new(OauthAccessToken)).Error; err != nil {
		return fmt.Errorf("Error creating oauth_access_tokens table: %s", err)
	}
	if err := db.CreateTable(new(OauthAuthorizationCode)).Error; err != nil {
		return fmt.Errorf("Error creating oauth_authorization_codes table: %s", err)
	}

	// SQLite does not support adding foreign keys via ALTER TABLE. FK
	// constraints are not enforced in test-mode SQLite; the tables retain
	// the same column shape so application logic behaves identically.
	if db.Dialect().GetName() == "sqlite3" {
		return nil
	}

	err := db.Model(new(OauthUser)).AddForeignKey(
		"role_id", "oauth_roles(id)",
		"RESTRICT", "RESTRICT",
	).Error
	if err != nil {
		return fmt.Errorf("Error creating foreign key on "+
			"oauth_users.role_id for oauth_roles(id): %s", err)
	}
	err = db.Model(new(OauthRefreshToken)).AddForeignKey(
		"client_id", "oauth_clients(id)",
		"RESTRICT", "RESTRICT",
	).Error
	if err != nil {
		return fmt.Errorf("Error creating foreign key on "+
			"oauth_refresh_tokens.client_id for oauth_clients(id): %s", err)
	}
	err = db.Model(new(OauthRefreshToken)).AddForeignKey(
		"user_id", "oauth_users(id)",
		"RESTRICT", "RESTRICT",
	).Error
	if err != nil {
		return fmt.Errorf("Error creating foreign key on "+
			"oauth_refresh_tokens.user_id for oauth_users(id): %s", err)
	}
	err = db.Model(new(OauthAccessToken)).AddForeignKey(
		"client_id", "oauth_clients(id)",
		"RESTRICT", "RESTRICT",
	).Error
	if err != nil {
		return fmt.Errorf("Error creating foreign key on "+
			"oauth_access_tokens.client_id for oauth_clients(id): %s", err)
	}
	err = db.Model(new(OauthAccessToken)).AddForeignKey(
		"user_id", "oauth_users(id)",
		"RESTRICT", "RESTRICT",
	).Error
	if err != nil {
		return fmt.Errorf("Error creating foreign key on "+
			"oauth_access_tokens.user_id for oauth_users(id): %s", err)
	}
	err = db.Model(new(OauthAuthorizationCode)).AddForeignKey(
		"client_id", "oauth_clients(id)",
		"RESTRICT", "RESTRICT",
	).Error
	if err != nil {
		return fmt.Errorf("Error creating foreign key on "+
			"oauth_authorization_codes.client_id for oauth_clients(id): %s", err)
	}
	err = db.Model(new(OauthAuthorizationCode)).AddForeignKey(
		"user_id", "oauth_users(id)",
		"RESTRICT", "RESTRICT",
	).Error
	if err != nil {
		return fmt.Errorf("Error creating foreign key on "+
			"oauth_authorization_codes.user_id for oauth_users(id): %s", err)
	}

	return nil
}

// migrate0002 adds the columns required for refresh-token rotation:
// revoked_at and parent_id on oauth_refresh_tokens. AutoMigrate is
// additive — it adds missing columns without touching existing data,
// so this is safe to run against an existing prod database.
func migrate0002(db *gorm.DB, name string) error {
	if err := db.AutoMigrate(new(OauthRefreshToken)).Error; err != nil {
		return fmt.Errorf("Error adding refresh-token rotation columns: %s", err)
	}
	return nil
}

// migrate0003 adds revoked_at to oauth_access_tokens so RFC 7009
// revocation (and the refresh-token cascade) can mark access tokens
// invalid without deleting their rows. Additive.
func migrate0003(db *gorm.DB, name string) error {
	if err := db.AutoMigrate(new(OauthAccessToken)).Error; err != nil {
		return fmt.Errorf("Error adding access-token revocation column: %s", err)
	}
	return nil
}

// migrate0004 adds the PKCE columns (code_challenge, code_challenge_method)
// to oauth_authorization_codes. Additive.
func migrate0004(db *gorm.DB, name string) error {
	if err := db.AutoMigrate(new(OauthAuthorizationCode)).Error; err != nil {
		return fmt.Errorf("Error adding PKCE columns: %s", err)
	}
	return nil
}

// migrate0005 adds token_endpoint_auth_method to oauth_clients. Default
// 'client_secret_basic' so existing rows behave exactly as before.
func migrate0005(db *gorm.DB, name string) error {
	if err := db.AutoMigrate(new(OauthClient)).Error; err != nil {
		return fmt.Errorf("Error adding token_endpoint_auth_method column: %s", err)
	}
	return nil
}
