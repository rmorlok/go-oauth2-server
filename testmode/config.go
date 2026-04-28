package testmode

import (
	"github.com/RichardKnop/go-oauth2-server/config"
)

// NewConfig returns an in-memory configuration suitable for the headless
// test provider. It bypasses the etcd/consul backend entirely so the server
// can boot without external dependencies.
//
// dbPath is the SQLite database path; pass ":memory:" for an ephemeral DB.
func NewConfig(dbPath string) *config.Config {
	return &config.Config{
		Database: config.DatabaseConfig{
			Type:         "sqlite3",
			DatabaseName: dbPath,
		},
		Oauth: config.OauthConfig{
			AccessTokenLifetime:  3600,
			RefreshTokenLifetime: 1209600,
			AuthCodeLifetime:     3600,
			RefreshTokenRotation: true, // tests usually want rotation; toggle via /test/refresh-tokens/rotate-policy
		},
		Session: config.SessionConfig{
			Secret:   "test_secret",
			Path:     "/",
			MaxAge:   86400,
			HTTPOnly: true,
		},
		IsDevelopment: true,
	}
}
