package testmode

import (
	"github.com/RichardKnop/go-oauth2-server/config"
)

const (
	defaultSyntheticRefreshTokenPrefix = "rt_"
	defaultSyntheticRefreshScope       = "loadtest.read"
)

// NewConfig returns an in-memory configuration suitable for the headless
// test provider. It bypasses the etcd/consul backend entirely so the server
// can boot without external dependencies.
//
// dbPath is the SQLite database path; pass ":memory:" for an ephemeral DB.
func NewConfig(dbPath string) *config.Config {
	return NewConfigWithOptions(dbPath, config.TelemetryOptions{})
}

// NewConfigWithOptions returns the same test-mode config as NewConfig plus
// explicit test-mode overrides such as telemetry export settings.
func NewConfigWithOptions(dbPath string, opts config.TelemetryOptions) *config.Config {
	cnf := &config.Config{
		Database: config.DatabaseConfig{
			Type:         "sqlite3",
			DatabaseName: dbPath,
		},
		Oauth: config.OauthConfig{
			AccessTokenLifetime:         3600,
			RefreshTokenLifetime:        1209600,
			AuthCodeLifetime:            3600,
			RefreshTokenRotation:        true, // tests usually want rotation; toggle via /test/refresh-tokens/rotate-policy
			SyntheticRefreshTokenPrefix: defaultSyntheticRefreshTokenPrefix,
			SyntheticRefreshScope:       defaultSyntheticRefreshScope,
		},
		Session: config.SessionConfig{
			Secret:   "test_secret",
			Path:     "/",
			MaxAge:   86400,
			HTTPOnly: true,
		},
		IsDevelopment: true,
		TestMode:      true,
	}
	opts.ApplyTo(cnf)
	return cnf
}
