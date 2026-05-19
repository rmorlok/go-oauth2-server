package config

import (
	"github.com/RichardKnop/go-oauth2-server/telemetry"
)

// DatabaseConfig stores database connection options
type DatabaseConfig struct {
	Type         string
	Host         string
	Port         int
	User         string
	Password     string
	DatabaseName string
	MaxIdleConns int
	MaxOpenConns int
}

// OauthConfig stores oauth service configuration options
type OauthConfig struct {
	AccessTokenLifetime  int
	RefreshTokenLifetime int
	AuthCodeLifetime     int

	// RefreshTokenRotation, when true, issues a new refresh token on every
	// `grant_type=refresh_token` exchange and revokes the prior one. The
	// new token's parent_id links back to the prior token for chain
	// inspection. Default off in production; the test-mode config sets it
	// to true so harnesses can exercise rotation by default.
	RefreshTokenRotation bool
}

// SessionConfig stores session configuration for the web app
type SessionConfig struct {
	Secret string
	Path   string
	// MaxAge=0 means no 'Max-Age' attribute specified.
	// MaxAge<0 means delete cookie now, equivalently 'Max-Age: 0'.
	// MaxAge>0 means Max-Age attribute present and given in seconds.
	MaxAge int
	// When you tag a cookie with the HttpOnly flag, it tells the browser that
	// this particular cookie should only be accessed by the server.
	// Any attempt to access the cookie from client script is strictly forbidden.
	HTTPOnly bool
}

// LoggingConfig configures the structured logger.
//
// Level is one of "debug", "info", "warn", "error" (case-insensitive). An
// empty Level defaults to "info" in production and "debug" when
// IsDevelopment is true.
//
// Format is "text" or "json". An empty Format defaults to "text" when
// IsDevelopment is true and "json" otherwise.
type LoggingConfig struct {
	Level  string `json:"level,omitempty"`
	Format string `json:"format,omitempty"`
}

// Config stores all configuration options
type Config struct {
	Database      DatabaseConfig
	Oauth         OauthConfig
	Session       SessionConfig
	Telemetry     telemetry.Config
	Logging       LoggingConfig
	IsDevelopment bool
}
