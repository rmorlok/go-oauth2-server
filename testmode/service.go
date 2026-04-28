package testmode

import (
	"github.com/RichardKnop/go-oauth2-server/config"
	"github.com/RichardKnop/go-oauth2-server/oauth"
	"github.com/jinzhu/gorm"
)

// Service holds dependencies for the test-mode control plane.
type Service struct {
	cnf          *config.Config
	db           *gorm.DB
	oauthService oauth.ServiceInterface
}

// NewService constructs a test-mode service.
func NewService(cnf *config.Config, db *gorm.DB, oauthService oauth.ServiceInterface) *Service {
	return &Service{
		cnf:          cnf,
		db:           db,
		oauthService: oauthService,
	}
}
