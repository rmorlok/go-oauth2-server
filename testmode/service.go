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
	recorder     *Recorder
}

// NewService constructs a test-mode service.
func NewService(cnf *config.Config, db *gorm.DB, oauthService oauth.ServiceInterface) *Service {
	return &Service{
		cnf:          cnf,
		db:           db,
		oauthService: oauthService,
		recorder:     NewRecorder(0),
	}
}

// Recorder returns the request recorder so callers (run_test_server.go) can
// install the recording middleware.
func (s *Service) Recorder() *Recorder {
	return s.recorder
}

// Middleware returns a negroni-compatible middleware that records requests
// matching classifyEndpoint.
func (s *Service) Middleware() *recorderMiddleware {
	return &recorderMiddleware{rec: s.recorder}
}
