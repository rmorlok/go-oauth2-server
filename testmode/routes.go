package testmode

import (
	"github.com/RichardKnop/go-oauth2-server/util/routes"
	"github.com/gorilla/mux"
)

// RegisterRoutes mounts /test/* control-plane routes under the given prefix.
func (s *Service) RegisterRoutes(router *mux.Router, prefix string) {
	subRouter := router.PathPrefix(prefix).Subrouter()
	routes.AddRoutes(s.GetRoutes(), subRouter)
}

// GetRoutes returns the routes exposed by the test-mode control plane.
func (s *Service) GetRoutes() []routes.Route {
	return []routes.Route{
		{
			Name:        "test_health",
			Method:      "GET",
			Pattern:     "/health",
			HandlerFunc: s.health,
		},
		{
			Name:        "test_create_client",
			Method:      "POST",
			Pattern:     "/clients",
			HandlerFunc: s.createClient,
		},
		{
			Name:        "test_create_user",
			Method:      "POST",
			Pattern:     "/users",
			HandlerFunc: s.createUser,
		},
	}
}
