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
		{
			Name:        "test_authorize",
			Method:      "POST",
			Pattern:     "/authorize",
			HandlerFunc: s.authorize,
		},
		{
			Name:        "test_requests",
			Method:      "GET",
			Pattern:     "/requests",
			HandlerFunc: s.requestsHandler,
		},
		{
			Name:        "test_enqueue_script",
			Method:      "POST",
			Pattern:     "/scripts",
			HandlerFunc: s.enqueueScript,
		},
		{
			Name:        "test_list_scripts",
			Method:      "GET",
			Pattern:     "/scripts",
			HandlerFunc: s.listScripts,
		},
		{
			Name:        "test_clear_scripts",
			Method:      "DELETE",
			Pattern:     "/scripts",
			HandlerFunc: s.clearScripts,
		},
	}
}
