package oauth

import (
	"net/http"

	"github.com/RichardKnop/go-oauth2-server/models"
	"github.com/RichardKnop/go-oauth2-server/util/response"
	"github.com/gorilla/mux"
)

// ScopePolicyFunc returns the required scope (space-separated) for the
// given path. ok=false means no policy is registered for the path.
type ScopePolicyFunc func(path string) (required string, ok bool)

// ServeSampleResource is the shared sample protected-resource handler:
// bearer auth + optional per-path scope policy + default JSON body.
//
// In production it is mounted as a sample target so an operator can
// validate an OAuth flow end-to-end (register a client, get a token,
// hit the resource). In test mode it gets a non-nil policy callback so
// /test/resource-policy registrations are honored.
//
// realm appears in WWW-Authenticate; pass "" for the package default.
func (s *Service) ServeSampleResource(w http.ResponseWriter, r *http.Request, realm string, policy ScopePolicyFunc) {
	token, errDesc := ExtractBearerToken(r)
	if errDesc != "" {
		WriteBearerError(w, http.StatusUnauthorized, "invalid_token", errDesc, realm, "")
		return
	}
	accessToken, err := s.Authenticate(token)
	if err != nil {
		WriteBearerError(w, http.StatusUnauthorized, "invalid_token", err.Error(), realm, "")
		return
	}
	if policy != nil {
		if required, ok := policy(r.URL.Path); ok {
			if !HasAllScopes(accessToken.Scope, required) {
				WriteBearerError(w, http.StatusForbidden, "insufficient_scope",
					"token does not have required scope(s)", realm, required)
				return
			}
		}
	}
	response.WriteJSON(w, sampleResourceBody(accessToken, r), http.StatusOK)
}

// SampleResourceHandler is the no-policy variant suitable for the
// production server. Mounted by RegisterSampleResource.
func (s *Service) SampleResourceHandler(w http.ResponseWriter, r *http.Request) {
	s.ServeSampleResource(w, r, "sample", nil)
}

// RegisterSampleResource mounts the sample resource as a catch-all under
// `prefix` so any HTTP method and any sub-path matches. Typical prefix
// is "/test/resource".
func (s *Service) RegisterSampleResource(router *mux.Router, prefix string) {
	router.PathPrefix(prefix + "/").HandlerFunc(s.SampleResourceHandler)
}

func sampleResourceBody(accessToken *models.OauthAccessToken, r *http.Request) map[string]any {
	body := map[string]any{
		"sub":       accessToken.UserID.String,
		"client_id": accessToken.ClientID.String,
		"scope":     accessToken.Scope,
		"path":      r.URL.Path,
	}
	if r.Method != http.MethodGet && r.Method != "" {
		body["method"] = r.Method
	}
	return body
}
