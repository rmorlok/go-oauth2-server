package oauth

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/RichardKnop/go-oauth2-server/util/response"
)

// ExtractBearerToken pulls a token from the Authorization header. Returns
// the empty string and an error message suitable for an `error_description`
// when the header is missing or malformed.
func ExtractBearerToken(r *http.Request) (string, string) {
	auth := r.Header.Get("Authorization")
	if auth == "" {
		return "", "missing Authorization header"
	}
	parts := strings.SplitN(auth, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") || parts[1] == "" {
		return "", "Authorization header must be 'Bearer <token>'"
	}
	return parts[1], ""
}

// WriteBearerError writes a Bearer-token error response per RFC 6750 §3.
// realm defaults to "go_oauth2_server" when empty. scope is optional;
// include it on insufficient_scope responses.
func WriteBearerError(w http.ResponseWriter, status int, code, description, realm, scope string) {
	if realm == "" {
		realm = "go_oauth2_server"
	}
	parts := []string{fmt.Sprintf(`realm="%s"`, realm)}
	if code != "" {
		parts = append(parts, fmt.Sprintf(`error="%s"`, code))
	}
	if description != "" {
		parts = append(parts, fmt.Sprintf(`error_description="%s"`, sanitizeBearerHeader(description)))
	}
	if scope != "" {
		parts = append(parts, fmt.Sprintf(`scope="%s"`, scope))
	}
	w.Header().Set("WWW-Authenticate", "Bearer "+strings.Join(parts, ", "))
	response.Error(w, code, status)
}

func sanitizeBearerHeader(s string) string {
	r := strings.NewReplacer(`"`, `'`, "\r", " ", "\n", " ")
	return r.Replace(s)
}

// HasAllScopes reports whether every space-separated scope in `required`
// is also present in `granted`.
func HasAllScopes(granted, required string) bool {
	if required == "" {
		return true
	}
	grantedSet := make(map[string]struct{})
	for _, s := range strings.Fields(granted) {
		grantedSet[s] = struct{}{}
	}
	for _, want := range strings.Fields(required) {
		if _, ok := grantedSet[want]; !ok {
			return false
		}
	}
	return true
}

// HasAnyScope reports whether at least one space-separated scope in
// `oneOf` is present in `granted`.
func HasAnyScope(granted, oneOf string) bool {
	if oneOf == "" {
		return true
	}
	grantedSet := make(map[string]struct{})
	for _, s := range strings.Fields(granted) {
		grantedSet[s] = struct{}{}
	}
	for _, want := range strings.Fields(oneOf) {
		if _, ok := grantedSet[want]; ok {
			return true
		}
	}
	return false
}
