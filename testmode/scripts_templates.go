package testmode

import "net/http"

// templateAction returns a base Action populated from a built-in template
// name. Explicit fields on the user-provided Action override the template
// defaults.
//
// Recognized templates:
//   - access_token_success: 200 with a sample bearer token + scope
//   - access_token_no_scope: 200 with a sample bearer token, no scope field
//   - invalid_grant: 400 {"error":"invalid_grant"}
//   - temporarily_unavailable_503: 503 {"error":"temporarily_unavailable"}
//   - malformed_json: 200 with a deliberately malformed body
func templateAction(name string) (Action, bool) {
	switch name {
	case "access_token_success":
		return Action{
			Status:  http.StatusOK,
			Headers: map[string]string{"Content-Type": "application/json"},
			Body:    `{"access_token":"00000000-0000-4000-8000-000000000000","expires_in":3600,"token_type":"Bearer","scope":"read"}`,
		}, true
	case "access_token_no_scope":
		return Action{
			Status:  http.StatusOK,
			Headers: map[string]string{"Content-Type": "application/json"},
			Body:    `{"access_token":"00000000-0000-4000-8000-000000000000","expires_in":3600,"token_type":"Bearer"}`,
		}, true
	case "invalid_grant":
		return Action{
			Status:  http.StatusBadRequest,
			Headers: map[string]string{"Content-Type": "application/json"},
			Body:    `{"error":"invalid_grant"}`,
		}, true
	case "temporarily_unavailable_503":
		return Action{
			Status:  http.StatusServiceUnavailable,
			Headers: map[string]string{"Content-Type": "application/json"},
			Body:    `{"error":"temporarily_unavailable"}`,
		}, true
	case "malformed_json":
		return Action{
			Status:  http.StatusOK,
			Headers: map[string]string{"Content-Type": "application/json"},
			Body:    `{not valid json`,
		}, true
	default:
		return Action{}, false
	}
}

// resolveTemplate fills in defaults from the template named by a.BodyTemplate
// when the caller did not specify a Status or Body explicitly.
func resolveTemplate(a Action) Action {
	if a.BodyTemplate == "" {
		return a
	}
	tpl, ok := templateAction(a.BodyTemplate)
	if !ok {
		return a
	}
	if a.Status == 0 {
		a.Status = tpl.Status
	}
	if a.Body == "" {
		a.Body = tpl.Body
	}
	if len(a.Headers) == 0 {
		a.Headers = tpl.Headers
	}
	return a
}
