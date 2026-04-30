package oauth

import (
	"database/sql"
	"errors"
	"testing"

	"github.com/RichardKnop/go-oauth2-server/models"
)

// TestVerifyPKCESpuriousVerifier covers the strict-mode branch in
// verifyPKCE that can't easily be triggered through the integration
// suite — by the time we reach the token endpoint with a strict client,
// the auth code already has a stored challenge (GrantAuthorizationCode
// rejects strict clients without one). This test simulates the
// transition case where RequirePKCE is flipped on after a code was
// issued under lax mode.
func TestVerifyPKCESpuriousVerifier(t *testing.T) {
	codeWithoutChallenge := &models.OauthAuthorizationCode{
		// CodeChallenge intentionally invalid (Valid: false).
	}
	codeWithChallenge := &models.OauthAuthorizationCode{
		CodeChallenge:       sql.NullString{String: "abc", Valid: true},
		CodeChallengeMethod: sql.NullString{String: PKCEMethodPlain, Valid: true},
	}

	laxClient := &models.OauthClient{RequirePKCE: false}
	strictClient := &models.OauthClient{RequirePKCE: true}

	cases := []struct {
		name     string
		code     *models.OauthAuthorizationCode
		client   *models.OauthClient
		verifier string
		want     error
	}{
		{
			name:     "lax client, no challenge, no verifier → ok",
			code:     codeWithoutChallenge,
			client:   laxClient,
			verifier: "",
			want:     nil,
		},
		{
			name:     "lax client, no challenge, spurious verifier → ok (RFC §4.5)",
			code:     codeWithoutChallenge,
			client:   laxClient,
			verifier: "anything",
			want:     nil,
		},
		{
			name:     "strict client, no challenge, no verifier → ok (transition case)",
			code:     codeWithoutChallenge,
			client:   strictClient,
			verifier: "",
			want:     nil,
		},
		{
			name:     "strict client, no challenge, spurious verifier → rejected",
			code:     codeWithoutChallenge,
			client:   strictClient,
			verifier: "anything",
			want:     ErrPKCEVerifierUnexpected,
		},
		{
			name:     "strict client, challenge stored, missing verifier → missing",
			code:     codeWithChallenge,
			client:   strictClient,
			verifier: "",
			want:     ErrPKCEVerifierMissing,
		},
		{
			name:     "lax client, challenge stored, matching verifier → ok",
			code:     codeWithChallenge,
			client:   laxClient,
			verifier: "abc",
			want:     nil,
		},
		{
			name:     "nil client behaves as lax (e.g. legacy callsites)",
			code:     codeWithoutChallenge,
			client:   nil,
			verifier: "anything",
			want:     nil,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := verifyPKCE(tc.code, tc.verifier, tc.client)
			if !errors.Is(got, tc.want) {
				t.Fatalf("verifyPKCE: want %v, got %v", tc.want, got)
			}
		})
	}
}
