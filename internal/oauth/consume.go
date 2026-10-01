// ConsumeCode is RF-02 Flow 2's steps 2-4 (docs/ARCHITECTURE.md §10),
// pulled out as its own function so #30's /token handler can call it
// unchanged, the same way #20's session.RotateLogin and #26's
// redirectError exist ahead of their first HTTP caller.

package oauth

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
)

// ErrInvalidGrant is RS-25's fixed, deliberately ambiguous response: a
// replayed code, an expired one, a code that never existed, a client_id
// or redirect_uri mismatch, and a failed PKCE check are all
// indistinguishable to the caller — the point is that the caller cannot
// tell which, not that this project cannot.
var ErrInvalidGrant = errors.New("oauth: invalid_grant")

// ConsumeCode atomically consumes value (CodeStore.Consume — RS-04's one
// round trip, never a GET then a DEL) and, on success, re-verifies it
// against clientID, redirectURI and codeVerifier exactly as the
// /authorize request that minted it bound them (RS-02, RS-01).
//
// On failure, ConsumeCode tells a genuine replay from "never existed or
// expired" by consulting CodeStore.TombstonedFamily: a replay within the
// tombstone's window (RF-12's access-token-TTL bound) revokes the family
// that code produced (RS-04: "replay revokes everything issued," not
// merely detected) before returning. Either way the returned error is the
// same ErrInvalidGrant — RS-25's ambiguity holds at this boundary too.
func ConsumeCode(ctx context.Context, codes CodeStore, families FamilyStore, value, clientID, redirectURI, codeVerifier string) (Code, error) {
	code, err := codes.Consume(ctx, value)
	if err != nil {
		if !errors.Is(err, ErrCodeNotFound) {
			return Code{}, fmt.Errorf("oauth: consume code: %w", err)
		}
		if revokeErr := revokeReplayedFamily(ctx, codes, families, value); revokeErr != nil {
			return Code{}, revokeErr
		}
		return Code{}, ErrInvalidGrant
	}

	if code.ClientID != clientID || code.RedirectURI != redirectURI {
		return Code{}, ErrInvalidGrant
	}
	if !verifyPKCE(codeVerifier, code.CodeChallenge) {
		return Code{}, ErrInvalidGrant
	}
	return code, nil
}

// revokeReplayedFamily is the branch Consume's failure takes: find out
// whether value's failure is a replay (a live tombstone) rather than an
// ordinary miss, and if so, revoke the family it names.
func revokeReplayedFamily(ctx context.Context, codes CodeStore, families FamilyStore, value string) error {
	familyID, found, err := codes.TombstonedFamily(ctx, value)
	if err != nil {
		return fmt.Errorf("oauth: look up code tombstone: %w", err)
	}
	if !found {
		return nil
	}
	if err := families.Revoke(ctx, familyID, "reuse_detected"); err != nil {
		return fmt.Errorf("oauth: revoke replayed family: %w", err)
	}
	return nil
}

// verifyPKCE is RFC 7636 §4.6's S256 check: BASE64URL-ENCODE(SHA256(code_
// verifier)) == code_challenge. RS-01 already refuses any other method at
// /authorize (#26), so this function only ever has S256 to check.
// Compared constant-time (crypto/subtle), the same convention
// identity/password.go's hash comparison follows — never == or
// bytes.Equal on a value derived from a secret an attacker is trying to
// guess (RS-15's reasoning, applied here to code_verifier rather than a
// password).
func verifyPKCE(codeVerifier, codeChallenge string) bool {
	sum := sha256.Sum256([]byte(codeVerifier))
	computed := base64.RawURLEncoding.EncodeToString(sum[:])
	return subtle.ConstantTimeCompare([]byte(computed), []byte(codeChallenge)) == 1
}
