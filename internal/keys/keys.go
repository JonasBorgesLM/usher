// Package keys loads and validates the signing keyset (ADR-0015), derives
// the currently signing key and the published JWKS from it (RS-09), and
// adapts it to tokenvalidator.KeySource for the gateway's in-process
// validation (REQUIREMENTS §7.4).
//
// It imports pkg/tokenvalidator — allowed, since only pkg importing
// internal/ is forbidden (ADR-0001), not the reverse — and nothing under
// internal/oauth or internal/proxy: rotation and signing are agnostic to
// which protocol package asked for a key.
package keys

import (
	"context"
	"crypto"
	"errors"
	"time"

	"github.com/JonasBorgesLM/usher/pkg/tokenvalidator"
)

// Key is one keyset entry: a private key plus the publication schedule
// RS-09 requires and ADR-0015 fixes the loader against.
type Key struct {
	KID       string
	Algorithm tokenvalidator.Algorithm
	Private   crypto.Signer
	PublishAt time.Time
	SignFrom  time.Time
	RetireAt  time.Time
}

// Denylist is the emergency-revocation path (ADR-0015 amendment, T-18's
// residual): a listed kid is excluded from Signing and Published
// immediately, independent of its configured windows. Configuration, read
// once at Load — revoking a key takes a restart, and a consumer validating
// directly keeps accepting that key's tokens until its own JWKS cache
// expires, which is the residual and not a defect in this type.
type Denylist []string

// Keyset is the loaded, validated set of keys. Its internal representation
// is deliberately unspecified here (docs/ARCHITECTURE.md §6) — M3 designs it
// alongside Load, Signing, Published and JWKS, which are the only things
// that need to agree on it.
type Keyset struct{}

// Load reads every key file under dir and validates its windows against
// clockSkew, maxAccessTokenTTL and consumerJWKSCacheTTL (RS-09's formula) —
// or returns the first violation, naming both keys and the window that
// failed. Called once at startup (ADR-0015: no periodic re-read).
//
// Implemented in M3 (REQUIREMENTS §11); until then it always fails, so a
// caller cannot mistake an unimplemented loader for an empty keyset.
func Load(dir string, clockSkew, maxAccessTokenTTL, consumerJWKSCacheTTL time.Duration, deny Denylist) (*Keyset, error) {
	return nil, errNotImplemented
}

var errNotImplemented = errors.New("keys: not implemented yet (M3)")

// ErrNoSigningKey reports that no key in the set has a SignFrom at or before
// the requested time.
var ErrNoSigningKey = errors.New("keys: no key signs at the given time")

// Signing returns the key that signs at t: the key whose SignFrom is the
// latest not after t among keys not yet RetireAt, or ErrNoSigningKey.
//
// Implemented in M3.
func (k *Keyset) Signing(t time.Time) (Key, error) {
	panic("keys: Signing not implemented (M3)")
}

// Published returns every key visible in the JWKS at t — PublishAt ≤ t <
// RetireAt — with any denylisted kid already excluded.
//
// Implemented in M3.
func (k *Keyset) Published(t time.Time) []Key {
	panic("keys: Published not implemented (M3)")
}

// JWKS renders Published(t) as an RFC 7517 key set containing only public
// parameters (RS-09).
//
// Implemented in M3.
func (k *Keyset) JWKS(t time.Time) ([]byte, error) {
	panic("keys: JWKS not implemented (M3)")
}

// keySource adapts a Keyset to tokenvalidator.KeySource. Its own internal
// representation is unspecified for the same reason Keyset's is.
type keySource struct{}

// AsKeySource adapts a Keyset to tokenvalidator.KeySource for in-process
// validation — the gateway's own consumer of pkg/tokenvalidator
// (REQUIREMENTS §7.4), sharing the same Validator type the demo resource
// server drives over HTTP via tokenvalidator.NewJWKSSource.
func (k *Keyset) AsKeySource() tokenvalidator.KeySource {
	return keySource{}
}

// Key implements tokenvalidator.KeySource. Implemented in M3.
func (s keySource) Key(ctx context.Context, kid string) (crypto.PublicKey, tokenvalidator.Algorithm, error) {
	panic("keys: keySource.Key not implemented (M3)")
}
