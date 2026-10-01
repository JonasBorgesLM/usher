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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/lestrrat-go/jwx/v4/jwk"

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

// String and GoString never print Private: unlike moat/secret.Value, Go's
// own crypto key types (rsa.PrivateKey, ecdsa.PrivateKey) have no such
// guard — their exported fields, including the private exponent, print in
// full under the default %v/%+v formatting Go's fmt package falls back to
// whenever a bare crypto.Signer, rather than a Key, is the top-level value
// being formatted. A Key reaching a log line or an error message by
// mistake must not be the second mistake that exposes it (RS-23).
func (k Key) String() string {
	return fmt.Sprintf("keys.Key{KID: %q, Algorithm: %s, Private: <redacted>, PublishAt: %s, SignFrom: %s, RetireAt: %s}",
		k.KID, k.Algorithm, k.PublishAt, k.SignFrom, k.RetireAt)
}

// GoString makes %#v redact the same way %v and %s already do via String.
func (k Key) GoString() string { return k.String() }

// MarshalJSON is the redaction that actually matters for this project:
// this project's own structured logger (cmd/usher's slog JSON handler,
// #23) falls back to json.Marshal for any attribute value with neither a
// LogValuer nor a MarshalJSON of its own, which — without this override —
// would serialize every exported field of the crypto.Signer underneath
// Private (rsa.PrivateKey's D and Primes; ecdsa.PrivateKey's D) in the
// clear. fmt.Stringer is not consulted on this path at all; this method is
// the only thing that is.
func (k Key) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		KID       string                   `json:"kid"`
		Algorithm tokenvalidator.Algorithm `json:"algorithm"`
		Private   string                   `json:"private"`
		PublishAt time.Time                `json:"publish_at"`
		SignFrom  time.Time                `json:"sign_from"`
		RetireAt  time.Time                `json:"retire_at"`
	}{
		KID:       k.KID,
		Algorithm: k.Algorithm,
		Private:   "<redacted>",
		PublishAt: k.PublishAt,
		SignFrom:  k.SignFrom,
		RetireAt:  k.RetireAt,
	})
}

// JWK wraps k as a jwk.Key carrying its kid and algorithm, ready to pass to
// jws.Sign via jws.WithKey. jws copies a jwk.Key's own "kid" field into the
// signature's protected header automatically; passing k.Private directly
// (a bare crypto.Signer, with no such field) would not — this is RS-09's
// "every JWT carries kid" made structural rather than left to every future
// call site to remember.
func (k Key) JWK() (jwk.Key, error) {
	signingKey, err := jwk.Import[jwk.Key](k.Private)
	if err != nil {
		return nil, fmt.Errorf("keys: build signing JWK for %q: %w", k.KID, err)
	}
	if err := signingKey.Set(jwk.KeyIDKey, k.KID); err != nil {
		return nil, fmt.Errorf("keys: set kid on signing JWK for %q: %w", k.KID, err)
	}
	if err := signingKey.Set(jwk.AlgorithmKey, string(k.Algorithm)); err != nil {
		return nil, fmt.Errorf("keys: set alg on signing JWK for %q: %w", k.KID, err)
	}
	return signingKey, nil
}

// Denylist is the emergency-revocation path (ADR-0015 amendment, T-18's
// residual): a listed kid is excluded from Signing and Published
// immediately, independent of its configured windows. Configuration, read
// once at Load — revoking a key takes a restart, and a consumer validating
// directly keeps accepting that key's tokens until its own JWKS cache
// expires, which is the residual and not a defect in this type.
type Denylist []string

// Keyset is the loaded, validated set of keys, sorted by SignFrom.
type Keyset struct {
	keys []Key
}

// keyMetadata is one key's on-disk schedule: "<kid>.json" next to
// "<kid>.pem" holding the PKCS8-encoded private key (ADR-0015: "a small
// metadata file" alongside the key itself). This pairing, and the filename
// convention, is this package's own choice — ADR-0015 decided the
// schedule's shape and the refusal conditions, not the serialization.
type keyMetadata struct {
	KID       string    `json:"kid"`
	Algorithm string    `json:"algorithm"`
	PublishAt time.Time `json:"publish_at"`
	SignFrom  time.Time `json:"sign_from"`
	RetireAt  time.Time `json:"retire_at"`
}

// ErrEmptyKeyset reports that no usable key remains after loading and
// applying deny — an empty directory, a directory of only denylisted keys,
// or a missing directory all collapse to "cannot start," per RNF-05.
var ErrEmptyKeyset = errors.New("keys: no usable signing keys in the keyset")

// Load reads every "<kid>.json" + "<kid>.pem" pair under dir and validates
// its windows against clockSkew, maxAccessTokenTTL and consumerJWKSCacheTTL
// (RS-09's formula) — or returns the first violation, naming both the key
// and the window that failed. Called once at startup (ADR-0015: no
// periodic re-read; rotation is a restart that picks up a key already
// installed with a future SignFrom).
func Load(dir string, clockSkew, maxAccessTokenTTL, consumerJWKSCacheTTL time.Duration, deny Denylist) (*Keyset, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("keys: read keyset directory %q: %w", dir, err)
	}

	denied := make(map[string]bool, len(deny))
	for _, kid := range deny {
		denied[kid] = true
	}

	seen := make(map[string]bool)
	var all []Key
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		kid := strings.TrimSuffix(entry.Name(), ".json")

		key, err := loadOneKey(dir, kid)
		if err != nil {
			return nil, err
		}
		if seen[key.KID] {
			return nil, fmt.Errorf("keys: duplicate kid %q in %q", key.KID, dir)
		}
		seen[key.KID] = true

		if denied[key.KID] {
			continue
		}
		all = append(all, key)
	}

	if len(all) == 0 {
		return nil, ErrEmptyKeyset
	}

	sort.Slice(all, func(i, j int) bool { return all[i].SignFrom.Before(all[j].SignFrom) })

	for i, k := range all {
		if k.PublishAt.After(k.SignFrom) {
			return nil, fmt.Errorf("keys: key %q: publish_at %s is after sign_from %s", k.KID, k.PublishAt, k.SignFrom)
		}
		if !k.SignFrom.Before(k.RetireAt) {
			return nil, fmt.Errorf("keys: key %q: sign_from %s is not before retire_at %s", k.KID, k.SignFrom, k.RetireAt)
		}
		if k.SignFrom.Sub(k.PublishAt) < consumerJWKSCacheTTL {
			return nil, fmt.Errorf("keys: key %q: published only %s before it signs, want at least consumer_JWKS_cache_TTL (%s)",
				k.KID, k.SignFrom.Sub(k.PublishAt), consumerJWKSCacheTTL)
		}
		// RS-09's retirement formula binds a RETIRING key to the key that
		// signs NEXT, not to its own successor's publish_at — only this
		// pairwise check matters, and only once a second key exists; a
		// single-key set (phase 2, REQUIREMENTS §11) has no pair to check.
		if i+1 < len(all) {
			next := all[i+1]
			minRetireAt := next.SignFrom.Add(maxAccessTokenTTL + clockSkew + consumerJWKSCacheTTL)
			if k.RetireAt.Before(minRetireAt) {
				return nil, fmt.Errorf(
					"keys: key %q retires at %s, before %s (next key %q signs from %s; retirement must cover max_access_token_TTL+clock_skew+consumer_JWKS_cache_TTL after that)",
					k.KID, k.RetireAt, minRetireAt, next.KID, next.SignFrom)
			}
		}
	}

	return &Keyset{keys: all}, nil
}

// loadOneKey reads one "<kid>.json" + "<kid>.pem" pair. dir is operator
// configuration, trusted per THREAT-MODEL.md's actor table, not request
// input, and kid comes from os.ReadDir's own listing of dir, never from an
// external caller — the dynamic path gosec's G304 flags is not reachable
// from outside this process's own startup configuration.
func loadOneKey(dir, kid string) (Key, error) {
	metaPath := filepath.Join(dir, kid+".json")
	metaBytes, err := os.ReadFile(metaPath) // #nosec G304 -- dir is trusted operator config, see doc comment above
	if err != nil {
		return Key{}, fmt.Errorf("keys: read %s: %w", metaPath, err)
	}
	var meta keyMetadata
	if unmarshalErr := json.Unmarshal(metaBytes, &meta); unmarshalErr != nil {
		return Key{}, fmt.Errorf("keys: parse %s: %w", metaPath, unmarshalErr)
	}
	if meta.KID != kid {
		return Key{}, fmt.Errorf("keys: %s: metadata kid %q does not match filename %q", metaPath, meta.KID, kid)
	}

	var algorithm tokenvalidator.Algorithm
	switch meta.Algorithm {
	case string(tokenvalidator.RS256):
		algorithm = tokenvalidator.RS256
	case string(tokenvalidator.ES256):
		algorithm = tokenvalidator.ES256
	default:
		return Key{}, fmt.Errorf("keys: %s: unsupported algorithm %q", metaPath, meta.Algorithm)
	}

	keyPath := filepath.Join(dir, kid+".pem")
	pemBytes, err := os.ReadFile(keyPath) // #nosec G304 -- same trust boundary as metaPath above
	if err != nil {
		return Key{}, fmt.Errorf("keys: read %s: %w", keyPath, err)
	}
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return Key{}, fmt.Errorf("keys: %s: not a PEM-encoded file", keyPath)
	}
	raw, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return Key{}, fmt.Errorf("keys: %s: parse PKCS8 private key: %w", keyPath, err)
	}
	signer, ok := raw.(crypto.Signer)
	if !ok {
		return Key{}, fmt.Errorf("keys: %s: key does not implement crypto.Signer", keyPath)
	}

	switch algorithm {
	case tokenvalidator.RS256:
		if _, ok := signer.(*rsa.PrivateKey); !ok {
			return Key{}, fmt.Errorf("keys: %s: algorithm RS256 requires an RSA key, got %T", keyPath, signer)
		}
	case tokenvalidator.ES256:
		ecKey, ok := signer.(*ecdsa.PrivateKey)
		if !ok {
			return Key{}, fmt.Errorf("keys: %s: algorithm ES256 requires an ECDSA key, got %T", keyPath, signer)
		}
		if ecKey.Curve != elliptic.P256() {
			return Key{}, fmt.Errorf("keys: %s: algorithm ES256 requires a P-256 key, got curve %s", keyPath, ecKey.Curve.Params().Name)
		}
	}

	return Key{
		KID:       meta.KID,
		Algorithm: algorithm,
		Private:   signer,
		PublishAt: meta.PublishAt,
		SignFrom:  meta.SignFrom,
		RetireAt:  meta.RetireAt,
	}, nil
}

// ErrNoSigningKey reports that no key in the set has a SignFrom at or
// before the requested time, or every such key has already retired.
var ErrNoSigningKey = errors.New("keys: no key signs at the given time")

// Signing returns the key that signs at t: the key whose SignFrom is the
// latest not after t among keys not yet RetireAt, or ErrNoSigningKey.
func (k *Keyset) Signing(t time.Time) (Key, error) {
	var best Key
	found := false
	for _, key := range k.keys {
		if key.SignFrom.After(t) {
			continue
		}
		if !t.Before(key.RetireAt) {
			continue // retired
		}
		if !found || key.SignFrom.After(best.SignFrom) {
			best = key
			found = true
		}
	}
	if !found {
		return Key{}, ErrNoSigningKey
	}
	return best, nil
}

// Published returns every key visible in the JWKS at t — PublishAt ≤ t <
// RetireAt — with any denylisted kid already excluded at Load.
func (k *Keyset) Published(t time.Time) []Key {
	var out []Key
	for _, key := range k.keys {
		if !key.PublishAt.After(t) && t.Before(key.RetireAt) {
			out = append(out, key)
		}
	}
	return out
}

// JWKS renders Published(t) as an RFC 7517 key set containing only public
// parameters (RS-09) — built from each key's public half alone
// (key.Private.Public()), so there is no private parameter in the result
// to accidentally fail to strip.
func (k *Keyset) JWKS(t time.Time) ([]byte, error) {
	set := jwk.NewSet()
	for _, key := range k.Published(t) {
		publicJWK, err := jwk.Import[jwk.Key](key.Private.Public())
		if err != nil {
			return nil, fmt.Errorf("keys: build JWK for %q: %w", key.KID, err)
		}
		if err := publicJWK.Set(jwk.KeyIDKey, key.KID); err != nil {
			return nil, fmt.Errorf("keys: set kid on JWK for %q: %w", key.KID, err)
		}
		if err := publicJWK.Set(jwk.AlgorithmKey, string(key.Algorithm)); err != nil {
			return nil, fmt.Errorf("keys: set alg on JWK for %q: %w", key.KID, err)
		}
		if err := set.AddKey(publicJWK); err != nil {
			return nil, fmt.Errorf("keys: add JWK for %q to set: %w", key.KID, err)
		}
	}
	return json.Marshal(set)
}

// ErrUnknownKID reports that no published key matches a requested kid —
// RS-09's kid denylist, an already-retired key, or a token forged with a
// kid that never existed all produce this, indistinguishably, by design
// (RS-25's error-ambiguity principle applied to key lookup).
var ErrUnknownKID = errors.New("keys: no published key matches the requested kid")

// keySource adapts a Keyset to tokenvalidator.KeySource.
type keySource struct{ keyset *Keyset }

// AsKeySource adapts a Keyset to tokenvalidator.KeySource for in-process
// validation — the gateway's own consumer of pkg/tokenvalidator
// (REQUIREMENTS §7.4), sharing the same Validator type the demo resource
// server drives over HTTP via tokenvalidator.NewJWKSSource.
func (k *Keyset) AsKeySource() tokenvalidator.KeySource {
	return &keySource{keyset: k}
}

// Key implements tokenvalidator.KeySource by looking the kid up among the
// keys currently published — the same set JWKS(now) would render, so an
// in-process validator and an external one resolve a kid identically.
func (s *keySource) Key(_ context.Context, kid string) (crypto.PublicKey, tokenvalidator.Algorithm, error) {
	for _, key := range s.keyset.Published(time.Now()) {
		if key.KID == kid {
			return key.Private.Public(), key.Algorithm, nil
		}
	}
	return nil, "", ErrUnknownKID
}
