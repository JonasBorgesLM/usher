// This file's LoadClients and Client.AuthenticateSecret: RF-01's static
// registry and RS-16's client authentication.

package identity

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"os"

	"github.com/JonasBorgesLM/moat/secret"
)

// clientFile is the on-disk JSON shape of one registry entry. Nothing more
// precise than RF-01's prose existed to write this from — the field names
// and the single-JSON-array-file layout are this package's own choice.
type clientFile struct {
	ClientID       string   `json:"client_id"`
	Confidential   bool     `json:"confidential"`
	SecretHash     string   `json:"secret_hash"` // hex SHA-256, "" for a public client
	RedirectURIs   []string `json:"redirect_uris"`
	GrantTypes     []string `json:"grant_types"`
	Scopes         []string `json:"scopes"`
	Audiences      []string `json:"audiences"`
	RequireConsent bool     `json:"require_consent"`
}

// sha256HexLen is the length of a SHA-256 digest hex-encoded: 32 bytes, 2
// hex characters each.
const sha256HexLen = 2 * sha256.Size

// LoadClients parses and validates a client registry file (RF-01): a JSON
// array of client entries. path is operator configuration (trusted per
// THREAT-MODEL.md's actor table), not request input. Called once at
// startup; any violation refuses rather than loading a partial registry
// (RNF-05).
func LoadClients(path string, allowedSchemes []string) ([]Client, error) {
	data, err := os.ReadFile(path) // #nosec G304 -- path is trusted operator config, see doc comment above
	if err != nil {
		return nil, fmt.Errorf("%w: read %s: %w", ErrInvalidClientRegistry, path, err)
	}

	var files []clientFile
	if err := json.Unmarshal(data, &files); err != nil {
		return nil, fmt.Errorf("%w: parse %s: %w", ErrInvalidClientRegistry, path, err)
	}
	if len(files) == 0 {
		return nil, fmt.Errorf("%w: %s declares no clients", ErrInvalidClientRegistry, path)
	}

	seen := make(map[string]bool, len(files))
	clients := make([]Client, 0, len(files))
	for _, f := range files {
		if f.ClientID == "" {
			return nil, fmt.Errorf("%w: a client has an empty client_id", ErrInvalidClientRegistry)
		}
		if seen[f.ClientID] {
			return nil, fmt.Errorf("%w: duplicate client_id %q", ErrInvalidClientRegistry, f.ClientID)
		}
		seen[f.ClientID] = true

		if err := validateSecretHash(f); err != nil {
			return nil, fmt.Errorf("client %q: %w", f.ClientID, err)
		}

		if len(f.RedirectURIs) == 0 {
			return nil, fmt.Errorf("%w: client %q declares no redirect_uris", ErrInvalidClientRegistry, f.ClientID)
		}
		for _, uri := range f.RedirectURIs {
			if err := validateRedirectURI(uri, allowedSchemes); err != nil {
				return nil, fmt.Errorf("client %q: %w", f.ClientID, err)
			}
		}

		if len(f.GrantTypes) == 0 {
			return nil, fmt.Errorf("%w: client %q declares no grant_types", ErrInvalidClientRegistry, f.ClientID)
		}

		clients = append(clients, Client{
			ID:             f.ClientID,
			Confidential:   f.Confidential,
			SecretHash:     f.SecretHash,
			RedirectURIs:   f.RedirectURIs,
			GrantTypes:     f.GrantTypes,
			Scopes:         f.Scopes,
			Audiences:      f.Audiences,
			RequireConsent: f.RequireConsent,
		})
	}
	return clients, nil
}

// validateSecretHash is RF-01's "declares... hashed client_secret when
// confidential" and RS-16's "public clients rely on PKCE alone": the two
// fields must agree, in both directions — a confidential client with no
// usable hash cannot authenticate at all, and a public client with one set
// contradicts the SecretHash=="" convention Client.AuthenticateSecret and
// every other reader of this type relies on.
func validateSecretHash(f clientFile) error {
	if f.Confidential {
		if len(f.SecretHash) != sha256HexLen {
			return fmt.Errorf("%w: confidential but secret_hash is not a %d-character hex SHA-256 (got %d characters)",
				ErrInvalidClientRegistry, sha256HexLen, len(f.SecretHash))
		}
		if _, err := hex.DecodeString(f.SecretHash); err != nil {
			return fmt.Errorf("%w: confidential but secret_hash is not valid hex: %w", ErrInvalidClientRegistry, err)
		}
		return nil
	}
	if f.SecretHash != "" {
		return fmt.Errorf("%w: public (confidential=false) but declares a secret_hash", ErrInvalidClientRegistry)
	}
	return nil
}

// validateRedirectURI is RF-01's three stated conditions, each named in the
// error so an operator does not have to guess which one failed.
func validateRedirectURI(raw string, allowedSchemes []string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("%w: redirect_uri %q: %w", ErrInvalidClientRegistry, raw, err)
	}
	if !u.IsAbs() {
		return fmt.Errorf("%w: redirect_uri %q is not absolute", ErrInvalidClientRegistry, raw)
	}
	if u.Fragment != "" {
		return fmt.Errorf("%w: redirect_uri %q carries a fragment", ErrInvalidClientRegistry, raw)
	}
	for _, s := range allowedSchemes {
		if u.Scheme == s {
			return nil
		}
	}
	return fmt.Errorf("%w: redirect_uri %q uses scheme %q, not in the allow-list %v", ErrInvalidClientRegistry, raw, u.Scheme, allowedSchemes)
}

// AuthenticateSecret reports whether presented is this client's registered
// secret (RS-16, client_secret_basic/client_secret_post — reading the
// credential out of the request is the caller's job, this is just the
// comparison): SHA-256 of presented, compared against SecretHash in
// constant time via secret.Value.Equal, never == or bytes.Equal (RS-15).
//
// A public client (SecretHash == "") never authenticates this way — PKCE
// does not turn a public client into a confidential one, so there is no
// secret to check against.
func (c Client) AuthenticateSecret(presented string) bool {
	if c.SecretHash == "" {
		return false
	}
	computed := sha256.Sum256([]byte(presented))
	computedHex := hex.EncodeToString(computed[:])
	return secret.New([]byte(computedHex)).Equal(secret.New([]byte(c.SecretHash)))
}
