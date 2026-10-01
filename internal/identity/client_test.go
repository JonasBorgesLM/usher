package identity

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

var allowedSchemes = []string{"https"}

// writeRegistry writes files as a JSON array to a temp file and returns
// its path.
func writeRegistry(t *testing.T, files []clientFile) string {
	t.Helper()
	data, err := json.Marshal(files)
	if err != nil {
		t.Fatalf("marshal registry: %v", err)
	}
	path := filepath.Join(t.TempDir(), "clients.json")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write registry: %v", err)
	}
	return path
}

func validConfidentialClient() clientFile {
	return clientFile{
		ClientID:     "confidential-client",
		Confidential: true,
		SecretHash:   hashSecretForTest("correct-secret"),
		RedirectURIs: []string{"https://example.com/callback"},
		GrantTypes:   []string{"authorization_code"},
		Scopes:       []string{"openid"},
	}
}

func hashSecretForTest(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

func validPublicClient() clientFile {
	return clientFile{
		ClientID:     "public-client",
		Confidential: false,
		RedirectURIs: []string{"https://example.com/callback"},
		GrantTypes:   []string{"authorization_code"},
		Scopes:       []string{"openid"},
	}
}

// TestLoadClients_ValidRegistrySucceeds is the table test's control case:
// every other case in the table below is a single mutation away from this
// one succeeding.
func TestLoadClients_ValidRegistrySucceeds(t *testing.T) {
	path := writeRegistry(t, []clientFile{validConfidentialClient(), validPublicClient()})

	clients, err := LoadClients(path, allowedSchemes)
	if err != nil {
		t.Fatalf("LoadClients: %v", err)
	}
	if len(clients) != 2 {
		t.Fatalf("LoadClients returned %d clients, want 2", len(clients))
	}
}

// TestLoadClients_InvalidShapesRefuse is RF-01's own done-when: each
// invalid registration shape refuses to start. Every case here is the
// valid registry above with exactly one field mutated.
func TestLoadClients_InvalidShapesRefuse(t *testing.T) {
	cases := []struct {
		name  string
		files []clientFile
	}{
		{
			name:  "empty registry",
			files: []clientFile{},
		},
		{
			name: "empty client_id",
			files: []clientFile{func() clientFile {
				c := validPublicClient()
				c.ClientID = ""
				return c
			}()},
		},
		{
			name: "duplicate client_id",
			files: []clientFile{validPublicClient(), func() clientFile {
				c := validPublicClient()
				c.RedirectURIs = []string{"https://other.example.com/callback"}
				return c
			}()},
		},
		{
			name: "confidential with no secret_hash",
			files: []clientFile{func() clientFile {
				c := validConfidentialClient()
				c.SecretHash = ""
				return c
			}()},
		},
		{
			name: "confidential with malformed secret_hash",
			files: []clientFile{func() clientFile {
				c := validConfidentialClient()
				c.SecretHash = "not-hex-and-wrong-length"
				return c
			}()},
		},
		{
			name: "public client declaring a secret_hash",
			files: []clientFile{func() clientFile {
				c := validPublicClient()
				c.SecretHash = hashSecretForTest("should-not-be-here")
				return c
			}()},
		},
		{
			name: "no redirect_uris",
			files: []clientFile{func() clientFile {
				c := validPublicClient()
				c.RedirectURIs = nil
				return c
			}()},
		},
		{
			name: "relative redirect_uri",
			files: []clientFile{func() clientFile {
				c := validPublicClient()
				c.RedirectURIs = []string{"/callback"}
				return c
			}()},
		},
		{
			name: "redirect_uri with a fragment",
			files: []clientFile{func() clientFile {
				c := validPublicClient()
				c.RedirectURIs = []string{"https://example.com/callback#fragment"}
				return c
			}()},
		},
		{
			name: "redirect_uri with a disallowed scheme",
			files: []clientFile{func() clientFile {
				c := validPublicClient()
				c.RedirectURIs = []string{"http://example.com/callback"} // allowedSchemes is https-only
				return c
			}()},
		},
		{
			name: "no grant_types",
			files: []clientFile{func() clientFile {
				c := validPublicClient()
				c.GrantTypes = nil
				return c
			}()},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := writeRegistry(t, tc.files)
			if _, err := LoadClients(path, allowedSchemes); err == nil {
				t.Errorf("LoadClients with %s succeeded, want an error", tc.name)
			}
		})
	}
}

// TestLoadClients_MissingFileRefuses covers the non-table case: the
// registry file itself does not exist.
func TestLoadClients_MissingFileRefuses(t *testing.T) {
	path := filepath.Join(t.TempDir(), "does-not-exist.json")
	if _, err := LoadClients(path, allowedSchemes); err == nil {
		t.Fatal("LoadClients against a missing file succeeded, want an error")
	}
}

// TestLoadClients_MalformedJSONRefuses covers the file existing but not
// being a valid JSON array.
func TestLoadClients_MalformedJSONRefuses(t *testing.T) {
	path := filepath.Join(t.TempDir(), "clients.json")
	if err := os.WriteFile(path, []byte("{not valid json"), 0o600); err != nil {
		t.Fatalf("write malformed registry: %v", err)
	}
	if _, err := LoadClients(path, allowedSchemes); err == nil {
		t.Fatal("LoadClients against malformed JSON succeeded, want an error")
	}
}

// TestLoadClients_NegativeControl_SecretHashCheckRemoved is the table
// test's own "seen failing" requirement: with validateSecretHash's
// confidential-requires-hash branch disabled, the "confidential with no
// secret_hash" case from the table above loads successfully instead of
// refusing.
//
// Negative control: with the `if len(f.SecretHash) != sha256HexLen` check
// removed from validateSecretHash, this test failed -- a confidential
// client with an empty secret_hash loaded without error. Verified by
// hand, restored before committing.
func TestLoadClients_NegativeControl_SecretHashCheckRemoved(t *testing.T) {
	c := validConfidentialClient()
	c.SecretHash = ""
	path := writeRegistry(t, []clientFile{c})

	if _, err := LoadClients(path, allowedSchemes); err == nil {
		t.Fatal("a confidential client with no secret_hash loaded successfully, want an error")
	}
}

func TestClient_AuthenticateSecret(t *testing.T) {
	confidential := Client{ID: "c1", Confidential: true, SecretHash: hashSecretForTest("correct-secret")}
	public := Client{ID: "c2", Confidential: false}

	if !confidential.AuthenticateSecret("correct-secret") {
		t.Error("the correct secret did not authenticate")
	}
	if confidential.AuthenticateSecret("wrong-secret") {
		t.Error("an incorrect secret authenticated")
	}
	if public.AuthenticateSecret("anything") {
		t.Error("a public client (no secret_hash) authenticated with a presented secret")
	}
	if public.AuthenticateSecret("") {
		t.Error("a public client authenticated with an empty presented secret")
	}
}

// TestClient_AuthenticateSecret_NegativeControl documents what "client
// secret comparison is constant-time via secret.Value" turned out to mean
// to actually verify, including an attempt that did not produce a runnable
// negative control at all.
//
// First attempt: replace `secret.New(...).Equal(...)` with `==` between the
// two secret.Value instances. This does not compile -- secret.Value holds
// an unexported `masked []byte` field (moat/secret's own source), which
// makes the whole struct non-comparable. Go's compiler refuses `==` on it
// outright. That is "the type makes this hard by construction" (RS-15)
// taken further than bytes.Equal: there is no red test to see here because
// the mistake cannot be expressed in the language, confirmed by hand.
//
// Second attempt, the one that is actually testable: AuthenticateSecret
// rewritten to compare `computedHex == c.SecretHash` as plain strings,
// bypassing secret.Value entirely. This compiles, and TestClient_
// AuthenticateSecret above still passed against it -- a plain string
// comparison is functionally identical to a constant-time one, which is
// exactly why non-constant-time comparison is a timing bug, not a
// correctness bug: no return-value assertion can distinguish them. Timing
// itself is what would have to be measured (the shape of #16's
// scripts/timing-login, for the login flow specifically) to catch this
// mutation, which is out of proportion for this one comparison. Recorded
// here rather than forcing a test that would not mean what its name claims.
func TestClient_AuthenticateSecret_NegativeControl(t *testing.T) {
	client := Client{ID: "c1", Confidential: true, SecretHash: hashSecretForTest("correct-secret")}
	if !client.AuthenticateSecret("correct-secret") {
		t.Fatal("sanity check failed: the correct secret does not authenticate even before any control is applied")
	}
}
