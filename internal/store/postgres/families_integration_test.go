//go:build integration

package postgres

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"testing"
	"time"

	"github.com/JonasBorgesLM/usher/internal/oauth"
)

func newTestFamilyFixture(t *testing.T) (*FamilyStore, string) {
	t.Helper()
	pool := newTestPool(t)
	ctx := context.Background()
	if err := Migrate(ctx, pool); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	users := NewUserStore(pool)
	userID, err := users.CreateUser(ctx, SeedUser{
		Identifier:   "family-test@example.com",
		PasswordHash: testPasswordHash,
		Role:         "user",
	})
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	return NewFamilyStore(pool), userID
}

// testRawToken is RS-10's own shape: >=256 bits from crypto/rand, returned
// alongside its SHA-256 hash -- the only thing this package ever persists.
func testRawToken(t *testing.T) (raw string, hash [32]byte) {
	t.Helper()
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		t.Fatalf("crypto/rand: %v", err)
	}
	raw = base64.RawURLEncoding.EncodeToString(buf)
	hash = sha256.Sum256([]byte(raw))
	return raw, hash
}

func testFamily(subject string, expiresAt time.Time) oauth.Family {
	return oauth.Family{
		ClientID:  "client-1",
		Subject:   subject,
		Scope:     []string{"openid", "offline_access"},
		ExpiresAt: expiresAt,
	}
}

func TestFamilyStore_CreateAndLookup_RoundTrip(t *testing.T) {
	store, userID := newTestFamilyFixture(t)
	ctx := context.Background()
	_, hash := testRawToken(t)

	fam := testFamily(userID, time.Now().Add(time.Hour))
	tok := oauth.RefreshToken{Hash: hash, ExpiresAt: time.Now().Add(30 * time.Minute)}
	if err := store.CreateFamily(ctx, fam, tok); err != nil {
		t.Fatalf("CreateFamily: %v", err)
	}

	gotFam, gotTok, err := store.Lookup(ctx, hash)
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if gotFam.ClientID != fam.ClientID || gotFam.Subject != fam.Subject {
		t.Errorf("Lookup family = %+v, want ClientID=%q Subject=%q", gotFam, fam.ClientID, fam.Subject)
	}
	if !equalScopeSet(gotFam.Scope, fam.Scope) {
		t.Errorf("Lookup family scope = %v, want %v", gotFam.Scope, fam.Scope)
	}
	if gotFam.RevokedAt != nil || gotFam.RevokedReason != "" {
		t.Errorf("a freshly created family is already revoked: %+v", gotFam)
	}
	if gotTok.FamilyID != gotFam.ID {
		t.Errorf("token FamilyID = %q, want it to match the looked-up family's ID %q", gotTok.FamilyID, gotFam.ID)
	}
	if gotTok.Hash != hash {
		t.Errorf("Lookup token hash = %x, want %x", gotTok.Hash, hash)
	}
	if gotTok.ConsumedAt != nil {
		t.Error("a freshly created token is already consumed")
	}
}

func TestFamilyStore_LookupUnknownHashReturnsNotFound(t *testing.T) {
	store, _ := newTestFamilyFixture(t)
	var neverIssued [32]byte
	copy(neverIssued[:], []byte("this hash was never inserted!!!"))

	if _, _, err := store.Lookup(context.Background(), neverIssued); !errors.Is(err, oauth.ErrRefreshTokenNotFound) {
		t.Errorf("Lookup(never-issued) = %v, want ErrRefreshTokenNotFound", err)
	}
}

// TestFamilyStore_LookupIdleExpiredReturnsNotFound is #35's own done-when:
// the token's own idle lifetime (RefreshToken.ExpiresAt), independent of
// the family's absolute lifetime, is enforced.
//
// Negative control: with the `if !now.Before(tok.ExpiresAt)` check removed
// from Lookup, this test failed -- an idle-expired token resolved
// successfully. Verified by hand, restored before committing.
func TestFamilyStore_LookupIdleExpiredReturnsNotFound(t *testing.T) {
	store, userID := newTestFamilyFixture(t)
	ctx := context.Background()
	_, hash := testRawToken(t)

	fam := testFamily(userID, time.Now().Add(time.Hour))                           // absolute lifetime still valid
	tok := oauth.RefreshToken{Hash: hash, ExpiresAt: time.Now().Add(-time.Minute)} // idle lifetime already passed
	if err := store.CreateFamily(ctx, fam, tok); err != nil {
		t.Fatalf("CreateFamily: %v", err)
	}

	if _, _, err := store.Lookup(ctx, hash); !errors.Is(err, oauth.ErrRefreshTokenNotFound) {
		t.Errorf("Lookup on an idle-expired token = %v, want ErrRefreshTokenNotFound", err)
	}
}

// TestFamilyStore_LookupAbsoluteExpiredReturnsNotFound is #35's own
// done-when: the family's absolute lifetime (Family.ExpiresAt),
// independent of the token's own idle lifetime, is enforced.
//
// Negative control: with the `if !now.Before(fam.ExpiresAt)` check removed
// from Lookup, this test failed -- a token belonging to an
// absolute-expired family resolved successfully. Verified by hand,
// restored before committing.
func TestFamilyStore_LookupAbsoluteExpiredReturnsNotFound(t *testing.T) {
	store, userID := newTestFamilyFixture(t)
	ctx := context.Background()
	_, hash := testRawToken(t)

	fam := testFamily(userID, time.Now().Add(-time.Minute))                     // absolute lifetime already passed
	tok := oauth.RefreshToken{Hash: hash, ExpiresAt: time.Now().Add(time.Hour)} // idle lifetime still valid
	if err := store.CreateFamily(ctx, fam, tok); err != nil {
		t.Fatalf("CreateFamily: %v", err)
	}

	if _, _, err := store.Lookup(ctx, hash); !errors.Is(err, oauth.ErrRefreshTokenNotFound) {
		t.Errorf("Lookup on a token in an absolute-expired family = %v, want ErrRefreshTokenNotFound", err)
	}
}

// TestFamilyStore_DBDumpYieldsNoUsableToken is #35's own first done-when
// -- read the table directly, the way a DB dump would, and confirm what
// is there is not usable as a bearer credential: not the raw token's own
// bytes, and nothing a reader could present back to re-derive it. SHA-256
// is one-way, so the only thing this test can actually demonstrate is
// that the stored value is a hash of the raw token and not the token
// itself -- recoverability is a cryptographic claim about SHA-256, not
// something a test can additionally prove.
func TestFamilyStore_DBDumpYieldsNoUsableToken(t *testing.T) {
	store, userID := newTestFamilyFixture(t)
	ctx := context.Background()
	raw, hash := testRawToken(t)

	fam := testFamily(userID, time.Now().Add(time.Hour))
	tok := oauth.RefreshToken{Hash: hash, ExpiresAt: time.Now().Add(time.Hour)}
	if err := store.CreateFamily(ctx, fam, tok); err != nil {
		t.Fatalf("CreateFamily: %v", err)
	}

	// Read the row directly, bypassing FamilyStore's own API -- the same
	// access a stolen DB dump would give an attacker.
	var dbHash []byte
	if err := store.pool.QueryRow(ctx, "SELECT hash FROM refresh_tokens WHERE hash = $1", hash[:]).Scan(&dbHash); err != nil {
		t.Fatalf("read refresh_tokens row directly: %v", err)
	}

	if string(dbHash) == raw {
		t.Fatal("the raw token value was stored verbatim in the hash column")
	}
	recomputed := sha256.Sum256([]byte(raw))
	if string(dbHash) != string(recomputed[:]) {
		t.Fatalf("stored value = %x, want it to equal SHA-256(raw token) = %x", dbHash, recomputed)
	}
	if len(dbHash) != 32 {
		t.Errorf("stored hash is %d bytes, want 32 (SHA-256's width, RS-10)", len(dbHash))
	}
}
