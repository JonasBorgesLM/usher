//go:build integration

package postgres

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/JonasBorgesLM/usher/internal/audit"
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
	return testFamilyForClient(subject, "client-1", expiresAt)
}

// testFamilyForClient is testFamily's own generalization, for #38's own
// tests: RevokeAllForSubject and RevokeForSubjectAndClient are only
// distinguishable from each other against a subject who holds families
// under more than one client.
func testFamilyForClient(subject, clientID string, expiresAt time.Time) oauth.Family {
	return oauth.Family{
		ClientID:  clientID,
		Subject:   subject,
		Scope:     []string{"openid", "offline_access"},
		ExpiresAt: expiresAt,
	}
}

// createTestUser is newTestFamilyFixture's own per-test variant, for
// tests that need a second, distinct subject against the same store.
func createTestUser(t *testing.T, store *FamilyStore, identifier string) string {
	t.Helper()
	userID, err := NewUserStore(store.pool).CreateUser(context.Background(), SeedUser{
		Identifier:   identifier,
		PasswordHash: testPasswordHash,
		Role:         "user",
	})
	if err != nil {
		t.Fatalf("CreateUser(%q): %v", identifier, err)
	}
	return userID
}

func TestFamilyStore_CreateAndLookup_RoundTrip(t *testing.T) {
	store, userID := newTestFamilyFixture(t)
	ctx := context.Background()
	_, hash := testRawToken(t)

	fam := testFamily(userID, time.Now().Add(time.Hour))
	tok := oauth.RefreshToken{Hash: hash, ExpiresAt: time.Now().Add(30 * time.Minute)}
	if _, err := store.CreateFamily(ctx, fam, tok); err != nil {
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
	if _, err := store.CreateFamily(ctx, fam, tok); err != nil {
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
	if _, err := store.CreateFamily(ctx, fam, tok); err != nil {
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
	if _, err := store.CreateFamily(ctx, fam, tok); err != nil {
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

// seedFamilyWithToken is #36's own fixture: a family and its one token,
// returning the family's real (database-generated) id alongside the
// token's hash -- every #36 test needs the real id to build a correctly
// bound successor RefreshToken.
func seedFamilyWithToken(t *testing.T, store *FamilyStore, userID string) (familyID string, hash [32]byte) {
	t.Helper()
	ctx := context.Background()
	_, hash = testRawToken(t)
	fam := testFamily(userID, time.Now().Add(time.Hour))
	tok := oauth.RefreshToken{Hash: hash, ExpiresAt: time.Now().Add(time.Hour)}
	familyID, err := store.CreateFamily(ctx, fam, tok)
	if err != nil {
		t.Fatalf("CreateFamily: %v", err)
	}
	return familyID, hash
}

func TestFamilyStore_Rotate_LegitimateExchangeSucceeds(t *testing.T) {
	store, userID := newTestFamilyFixture(t)
	ctx := context.Background()
	familyID, hash := seedFamilyWithToken(t, store, userID)
	_, nextHash := testRawToken(t)

	consumed, err := store.Rotate(ctx, hash, oauth.RefreshToken{Hash: nextHash, FamilyID: familyID, ExpiresAt: time.Now().Add(time.Hour)})
	if err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	if !consumed {
		t.Fatal("Rotate on a fresh, unconsumed token reported consumed=false")
	}

	// The successor must itself now be a usable, unconsumed token.
	_, nextTok, err := store.Lookup(ctx, nextHash)
	if err != nil {
		t.Fatalf("Lookup(successor): %v", err)
	}
	if nextTok.ConsumedAt != nil {
		t.Error("the successor token is already consumed")
	}

	// Replaying the original (now-consumed) token must report reuse.
	_, anotherHash := testRawToken(t)
	consumed, err = store.Rotate(ctx, hash, oauth.RefreshToken{Hash: anotherHash, FamilyID: familyID, ExpiresAt: time.Now().Add(time.Hour)})
	if err != nil {
		t.Fatalf("Rotate (replay): %v", err)
	}
	if consumed {
		t.Error("replaying an already-consumed token reported consumed=true")
	}
}

// TestFamilyStore_Rotate_SuccessorUnusableAfterFamilyRevoked is #36's own
// finding: a family revoked for reuse (on one token) must also refuse
// its never-consumed successor -- otherwise a detected reuse would stop
// nothing. Exercises Rotate's own `f.revoked_at IS NULL` condition
// directly, independent of whatever earlier check (RS-34's binding,
// #37) might also have caught this upstream.
//
// Negative control: with the `AND f.revoked_at IS NULL` clause removed
// from Rotate's UPDATE (reverting to docs/ARCHITECTURE.md §2.2's
// original "verbatim" query), this test failed -- the successor token
// rotated successfully despite its family being revoked. Verified by
// hand, restored before committing.
func TestFamilyStore_Rotate_SuccessorUnusableAfterFamilyRevoked(t *testing.T) {
	store, userID := newTestFamilyFixture(t)
	ctx := context.Background()
	familyID, hashA := seedFamilyWithToken(t, store, userID)

	// Legitimate rotation: A -> B.
	_, hashB := testRawToken(t)
	consumed, err := store.Rotate(ctx, hashA, oauth.RefreshToken{Hash: hashB, FamilyID: familyID, ExpiresAt: time.Now().Add(time.Hour)})
	if err != nil || !consumed {
		t.Fatalf("first rotation: consumed=%v err=%v", consumed, err)
	}

	// Replay A: reuse. The family is revoked exactly as
	// oauth.RotateRefreshToken would (tested there against a fake); this
	// test drives the store directly to isolate Rotate's own SQL.
	_, hashC := testRawToken(t)
	consumed, err = store.Rotate(ctx, hashA, oauth.RefreshToken{Hash: hashC, FamilyID: familyID, ExpiresAt: time.Now().Add(time.Hour)})
	if err != nil {
		t.Fatalf("replay rotation: %v", err)
	}
	if consumed {
		t.Fatal("replaying an already-consumed token succeeded")
	}
	if err := store.Revoke(ctx, familyID, "reuse_detected"); err != nil {
		t.Fatalf("Revoke: %v", err)
	}

	// The successor B was never consumed -- its own row alone would
	// still satisfy a naive compare-and-set. It must still be refused,
	// because its family is now revoked.
	_, hashD := testRawToken(t)
	consumed, err = store.Rotate(ctx, hashB, oauth.RefreshToken{Hash: hashD, FamilyID: familyID, ExpiresAt: time.Now().Add(time.Hour)})
	if err != nil {
		t.Fatalf("successor rotation: %v", err)
	}
	if consumed {
		t.Error("the successor token rotated successfully even though its family was revoked")
	}
}

// TestRotateRefreshToken_ConcurrentReuse_ExactlyOneIssuanceFamilyRevoked
// is #36's own first three done-when items, all from the same race: 50
// goroutines simultaneously present the SAME unconsumed token. Exactly
// one must succeed; the rest are reuse by ADR-0012's own definition (no
// grace window -- a race loser is not distinguished from a genuine
// replay), which must revoke the family and emit a high-severity audit
// event. Run against the real FamilyStore (never a fake) because RS-11's
// claim is about real Postgres's own atomicity, under -race.
func TestRotateRefreshToken_ConcurrentReuse_ExactlyOneIssuanceFamilyRevoked(t *testing.T) {
	store, userID := newTestFamilyFixture(t)
	familyID, hash := seedFamilyWithToken(t, store, userID)

	const n = 50
	nextHashes := make([][32]byte, n)
	for i := range n {
		_, nextHashes[i] = testRawToken(t)
	}

	sink := audit.NewMemorySink()
	var successes atomic.Int32
	var invalidGrants atomic.Int32
	var wg sync.WaitGroup
	wg.Add(n)
	for i := range n {
		go func(i int) {
			defer wg.Done()
			err := oauth.RotateRefreshToken(context.Background(), store, sink, hash,
				oauth.RefreshToken{Hash: nextHashes[i], FamilyID: familyID, ExpiresAt: time.Now().Add(time.Hour)})
			switch {
			case err == nil:
				successes.Add(1)
			case errors.Is(err, oauth.ErrInvalidGrant):
				invalidGrants.Add(1)
			default:
				t.Errorf("RotateRefreshToken: unexpected error: %v", err)
			}
		}(i)
	}
	wg.Wait()

	if got := successes.Load(); got != 1 {
		t.Errorf("successful rotations = %d, want exactly 1", got)
	}
	if got := invalidGrants.Load(); got != n-1 {
		t.Errorf("invalid_grant outcomes = %d, want %d", got, n-1)
	}

	var revokedAt *time.Time
	var revokedReason *string
	if err := store.pool.QueryRow(context.Background(),
		"SELECT revoked_at, revoked_reason FROM refresh_families WHERE id = $1", familyID,
	).Scan(&revokedAt, &revokedReason); err != nil {
		t.Fatalf("read refresh_families row: %v", err)
	}
	if revokedAt == nil || revokedReason == nil || *revokedReason != "reuse_detected" {
		t.Errorf("family revoked_at=%v revoked_reason=%v, want revoked with reason reuse_detected", revokedAt, revokedReason)
	}

	var highSeverity []audit.Event
	for _, e := range sink.Events() {
		if e.Type == audit.EventRefreshReuse {
			highSeverity = append(highSeverity, e)
		}
	}
	if len(highSeverity) == 0 {
		t.Error("no EventRefreshReuse event was emitted")
	}
	for _, e := range highSeverity {
		if e.Outcome != audit.OutcomeFailure {
			t.Errorf("EventRefreshReuse outcome = %q, want %q", e.Outcome, audit.OutcomeFailure)
		}
	}
}

// TestFamilyStore_Rotate_NegativeControl_ReadThenWriteLetsMultipleWin is
// #36's own fourth done-when: "verified failing against a read-then-write
// consumption." Rather than editing the real Rotate and reverting (which
// would leave the production file momentarily broken for a window), this
// runs the identical concurrency race against a deliberately non-atomic
// SELECT-then-UPDATE implementation defined only in this test file --
// the same approach #29's own CodeStore negative control used for
// authorization codes.
//
// The race must be forced with an explicit barrier: an earlier attempt
// without one (this project's own established lesson, #29) did not
// reproduce the race reliably under a fast local Postgres round trip.
func TestFamilyStore_Rotate_NegativeControl_ReadThenWriteLetsMultipleWin(t *testing.T) {
	store, userID := newTestFamilyFixture(t)
	_, hash := seedFamilyWithToken(t, store, userID)
	ctx := context.Background()

	const n = 50
	var barrier sync.WaitGroup
	barrier.Add(n)

	brokenRotate := func() (bool, error) {
		var consumedAt *time.Time
		if err := store.pool.QueryRow(ctx, "SELECT consumed_at FROM refresh_tokens WHERE hash = $1", hash[:]).Scan(&consumedAt); err != nil {
			barrier.Done()
			return false, err
		}
		barrier.Done()
		barrier.Wait() // every goroutine's read completes before any write
		if consumedAt != nil {
			return false, nil
		}
		if _, err := store.pool.Exec(ctx, "UPDATE refresh_tokens SET consumed_at = now() WHERE hash = $1", hash[:]); err != nil {
			return false, err
		}
		return true, nil
	}

	var wins atomic.Int32
	var wg sync.WaitGroup
	wg.Add(n)
	for range n {
		go func() {
			defer wg.Done()
			ok, err := brokenRotate()
			if err != nil {
				t.Error(err)
				return
			}
			if ok {
				wins.Add(1)
			}
		}()
	}
	wg.Wait()

	got := wins.Load()
	if got <= 1 {
		t.Fatalf("read-then-write negative control: %d of %d callers won, want more than 1 (the forced race did not reproduce)", got, n)
	}
	t.Logf("read-then-write negative control: %d of %d concurrent callers incorrectly succeeded", got, n)
}

// TestFamilyStore_RevokeAllForSubject_RevokesEveryFamilyAcrossClients is
// #38's own done-when for administrative revocation (RF-06): every
// family subject holds, regardless of which client it was issued to, is
// revoked -- unlike RevokeForSubjectAndClient, this must NOT stop at one
// client. The negative space this guards against (another subject left
// untouched; an earlier revocation reason not clobbered) has its own
// dedicated tests below, each with its own verified negative control.
func TestFamilyStore_RevokeAllForSubject_RevokesEveryFamilyAcrossClients(t *testing.T) {
	store, userID := newTestFamilyFixture(t)
	ctx := context.Background()
	_, hashA := testRawToken(t)
	_, hashB := testRawToken(t)

	famA := testFamilyForClient(userID, "client-a", time.Now().Add(time.Hour))
	idA, err := store.CreateFamily(ctx, famA, oauth.RefreshToken{Hash: hashA, ExpiresAt: time.Now().Add(time.Hour)})
	if err != nil {
		t.Fatalf("CreateFamily(client-a): %v", err)
	}
	famB := testFamilyForClient(userID, "client-b", time.Now().Add(time.Hour))
	idB, err := store.CreateFamily(ctx, famB, oauth.RefreshToken{Hash: hashB, ExpiresAt: time.Now().Add(time.Hour)})
	if err != nil {
		t.Fatalf("CreateFamily(client-b): %v", err)
	}

	if err := store.RevokeAllForSubject(ctx, userID, "admin"); err != nil {
		t.Fatalf("RevokeAllForSubject: %v", err)
	}

	for _, id := range []string{idA, idB} {
		var revokedAt *time.Time
		var revokedReason *string
		if err := store.pool.QueryRow(ctx,
			"SELECT revoked_at, revoked_reason FROM refresh_families WHERE id = $1", id,
		).Scan(&revokedAt, &revokedReason); err != nil {
			t.Fatalf("read refresh_families(%s): %v", id, err)
		}
		if revokedAt == nil || revokedReason == nil || *revokedReason != "admin" {
			t.Errorf("family %s revoked_at=%v revoked_reason=%v, want revoked with reason admin", id, revokedAt, revokedReason)
		}
	}
}

// TestFamilyStore_RevokeAllForSubject_DoesNotTouchAnotherSubject is the
// administrative case's own boundary in the other direction: a different
// subject's family, even under the same client, must be untouched.
//
// Negative control: with `subject = $2` removed from
// RevokeAllForSubject's WHERE clause, this test failed -- the other
// subject's family was revoked too. Verified by hand, restored before
// committing.
func TestFamilyStore_RevokeAllForSubject_DoesNotTouchAnotherSubject(t *testing.T) {
	store, userID := newTestFamilyFixture(t)
	ctx := context.Background()
	otherUserID := createTestUser(t, store, "family-test-other@example.com")

	_, hashMine := testRawToken(t)
	mine := testFamily(userID, time.Now().Add(time.Hour))
	if _, err := store.CreateFamily(ctx, mine, oauth.RefreshToken{Hash: hashMine, ExpiresAt: time.Now().Add(time.Hour)}); err != nil {
		t.Fatalf("CreateFamily(mine): %v", err)
	}

	_, hashOther := testRawToken(t)
	other := testFamily(otherUserID, time.Now().Add(time.Hour))
	idOther, err := store.CreateFamily(ctx, other, oauth.RefreshToken{Hash: hashOther, ExpiresAt: time.Now().Add(time.Hour)})
	if err != nil {
		t.Fatalf("CreateFamily(other): %v", err)
	}

	if err := store.RevokeAllForSubject(ctx, userID, "admin"); err != nil {
		t.Fatalf("RevokeAllForSubject: %v", err)
	}

	var revokedAt *time.Time
	if err := store.pool.QueryRow(ctx,
		"SELECT revoked_at FROM refresh_families WHERE id = $1", idOther,
	).Scan(&revokedAt); err != nil {
		t.Fatalf("read refresh_families(other): %v", err)
	}
	if revokedAt != nil {
		t.Error("another subject's family was revoked by RevokeAllForSubject")
	}
}

// TestFamilyStore_RevokeForSubjectAndClient_ScopedToOneClient is #38's
// own done-when for consent revocation (RF-13): only the families the
// subject holds under the one revoked client are touched -- the same
// subject's family under a different client must survive.
//
// Negative control: with `AND client_id = $3` removed from
// RevokeForSubjectAndClient's WHERE clause, this test failed -- the same
// subject's family under client-b was revoked too, even though only
// client-a's consent was revoked. Verified by hand, restored before
// committing.
func TestFamilyStore_RevokeForSubjectAndClient_ScopedToOneClient(t *testing.T) {
	store, userID := newTestFamilyFixture(t)
	ctx := context.Background()
	_, hashA := testRawToken(t)
	_, hashB := testRawToken(t)

	famA := testFamilyForClient(userID, "client-a", time.Now().Add(time.Hour))
	idA, err := store.CreateFamily(ctx, famA, oauth.RefreshToken{Hash: hashA, ExpiresAt: time.Now().Add(time.Hour)})
	if err != nil {
		t.Fatalf("CreateFamily(client-a): %v", err)
	}
	famB := testFamilyForClient(userID, "client-b", time.Now().Add(time.Hour))
	idB, err := store.CreateFamily(ctx, famB, oauth.RefreshToken{Hash: hashB, ExpiresAt: time.Now().Add(time.Hour)})
	if err != nil {
		t.Fatalf("CreateFamily(client-b): %v", err)
	}

	if err := store.RevokeForSubjectAndClient(ctx, userID, "client-a", "consent_revoked"); err != nil {
		t.Fatalf("RevokeForSubjectAndClient: %v", err)
	}

	var revokedAtA, revokedAtB *time.Time
	var revokedReasonA *string
	if err := store.pool.QueryRow(ctx, "SELECT revoked_at, revoked_reason FROM refresh_families WHERE id = $1", idA).
		Scan(&revokedAtA, &revokedReasonA); err != nil {
		t.Fatalf("read refresh_families(client-a): %v", err)
	}
	if revokedAtA == nil || revokedReasonA == nil || *revokedReasonA != "consent_revoked" {
		t.Errorf("client-a family revoked_at=%v revoked_reason=%v, want revoked with reason consent_revoked", revokedAtA, revokedReasonA)
	}

	if err := store.pool.QueryRow(ctx, "SELECT revoked_at FROM refresh_families WHERE id = $1", idB).Scan(&revokedAtB); err != nil {
		t.Fatalf("read refresh_families(client-b): %v", err)
	}
	if revokedAtB != nil {
		t.Error("client-b's family was revoked by a RevokeForSubjectAndClient call scoped to client-a")
	}
}

// TestFamilyStore_RevokeAllForSubject_DoesNotOverwriteEarlierReason is
// Revoke's own idempotency contract, extended to the two revoke-many
// methods: a family already revoked (here, by reuse detection) keeps its
// first-recorded reason rather than a later administrative sweep
// clobbering the record of what actually happened first (ADR-0017).
//
// Negative control: with `AND revoked_at IS NULL` removed from
// RevokeAllForSubject's UPDATE, this test failed -- the family's reason
// was overwritten from reuse_detected to admin. Verified by hand,
// restored before committing.
func TestFamilyStore_RevokeAllForSubject_DoesNotOverwriteEarlierReason(t *testing.T) {
	store, userID := newTestFamilyFixture(t)
	ctx := context.Background()
	familyID, _ := seedFamilyWithToken(t, store, userID)

	if err := store.Revoke(ctx, familyID, "reuse_detected"); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if err := store.RevokeAllForSubject(ctx, userID, "admin"); err != nil {
		t.Fatalf("RevokeAllForSubject: %v", err)
	}

	var revokedReason *string
	if err := store.pool.QueryRow(ctx, "SELECT revoked_reason FROM refresh_families WHERE id = $1", familyID).Scan(&revokedReason); err != nil {
		t.Fatalf("read refresh_families: %v", err)
	}
	if revokedReason == nil || *revokedReason != "reuse_detected" {
		t.Errorf("revoked_reason = %v, want it to keep its first-recorded value reuse_detected", revokedReason)
	}
}
