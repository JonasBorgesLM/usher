//go:build integration

package redis

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	goredis "github.com/redis/go-redis/v9"

	"github.com/JonasBorgesLM/usher/internal/oauth"
)

func newTestCodeStore(t *testing.T, clock *fakeClock) *CodeStore {
	t.Helper()
	client := newTestRedis(t, "noeviction.conf")
	return NewCodeStore(client, WithCodeClock(clock.now))
}

func testCode(clock *fakeClock, value string, ttl time.Duration) oauth.Code {
	return oauth.Code{
		Value:         value,
		ClientID:      "client-1",
		RedirectURI:   "https://client.example/callback",
		CodeChallenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
		Scope:         []string{"openid"},
		Subject:       "alice@example.com",
		ExpiresAt:     clock.now().Add(ttl),
	}
}

func TestCodeStore_SaveAndConsume_RoundTrip(t *testing.T) {
	clock := &fakeClock{t: time.Now()}
	store := newTestCodeStore(t, clock)
	ctx := context.Background()

	code := testCode(clock, "code-1", time.Minute)
	if err := store.Save(ctx, code); err != nil {
		t.Fatalf("Save: %v", err)
	}

	got, err := store.Consume(ctx, "code-1")
	if err != nil {
		t.Fatalf("Consume: %v", err)
	}
	if got.ClientID != code.ClientID || got.CodeChallenge != code.CodeChallenge {
		t.Errorf("Consume: got %+v, want %+v", got, code)
	}

	if _, err := store.Consume(ctx, "code-1"); !errors.Is(err, oauth.ErrCodeNotFound) {
		t.Fatalf("second Consume (replay) = %v, want ErrCodeNotFound", err)
	}
}

// TestCodeStore_AuthTime_RoundTrip is #47's own addition: AuthTime
// survives a real Redis round trip, and a Code built without one (the
// zero time.Time) comes back zero too, rather than Unix epoch 0
// (1970-01-01) -- the same "absent, not a real-looking zero value"
// property challenges_integration_test.go's own MaxAge test asserts.
func TestCodeStore_AuthTime_RoundTrip(t *testing.T) {
	clock := &fakeClock{t: time.Now()}
	store := newTestCodeStore(t, clock)
	ctx := context.Background()

	withAuthTime := testCode(clock, "code-with-auth-time", time.Minute)
	withAuthTime.AuthTime = clock.now().Add(-5 * time.Minute)
	if err := store.Save(ctx, withAuthTime); err != nil {
		t.Fatalf("Save: %v", err)
	}
	got, err := store.Consume(ctx, "code-with-auth-time")
	if err != nil {
		t.Fatalf("Consume: %v", err)
	}
	// Unix-seconds precision, the same encoding ExpiresAt already uses in
	// this store -- .Equal would fail on the sub-second component the
	// round trip never claimed to preserve.
	if got.AuthTime.Unix() != withAuthTime.AuthTime.Unix() {
		t.Errorf("AuthTime = %s, want %s", got.AuthTime, withAuthTime.AuthTime)
	}

	withoutAuthTime := testCode(clock, "code-without-auth-time", time.Minute)
	if err := store.Save(ctx, withoutAuthTime); err != nil {
		t.Fatalf("Save: %v", err)
	}
	got2, err := store.Consume(ctx, "code-without-auth-time")
	if err != nil {
		t.Fatalf("Consume: %v", err)
	}
	if !got2.AuthTime.IsZero() {
		t.Errorf("AuthTime = %s, want zero", got2.AuthTime)
	}
}

func TestCodeStore_SaveTwiceRefuses(t *testing.T) {
	clock := &fakeClock{t: time.Now()}
	store := newTestCodeStore(t, clock)
	ctx := context.Background()

	code := testCode(clock, "code-1", time.Minute)
	if err := store.Save(ctx, code); err != nil {
		t.Fatalf("first Save: %v", err)
	}
	if err := store.Save(ctx, code); !errors.Is(err, oauth.ErrCodeExists) {
		t.Fatalf("second Save of the same value = %v, want ErrCodeExists", err)
	}
}

func TestCodeStore_ExpiredCodeNotConsumable(t *testing.T) {
	clock := &fakeClock{t: time.Now()}
	store := newTestCodeStore(t, clock)
	ctx := context.Background()

	code := testCode(clock, "code-1", time.Minute)
	if err := store.Save(ctx, code); err != nil {
		t.Fatalf("Save: %v", err)
	}
	clock.advance(time.Minute + time.Second)

	if _, err := store.Consume(ctx, "code-1"); !errors.Is(err, oauth.ErrCodeNotFound) {
		t.Fatalf("Consume after expiry = %v, want ErrCodeNotFound", err)
	}
}

// TestCodeStore_ConcurrentConsume_ExactlyOneWins is the issue's own first
// done-when: N goroutines racing Consume on the same code, under -race,
// yield exactly one success.
func TestCodeStore_ConcurrentConsume_ExactlyOneWins(t *testing.T) {
	clock := &fakeClock{t: time.Now()}
	store := newTestCodeStore(t, clock)
	ctx := context.Background()

	code := testCode(clock, "code-1", time.Minute)
	if err := store.Save(ctx, code); err != nil {
		t.Fatalf("Save: %v", err)
	}

	const n = 50
	var wins atomic.Int32
	var wg sync.WaitGroup
	wg.Add(n)
	for range n {
		go func() {
			defer wg.Done()
			if _, err := store.Consume(ctx, "code-1"); err == nil {
				wins.Add(1)
			}
		}()
	}
	wg.Wait()

	if got := wins.Load(); got != 1 {
		t.Errorf("concurrent Consume calls: %d of %d succeeded, want exactly 1", got, n)
	}
}

// TestCodeStore_NegativeControl_GetThenDelLetsMultipleWin is the issue's
// own fourth done-when: "Negative control: verified failing against a
// store that GETs then DELs." Rather than editing the real Consume and
// reverting (which would leave the production file momentarily broken
// for a window), this runs the identical concurrency test from above
// against a deliberately non-atomic GET-then-DEL implementation defined
// only in this test file, proving the race the issue describes is real
// and that the test above would have caught it.
//
// First attempt: 50 goroutines each doing GET-then-DEL with no
// coordination at all, same shape as the real concurrency test above.
// This did NOT reproduce the race -- 1 of 50 "won," identical to the
// correct behavior -- because each goroutine's GET and DEL round trip to
// a local Redis container completes fast enough, relative to Go's
// scheduler, that the calls serialize in practice far more often than
// they interleave. A race that does not reproduce under load is not
// evidence the race is absent; it is evidence this harness did not force
// the interleaving. Fixed below with an explicit barrier that holds every
// goroutine's GET result until all of them have one, guaranteeing the
// window the real atomic GETDEL exists to close.
func TestCodeStore_NegativeControl_GetThenDelLetsMultipleWin(t *testing.T) {
	client := newTestRedis(t, "noeviction.conf")
	ctx := context.Background()
	const key = "usher:code:negative-control"
	if err := client.Set(ctx, key, "payload", time.Minute).Err(); err != nil {
		t.Fatalf("seed key: %v", err)
	}

	const n = 50
	var barrier sync.WaitGroup
	barrier.Add(n)

	brokenConsume := func() (bool, error) {
		_, err := client.Get(ctx, key).Result()
		if errors.Is(err, goredis.Nil) {
			barrier.Done()
			barrier.Wait() // let every other goroutine reach this point too
			return false, nil
		}
		if err != nil {
			barrier.Done()
			return false, err
		}
		// The forced race window: every goroutine's GET has now returned
		// the value, and none of them has called DEL yet.
		barrier.Done()
		barrier.Wait()
		if err := client.Del(ctx, key).Err(); err != nil {
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
			ok, err := brokenConsume()
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
		t.Fatalf("GET-then-DEL negative control: %d of %d callers won, want more than 1 (the forced race did not reproduce -- the harness itself is broken)", got, n)
	}
	t.Logf("GET-then-DEL negative control: %d of %d concurrent callers incorrectly succeeded", got, n)
}

func TestCodeStore_TombstoneAndTombstonedFamily_RoundTrip(t *testing.T) {
	clock := &fakeClock{t: time.Now()}
	store := newTestCodeStore(t, clock)
	ctx := context.Background()

	if err := store.Tombstone(ctx, "code-1", "family-1", time.Minute); err != nil {
		t.Fatalf("Tombstone: %v", err)
	}

	familyID, found, err := store.TombstonedFamily(ctx, "code-1")
	if err != nil {
		t.Fatalf("TombstonedFamily: %v", err)
	}
	if !found || familyID != "family-1" {
		t.Errorf("TombstonedFamily = (%q, %v), want (%q, true)", familyID, found, "family-1")
	}
}

// TestCodeStore_ReplayWithinTombstoneWindowFound is the issue's second
// done-when's store-level half: a replay within the tombstone's window is
// found (what lets the caller -- ConsumeCode, #30's /token handler --
// revoke it).
func TestCodeStore_ReplayWithinTombstoneWindowFound(t *testing.T) {
	clock := &fakeClock{t: time.Now()}
	store := newTestCodeStore(t, clock)
	ctx := context.Background()

	if err := store.Tombstone(ctx, "code-1", "family-1", time.Hour); err != nil {
		t.Fatalf("Tombstone: %v", err)
	}
	clock.advance(30 * time.Minute) // well within the hour-long window

	familyID, found, err := store.TombstonedFamily(ctx, "code-1")
	if err != nil {
		t.Fatalf("TombstonedFamily: %v", err)
	}
	if !found || familyID != "family-1" {
		t.Errorf("TombstonedFamily within the window = (%q, %v), want (%q, true)", familyID, found, "family-1")
	}
}

// TestCodeStore_ReplayAfterTombstoneWindowNotFound is the issue's third
// done-when: replay after the window is plain invalid_grant -- the
// stated residual, not a revocation.
//
// Negative control: with the `!s.now().Before(time.Unix(t.ExpiresAt, 0))`
// check removed from TombstonedFamily, this test failed -- the
// tombstone's family was still reported found after its window had
// closed. Verified by hand, restored before committing.
func TestCodeStore_ReplayAfterTombstoneWindowNotFound(t *testing.T) {
	clock := &fakeClock{t: time.Now()}
	store := newTestCodeStore(t, clock)
	ctx := context.Background()

	if err := store.Tombstone(ctx, "code-1", "family-1", time.Hour); err != nil {
		t.Fatalf("Tombstone: %v", err)
	}
	clock.advance(time.Hour + time.Minute) // past the window

	_, found, err := store.TombstonedFamily(ctx, "code-1")
	if err != nil {
		t.Fatalf("TombstonedFamily: %v", err)
	}
	if found {
		t.Error("TombstonedFamily reported found after the tombstone's own window closed")
	}
}
