//go:build integration

package redis

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/JonasBorgesLM/usher/internal/session"
)

// fakeClock is a settable clock for the idle/absolute expiry tests —
// REQUIREMENTS §10 and issue #19's own wording both ask for one, rather
// than waiting out a real TTL.
type fakeClock struct{ t time.Time }

func (c *fakeClock) now() time.Time          { return c.t }
func (c *fakeClock) advance(d time.Duration) { c.t = c.t.Add(d) }

func newTestSessionStore(t *testing.T, clock *fakeClock, idleTTL, absoluteTTL time.Duration) *SessionStore {
	t.Helper()
	client := newTestRedis(t, "noeviction.conf")
	return NewSessionStore(client, idleTTL, absoluteTTL, WithSessionClock(clock.now))
}

func TestSessionStore_SaveAndGet_RoundTrip(t *testing.T) {
	clock := &fakeClock{t: time.Now()}
	store := newTestSessionStore(t, clock, time.Hour, 24*time.Hour)
	ctx := context.Background()

	sess := session.BrowserSession{
		ID: "raw-session-id-1", Subject: "alice@example.com",
		AuthTime: clock.now(), IdleUntil: clock.now().Add(time.Hour), ExpiresAt: clock.now().Add(24 * time.Hour),
	}
	if err := store.Save(ctx, sess); err != nil {
		t.Fatalf("Save: %v", err)
	}

	got, err := store.Get(ctx, "raw-session-id-1")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Subject != "alice@example.com" {
		t.Errorf("Get: got %+v", got)
	}
}

// TestSessionStore_IdleExpiry is the issue's own wording, with a fake
// clock: a session that has not been used within its idle window is
// refused, even though its absolute lifetime has not passed.
//
// Negative control: with the `now.After(sess.IdleUntil)` half of Get's
// check removed, this test failed to observe an error — verified by hand,
// restored before committing.
func TestSessionStore_IdleExpiry(t *testing.T) {
	clock := &fakeClock{t: time.Now()}
	store := newTestSessionStore(t, clock, 30*time.Minute, 24*time.Hour)
	ctx := context.Background()

	sess := session.BrowserSession{
		ID: "idle-expiry-id", Subject: "alice@example.com",
		AuthTime: clock.now(), IdleUntil: clock.now().Add(30 * time.Minute), ExpiresAt: clock.now().Add(24 * time.Hour),
	}
	if err := store.Save(ctx, sess); err != nil {
		t.Fatalf("Save: %v", err)
	}

	clock.advance(31 * time.Minute) // past idle, well within absolute

	if _, err := store.Get(ctx, "idle-expiry-id"); err != session.ErrSessionNotFound {
		t.Fatalf("Get after idle expiry = %v, want ErrSessionNotFound", err)
	}
}

// TestSessionStore_AbsoluteExpiry is the same property for the other
// lifetime, isolated from it: the idle window (24h) is deliberately far
// longer than the absolute one (1h) and Get is called only once, so
// there is no idle-window extension anywhere in this test to also explain
// a refusal — only ExpiresAt can.
//
// An earlier version of this test called Get in a loop with a short idle
// window, expecting to isolate the absolute check the same way — it did
// not: Get's own IdleUntil-extension is capped at ExpiresAt, so once the
// idle window had been extended even once, the capped IdleUntil made the
// *idle* check alone refuse the session too, and removing the absolute
// check from Get did not make that version of the test fail. Rewritten to
// this shape instead of leaving the non-isolating version in place;
// recorded for the same reason the wrong controls in #16 and #18 were.
//
// Negative control (against this version): with the
// `now.After(sess.ExpiresAt)` half of Get's check removed, this test still
// failed — but via a different, wrapped error from Save's own ttl<=0
// guard when Get tried to re-persist the extended idle window, not the
// bare ErrSessionNotFound this test expects. A confusing failure mode is
// still a failure: the assertion below correctly rejected it. Verified by
// hand, restored before committing.
func TestSessionStore_AbsoluteExpiry(t *testing.T) {
	clock := &fakeClock{t: time.Now()}
	store := newTestSessionStore(t, clock, 24*time.Hour, time.Hour)
	ctx := context.Background()

	sess := session.BrowserSession{
		ID: "absolute-expiry-id", Subject: "alice@example.com",
		AuthTime: clock.now(), IdleUntil: clock.now().Add(24 * time.Hour), ExpiresAt: clock.now().Add(time.Hour),
	}
	if err := store.Save(ctx, sess); err != nil {
		t.Fatalf("Save: %v", err)
	}

	clock.advance(70 * time.Minute) // past the 1h absolute deadline, nowhere near the 24h idle window

	if _, err := store.Get(ctx, "absolute-expiry-id"); err != session.ErrSessionNotFound {
		t.Fatalf("Get past the absolute deadline = %v, want ErrSessionNotFound", err)
	}
}

// TestSessionStore_LogoutRefusesReplay is the issue's own wording: after
// Delete, the old session id is refused even if presented again.
func TestSessionStore_LogoutRefusesReplay(t *testing.T) {
	clock := &fakeClock{t: time.Now()}
	store := newTestSessionStore(t, clock, time.Hour, 24*time.Hour)
	ctx := context.Background()

	sess := session.BrowserSession{
		ID: "logout-id", Subject: "alice@example.com",
		AuthTime: clock.now(), IdleUntil: clock.now().Add(time.Hour), ExpiresAt: clock.now().Add(24 * time.Hour),
	}
	if err := store.Save(ctx, sess); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if err := store.Delete(ctx, "logout-id"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := store.Get(ctx, "logout-id"); err != session.ErrSessionNotFound {
		t.Fatalf("Get after Delete (replay) = %v, want ErrSessionNotFound", err)
	}
}

// TestSessionStore_DumpHoldsNoUsableSessionID is RS-31's parallel to
// RS-10: a full dump of every key and value this store ever wrote must not
// contain the raw session id anywhere — only its SHA-256, via the key, is
// ever persisted.
//
// Negative control: with SessionStore.key changed to return rawID
// unhashed, this test failed — the raw id appeared as the Redis key
// itself. Verified by hand, restored before committing.
func TestSessionStore_DumpHoldsNoUsableSessionID(t *testing.T) {
	clock := &fakeClock{t: time.Now()}
	client := newTestRedis(t, "noeviction.conf")
	store := NewSessionStore(client, time.Hour, 24*time.Hour, WithSessionClock(clock.now))
	ctx := context.Background()

	const rawID = "super-secret-raw-session-id-nobody-should-see-in-a-dump"
	sess := session.BrowserSession{
		ID: rawID, Subject: "alice@example.com",
		AuthTime: clock.now(), IdleUntil: clock.now().Add(time.Hour), ExpiresAt: clock.now().Add(24 * time.Hour),
	}
	if err := store.Save(ctx, sess); err != nil {
		t.Fatalf("Save: %v", err)
	}

	keys, err := client.Keys(ctx, "*").Result()
	if err != nil {
		t.Fatalf("KEYS *: %v", err)
	}
	if len(keys) == 0 {
		t.Fatal("no keys found after Save — test fixture is broken")
	}
	for _, key := range keys {
		if strings.Contains(key, rawID) {
			t.Errorf("raw session id appears in a Redis key: %q", key)
		}
		values, err := client.HGetAll(ctx, key).Result()
		if err != nil {
			t.Fatalf("HGETALL %q: %v", key, err)
		}
		for field, value := range values {
			if strings.Contains(value, rawID) {
				t.Errorf("raw session id appears in key %q field %q", key, field)
			}
		}
	}
}
