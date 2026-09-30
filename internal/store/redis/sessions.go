package redis

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"time"

	goredis "github.com/redis/go-redis/v9"

	"github.com/JonasBorgesLM/usher/internal/session"
)

// SessionStore implements session.SessionStore over Redis, keyed by the
// SHA-256 of the raw session id (RS-31) — a dump of this store's keys and
// values never contains a usable raw id, the same property RS-10 requires
// of refresh tokens: only the hash is ever written.
type SessionStore struct {
	client      goredis.Cmdable
	keyPrefix   string
	idleTTL     time.Duration
	absoluteTTL time.Duration
	now         func() time.Time
}

var _ session.SessionStore = (*SessionStore)(nil)

// SessionStoreOption configures a SessionStore at construction.
type SessionStoreOption func(*SessionStore)

// WithSessionClock overrides the store's clock — the injection point that
// makes idle and absolute expiry testable without a real clock.
func WithSessionClock(now func() time.Time) SessionStoreOption {
	return func(s *SessionStore) { s.now = now }
}

// WithSessionKeyPrefix overrides the default Redis key prefix.
func WithSessionKeyPrefix(prefix string) SessionStoreOption {
	return func(s *SessionStore) { s.keyPrefix = prefix }
}

// NewSessionStore builds a SessionStore enforcing idleTTL and absoluteTTL
// (RF-12) on every session it stores.
func NewSessionStore(client goredis.Cmdable, idleTTL, absoluteTTL time.Duration, opts ...SessionStoreOption) *SessionStore {
	s := &SessionStore{
		client: client, keyPrefix: "usher:session:",
		idleTTL: idleTTL, absoluteTTL: absoluteTTL, now: time.Now,
	}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

func (s *SessionStore) key(rawID string) string {
	sum := sha256.Sum256([]byte(rawID))
	return s.keyPrefix + hex.EncodeToString(sum[:])
}

// Save implements session.SessionStore. The Redis key's own TTL is set to
// the session's absolute remaining lifetime — a physical backstop, not the
// enforcement mechanism: Get's own idle/absolute check (against s.now, not
// Redis's clock) is what actually decides whether a session is still
// valid, which is what makes both lifetimes testable with a fake clock
// regardless of how Redis itself is configured.
func (s *SessionStore) Save(ctx context.Context, sess session.BrowserSession) error {
	ttl := sess.ExpiresAt.Sub(s.now())
	if ttl <= 0 {
		return fmt.Errorf("redis: save session: already past its absolute expiry (%s)", sess.ExpiresAt)
	}
	key := s.key(sess.ID)
	if err := s.client.HSet(ctx, key,
		"subject", sess.Subject,
		"auth_time", sess.AuthTime.Unix(),
		"idle_until", sess.IdleUntil.Unix(),
		"expires_at", sess.ExpiresAt.Unix(),
	).Err(); err != nil {
		return fmt.Errorf("redis: save session: %w", err)
	}
	if err := s.client.Expire(ctx, key, ttl).Err(); err != nil {
		return fmt.Errorf("redis: set session ttl: %w", err)
	}
	return nil
}

// Get implements session.SessionStore: looks up by the SHA-256 of rawID,
// refuses a session past either lifetime (RF-12) against s.now — not
// Redis's own TTL, which is a backstop and not consulted here — and, for a
// session that is still valid, extends IdleUntil, capped at ExpiresAt so a
// session near its absolute deadline does not get a fresh idle window past
// it.
func (s *SessionStore) Get(ctx context.Context, rawID string) (session.BrowserSession, error) {
	data, err := s.client.HGetAll(ctx, s.key(rawID)).Result()
	if err != nil {
		return session.BrowserSession{}, fmt.Errorf("redis: get session: %w", err)
	}
	if len(data) == 0 {
		return session.BrowserSession{}, session.ErrSessionNotFound
	}
	sess, err := decodeSession(rawID, data)
	if err != nil {
		return session.BrowserSession{}, err
	}

	now := s.now()
	if now.After(sess.IdleUntil) || now.After(sess.ExpiresAt) {
		return session.BrowserSession{}, session.ErrSessionNotFound
	}

	newIdle := now.Add(s.idleTTL)
	if newIdle.After(sess.ExpiresAt) {
		newIdle = sess.ExpiresAt
	}
	sess.IdleUntil = newIdle
	if err := s.Save(ctx, sess); err != nil {
		return session.BrowserSession{}, err
	}
	return sess, nil
}

// Delete implements session.SessionStore.
func (s *SessionStore) Delete(ctx context.Context, rawID string) error {
	if err := s.client.Del(ctx, s.key(rawID)).Err(); err != nil {
		return fmt.Errorf("redis: delete session: %w", err)
	}
	return nil
}

var errMissingField = errors.New("redis: session record missing a field")

func decodeSession(rawID string, data map[string]string) (session.BrowserSession, error) {
	authTime, err := parseUnixField(data, "auth_time")
	if err != nil {
		return session.BrowserSession{}, err
	}
	idleUntil, err := parseUnixField(data, "idle_until")
	if err != nil {
		return session.BrowserSession{}, err
	}
	expiresAt, err := parseUnixField(data, "expires_at")
	if err != nil {
		return session.BrowserSession{}, err
	}
	return session.BrowserSession{
		ID:        rawID,
		Subject:   data["subject"],
		AuthTime:  authTime,
		IdleUntil: idleUntil,
		ExpiresAt: expiresAt,
	}, nil
}

func parseUnixField(data map[string]string, field string) (time.Time, error) {
	raw, ok := data[field]
	if !ok {
		return time.Time{}, fmt.Errorf("%w: %s", errMissingField, field)
	}
	sec, err := strconv.ParseInt(raw, 10, 64)
	if err != nil {
		return time.Time{}, fmt.Errorf("redis: decode session %s: %w", field, err)
	}
	return time.Unix(sec, 0), nil
}
