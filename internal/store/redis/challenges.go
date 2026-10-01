package redis

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	goredis "github.com/redis/go-redis/v9"

	"github.com/JonasBorgesLM/usher/internal/session"
)

// ChallengeStore implements session.ChallengeStore over Redis. Unlike
// SessionStore and RefreshToken (RS-31, RS-10), nothing in RS-05 asks for
// the challenge id to be hashed at rest: holding a live, unconsumed
// challenge id grants whatever the /authorize request that minted it
// already granted (a client_id, redirect_uri and scope it already passed
// RS-28's own validation for) and nothing more — unlike a session or
// refresh token, it is not itself a bearer credential for an authenticated
// identity. Stored as a single JSON string value per id, not a hash, so
// Consume can be one atomic GETDEL round trip (RS-05's single-use,
// matching CodeStore.Consume's own doc comment on this exact choice).
type ChallengeStore struct {
	client    goredis.Cmdable
	keyPrefix string
	now       func() time.Time
}

var _ session.ChallengeStore = (*ChallengeStore)(nil)

// ChallengeStoreOption configures a ChallengeStore at construction.
type ChallengeStoreOption func(*ChallengeStore)

// WithChallengeClock overrides the store's clock — the injection point
// that makes expiry (RF-12) testable without a real clock.
func WithChallengeClock(now func() time.Time) ChallengeStoreOption {
	return func(s *ChallengeStore) { s.now = now }
}

// WithChallengeKeyPrefix overrides the default Redis key prefix.
func WithChallengeKeyPrefix(prefix string) ChallengeStoreOption {
	return func(s *ChallengeStore) { s.keyPrefix = prefix }
}

// NewChallengeStore builds a ChallengeStore.
func NewChallengeStore(client goredis.Cmdable, opts ...ChallengeStoreOption) *ChallengeStore {
	s := &ChallengeStore{client: client, keyPrefix: "usher:challenge:", now: time.Now}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

func (s *ChallengeStore) key(id string) string {
	return s.keyPrefix + id
}

// challengeJSON is the on-the-wire shape saved to Redis. A separate type
// from session.Challenge, the same way sessions.go keeps Redis encoding
// decisions out of the domain type: this project's convention is that
// internal/session declares the contract and internal/store/redis owns
// its own serialization choices against it.
type challengeJSON struct {
	ID            string   `json:"id"`
	ClientID      string   `json:"client_id"`
	RedirectURI   string   `json:"redirect_uri"`
	Scope         []string `json:"scope"`
	State         string   `json:"state"`
	CodeChallenge string   `json:"code_challenge"`
	Nonce         string   `json:"nonce"`
	Subject       string   `json:"subject"`
	ExpiresAt     int64    `json:"expires_at"` // Unix seconds
}

func encodeChallenge(c session.Challenge) challengeJSON {
	return challengeJSON{
		ID: c.ID, ClientID: c.ClientID, RedirectURI: c.RedirectURI,
		Scope: c.Scope, State: c.State, CodeChallenge: c.CodeChallenge,
		Nonce: c.Nonce, Subject: c.Subject, ExpiresAt: c.ExpiresAt.Unix(),
	}
}

func decodeChallenge(data string) (session.Challenge, error) {
	var j challengeJSON
	if err := json.Unmarshal([]byte(data), &j); err != nil {
		return session.Challenge{}, fmt.Errorf("redis: decode challenge: %w", err)
	}
	return session.Challenge{
		ID: j.ID, ClientID: j.ClientID, RedirectURI: j.RedirectURI,
		Scope: j.Scope, State: j.State, CodeChallenge: j.CodeChallenge,
		Nonce: j.Nonce, Subject: j.Subject, ExpiresAt: time.Unix(j.ExpiresAt, 0),
	}, nil
}

// Save implements session.ChallengeStore. The Redis key's own TTL is a
// physical backstop, not the enforcement mechanism — Get's and Consume's
// own expiry check against s.now() (not Redis's clock) is what actually
// decides validity, the same reasoning sessions.go's Save documents, and
// what makes RF-12's lifetime testable with a fake clock regardless of
// how Redis itself is configured.
func (s *ChallengeStore) Save(ctx context.Context, c session.Challenge) error {
	ttl := c.ExpiresAt.Sub(s.now())
	if ttl <= 0 {
		return fmt.Errorf("redis: save challenge: already past its expiry (%s)", c.ExpiresAt)
	}
	data, err := json.Marshal(encodeChallenge(c))
	if err != nil {
		return fmt.Errorf("redis: encode challenge: %w", err)
	}
	if err := s.client.Set(ctx, s.key(c.ID), data, ttl).Err(); err != nil {
		return fmt.Errorf("redis: save challenge: %w", err)
	}
	return nil
}

// Get implements session.ChallengeStore: reads without consuming, and
// refuses a challenge past its expiry (RF-12) against s.now(), the same
// "not Redis's own TTL" reasoning as Save.
func (s *ChallengeStore) Get(ctx context.Context, id string) (session.Challenge, error) {
	data, err := s.client.Get(ctx, s.key(id)).Result()
	if errors.Is(err, goredis.Nil) {
		return session.Challenge{}, session.ErrChallengeNotFound
	}
	if err != nil {
		return session.Challenge{}, fmt.Errorf("redis: get challenge: %w", err)
	}
	c, err := decodeChallenge(data)
	if err != nil {
		return session.Challenge{}, err
	}
	if !s.now().Before(c.ExpiresAt) {
		return session.Challenge{}, session.ErrChallengeNotFound
	}
	return c, nil
}

// SetSubject implements session.ChallengeStore: records the authenticated
// subject on a still-pending, still-valid challenge. Reuses Get's own
// existence-and-expiry check rather than duplicating it.
func (s *ChallengeStore) SetSubject(ctx context.Context, id, subject string) error {
	c, err := s.Get(ctx, id)
	if err != nil {
		return err
	}
	c.Subject = subject
	return s.Save(ctx, c)
}

// Consume implements session.ChallengeStore: a single atomic GETDEL,
// RS-05's single-use property made a round trip rather than a
// read-then-delete race (the same shape RS-04 forbids for authorization
// codes, and CodeStore.Consume's own doc comment names GETDEL explicitly
// for this reason). A challenge GETDEL finds already expired is reported
// as not-found, same as Get would: the key is gone either way, but the
// caller should not be able to tell "replayed after use" from "expired
// without ever being used" (RS-25's ambiguity principle, applied here to
// challenge consumption specifically because that is what RS-05's
// single-use property is actually protecting against).
func (s *ChallengeStore) Consume(ctx context.Context, id string) (session.Challenge, error) {
	data, err := s.client.GetDel(ctx, s.key(id)).Result()
	if errors.Is(err, goredis.Nil) {
		return session.Challenge{}, session.ErrChallengeNotFound
	}
	if err != nil {
		return session.Challenge{}, fmt.Errorf("redis: consume challenge: %w", err)
	}
	c, err := decodeChallenge(data)
	if err != nil {
		return session.Challenge{}, err
	}
	if !s.now().Before(c.ExpiresAt) {
		return session.Challenge{}, session.ErrChallengeNotFound
	}
	return c, nil
}
