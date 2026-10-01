package redis

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	goredis "github.com/redis/go-redis/v9"

	"github.com/JonasBorgesLM/usher/internal/oauth"
)

// CodeStore implements oauth.CodeStore over Redis. A code is stored as a
// single JSON string per value (the same shape ChallengeStore uses, for the
// same reason: nothing in RS-04 asks for it to be hashed at rest the way
// RS-31/RS-10 ask of sessions and refresh tokens — a live code grants only
// what /authorize's own RS-28 validation and RS-01's PKCE binding already
// constrain it to). That shape is what lets Consume be one atomic GETDEL
// round trip — RS-04's whole point, stated in the issue itself: "the
// obvious implementation is the vulnerability," a GET followed by a DEL
// lets two concurrent exchanges of the same code both succeed.
type CodeStore struct {
	client    goredis.Cmdable
	keyPrefix string
	now       func() time.Time
}

var _ oauth.CodeStore = (*CodeStore)(nil)

// CodeStoreOption configures a CodeStore at construction.
type CodeStoreOption func(*CodeStore)

// WithCodeClock overrides the store's clock — the injection point that
// makes both a code's own expiry and a tombstone's window testable
// without a real wait.
func WithCodeClock(now func() time.Time) CodeStoreOption {
	return func(s *CodeStore) { s.now = now }
}

// WithCodeKeyPrefix overrides the default Redis key prefix.
func WithCodeKeyPrefix(prefix string) CodeStoreOption {
	return func(s *CodeStore) { s.keyPrefix = prefix }
}

// NewCodeStore builds a CodeStore.
func NewCodeStore(client goredis.Cmdable, opts ...CodeStoreOption) *CodeStore {
	s := &CodeStore{client: client, keyPrefix: "usher:code:", now: time.Now}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

func (s *CodeStore) codeKey(value string) string      { return s.keyPrefix + value }
func (s *CodeStore) tombstoneKey(value string) string { return s.keyPrefix + "tombstone:" + value }

type codeJSON struct {
	Value         string   `json:"value"`
	ClientID      string   `json:"client_id"`
	RedirectURI   string   `json:"redirect_uri"`
	CodeChallenge string   `json:"code_challenge"`
	Nonce         string   `json:"nonce"`
	Scope         []string `json:"scope"`
	Subject       string   `json:"subject"`
	ExpiresAt     int64    `json:"expires_at"` // Unix seconds
}

func encodeCode(c oauth.Code) codeJSON {
	return codeJSON{
		Value: c.Value, ClientID: c.ClientID, RedirectURI: c.RedirectURI,
		CodeChallenge: c.CodeChallenge, Nonce: c.Nonce, Scope: c.Scope,
		Subject: c.Subject, ExpiresAt: c.ExpiresAt.Unix(),
	}
}

func decodeCode(data string) (oauth.Code, error) {
	var j codeJSON
	if err := json.Unmarshal([]byte(data), &j); err != nil {
		return oauth.Code{}, fmt.Errorf("redis: decode code: %w", err)
	}
	return oauth.Code{
		Value: j.Value, ClientID: j.ClientID, RedirectURI: j.RedirectURI,
		CodeChallenge: j.CodeChallenge, Nonce: j.Nonce, Scope: j.Scope,
		Subject: j.Subject, ExpiresAt: time.Unix(j.ExpiresAt, 0),
	}, nil
}

// Save implements oauth.CodeStore. SetNX, not Set: two Saves racing on the
// same value (which should never happen, since Value comes from
// crypto/rand, but "should never happen" is exactly the class of
// assumption RS-04's own reasoning distrusts) report the collision as
// ErrCodeExists instead of one silently overwriting the other.
func (s *CodeStore) Save(ctx context.Context, c oauth.Code) error {
	ttl := c.ExpiresAt.Sub(s.now())
	if ttl <= 0 {
		return fmt.Errorf("redis: save code: already past its expiry (%s)", c.ExpiresAt)
	}
	data, err := json.Marshal(encodeCode(c))
	if err != nil {
		return fmt.Errorf("redis: encode code: %w", err)
	}
	ok, err := s.client.SetNX(ctx, s.codeKey(c.Value), data, ttl).Result()
	if err != nil {
		return fmt.Errorf("redis: save code: %w", err)
	}
	if !ok {
		return oauth.ErrCodeExists
	}
	return nil
}

// Consume implements oauth.CodeStore: one atomic GETDEL, never a GET
// followed by a DEL. A code GETDEL finds already expired is reported as
// not-found, the same "the key is gone either way" reasoning
// ChallengeStore.Consume documents.
func (s *CodeStore) Consume(ctx context.Context, value string) (oauth.Code, error) {
	data, err := s.client.GetDel(ctx, s.codeKey(value)).Result()
	if errors.Is(err, goredis.Nil) {
		return oauth.Code{}, oauth.ErrCodeNotFound
	}
	if err != nil {
		return oauth.Code{}, fmt.Errorf("redis: consume code: %w", err)
	}
	c, err := decodeCode(data)
	if err != nil {
		return oauth.Code{}, err
	}
	if !s.now().Before(c.ExpiresAt) {
		return oauth.Code{}, oauth.ErrCodeNotFound
	}
	return c, nil
}

type tombstoneJSON struct {
	FamilyID  string `json:"family_id"`
	ExpiresAt int64  `json:"expires_at"` // Unix seconds
}

// Tombstone implements oauth.CodeStore. ttl is relative (the caller's own
// "access token's maximum lifetime"); stored as an absolute expiry against
// s.now(), the same "not Redis's own TTL" reasoning every other store in
// this package uses, so that "replay after the window" is testable with a
// fake clock rather than a real wait. Redis's own EXPIRE is still set, as
// the physical backstop.
func (s *CodeStore) Tombstone(ctx context.Context, value, familyID string, ttl time.Duration) error {
	if ttl <= 0 {
		return fmt.Errorf("redis: tombstone code: ttl must be positive, got %s", ttl)
	}
	data, err := json.Marshal(tombstoneJSON{FamilyID: familyID, ExpiresAt: s.now().Add(ttl).Unix()})
	if err != nil {
		return fmt.Errorf("redis: encode tombstone: %w", err)
	}
	if err := s.client.Set(ctx, s.tombstoneKey(value), data, ttl).Err(); err != nil {
		return fmt.Errorf("redis: tombstone code: %w", err)
	}
	return nil
}

// TombstonedFamily implements oauth.CodeStore. A tombstone past its own
// window is reported as not-found, matching the stated residual (RS-04:
// "a replay after the tombstone expires... is an ordinary invalid_grant
// with no revocation").
func (s *CodeStore) TombstonedFamily(ctx context.Context, value string) (familyID string, found bool, err error) {
	data, getErr := s.client.Get(ctx, s.tombstoneKey(value)).Result()
	if errors.Is(getErr, goredis.Nil) {
		return "", false, nil
	}
	if getErr != nil {
		return "", false, fmt.Errorf("redis: look up code tombstone: %w", getErr)
	}
	var t tombstoneJSON
	if unmarshalErr := json.Unmarshal([]byte(data), &t); unmarshalErr != nil {
		return "", false, fmt.Errorf("redis: decode code tombstone: %w", unmarshalErr)
	}
	if !s.now().Before(time.Unix(t.ExpiresAt, 0)) {
		return "", false, nil
	}
	return t.FamilyID, true, nil
}
