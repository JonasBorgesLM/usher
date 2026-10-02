package redis

import (
	"context"
	"fmt"
	"time"

	goredis "github.com/redis/go-redis/v9"

	"github.com/JonasBorgesLM/usher/internal/proxy"
)

// Denylist implements proxy.Denylist over Redis (REQUIREMENTS §7.1,
// ADR-0014): one key per revoked access token's jti, with Redis's own
// TTL set to the token's remaining lifetime — past that TTL the token
// would have expired on its own anyway, so there is nothing left worth
// denying. Written by cmd/usher's /revoke handler (#38); read by the
// gateway's own proxy.NewHandler, not yet implemented (M6) — this store
// is the one place both sides of that boundary meet, over Redis rather
// than a shared Go type, the same way every other cross-boundary state
// in this project does (ADR-0001).
type Denylist struct {
	client    goredis.Cmdable
	keyPrefix string
}

var _ proxy.Denylist = (*Denylist)(nil)

// DenylistOption configures a Denylist at construction.
type DenylistOption func(*Denylist)

// WithDenylistKeyPrefix overrides the default Redis key prefix.
func WithDenylistKeyPrefix(prefix string) DenylistOption {
	return func(d *Denylist) { d.keyPrefix = prefix }
}

// NewDenylist builds a Denylist.
func NewDenylist(client goredis.Cmdable, opts ...DenylistOption) *Denylist {
	d := &Denylist{client: client, keyPrefix: "usher:denylist:"}
	for _, opt := range opts {
		opt(d)
	}
	return d
}

func (d *Denylist) key(jti string) string { return d.keyPrefix + jti }

// Add implements proxy.Denylist. ttl <= 0 is a documented no-op, not an
// error: it means the access token's own exp has already passed (or is
// passing right now), so there is no window left for the gateway to
// shorten — the token's own expiry already excludes it by the time any
// request could present it.
func (d *Denylist) Add(ctx context.Context, jti string, ttl time.Duration) error {
	if ttl <= 0 {
		return nil
	}
	if err := d.client.Set(ctx, d.key(jti), "1", ttl).Err(); err != nil {
		return fmt.Errorf("redis: add to denylist: %w", err)
	}
	return nil
}

// Contains implements proxy.Denylist.
func (d *Denylist) Contains(ctx context.Context, jti string) (bool, error) {
	n, err := d.client.Exists(ctx, d.key(jti)).Result()
	if err != nil {
		return false, fmt.Errorf("redis: check denylist: %w", err)
	}
	return n > 0, nil
}
