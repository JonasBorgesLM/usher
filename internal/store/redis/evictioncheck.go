package redis

import (
	"errors"
	"fmt"

	"github.com/JonasBorgesLM/moat/redisstore"
	goredis "github.com/redis/go-redis/v9"
)

// ErrEvictionPolicyUnverified reports that NewRateLimitStore could not
// establish that the server will not evict rate-limit keys under memory
// pressure (RNF-07). "Not verified" covers every outcome redisstore.New can
// return except a positive one — CONFIG disabled, an unreachable server, a
// reply it could not parse — and RNF-05 treats all of them the same way:
// refuse to start, never assume the common (and, for a local container,
// checkable) case is fine.
var ErrEvictionPolicyUnverified = errors.New("redis: eviction policy unverified")

// NewRateLimitStore wraps client in a moat/redisstore.Store for the account
// axis of RS-22's two-axis rate limiting, after confirming the server will
// not evict rate-limit keys under memory pressure. Eviction under any
// policy discards buckets without knowing what they are, and
// preferentially discards the bucket of the client already being throttled
// — making no requests while blocked is the best candidate under any
// recency- or TTL-based policy — which un-throttles exactly the client the
// limiter exists to stop.
//
// This is REQUIREMENTS RNF-07's own example, made real:
//
//	if check := store.EvictionCheck(); !check.Verified() {
//	    return fmt.Errorf("redis eviction policy unverified: %s", check)
//	}
func NewRateLimitStore(client goredis.Scripter, opts ...redisstore.Option) (*redisstore.Store, error) {
	store, err := redisstore.New(client, opts...)
	if err != nil {
		// New itself already refuses when it can positively prove the policy
		// is unsafe (redisstore.ErrUnsafeEvictionPolicy) — wrapped under the
		// same sentinel as the "could not be established at all" case below,
		// so a caller has one error to check regardless of which the server
		// actually did.
		return nil, fmt.Errorf("%w: %w", ErrEvictionPolicyUnverified, err)
	}
	if check := store.EvictionCheck(); !check.Verified() {
		return nil, fmt.Errorf("%w: %s", ErrEvictionPolicyUnverified, check)
	}
	return store, nil
}
