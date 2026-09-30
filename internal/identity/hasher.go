package identity

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// Hasher bounds concurrent Argon2id operations to a fixed number of slots
// (RS-33). Argon2id's memory-hardness is what makes offline cracking
// expensive; on an unauthenticated endpoint it is also a memory-exhaustion
// lever without this bound — fifty concurrent attempts at 64 MiB each is
// 3.2 GiB. Hash and Verify share one budget: a real login that triggers a
// rehash and a dummy-hash check for a non-existent user (RS-14) compete for
// the same slots, which is what keeps the saturation path from becoming an
// enumeration oracle — the wait looks the same either way, because the
// semaphore never looks at what it is being asked to hash before deciding
// whether a slot is free.
type Hasher struct {
	sem    chan struct{}
	wait   time.Duration
	params Params

	// hashFn and verifyFn default to HashPassword and VerifyPassword.
	// Unexported and overridable only within this package's own tests, to
	// control how long a slot stays held deterministically instead of
	// depending on real Argon2id timing.
	hashFn   func(password string, params Params) (string, error)
	verifyFn func(password, encoded string) (bool, error)
}

// ErrHashingBudgetExceeded reports that slots * params.Memory exceeds
// ceilingKiB (RS-33) — a construction-time refusal, not a runtime warning.
var ErrHashingBudgetExceeded = errors.New("identity: hashing memory budget exceeds the configured ceiling")

// NewHasher builds a Hasher with slots concurrent slots, each bounded to
// wait for a free slot before giving up, hashing under params. It fails
// with ErrHashingBudgetExceeded if slots * params.Memory exceeds
// ceilingKiB, and with a plain error if slots or wait themselves are not
// positive — a caller wiring this at startup (RNF-05) treats either as a
// reason to refuse to start, not to run degraded.
func NewHasher(slots int, wait time.Duration, params Params, ceilingKiB uint64) (*Hasher, error) {
	if slots <= 0 {
		return nil, fmt.Errorf("identity: hasher concurrency must be positive, got %d", slots)
	}
	if wait <= 0 {
		return nil, fmt.Errorf("identity: hasher saturation wait must be positive, got %s", wait)
	}
	budget := uint64(slots) * uint64(params.Memory)
	if budget > ceilingKiB {
		return nil, fmt.Errorf("%w: %d slots x %d KiB = %d KiB, ceiling is %d KiB",
			ErrHashingBudgetExceeded, slots, params.Memory, budget, ceilingKiB)
	}
	return &Hasher{
		sem: make(chan struct{}, slots), wait: wait, params: params,
		hashFn: HashPassword, verifyFn: VerifyPassword,
	}, nil
}

// ErrSaturated reports that no slot became free within the bounded wait.
// The caller maps this to an HTTP 503 — Hasher itself has no HTTP
// dependency — never to a longer wait or a bypass of the bound.
var ErrSaturated = errors.New("identity: hashing capacity saturated")

// acquire blocks for up to h.wait for a free slot, or returns ErrSaturated.
// A canceled ctx returns ctx.Err() instead — distinct from saturation, since
// the caller going away is not the semaphore being full.
func (h *Hasher) acquire(ctx context.Context) error {
	timer := time.NewTimer(h.wait)
	defer timer.Stop()
	select {
	case h.sem <- struct{}{}:
		return nil
	case <-timer.C:
		return ErrSaturated
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (h *Hasher) release() { <-h.sem }

// Hash hashes password under h's Params, gated by the concurrency bound.
func (h *Hasher) Hash(ctx context.Context, password string) (string, error) {
	if err := h.acquire(ctx); err != nil {
		return "", err
	}
	defer h.release()
	return h.hashFn(password, h.params)
}

// Verify checks password against encoded, gated by the same bound Hash
// uses.
func (h *Hasher) Verify(ctx context.Context, password, encoded string) (bool, error) {
	if err := h.acquire(ctx); err != nil {
		return false, err
	}
	defer h.release()
	return h.verifyFn(password, encoded)
}
