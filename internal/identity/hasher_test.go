package identity

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestNewHasher_RejectsNonPositiveInputs(t *testing.T) {
	if _, err := NewHasher(0, time.Second, weakParams, 1<<30); err == nil {
		t.Error("NewHasher succeeded with 0 slots; want an error")
	}
	if _, err := NewHasher(1, 0, weakParams, 1<<30); err == nil {
		t.Error("NewHasher succeeded with a zero wait; want an error")
	}
}

// TestNewHasher_RefusesOverBudget is RS-33's own startup check: slots *
// Memory above the configured ceiling refuses construction rather than
// starting a process that can be pushed past its memory budget by fifty
// concurrent login attempts.
//
// Negative control: with the budget check removed, this test failed to
// observe an error — verified by hand, restored before committing.
func TestNewHasher_RefusesOverBudget(t *testing.T) {
	params := Params{Memory: 64 * 1024, Iterations: 1, Parallelism: 1, SaltLength: 16, KeyLength: 32} // 64 MiB
	const slots = 50
	// 50 * 64 MiB = 3200 MiB, comfortably over a 1 GiB ceiling.
	_, err := NewHasher(slots, time.Second, params, 1<<20 /* 1 GiB in KiB */)
	if !errors.Is(err, ErrHashingBudgetExceeded) {
		t.Fatalf("NewHasher(%d slots, 64 MiB, 1 GiB ceiling) = %v, want ErrHashingBudgetExceeded", slots, err)
	}
}

func TestNewHasher_AcceptsInBudget(t *testing.T) {
	params := Params{Memory: 64 * 1024, Iterations: 1, Parallelism: 1, SaltLength: 16, KeyLength: 32}
	if _, err := NewHasher(8, time.Second, params, 1<<20); err != nil {
		t.Fatalf("NewHasher(8 slots, 64 MiB, 1 GiB ceiling) = %v, want success", err)
	}
}

// blockingHasher builds a Hasher whose hashFn/verifyFn signal on acquired
// when entered and block on release until it is closed — giving the test
// precise control over how long a slot stays held, instead of depending on
// real Argon2id timing.
func blockingHasher(t *testing.T, slots int, wait time.Duration) (h *Hasher, acquired, release chan struct{}) {
	t.Helper()
	h, err := NewHasher(slots, wait, weakParams, 1<<30)
	if err != nil {
		t.Fatalf("NewHasher: %v", err)
	}
	acquired = make(chan struct{}, slots+1)
	release = make(chan struct{})
	block := func() (bool, error) {
		acquired <- struct{}{}
		<-release
		return true, nil
	}
	h.verifyFn = func(password, encoded string) (bool, error) { return block() }
	h.hashFn = func(password string, params Params) (string, error) { _, err := block(); return "", err }
	return h, acquired, release
}

// TestHasher_NPlus1Saturates is the issue's own scenario: with N slots
// held, the N+1th call waits, then gets ErrSaturated once the bounded wait
// elapses — not immediately, and not indefinitely.
//
// Negative control: with acquire's timeout branch removed (a plain blocking
// send on h.sem), this test was run and hung past its own deadline instead
// of observing ErrSaturated — verified by hand, restored before committing.
func TestHasher_NPlus1Saturates(t *testing.T) {
	const slots = 2
	const wait = 80 * time.Millisecond
	h, acquired, release := blockingHasher(t, slots, wait)
	defer close(release)

	for i := 0; i < slots; i++ {
		go func() { _, _ = h.Verify(context.Background(), "x", "y") }()
	}
	for i := 0; i < slots; i++ {
		<-acquired // wait until both slots are genuinely held, not just started
	}

	start := time.Now()
	_, err := h.Verify(context.Background(), "x", "y")
	elapsed := time.Since(start)

	if !errors.Is(err, ErrSaturated) {
		t.Fatalf("Verify with all slots held = %v, want ErrSaturated", err)
	}
	if elapsed < wait {
		t.Errorf("Verify returned after %s, before its %s wait elapsed", elapsed, wait)
	}
	if elapsed > 5*wait {
		t.Errorf("Verify returned after %s, far past its %s wait — the timeout is not bounding it tightly", elapsed, wait)
	}
}

func TestHasher_SlotFreesForTheNextCaller(t *testing.T) {
	const slots = 1
	h, acquired, release := blockingHasher(t, slots, 200*time.Millisecond)

	done := make(chan error, 1)
	go func() { _, err := h.Verify(context.Background(), "x", "y"); done <- err }()
	<-acquired
	close(release) // let the first call finish and free its slot

	if err := <-done; err != nil {
		t.Fatalf("first Verify: %v", err)
	}

	// The slot must be free again now — a second call should not need to
	// wait at all.
	h2, err := NewHasher(slots, 50*time.Millisecond, weakParams, 1<<30)
	if err != nil {
		t.Fatalf("NewHasher: %v", err)
	}
	if _, err := h2.Verify(context.Background(), "x", encodedForVerify(t)); err != nil {
		t.Fatalf("Verify on a fresh Hasher with a free slot: %v", err)
	}
}

// encodedForVerify returns a real, valid PHC hash for tests that call the
// real (non-injected) VerifyPassword and need something well-formed to
// check against.
func encodedForVerify(t *testing.T) string {
	t.Helper()
	encoded, err := HashPassword("x", weakParams)
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	return encoded
}

// TestHasher_SaturationIdenticalForRealAndDummyHash is RS-14 extended to the
// saturation path (issue #15's own wording: "the saturation path must do
// equal work for existing and non-existent accounts, or the queue becomes
// the enumeration oracle RS-14 closed"). acquire runs before verifyFn is
// ever called, so which encoded string is passed cannot affect whether or
// how long a caller waits — this test asserts that property rather than
// leaving it implied by the code's shape.
func TestHasher_SaturationIdenticalForRealAndDummyHash(t *testing.T) {
	const wait = 60 * time.Millisecond
	realHash := "$argon2id$v=19$m=8192,t=1,p=1$cmVhbC1zYWx0$cmVhbC1oYXNo"      // #nosec G101 -- fixture
	dummyHash := "$argon2id$v=19$m=8192,t=1,p=1$ZHVtbXktc2FsdA$ZHVtbXktaGFzaA" // #nosec G101 -- fixture

	measure := func(encoded string) (time.Duration, error) {
		h, acquired, release := blockingHasher(t, 1, wait)
		go func() { _, _ = h.Verify(context.Background(), "occupying", "y") }()
		<-acquired
		defer close(release)

		start := time.Now()
		_, err := h.Verify(context.Background(), "x", encoded)
		return time.Since(start), err
	}

	realElapsed, realErr := measure(realHash)
	dummyElapsed, dummyErr := measure(dummyHash)

	if !errors.Is(realErr, ErrSaturated) || !errors.Is(dummyErr, ErrSaturated) {
		t.Fatalf("errors differ: real=%v dummy=%v, want ErrSaturated for both", realErr, dummyErr)
	}
	diff := realElapsed - dummyElapsed
	if diff < 0 {
		diff = -diff
	}
	if diff > wait/2 {
		t.Errorf("saturation timing differs by %s between a real and a dummy hash (real=%s, dummy=%s) — the wait should not depend on which was passed",
			diff, realElapsed, dummyElapsed)
	}
}
