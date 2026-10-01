package audit

import (
	"context"
	"sync"
)

// MemorySink is the in-process sink ADR-0017 calls for: a way to observe
// emitted events in a test without a running crier. It never drops — the
// bounded buffer and drop accounting are CrierEmitter's concern, not every
// Emitter's.
type MemorySink struct {
	mu     sync.Mutex
	events []Event
}

// NewMemorySink returns an empty sink.
func NewMemorySink() *MemorySink { return &MemorySink{} }

// Emit appends e. Safe for concurrent use, since a real handler path may
// call it from more than one request goroutine.
func (s *MemorySink) Emit(_ context.Context, e Event) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.events = append(s.events, e)
}

// Events returns a snapshot of every event Emit has recorded, oldest first.
func (s *MemorySink) Events() []Event {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Event, len(s.events))
	copy(out, s.events)
	return out
}
