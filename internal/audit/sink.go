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

// MemoryRecorder is Recorder in memory, for tests: it keeps every Record it
// accepts, and fails every Record with Err while Err is set, as a poisoned
// or full log would, so a test can show what an action does when its record
// fails (ADR-0023).
type MemoryRecorder struct {
	mu      sync.Mutex
	records []Record
	err     error
}

// NewMemoryRecorder returns an empty recorder that accepts every Record.
func NewMemoryRecorder() *MemoryRecorder { return &MemoryRecorder{} }

// Record keeps r, or returns the error set by Fail without keeping it.
func (m *MemoryRecorder) Record(_ context.Context, r Record) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.err != nil {
		return m.err
	}
	m.records = append(m.records, r)
	return nil
}

// Fail makes every later Record return err; nil makes them succeed again.
func (m *MemoryRecorder) Fail(err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.err = err
}

// Records returns a snapshot of every Record kept, oldest first.
func (m *MemoryRecorder) Records() []Record {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]Record, len(m.records))
	copy(out, m.records)
	return out
}
