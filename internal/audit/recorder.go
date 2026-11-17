package audit

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"time"
)

// Record is one event recorded through a Recorder (ADR-0023). It carries
// what an Event does, minus the free-form Detail: a record is evidence, kept
// for as long as the log exists, and a free-form map is where a secret or a
// person's data would slip in unnoticed.
type Record struct {
	// ID identifies the action, not the attempt to record it: generate it
	// with NewRecordID before the action, and reuse it on every retry, so a
	// retry after an unknown outcome is recorded once.
	ID      string
	Type    EventType
	Outcome Outcome
	// Subject is the canonical login identifier (RS-35), or "". A Recorder
	// never stores it in clear: the tally adapter replaces it with a random
	// SubjectRef from its vault (ADR-0023, Decision 3).
	Subject  string
	ClientID string
	// SourceAddr is the client's address, or "". It is personal data, so a
	// Recorder stores it only sealed under the subject's key, and drops it
	// when there is no subject to seal it for.
	SourceAddr string
	At         time.Time
}

// Recorder records a Record durably before returning (ADR-0023). A nil
// error means the record is stored; any other error means it may not be,
// and the caller applies ADR-0023's policy for the action's direction of
// privilege: deny a grant, execute a reduction and retry its record with the
// same ID.
//
// Unlike Emitter, Record blocks for as long as one durable append takes,
// and reports failure. The two are separate ports with separate contracts
// on purpose (ADR-0023, the alternatives rejected).
type Recorder interface {
	Record(ctx context.Context, r Record) error
}

// NewRecordID returns a fresh random ID for a Record: 128 bits, hex.
func NewRecordID() string {
	var b [16]byte
	_, _ = rand.Read(b[:]) // crypto/rand.Read never returns an error (Go 1.24+)
	return hex.EncodeToString(b[:])
}
