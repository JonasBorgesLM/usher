// Package audit defines the event schema RF-09 requires and the Emitter
// interface that delivers it. The event schema is versioned so a consumer
// (crier, RI-03) evolves independently of this project's Go types.
package audit

import (
	"context"
	"time"
)

// EventType names what happened.
type EventType string

// The event types RF-09 and the flows in docs/ARCHITECTURE.md emit.
const (
	EventLoginAttempt    EventType = "login_attempt"
	EventConsentGranted  EventType = "consent_granted"
	EventTokenIssued     EventType = "token_issued"
	EventRefreshReuse    EventType = "refresh_reuse_detected"
	EventCodeReplay      EventType = "code_replay_detected" // RS-04's sibling to EventRefreshReuse
	EventRevocation      EventType = "revocation"
	EventRateLimited     EventType = "rate_limited"
	EventGatewayRejected EventType = "gateway_rejected"
)

// Outcome is whether the attempt the Event describes succeeded.
type Outcome string

// The two outcomes an Event records.
const (
	OutcomeSuccess Outcome = "success"
	OutcomeFailure Outcome = "failure"
)

// Event is one audit record.
type Event struct {
	SchemaVersion int
	Type          EventType
	Outcome       Outcome
	Subject       string // canonicalized (RS-35) or ""
	ClientID      string
	RequestID     string
	SourceAddr    string
	Detail        map[string]string // caller's contract: never a secret (RS-23) — Emit does not scan for one
	At            time.Time
}

// Emitter accepts an Event for delivery. Emit must never block its caller on
// a slow or unreachable sink — the bounded buffer and the drop counting
// (ADR-0017) live inside the crier-backed implementation, not in this
// interface, so a test double can be a synchronous slice with no such
// concern.
//
// EventRefreshReuse and EventCodeReplay are emitted in addition to, never
// instead of, the RevokedReason written on the oauth.Family row in the same
// transaction that revokes it (ADR-0017) — the row is what survives if an
// Emitter implementation cannot deliver.
type Emitter interface {
	Emit(ctx context.Context, e Event)
}
