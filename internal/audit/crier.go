// This file's CrierEmitter sends Events to crier's v1 ingestion endpoint
// (crier/receivers/http, crier/ADR-0012: `POST /v1/logs`, Bearer
// "<service>:<token>"), authenticated with usher's own credential (RI-03).
//
// ADR-0017's Amendment decided crier-unreachable behaviour: a bounded
// in-memory buffer, then drop and count once it is full. Nothing here
// blocks Emit's caller — a slow or unreachable crier must never slow down a
// login.

package audit

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/JonasBorgesLM/moat/secret"
)

// sendTimeout bounds one delivery attempt, so a crier that accepts the
// connection but never answers cannot hold the sender goroutine open
// indefinitely.
const sendTimeout = 5 * time.Second

// CrierEmitter buffers Events and ships them to crier on a background
// goroutine. Construct with NewCrierEmitter; the zero value is not usable
// (its buffer channel is nil).
type CrierEmitter struct {
	client      *http.Client
	baseURL     string
	serviceName string
	token       secret.Value
	logger      *slog.Logger
	now         func() time.Time

	buffer  chan Event
	stop    chan struct{}
	stopped chan struct{}

	mu    sync.Mutex
	drops map[string]int
}

// NewCrierEmitter starts the background sender and returns a ready
// CrierEmitter. bufferSize is ADR-0017's bound: once it is full, Emit drops
// the new event and counts it rather than blocking the caller or growing
// without limit. A nil logger defaults to slog.Default() — drops are
// logged locally (RNF-04's "infrastructure failure denies" does not apply
// to best-effort audit delivery, but a silent drop would still be a second,
// undocumented failure mode on top of the one ADR-0017 already accepted).
func NewCrierEmitter(client *http.Client, baseURL, serviceName string, token secret.Value, bufferSize int, logger *slog.Logger) *CrierEmitter {
	if client == nil {
		client = http.DefaultClient
	}
	if logger == nil {
		logger = slog.Default()
	}
	if bufferSize < 1 {
		bufferSize = 1
	}
	e := &CrierEmitter{
		client:      client,
		baseURL:     baseURL,
		serviceName: serviceName,
		token:       token,
		logger:      logger,
		now:         time.Now,
		buffer:      make(chan Event, bufferSize),
		stop:        make(chan struct{}),
		stopped:     make(chan struct{}),
		drops:       make(map[string]int),
	}
	go e.run()
	return e
}

// Emit never blocks: a full buffer drops e and counts the reason instead of
// waiting for room, which is the property that keeps a stalled crier from
// becoming a stalled login.
func (e *CrierEmitter) Emit(ctx context.Context, ev Event) {
	select {
	case e.buffer <- ev:
	default:
		e.countDrop("buffer_full")
		e.logger.WarnContext(ctx, "audit: buffer full, event dropped", "event_type", ev.Type)
	}
}

// Drops returns a snapshot of every counted drop reason, for tests and for
// whatever exposes it as a metric once one exists.
func (e *CrierEmitter) Drops() map[string]int {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := make(map[string]int, len(e.drops))
	for k, v := range e.drops {
		out[k] = v
	}
	return out
}

// Close stops the background sender and waits for it to exit. Events still
// sitting in the buffer when Close is called are not drained or counted —
// ADR-0017 specifies unreachable-crier behaviour, not shutdown behaviour,
// and RNF-11's graceful shutdown (a later issue) is where a drain deadline
// belongs if one is decided.
func (e *CrierEmitter) Close() {
	close(e.stop)
	<-e.stopped
}

func (e *CrierEmitter) run() {
	defer close(e.stopped)
	for {
		select {
		case ev := <-e.buffer:
			e.send(ev)
		case <-e.stop:
			return
		}
	}
}

func (e *CrierEmitter) send(ev Event) {
	payload, err := json.Marshal(toWireRequest(ev, e.serviceName))
	if err != nil {
		e.countDrop("encode_error")
		e.logger.Warn("audit: encode event", "event_type", ev.Type, "error", err)
		return
	}

	// Bounded so a crier that accepts the connection but never answers
	// cannot hold this goroutine (and, transitively, the buffer slot behind
	// it) open indefinitely — "unreachable" and "too slow to matter" should
	// fail the same way here.
	ctx, cancel := context.WithTimeout(context.Background(), sendTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, e.baseURL+"/v1/logs", bytes.NewReader(payload))
	if err != nil {
		e.countDrop("request_error")
		e.logger.Warn("audit: build request", "event_type", ev.Type, "error", err)
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+e.serviceName+":"+string(e.token.Bytes()))

	resp, err := e.client.Do(req)
	if err != nil {
		// Unreachable (or too slow — sendTimeout expired): ADR-0017's "drop
		// and count," not a retry — a retry queue is more state this
		// best-effort path does not need.
		e.countDrop("unreachable")
		e.logger.Warn("audit: crier unreachable, event dropped", "event_type", ev.Type, "error", err)
		return
	}
	defer func() {
		if cerr := resp.Body.Close(); cerr != nil {
			e.logger.Warn("audit: close crier response body", "error", cerr)
		}
	}()
	if resp.StatusCode != http.StatusAccepted {
		e.countDrop("rejected")
		e.logger.Warn("audit: crier rejected event", "event_type", ev.Type, "status", resp.StatusCode)
	}
}

func (e *CrierEmitter) countDrop(reason string) {
	e.mu.Lock()
	e.drops[reason]++
	e.mu.Unlock()
}

// severityFor maps Outcome onto OTel's severity scale (crier's wire
// format): a failure is worth a human's attention at a glance in a log
// viewer sorted by severity; a success is routine.
func severityFor(o Outcome) (number int, text string) {
	if o == OutcomeFailure {
		return 13, "WARN"
	}
	return 9, "INFO"
}

// wireLogsRequest and wireRecord mirror crier's receivers/http/wire.go v1
// decoder closely enough to satisfy it — field names and the unknown-field
// rejection crier/ADR-0012 documents mean an extra or misnamed field here
// is a 400, not a silently dropped one.
type wireLogsRequest struct {
	Records []wireRecord `json:"records"`
}

type wireRecord struct {
	Timestamp      string         `json:"timestamp"`
	SeverityNumber int            `json:"severityNumber"`
	SeverityText   string         `json:"severityText"`
	Body           string         `json:"body"`
	Attributes     map[string]any `json:"attributes"`
	Resource       wireResource   `json:"resource"`
}

type wireResource struct {
	ServiceName string `json:"serviceName"`
}

// toWireRequest builds the payload sent to crier. Every attribute here is
// either a structured Event field (never a secret by this type's own
// contract) or an entry from Detail, which is the caller's contract not to
// put a secret in (Event's own doc comment) — this function does not scan
// Detail's values for one, the same way Emit does not; what makes that
// contract hold in practice is that moat/secret.Value's own String,
// MarshalJSON and MarshalText overrides return secret.Redacted for exactly
// the "lazy" paths a caller reaches for first, so even a mistake here
// cannot put the real bytes into a map[string]string without the caller
// deliberately calling Value.Bytes() against its own doc comment.
func toWireRequest(e Event, serviceName string) wireLogsRequest {
	number, text := severityFor(e.Outcome)

	attrs := map[string]any{
		"schemaVersion": e.SchemaVersion,
		"eventType":     string(e.Type),
		"outcome":       string(e.Outcome),
	}
	if e.Subject != "" {
		attrs["subject"] = e.Subject
	}
	if e.ClientID != "" {
		attrs["clientId"] = e.ClientID
	}
	if e.RequestID != "" {
		attrs["requestId"] = e.RequestID
	}
	if e.SourceAddr != "" {
		attrs["sourceAddr"] = e.SourceAddr
	}
	for k, v := range e.Detail {
		attrs["detail."+k] = v
	}

	return wireLogsRequest{Records: []wireRecord{{
		Timestamp:      e.At.UTC().Format(time.RFC3339),
		SeverityNumber: number,
		SeverityText:   text,
		Body:           fmt.Sprintf("%s %s", e.Type, e.Outcome),
		Attributes:     attrs,
		Resource:       wireResource{ServiceName: serviceName},
	}}}
}
