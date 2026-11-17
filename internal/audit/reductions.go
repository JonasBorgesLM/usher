package audit

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"time"
)

// ErrRecorderDown means a Recorder cannot record anything more until the
// process restarts: the tally log is poisoned after any write or fsync
// error, and a retry within the process cannot reach it (ADR-0023's
// amendment, #167). A Recorder wraps its own error with it.
var ErrRecorderDown = errors.New("audit: the recorder is down until the process restarts")

// Reductions records the actions that reduce privilege, and the
// informational events, without ever blocking them on the log (ADR-0023,
// Decision 2): the action has already executed when Record is called, and
// Record returns nothing a caller could deny it on.
//
// A record that fails is retried in the background, a few times, with the
// same ID, so a retry after an unknown outcome is recorded once. It stops at
// once when the Recorder is down, since nothing in this process can reach
// the log again. A record it gives up on is logged at error level with its
// ID, type, client and time, and never its subject or source address: the
// alarm is how an operator learns the log is missing something, and the
// log line must not become a second, unprotected audit trail of people.
type Reductions struct {
	rec     Recorder
	logger  *slog.Logger
	backoff []time.Duration
	timeout time.Duration
	wg      sync.WaitGroup
}

// NewReductions returns Reductions over rec. logger nil discards.
func NewReductions(rec Recorder, logger *slog.Logger) *Reductions {
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	return &Reductions{
		rec:    rec,
		logger: logger,
		// Three retries over about four seconds: enough for a context that
		// ended mid-append or a slow fsync, not a queue.
		backoff: []time.Duration{200 * time.Millisecond, time.Second, 3 * time.Second},
		timeout: 2 * time.Second,
	}
}

// Record records r, whose action has already executed. It tries once on
// ctx, and on failure alarms and retries in the background.
func (d *Reductions) Record(ctx context.Context, r Record) {
	err := d.rec.Record(ctx, r)
	if err == nil {
		return
	}
	d.logger.ErrorContext(ctx, "audit: an executed action's record failed; retrying",
		"record_id", r.ID, "type", r.Type, "error", err)
	if errors.Is(err, ErrRecorderDown) {
		d.giveUp(ctx, r, err)
		return
	}
	d.wg.Add(1)
	go d.retry(context.WithoutCancel(ctx), r)
}

func (d *Reductions) retry(ctx context.Context, r Record) {
	defer d.wg.Done()
	var err error
	for _, wait := range d.backoff {
		time.Sleep(wait)
		attempt, cancel := context.WithTimeout(ctx, d.timeout)
		err = d.rec.Record(attempt, r)
		cancel()
		if err == nil {
			d.logger.InfoContext(ctx, "audit: a retried record was stored", "record_id", r.ID, "type", r.Type)
			return
		}
		if errors.Is(err, ErrRecorderDown) {
			break
		}
	}
	d.giveUp(ctx, r, err)
}

func (d *Reductions) giveUp(ctx context.Context, r Record, err error) {
	d.logger.ErrorContext(ctx, "audit: an executed action was NOT recorded",
		"record_id", r.ID, "type", r.Type, "outcome", r.Outcome, "client_id", r.ClientID,
		"at", r.At, "error", err)
}

// Wait blocks until every background retry has finished, so the log is
// closed only after them.
func (d *Reductions) Wait() { d.wg.Wait() }
