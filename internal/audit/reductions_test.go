package audit

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"
)

// flakyRecorder fails its first fails calls with err, then accepts.
type flakyRecorder struct {
	mu    sync.Mutex
	fails int
	err   error
	calls []Record
}

func (f *flakyRecorder) Record(_ context.Context, r Record) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, r)
	if len(f.calls) <= f.fails {
		return f.err
	}
	return nil
}

func (f *flakyRecorder) attempts() []Record {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]Record(nil), f.calls...)
}

func newTestReductions(rec Recorder) (*Reductions, *bytes.Buffer) {
	var logs bytes.Buffer
	d := NewReductions(rec, slog.New(slog.NewTextHandler(&logs, nil)))
	d.backoff = []time.Duration{time.Millisecond, time.Millisecond, time.Millisecond}
	return d, &logs
}

func reduction() Record {
	return Record{ID: NewRecordID(), Type: EventRevocation, Outcome: OutcomeSuccess,
		Subject: "user-1", ClientID: "web-app", SourceAddr: "203.0.113.7", At: time.Unix(1_700_000_000, 0)}
}

// A record that fails for a moment is stored by a retry, with the same ID.
func TestReductions_RetryWithTheSameID(t *testing.T) {
	rec := &flakyRecorder{fails: 2, err: context.DeadlineExceeded}
	d, logs := newTestReductions(rec)
	r := reduction()
	d.Record(context.Background(), r)
	d.Wait()
	calls := rec.attempts()
	if len(calls) != 3 {
		t.Fatalf("%d attempts, want 3 (one, then two retries)", len(calls))
	}
	for _, c := range calls {
		if c.ID != r.ID {
			t.Fatalf("a retry used ID %q, want %q", c.ID, r.ID)
		}
	}
	if !strings.Contains(logs.String(), "a retried record was stored") {
		t.Fatalf("no log of the stored retry:\n%s", logs)
	}
}

// A recorder that is down is not retried: nothing in this process can reach
// the log again. The alarm names the record and never the person.
//
// Seen failing with the ErrRecorderDown check removed from Record: two
// attempts, the second a retry the loop's own check then stopped.
func TestReductions_GiveUpAtOnceWhenTheRecorderIsDown(t *testing.T) {
	rec := &flakyRecorder{fails: 100, err: fmt.Errorf("tally: %w", ErrRecorderDown)}
	d, logs := newTestReductions(rec)
	r := reduction()
	d.Record(context.Background(), r)
	d.Wait()
	if n := len(rec.attempts()); n != 1 {
		t.Fatalf("%d attempts on a recorder that is down, want 1", n)
	}
	out := logs.String()
	if !strings.Contains(out, "was NOT recorded") || !strings.Contains(out, r.ID) {
		t.Fatalf("no alarm naming the record:\n%s", out)
	}
	for _, personal := range []string{r.Subject, r.SourceAddr} {
		if strings.Contains(out, personal) {
			t.Fatalf("the alarm logs %q:\n%s", personal, out)
		}
	}
}

// A record that keeps failing is retried a bounded number of times, then
// alarmed, and Wait returns.
func TestReductions_BoundedRetries(t *testing.T) {
	rec := &flakyRecorder{fails: 100, err: errors.New("slow disk")}
	d, logs := newTestReductions(rec)
	d.Record(context.Background(), reduction())
	d.Wait()
	if n := len(rec.attempts()); n != 4 {
		t.Fatalf("%d attempts, want 4 (one and three retries)", n)
	}
	if !strings.Contains(logs.String(), "was NOT recorded") {
		t.Fatalf("no alarm after the retries:\n%s", logs)
	}
}

// A record that succeeds at once starts nothing in the background.
func TestReductions_NoRetryOnSuccess(t *testing.T) {
	rec := &flakyRecorder{}
	d, logs := newTestReductions(rec)
	d.Record(context.Background(), reduction())
	d.Wait()
	if n := len(rec.attempts()); n != 1 || logs.Len() != 0 {
		t.Fatalf("%d attempts and logs %q, want 1 and none", n, logs)
	}
}
