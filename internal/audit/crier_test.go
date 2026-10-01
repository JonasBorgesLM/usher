package audit

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/JonasBorgesLM/moat/secret"
)

func testEvent() Event {
	return Event{
		SchemaVersion: 1,
		Type:          EventLoginAttempt,
		Outcome:       OutcomeFailure,
		Subject:       "alice@example.com",
		SourceAddr:    "203.0.113.7",
		At:            time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
	}
}

// TestCrierEmitter_DeliversOverHTTP is the golden path: a reachable crier
// receives the wire-format payload CrierEmitter sends, authenticated with
// the configured credential.
func TestCrierEmitter_DeliversOverHTTP(t *testing.T) {
	received := make(chan *http.Request, 1)
	var body []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ = io.ReadAll(r.Body)
		received <- r
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()

	emitter := NewCrierEmitter(srv.Client(), srv.URL, "usher", secret.New([]byte("ingest-token")), 10, nil)
	defer emitter.Close()

	emitter.Emit(context.Background(), testEvent())

	select {
	case r := <-received:
		if got := r.URL.Path; got != "/v1/logs" {
			t.Errorf("request path = %q, want /v1/logs", got)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer usher:ingest-token" {
			t.Errorf("Authorization = %q, want %q", got, "Bearer usher:ingest-token")
		}
		if !strings.Contains(string(body), `"subject":"alice@example.com"`) {
			t.Errorf("payload does not carry the event's subject: %s", body)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for the event to reach crier")
	}
}

// TestCrierEmitter_UnreachableDropsAndCounts is ADR-0017's Amendment: when
// crier cannot be reached, the event is dropped and the reason counted —
// not retried, not blocking.
//
// Negative control: with the e.countDrop("unreachable") call removed from
// send's error branch, this test failed — "drop was never counted: map[]"
// — even though the log line confirms the unreachable request still
// happened. Verified by hand, restored before committing.
func TestCrierEmitter_UnreachableDropsAndCounts(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusAccepted)
	}))
	unreachableURL := srv.URL
	srv.Close() // nothing listens here anymore

	emitter := NewCrierEmitter(http.DefaultClient, unreachableURL, "usher", secret.New([]byte("ingest-token")), 10, nil)
	defer emitter.Close()

	emitter.Emit(context.Background(), testEvent())

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if emitter.Drops()["unreachable"] > 0 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("drop was never counted: %v", emitter.Drops())
}

// TestCrierEmitter_BufferFullDropsAndCounts is ADR-0017's bounded buffer:
// once it is full, Emit drops the new event and counts it rather than
// blocking the caller or growing without limit.
//
// Negative control: with the `default:` branch of Emit's select changed to
// block on `e.buffer <- ev` instead of dropping, this test hung instead of
// completing -- the third Emit call blocked forever waiting for buffer
// room that the deliberately-stuck first event never freed. Verified by
// hand (killed the hung test run), restored before committing.
func TestCrierEmitter_BufferFullDropsAndCounts(t *testing.T) {
	serverReceived := make(chan struct{})
	var once sync.Once
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		once.Do(func() { close(serverReceived) })
		<-release
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()

	emitter := NewCrierEmitter(srv.Client(), srv.URL, "usher", secret.New([]byte("ingest-token")), 1, nil)
	defer func() {
		close(release)
		emitter.Close()
	}()

	emitter.Emit(context.Background(), testEvent()) // dequeued, send() now blocked in the handler

	select {
	case <-serverReceived:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for the first event to reach the handler")
	}

	emitter.Emit(context.Background(), testEvent()) // fills the now-empty buffer slot
	emitter.Emit(context.Background(), testEvent()) // buffer full: dropped

	if got := emitter.Drops()["buffer_full"]; got != 1 {
		t.Errorf(`Drops()["buffer_full"] = %d, want 1 (drops: %v)`, got, emitter.Drops())
	}
}

// TestCrierEmitter_SecretNeverReachesWire proves the issue's "no event
// carries a secret" property against the actual wire payload, not just
// against moat/secret.Value in isolation: a caller who reaches for the
// laziest way to stringify a secret.Value -- fmt.Sprintf("%v", v) and
// v.String(), both of which a developer unfamiliar with secret.Value would
// try first -- still only ever produces secret.Redacted, which is what
// this test confirms actually leaves the wire, never the real bytes.
//
// The "protection" here lives in moat/secret, not in this package, so the
// usual "remove the protection" control does not apply to our own code.
// Instead: this test was run once with a third Detail entry,
// "attempted_password_raw": string(token.Bytes()) -- a caller deliberately
// bypassing secret.Value's safe stringification -- and it correctly
// failed, with the real secret visible in the captured payload. That
// proves this test can observe a real leak rather than passing vacuously;
// the entry was then removed, since the point was to exercise the test,
// not to leave a real leak in the fixture. Verified by hand.

func TestCrierEmitter_SecretNeverReachesWire(t *testing.T) {
	const realSecret = "super-secret-password-value-0123456789"
	token := secret.New([]byte(realSecret))

	ev := testEvent()
	ev.Detail = map[string]string{
		"attempted_password_sprintf": fmt.Sprintf("%v", token), //nolint:gocritic // deliberately the lazy fmt.Sprintf path a caller unfamiliar with secret.Value would try, not a style choice
		"attempted_password_string":  token.String(),
	}

	received := make(chan []byte, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		received <- b
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()

	emitter := NewCrierEmitter(srv.Client(), srv.URL, "usher", secret.New([]byte("ingest-token")), 10, nil)
	defer emitter.Close()

	emitter.Emit(context.Background(), ev)

	select {
	case body := <-received:
		if strings.Contains(string(body), realSecret) {
			t.Fatalf("the real secret reached the wire payload: %s", body)
		}
		if !strings.Contains(string(body), secret.Redacted) {
			t.Errorf("expected %q in the payload, got: %s", secret.Redacted, body)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for the event to reach crier")
	}
}
