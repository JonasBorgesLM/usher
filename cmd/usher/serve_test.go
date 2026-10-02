package main

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"testing"
	"time"
)

// TestServe_DrainsInFlightAndRefusesNew is RNF-11's second done-when item:
// an in-flight request completes after shutdown is requested, and a new
// request made after shutdown has begun is refused, not queued or served.
//
// Negative control: with `srv.Shutdown(shutdownCtx)` replaced by
// `time.Sleep(drainDeadline)` (stopping nothing, just waiting), this test
// failed -- the "new request after shutdown" phase succeeded with 200
// instead of being refused, because the listener was still accepting.
// Verified by hand, restored before committing.
func TestServe_DrainsInFlightAndRefusesNew(t *testing.T) {
	reached := make(chan struct{})
	release := make(chan struct{})
	mux := http.NewServeMux()
	mux.HandleFunc("/slow", func(w http.ResponseWriter, r *http.Request) {
		close(reached)
		<-release
		w.WriteHeader(http.StatusOK)
	})

	ln, err := new(net.ListenConfig).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := ln.Addr().String()

	srv := newServer(mux)
	ctx, cancel := context.WithCancel(context.Background())
	serveDone := make(chan error, 1)
	go func() { serveDone <- serve(ctx, srv, ln, 5*time.Second, slog.New(slog.DiscardHandler)) }()

	// Start the in-flight request and wait until the handler is actually
	// blocked inside it, so the shutdown below genuinely races a request
	// in progress rather than one that has not started yet.
	slowDone := make(chan *http.Response, 1)
	go func() {
		resp, err := http.Get("http://" + addr + "/slow") //nolint:noctx,bodyclose // test client; body is closed by the receiver of slowDone, after reading the full response
		if err != nil {
			t.Error(err)
			slowDone <- nil
			return
		}
		slowDone <- resp
	}()
	<-reached

	cancel() // RNF-11's SIGTERM-equivalent trigger

	// Shutdown stops accepting new connections synchronously, inside
	// srv.Shutdown — but serve's own goroutine needs a moment to reach that
	// call after ctx.Done() fires. Poll instead of a single fixed sleep.
	deadline := time.Now().Add(2 * time.Second)
	var refused error
	for time.Now().Before(deadline) {
		resp, getErr := http.Get("http://" + addr + "/anything") //nolint:noctx // test client
		if getErr != nil {
			refused = getErr
			break
		}
		_ = resp.Body.Close()
		time.Sleep(10 * time.Millisecond)
	}
	if refused == nil {
		t.Error("a request made after shutdown began was not refused")
	}

	close(release) // let the in-flight request finish

	resp := <-slowDone
	if resp == nil {
		t.Fatal("the in-flight request did not complete successfully")
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("in-flight request status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
	if _, err := io.ReadAll(resp.Body); err != nil {
		t.Errorf("read in-flight response body: %v", err)
	}

	if err := <-serveDone; err != nil {
		t.Errorf("serve returned %v, want nil", err)
	}
}

// TestServe_ClosersRunOnShutdown is RNF-11's "then closes stores": every
// closer passed to serve runs once shutdown begins, independent of
// whether the HTTP drain itself succeeds.
func TestServe_ClosersRunOnShutdown(t *testing.T) {
	ln, err := new(net.ListenConfig).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv := newServer(http.NewServeMux())
	ctx, cancel := context.WithCancel(context.Background())

	var closed []string
	closer := func(name string) func() error {
		return func() error {
			closed = append(closed, name)
			return nil
		}
	}

	serveDone := make(chan error, 1)
	go func() {
		serveDone <- serve(ctx, srv, ln, time.Second, slog.New(slog.DiscardHandler),
			closer("postgres"), closer("redis"))
	}()

	cancel()
	if err := <-serveDone; err != nil {
		t.Fatalf("serve: %v", err)
	}

	if len(closed) != 2 || closed[0] != "postgres" || closed[1] != "redis" {
		t.Errorf("closed = %v, want [postgres redis]", closed)
	}
}

// TestServe_CloserErrorDoesNotStopOthers is the half of "then closes
// stores" that a single success-only test cannot show: one failing closer
// must not prevent the next one from running.
//
// Negative control: with the `if err := c(); err != nil` check changed to
// `return err` (stopping the loop on the first failure), this test
// failed -- "redis" was never reached. Verified by hand, restored before
// committing.
func TestServe_CloserErrorDoesNotStopOthers(t *testing.T) {
	ln, err := new(net.ListenConfig).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv := newServer(http.NewServeMux())
	ctx, cancel := context.WithCancel(context.Background())

	var closed []string
	failing := func() error {
		closed = append(closed, "postgres")
		return errors.New("close failed")
	}
	ok := func() error {
		closed = append(closed, "redis")
		return nil
	}

	serveDone := make(chan error, 1)
	go func() { serveDone <- serve(ctx, srv, ln, time.Second, slog.New(slog.DiscardHandler), failing, ok) }()

	cancel()
	<-serveDone

	if len(closed) != 2 || closed[1] != "redis" {
		t.Errorf("closed = %v, want the second closer to still run after the first failed", closed)
	}
}

// TestNewServer_AllTimeoutsSet is RS-21's server half of #40's own third
// done-when ("server and upstream timeouts all set"). The upstream half
// is internal/proxy's own TestUpstreamTransport_AllTimeoutsSet.
//
// Negative control: with `ReadHeaderTimeout` temporarily zeroed in
// newServer, this test failed. Verified by hand for each of the four
// fields in turn, restored before committing.
func TestNewServer_AllTimeoutsSet(t *testing.T) {
	srv := newServer(http.NewServeMux())

	if srv.ReadHeaderTimeout == 0 {
		t.Error("ReadHeaderTimeout is unset")
	}
	if srv.ReadTimeout == 0 {
		t.Error("ReadTimeout is unset")
	}
	if srv.WriteTimeout == 0 {
		t.Error("WriteTimeout is unset")
	}
	if srv.IdleTimeout == 0 {
		t.Error("IdleTimeout is unset")
	}
}
