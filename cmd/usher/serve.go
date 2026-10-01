// RNF-11's graceful shutdown: stop accepting, drain in-flight requests
// within a bounded deadline, then close stores.
package main

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"time"
)

// newServer builds the http.Server RS-21 requires explicit timeouts on:
// ReadHeaderTimeout guards against Slowloris, the other three against a
// client or upstream that opens a connection and never finishes it. The
// net/http default is no timeout at all on any of the four.
func newServer(handler http.Handler) *http.Server {
	return &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
}

// serve runs srv over ln until ctx is canceled -- SIGTERM, in production,
// through signal.NotifyContext at the real entry point -- then drains
// in-flight requests for up to drainDeadline before forcing them closed,
// and calls every closer afterward regardless of whether the drain
// finished in time: a store that fails to close cleanly must not stop the
// others from trying.
//
// Taking ln rather than an address, and calling Serve rather than
// ListenAndServe, is what makes this testable against a real listener on
// an ephemeral port without a production caller needing to know that.
func serve(ctx context.Context, srv *http.Server, ln net.Listener, drainDeadline time.Duration, logger *slog.Logger, closers ...func() error) error {
	serveErr := make(chan error, 1)
	go func() {
		err := srv.Serve(ln)
		if errors.Is(err, http.ErrServerClosed) {
			err = nil
		}
		serveErr <- err
	}()

	select {
	case err := <-serveErr:
		// The server stopped on its own -- a listener error -- before any
		// shutdown was requested. Nothing to drain or close: it was never
		// serving traffic to begin with.
		return err
	case <-ctx.Done():
	}

	// Deliberately not derived from ctx: ctx is already Done() at this
	// point (that is why we are here), and a context derived from an
	// already-canceled one is canceled too, which would make the drain
	// deadline below zero instead of drainDeadline.
	shutdownCtx, cancel := context.WithTimeout(context.Background(), drainDeadline)
	defer cancel()
	shutdownErr := srv.Shutdown(shutdownCtx) //nolint:contextcheck // see comment above shutdownCtx

	for _, c := range closers {
		if err := c(); err != nil {
			logger.Error("serve: close dependency during shutdown", "error", err)
		}
	}

	if err := <-serveErr; err != nil {
		return err
	}
	return shutdownErr
}
