// RNF-10's "Logs are structured JSON (log/slog) correlated by request id."
package main

import (
	"context"
	"io"
	"log/slog"

	"github.com/go-chi/chi/v5/middleware"
)

// newProductionLogger is the one *slog.Logger production wiring builds:
// JSON records, each carrying the request id chi's own middleware.RequestID
// put in the request's context — automatically, with no change needed at
// any of this package's existing h.logger.ErrorContext(r.Context(), ...)
// call sites, because requestIDHandler reads it from ctx on every record.
func newProductionLogger(w io.Writer) *slog.Logger {
	return slog.New(&requestIDHandler{next: slog.NewJSONHandler(w, nil)})
}

// requestIDHandler decorates a slog.Handler with the one context-derived
// attribute this project correlates logs by. slog's own documentation is
// explicit that it does not read context values on its own; a Handler that
// does is the sanctioned way to add exactly one back, instead of threading
// a per-request logger through every function that might log.
type requestIDHandler struct {
	next slog.Handler
}

func (h *requestIDHandler) Enabled(ctx context.Context, level slog.Level) bool {
	return h.next.Enabled(ctx, level)
}

func (h *requestIDHandler) Handle(ctx context.Context, record slog.Record) error {
	if id := middleware.GetReqID(ctx); id != "" {
		record.AddAttrs(slog.String("request_id", id))
	}
	return h.next.Handle(ctx, record)
}

func (h *requestIDHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &requestIDHandler{next: h.next.WithAttrs(attrs)}
}

func (h *requestIDHandler) WithGroup(name string) slog.Handler {
	return &requestIDHandler{next: h.next.WithGroup(name)}
}
