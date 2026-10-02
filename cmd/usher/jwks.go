// GET /.well-known/jwks.json (RS-09, ADR-0015): every key between its own
// publish_at and retire_at, rendered by keys.Keyset.JWKS -- never a private
// parameter (proven at that layer by internal/keys' own
// TestJWKS_NoPrivateParameters; this file's own test exercises the same
// property through the real HTTP response, not Keyset.JWKS again). Cached
// for exactly the consumer cache TTL the signing keyset's own retirement
// formula was built against (RS-09), so an operator can never configure the
// two to disagree.
package main

import (
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/JonasBorgesLM/usher/internal/keys"
)

type jwksHandler struct {
	keyset           *keys.Keyset
	consumerCacheTTL time.Duration
	now              func() time.Time
	logger           *slog.Logger
}

func (h *jwksHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, err := h.keyset.JWKS(h.now())
	if err != nil {
		h.logger.ErrorContext(r.Context(), "jwks: render", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", fmt.Sprintf("public, max-age=%d", int(h.consumerCacheTTL.Seconds())))
	w.WriteHeader(http.StatusOK)
	if _, err := w.Write(body); err != nil {
		h.logger.ErrorContext(r.Context(), "jwks: write response", "error", err)
	}
}
