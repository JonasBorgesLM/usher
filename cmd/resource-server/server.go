// server.go is this binary's whole protected API — kept deliberately
// small (ADR-0013: "the demo service is written only to be protected; it
// must stay small, or it becomes a second product"). It validates every
// bearer token itself, against the published JWKS, through
// pkg/tokenvalidator — never through anything under internal/, which
// check-boundaries.sh enforces structurally by this binary's own module
// path (cmd/resource-server is not even able to import internal/).
package main

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"

	"github.com/JonasBorgesLM/moat/realip"
	"github.com/JonasBorgesLM/usher/pkg/tokenvalidator"
)

// widget is the whole demo resource this service protects — intentionally
// trivial, since what this binary exists to demonstrate is RS-18's
// defence in depth, not a real product.
type widget struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

var demoWidgets = []widget{
	{ID: "1", Name: "left"},
	{ID: "2", Name: "right"},
}

// widgetsResponse echoes back the authenticated subject alongside the
// resource itself, precisely so a test (or an operator, manually) can
// see which identity the token actually carried — RI-04/RS-18's own
// point made observable: this value comes from claims.Subject only,
// never from any X-Auth-* header a caller might send.
type widgetsResponse struct {
	Subject string   `json:"subject"`
	Widgets []widget `json:"widgets"`
}

// bearerToken extracts the credential from an "Authorization: Bearer
// ..." header — the same shape internal/proxy's own bearerToken uses,
// duplicated rather than shared since this binary cannot import
// internal/ and the two packages have no third place to share it from
// that both could import.
func bearerToken(r *http.Request) (token string, ok bool) {
	return strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
}

// widgetsHandler is RS-18 itself: this service trusts nothing about who
// is calling except what validator proves about the bearer token,
// regardless of whether the request arrived through usher's gateway or
// reached this service directly. It reads no X-Auth-* header anywhere —
// not to strip one (RS-17 is the gateway's own job, not this service's),
// but because nothing here ever looks at that namespace in the first
// place; an authorization decision from it is not a line that exists to
// be removed (RI-04, T-13).
func widgetsHandler(validator *tokenvalidator.Validator, audience string, logger *slog.Logger) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token, ok := bearerToken(r)
		if !ok {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		claims, err := validator.ValidateAccessToken(r.Context(), token, audience)
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		if encErr := json.NewEncoder(w).Encode(widgetsResponse{Subject: claims.Subject, Widgets: demoWidgets}); encErr != nil {
			logger.ErrorContext(r.Context(), "resource-server: encode widgets response", "error", encErr)
		}
	})
}

// discardLogger is used where a caller does not supply one (tests) —
// cmd/usher/login.go's own convention, duplicated for the same reason
// as everything else in this package.
func discardLogger() *slog.Logger {
	return slog.New(slog.DiscardHandler)
}

func healthzHandler(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)
}

// withClientIPLogging logs the real client address behind usher's own
// gateway (ADR-0010: this service declares the gateway's CIDR as its
// only trusted proxy, exactly as the ADR's own wording anticipates) —
// an accurate record of who actually called, never an authorization
// input. extractor.ClientIP falls back to the raw peer address when the
// forwarding chain is absent or untrusted; it does not fail the request
// either way (RS-18's own auth check, not this logging, is what decides
// whether the request proceeds).
func withClientIPLogging(extractor *realip.Extractor, logger *slog.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip, err := extractor.ClientIP(r)
		if err != nil {
			logger.WarnContext(r.Context(), "resource-server: client ip undeterminable", "error", err)
		} else {
			logger.InfoContext(r.Context(), "resource-server: request", "client_ip", ip.String(), "method", r.Method, "path", r.URL.Path)
		}
		next.ServeHTTP(w, r)
	})
}

// newRouter builds the whole service: /healthz for the compose
// healthcheck (RNF-06), no auth; /widgets, the one protected route,
// behind validator. middleware.RequestID is chi's own, correlating log
// records the same way cmd/usher's own newProductionLogger reads it back
// out — duplicated here for the same reason bearerToken is: this binary
// cannot import cmd/usher either.
func newRouter(validator *tokenvalidator.Validator, audience string, extractor *realip.Extractor, logger *slog.Logger) *chi.Mux {
	r := chi.NewRouter()
	r.Use(middleware.RequestID)
	r.Use(func(next http.Handler) http.Handler { return withClientIPLogging(extractor, logger, next) })
	r.Get("/healthz", healthzHandler)
	r.Get("/widgets", widgetsHandler(validator, audience, logger).ServeHTTP)
	return r
}

// requestIDHandler is cmd/usher/log.go's own type, duplicated for the
// same reason as bearerToken above.
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
