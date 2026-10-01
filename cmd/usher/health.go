// RNF-10's two endpoints. /healthz answers "is the process alive" with no
// dependency checked -- a liveness probe that checked a dependency would
// turn one database outage into every pod restarting, which is the
// opposite of what liveness is for. /readyz answers "should an
// orchestrator send this instance traffic," which does depend on Postgres,
// Redis, the eviction check and the signing keyset (REQUIREMENTS §7.1,
// RNF-07, ADR-0015).
package main

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
)

// ReadinessCheck is one dependency /readyz polls, named so a failing
// response can say which one -- the same way crier's own /readyz does
// (crier/demo/README.md: "the readiness reason names which destinations
// are refusing calls").
type ReadinessCheck struct {
	Name  string
	Check func(ctx context.Context) error
}

type readinessResult struct {
	Name  string `json:"name"`
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
}

func healthzHandler(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)
}

// readinessHandler serves /readyz. Every check always runs, even after an
// earlier one fails: a partial-outage report naming every affected
// dependency is more useful to an operator than stopping at the first.
type readinessHandler struct {
	checks []ReadinessCheck
	logger *slog.Logger
}

func (h *readinessHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	results := make([]readinessResult, 0, len(h.checks))
	allOK := true
	for _, c := range h.checks {
		res := readinessResult{Name: c.Name, OK: true}
		if err := c.Check(r.Context()); err != nil {
			res.OK = false
			res.Error = err.Error()
			allOK = false
		}
		results = append(results, res)
	}

	w.Header().Set("Content-Type", "application/json")
	if !allOK {
		w.WriteHeader(http.StatusServiceUnavailable)
	}
	if err := json.NewEncoder(w).Encode(map[string]any{"checks": results}); err != nil {
		h.logger.ErrorContext(r.Context(), "readyz: encode response", "error", err)
	}
}
