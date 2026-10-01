package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5/middleware"
)

// TestNewProductionLogger_CorrelatesByRequestID is RNF-10's "structured
// JSON logs correlated by request id": a log emitted through a request's
// context, inside a handler wrapped by chi's own middleware.RequestID,
// carries that exact request id as a JSON attribute -- proven against the
// real middleware chi ships, not a hand-built stand-in for it.
//
// Negative control: with the `record.AddAttrs(...)` call removed from
// requestIDHandler.Handle, this test failed -- the logged line had no
// request_id field at all. Verified by hand, restored before committing.
func TestNewProductionLogger_CorrelatesByRequestID(t *testing.T) {
	var buf bytes.Buffer
	logger := newProductionLogger(&buf)

	var capturedID string
	h := middleware.RequestID(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		capturedID = middleware.GetReqID(r.Context())
		logger.ErrorContext(r.Context(), "something went wrong")
	}))

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/", http.NoBody)
	h.ServeHTTP(httptest.NewRecorder(), req)

	if capturedID == "" {
		t.Fatal("chi's own middleware.RequestID did not inject a request id -- test fixture is broken")
	}

	var logged map[string]any
	if err := json.Unmarshal(buf.Bytes(), &logged); err != nil {
		t.Fatalf("log output is not valid JSON: %v, output: %s", err, buf.String())
	}
	if logged["request_id"] != capturedID {
		t.Errorf("logged request_id = %v, want %q", logged["request_id"], capturedID)
	}
	if logged["msg"] != "something went wrong" {
		t.Errorf("logged msg = %v, want %q", logged["msg"], "something went wrong")
	}
}

// TestNewProductionLogger_NoRequestIDOmitsAttribute is the same handler's
// other path: a log emitted with no request id in context (outside any
// request, e.g. at startup) is still valid JSON, just without the field,
// rather than a zero-value placeholder that would look like a real id.
func TestNewProductionLogger_NoRequestIDOmitsAttribute(t *testing.T) {
	var buf bytes.Buffer
	logger := newProductionLogger(&buf)

	logger.Info("starting up")

	var logged map[string]any
	if err := json.Unmarshal(buf.Bytes(), &logged); err != nil {
		t.Fatalf("log output is not valid JSON: %v, output: %s", err, buf.String())
	}
	if _, ok := logged["request_id"]; ok {
		t.Errorf("logged a request_id with no request in flight: %v", logged["request_id"])
	}
}
