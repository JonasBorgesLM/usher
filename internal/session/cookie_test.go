package session

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// TestNewSessionCookie_AttributesAsserted is the issue's own wording: the
// cookie attributes are checked against the actual serialized Set-Cookie
// header, not against the http.Cookie struct's fields directly — a struct
// field can be right while the serialization is wrong (a stdlib detail
// that has bitten real code before), so the header is what a browser
// actually receives and what this test actually reads.
//
// Negative control: with SameSite left unset (the http.Cookie zero value)
// instead of explicitly SameSiteLaxMode, this test's SameSite assertion
// failed — the header carried no SameSite attribute at all. Verified by
// hand, restored before committing.
func TestNewSessionCookie_AttributesAsserted(t *testing.T) {
	rec := httptest.NewRecorder()
	http.SetCookie(rec, NewSessionCookie("the-raw-id", 12*time.Hour))
	header := rec.Header().Get("Set-Cookie")

	checks := map[string]bool{
		"name has __Host- prefix": strings.HasPrefix(header, "__Host-usher-session="),
		"Secure":                  strings.Contains(header, "Secure"),
		"HttpOnly":                strings.Contains(header, "HttpOnly"),
		"SameSite=Lax":            strings.Contains(header, "SameSite=Lax"),
		"Path=/":                  strings.Contains(header, "Path=/"),
		"no Domain attribute":     !strings.Contains(header, "Domain="),
	}
	for check, ok := range checks {
		if !ok {
			t.Errorf("Set-Cookie header missing %s: %q", check, header)
		}
	}
}

func TestExpiredSessionCookie_ClearsImmediately(t *testing.T) {
	rec := httptest.NewRecorder()
	http.SetCookie(rec, ExpiredSessionCookie())
	header := rec.Header().Get("Set-Cookie")

	if !strings.HasPrefix(header, "__Host-usher-session=") {
		t.Errorf("Set-Cookie header does not clear the right cookie name: %q", header)
	}
	if !strings.Contains(header, "Max-Age=0") {
		t.Errorf("Set-Cookie header does not expire the cookie immediately: %q", header)
	}
}

func TestRawSessionID_MissingCookie(t *testing.T) {
	r := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/", http.NoBody)
	if _, err := RawSessionID(r); !errors.Is(err, ErrSessionNotFound) {
		t.Errorf("RawSessionID with no cookie = %v, want ErrSessionNotFound", err)
	}
}

func TestRawSessionID_RoundTrip(t *testing.T) {
	rec := httptest.NewRecorder()
	http.SetCookie(rec, NewSessionCookie("the-raw-id", time.Hour))

	r := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/", http.NoBody)
	r.Header.Set("Cookie", rec.Header().Get("Set-Cookie"))

	got, err := RawSessionID(r)
	if err != nil {
		t.Fatalf("RawSessionID: %v", err)
	}
	if got != "the-raw-id" {
		t.Errorf("RawSessionID = %q, want %q", got, "the-raw-id")
	}
}

func TestNewRawID_DistinctAndRightLength(t *testing.T) {
	a, err := NewRawID()
	if err != nil {
		t.Fatalf("NewRawID: %v", err)
	}
	b, err := NewRawID()
	if err != nil {
		t.Fatalf("NewRawID: %v", err)
	}
	if a == b {
		t.Error("two calls to NewRawID produced the same id")
	}
	// base64.RawURLEncoding of 32 bytes is 43 characters, no padding.
	if len(a) != 43 {
		t.Errorf("NewRawID produced a %d-character id, want 43 (32 bytes, unpadded base64)", len(a))
	}
}
