package session

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net/http"
	"time"
)

// CookieName is the browser session cookie (RS-31). The __Host- prefix
// requires — and browsers enforce, silently refusing to set the cookie
// otherwise, not merely warning — Secure, Path=/, and no Domain attribute.
// Those three are non-negotiable because of the prefix, not independently
// chosen, which is why NewSessionCookie and ExpiredSessionCookie hard-code
// them rather than taking them as parameters.
const CookieName = "__Host-usher-session"

// NewRawID generates a fresh session id of at least 256 bits (RS-31),
// base64-encoded (URL-safe, unpadded) for direct use as a cookie value.
// Only its SHA-256 ever reaches a SessionStore — see
// internal/store/redis's implementation.
func NewRawID() (string, error) {
	buf := make([]byte, 32) // 256 bits
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("session: generate id: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

// NewSessionCookie builds the Set-Cookie value for a fresh session. maxAge
// should be the session's absolute lifetime (RF-12) — the cookie's own
// expiry is a client-side convenience on top of the server-side enforcement
// SessionStore does; a client that ignores it and replays an old cookie
// anyway is exactly what the store's own expiry check is for.
func NewSessionCookie(rawID string, maxAge time.Duration) *http.Cookie {
	return &http.Cookie{
		Name:     CookieName,
		Value:    rawID,
		Path:     "/",
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(maxAge.Seconds()),
	}
}

// ExpiredSessionCookie clears the session cookie — MaxAge=-1 tells the
// browser to delete it now. Its attributes must match NewSessionCookie's
// exactly, or the browser treats this as a different cookie and leaves the
// original in place.
//
// This is RS-31's client-side half, not the mechanism: deleting the
// server-side session (SessionStore.Delete) is what actually ends it, and
// must happen first — a response that clears the cookie before the delete
// completes leaves a window where the old, still-live session id is briefly
// the only copy of "this session is over."
func ExpiredSessionCookie() *http.Cookie {
	return &http.Cookie{
		Name:     CookieName,
		Value:    "",
		Path:     "/",
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	}
}

// RawSessionID extracts the session cookie's raw value from r, or
// ErrSessionNotFound if it is not present.
func RawSessionID(r *http.Request) (string, error) {
	c, err := r.Cookie(CookieName)
	if err != nil {
		return "", ErrSessionNotFound
	}
	return c.Value, nil
}
