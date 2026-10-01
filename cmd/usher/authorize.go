// GET /authorize is RS-28's validation order, exactly: client_id known,
// then redirect_uri exact-matched (RS-02), then everything else reported
// to the now-verified redirect_uri as an RFC 6749 §4.1.2.1 error (RS-01's
// PKCE, RS-03's state, scope). The first two steps never redirect — there
// is nowhere verified to send one yet (RS-28's whole point). On full
// success, this hands off to /login with a pending session.Challenge
// (RF-02); login, consent and code issuance are later issues.
package main

import (
	"html/template"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/JonasBorgesLM/usher/internal/identity"
	"github.com/JonasBorgesLM/usher/internal/session"
)

type authorizeHandler struct {
	clients      []identity.Client
	challenges   session.ChallengeStore
	issuer       string
	challengeTTL time.Duration
	now          func() time.Time
	errorTmpl    *template.Template
	logger       *slog.Logger
}

type authorizeErrorPageData struct {
	Message string
}

func (h *authorizeHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()

	// RS-28 step 1: client_id known, or render locally. No redirect target
	// exists yet.
	client, ok := h.lookupClient(q.Get("client_id"))
	if !ok {
		h.renderError(w, r, "unknown client_id")
		return
	}

	// RS-28 step 2 (RS-02): redirect_uri exact-matched against THIS
	// client's registered list. Still no redirect on failure.
	redirectURI := q.Get("redirect_uri")
	if !exactRedirectURIMatch(redirectURI, client.RedirectURIs) {
		h.renderError(w, r, "redirect_uri does not match a registered URI for this client")
		return
	}

	// RS-28 step 3: redirect_uri is verified from here on. Every further
	// problem is reported TO IT (RFC 6749 §4.1.2.1), never rendered
	// locally and never silently dropped.
	state := q.Get("state")

	if q.Get("response_type") != "code" {
		h.redirectError(w, r, redirectURI, state, "unsupported_response_type", `response_type must be "code"`)
		return
	}
	if state == "" {
		h.redirectError(w, r, redirectURI, state, "invalid_request", "state is required")
		return
	}
	codeChallenge := q.Get("code_challenge")
	if codeChallenge == "" || q.Get("code_challenge_method") != "S256" {
		h.redirectError(w, r, redirectURI, state, "invalid_request", "code_challenge with code_challenge_method=S256 is required")
		return
	}
	scope := splitScope(q.Get("scope"))
	if !scopeSubset(scope, client.Scopes) {
		h.redirectError(w, r, redirectURI, state, "invalid_scope", "requested scope exceeds what this client may request")
		return
	}

	id, err := session.NewRawID()
	if err != nil {
		h.logger.ErrorContext(r.Context(), "authorize: generate challenge id", "error", err)
		h.redirectError(w, r, redirectURI, state, "server_error", "")
		return
	}
	challenge := session.Challenge{
		ID:            id,
		ClientID:      client.ID,
		RedirectURI:   redirectURI,
		Scope:         scope,
		State:         state,
		CodeChallenge: codeChallenge,
		Nonce:         q.Get("nonce"), // "" if absent (RS-30)
		ExpiresAt:     h.now().Add(h.challengeTTL),
	}
	if err := h.challenges.Save(r.Context(), challenge); err != nil {
		h.logger.ErrorContext(r.Context(), "authorize: save challenge", "error", err)
		h.redirectError(w, r, redirectURI, state, "server_error", "")
		return
	}

	// RS-05: no other parameter in the query string.
	http.Redirect(w, r, "/login?login_challenge="+url.QueryEscape(id), http.StatusFound)
}

func (h *authorizeHandler) lookupClient(clientID string) (identity.Client, bool) {
	return lookupClient(h.clients, clientID)
}

// lookupClient is shared with consent.go: both handlers resolve a
// challenge or request's client_id against the same static registry.
func lookupClient(clients []identity.Client, clientID string) (identity.Client, bool) {
	if clientID == "" {
		return identity.Client{}, false
	}
	for _, c := range clients {
		if c.ID == clientID {
			return c, true
		}
	}
	return identity.Client{}, false
}

// renderError is RS-28 steps 1-2's failure path: no redirect_uri has been
// verified, so nothing is redirected to, ever.
func (h *authorizeHandler) renderError(w http.ResponseWriter, r *http.Request, message string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusBadRequest)
	if err := h.errorTmpl.Execute(w, authorizeErrorPageData{Message: message}); err != nil {
		h.logger.ErrorContext(r.Context(), "authorize: render error page", "error", err)
	}
}

// redirectError is RS-28 step 3's failure path: redirectURI is already
// verified, so the error is reported to it via the shared RFC 6749
// §4.1.2.1 helper (oauth_errors.go) that consent.go's denial path also
// uses.
func (h *authorizeHandler) redirectError(w http.ResponseWriter, r *http.Request, redirectURI, state, errCode, description string) {
	redirectOAuthError(w, r, h.logger, h.issuer, redirectURI, state, errCode, description,
		func(message string) { h.renderError(w, r, message) })
}

// exactRedirectURIMatch is RS-02: no prefix match, no wildcard, no
// normalization. String equality against the registered list, nothing
// else -- a scheme/host case difference, a trailing slash, or a percent-
// encoding variant is a different string and does not match.
func exactRedirectURIMatch(candidate string, registered []string) bool {
	for _, r := range registered {
		if candidate == r {
			return true
		}
	}
	return false
}

// splitScope is OAuth's own space-delimited scope string (RFC 6749 §3.3).
func splitScope(raw string) []string {
	if raw == "" {
		return nil
	}
	return strings.Fields(raw)
}

// scopeSubset reports whether every entry in requested also appears in
// allowed.
func scopeSubset(requested, allowed []string) bool {
	allowedSet := make(map[string]bool, len(allowed))
	for _, s := range allowed {
		allowedSet[s] = true
	}
	for _, s := range requested {
		if !allowedSet[s] {
			return false
		}
	}
	return true
}
