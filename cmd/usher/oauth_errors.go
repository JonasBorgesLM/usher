// redirectOAuthError is RFC 6749 §4.1.2.1's error shape, shared by every
// handler that reports a problem to an already-verified redirect_uri
// (authorize.go's RS-28 step 3, consent.go's denial path): always carries
// iss (RS-29/RFC 9207), echoes state unchanged when the request carried
// one (RS-03), and never redirects anywhere the caller has not already
// confirmed is the client's own registered URI.
package main

import (
	"log/slog"
	"net/http"
	"net/url"
)

func redirectOAuthError(
	w http.ResponseWriter, r *http.Request, logger *slog.Logger,
	issuer, redirectURI, state, errCode, description string,
	onParseError func(message string),
) {
	u, err := url.Parse(redirectURI)
	if err != nil {
		// Every call site reaches this function only after
		// exactRedirectURIMatch has already confirmed redirectURI against
		// the client's registered list, and LoadClients refuses an
		// unparsable redirect_uri at startup (#25) -- this path is
		// defensive, not expected to be reachable.
		logger.ErrorContext(r.Context(), "oauth: parse verified redirect_uri", "error", err)
		onParseError("internal error")
		return
	}
	q := u.Query()
	q.Set("error", errCode)
	if description != "" {
		q.Set("error_description", description)
	}
	if state != "" {
		q.Set("state", state)
	}
	q.Set("iss", issuer)
	u.RawQuery = q.Encode()
	// #nosec G710 -- every call site reaches this function only after
	// exactRedirectURIMatch has already confirmed redirectURI against the
	// client's registered list (RS-28 step 2); that is the actual control,
	// asserted by TestAuthorize_RedirectURIVariantsRejected and
	// TestAuthorize_BothRedirectURIAndPKCEFailGetsNonRedirectingResponse,
	// not a taint-analysis-shaped one at this call.
	http.Redirect(w, r, u.String(), http.StatusFound)
}

// redirectWithCode is RF-02 Flow 1 step 11's success counterpart to
// redirectOAuthError: code, the original state unchanged (RS-03), and iss
// (RS-29), on the same already-verified redirect_uri. The code in the
// query string is RS-24's one deliberate exception — "the authorization
// code in the redirect is the one parameter the protocol puts there."
func redirectWithCode(w http.ResponseWriter, r *http.Request, logger *slog.Logger, issuer, redirectURI, state, code string) {
	u, err := url.Parse(redirectURI)
	if err != nil {
		// Unreachable in practice: redirectURI here is always a
		// Challenge's own field, itself copied from a request
		// exactRedirectURIMatch already accepted and LoadClients already
		// validated as absolute (#25, #26) before the challenge was ever
		// saved.
		logger.ErrorContext(r.Context(), "oauth: parse verified redirect_uri", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	q := u.Query()
	q.Set("code", code)
	if state != "" {
		q.Set("state", state)
	}
	q.Set("iss", issuer)
	u.RawQuery = q.Encode()
	// #nosec G710 -- same reasoning as redirectOAuthError above: redirectURI
	// reaches this function only after exactRedirectURIMatch has already
	// confirmed it against the client's registered list.
	http.Redirect(w, r, u.String(), http.StatusFound)
}
