// GET/POST /consent is RF-13's consent flow: if a prior grant already
// covers the requested scope, or the client never requires consent (RF-01),
// skip the form; otherwise render it, with the client id and requested
// scopes rendered through html/template's default escaping, never
// template.HTML (RS-36, T-21/T-20). Once consent is satisfied,
// completeConsent finishes RF-02 Flow 1 itself (docs/ARCHITECTURE.md §10,
// steps 10-11): consume the challenge, mint a fresh Code, and redirect to
// redirect_uri with it — #30's /token handler is this Code's only
// consumer.
package main

import (
	"html/template"
	"log/slog"
	"net/http"
	"net/url"
	"time"

	"github.com/JonasBorgesLM/moat/csrf"
	"github.com/JonasBorgesLM/usher/internal/identity"
	"github.com/JonasBorgesLM/usher/internal/oauth"
	"github.com/JonasBorgesLM/usher/internal/session"
)

type consentHandler struct {
	clients    []identity.Client
	challenges session.ChallengeStore
	consents   oauth.ConsentStore
	codes      oauth.CodeStore
	protector  *csrf.Protector
	issuer     string
	codeTTL    time.Duration
	now        func() time.Time

	consentTmpl *template.Template
	errorTmpl   *template.Template
	logger      *slog.Logger
}

type consentPageData struct {
	CSRFToken string
	Challenge string
	ClientID  string
	Scope     []string
}

func (h *consentHandler) get(w http.ResponseWriter, r *http.Request) {
	h.serve(w, r, r.URL.Query().Get("login_challenge"))
}

func (h *consentHandler) serve(w http.ResponseWriter, r *http.Request, challengeID string) {
	challenge, err := h.challenges.Get(r.Context(), challengeID)
	if err != nil {
		h.renderError(w, r, "unknown or expired authorization request")
		return
	}
	if challenge.Subject == "" {
		// Login has not happened yet for this challenge -- send it there
		// first, the same hand-off direction login.go's own completeLogin
		// uses going the other way.
		http.Redirect(w, r, "/login?login_challenge="+url.QueryEscape(challengeID), http.StatusSeeOther)
		return
	}

	client, ok := lookupClient(h.clients, challenge.ClientID)
	if !ok {
		// /authorize already validated this client_id when the challenge
		// was created (#26); reaching here with an unknown one means the
		// registry changed under a live challenge, not a client mistake.
		h.logger.ErrorContext(r.Context(), "consent: challenge's client_id no longer in the registry", "client_id", challenge.ClientID)
		h.renderError(w, r, "internal error")
		return
	}

	if !client.RequireConsent {
		h.completeConsent(w, r, challenge)
		return
	}

	granted, ok, err := h.consents.Granted(r.Context(), challenge.Subject, challenge.ClientID)
	if err != nil {
		h.logger.ErrorContext(r.Context(), "consent: look up prior grant", "error", err)
		h.renderError(w, r, "internal error")
		return
	}
	if ok && scopeSubset(challenge.Scope, granted) {
		h.completeConsent(w, r, challenge)
		return
	}

	h.renderConsentForm(w, r, challenge)
}

func (h *consentHandler) post(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	challengeID := r.PostForm.Get("login_challenge")
	challenge, err := h.challenges.Get(r.Context(), challengeID)
	if err != nil {
		h.renderError(w, r, "unknown or expired authorization request")
		return
	}
	if challenge.Subject == "" {
		http.Redirect(w, r, "/login?login_challenge="+url.QueryEscape(challengeID), http.StatusSeeOther)
		return
	}

	if r.PostForm.Get("decision") != "allow" {
		redirectOAuthError(w, r, h.logger, h.issuer, challenge.RedirectURI, challenge.State,
			"access_denied", "the resource owner denied the request",
			func(message string) { h.renderError(w, r, message) })
		return
	}

	granted, _, err := h.consents.Granted(r.Context(), challenge.Subject, challenge.ClientID)
	if err != nil {
		h.logger.ErrorContext(r.Context(), "consent: look up prior grant", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if err := h.consents.Grant(r.Context(), challenge.Subject, challenge.ClientID, unionScope(granted, challenge.Scope)); err != nil {
		h.logger.ErrorContext(r.Context(), "consent: grant", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	h.completeConsent(w, r, challenge)
}

// completeConsent is RF-02 Flow 1 steps 10-11 (docs/ARCHITECTURE.md §10):
// ChallengeStore.Consume (single-use, RS-05) for the final Challenge, mint
// a fresh Code from crypto/rand bound to its client_id, redirect_uri,
// code_challenge, nonce and scope (RS-04, RS-30), CodeStore.Save it, and
// redirect to redirect_uri with code, the original state unchanged
// (RS-03), and iss (RS-29).
func (h *consentHandler) completeConsent(w http.ResponseWriter, r *http.Request, challenge session.Challenge) {
	final, err := h.challenges.Consume(r.Context(), challenge.ID)
	if err != nil {
		h.logger.ErrorContext(r.Context(), "consent: consume challenge", "error", err)
		h.renderError(w, r, "internal error")
		return
	}

	value, err := session.NewRawID()
	if err != nil {
		h.logger.ErrorContext(r.Context(), "consent: generate code", "error", err)
		h.renderError(w, r, "internal error")
		return
	}
	code := oauth.Code{
		Value:         value,
		ClientID:      final.ClientID,
		RedirectURI:   final.RedirectURI,
		CodeChallenge: final.CodeChallenge,
		Nonce:         final.Nonce,
		Scope:         final.Scope,
		Subject:       final.Subject,
		ExpiresAt:     h.now().Add(h.codeTTL),
	}
	if err := h.codes.Save(r.Context(), code); err != nil {
		h.logger.ErrorContext(r.Context(), "consent: save code", "error", err)
		h.renderError(w, r, "internal error")
		return
	}

	redirectWithCode(w, r, h.logger, h.issuer, final.RedirectURI, final.State, code.Value)
}

func (h *consentHandler) renderConsentForm(w http.ResponseWriter, r *http.Request, c session.Challenge) {
	data := consentPageData{Challenge: c.ID, ClientID: c.ClientID, Scope: c.Scope}
	if token, ok := csrf.Token(r); ok {
		data.CSRFToken = token
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := h.consentTmpl.Execute(w, data); err != nil {
		h.logger.ErrorContext(r.Context(), "consent: render consent form", "error", err)
	}
}

type consentErrorPageData struct {
	Message string
}

func (h *consentHandler) renderError(w http.ResponseWriter, r *http.Request, message string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusBadRequest)
	if err := h.errorTmpl.Execute(w, consentErrorPageData{Message: message}); err != nil {
		h.logger.ErrorContext(r.Context(), "consent: render error page", "error", err)
	}
}

// unionScope is RF-13: a new grant replaces the stored scope with the
// union of the prior grant and the newly requested scope, never a loss of
// something already granted.
func unionScope(a, b []string) []string {
	seen := make(map[string]bool, len(a)+len(b))
	out := make([]string, 0, len(a)+len(b))
	for _, s := range a {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	for _, s := range b {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}
