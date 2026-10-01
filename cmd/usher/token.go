// POST /token is RF-02 Flow 2 (docs/ARCHITECTURE.md §11), M2's slice of it:
// the authorization_code grant, issuing an access token only — no refresh
// token (M4), no id_token (M7). Client authentication (RS-16), PKCE
// re-verification and replay detection are oauth.ConsumeCode's own job
// (#29); this handler authenticates the client, calls it, and on success
// signs the access token with typ: at+jwt (RFC 9068) and the requested
// resource server's audience. Every error follows RFC 6749 §5.2's fixed
// codes (RS-25) — invalid_grant in particular never varies its body across
// any of ConsumeCode's distinct failure causes.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jws"

	"github.com/JonasBorgesLM/usher/internal/identity"
	"github.com/JonasBorgesLM/usher/internal/keys"
	"github.com/JonasBorgesLM/usher/internal/oauth"
	"github.com/JonasBorgesLM/usher/internal/session"
	"github.com/JonasBorgesLM/usher/pkg/tokenvalidator"
)

type tokenHandler struct {
	clients        []identity.Client
	codes          oauth.CodeStore
	keyset         *keys.Keyset
	issuer         string
	accessTokenTTL time.Duration
	now            func() time.Time
	logger         *slog.Logger
}

// tokenErrorBody is RFC 6749 §5.2's fixed error shape.
type tokenErrorBody struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description,omitempty"`
}

// tokenSuccessBody is RFC 6749 §5.1's response, M2's slice of RF-03: no
// refresh_token, no id_token.
type tokenSuccessBody struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
	Scope       string `json:"scope,omitempty"`
}

// accessTokenClaims is RS-07's full claim set for an access token:
// iss/aud/exp/nbf/iat/jti, plus sub, client_id and scope, which RFC 9068
// requires even though RS-07's own list does not spell them out
// separately. typ: at+jwt (RS-07, RS-08) lives in the JWS protected
// header, per RFC 9068 — not here.
type accessTokenClaims struct {
	Issuer    string   `json:"iss"`
	Subject   string   `json:"sub"`
	Audience  []string `json:"aud"`
	ClientID  string   `json:"client_id"`
	Scope     string   `json:"scope,omitempty"`
	ExpiresAt int64    `json:"exp"`
	NotBefore int64    `json:"nbf"`
	IssuedAt  int64    `json:"iat"`
	JTI       string   `json:"jti"`
}

func (h *tokenHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		h.writeError(w, http.StatusBadRequest, "invalid_request")
		return
	}

	if r.PostForm.Get("grant_type") != "authorization_code" {
		h.writeError(w, http.StatusBadRequest, "unsupported_grant_type")
		return
	}

	client, errCode := h.authenticateClient(r)
	if errCode != "" {
		if errCode == "invalid_client" {
			w.Header().Set("WWW-Authenticate", `Basic realm="usher"`)
			h.writeError(w, http.StatusUnauthorized, errCode)
			return
		}
		h.writeError(w, http.StatusBadRequest, errCode)
		return
	}

	code := r.PostForm.Get("code")
	redirectURI := r.PostForm.Get("redirect_uri")
	verifier := r.PostForm.Get("code_verifier")
	if code == "" || redirectURI == "" || verifier == "" {
		h.writeError(w, http.StatusBadRequest, "invalid_request")
		return
	}

	issued, err := oauth.ConsumeCode(r.Context(), h.codes, noFamilyStore{}, code, client.ID, redirectURI, verifier)
	if err != nil {
		if errors.Is(err, oauth.ErrInvalidGrant) {
			h.writeError(w, http.StatusBadRequest, "invalid_grant")
			return
		}
		h.logger.ErrorContext(r.Context(), "token: consume code", "error", err)
		h.writeError(w, http.StatusInternalServerError, "server_error")
		return
	}

	key, err := h.keyset.Signing(h.now())
	if err != nil {
		h.logger.ErrorContext(r.Context(), "token: no signing key", "error", err)
		h.writeError(w, http.StatusInternalServerError, "server_error")
		return
	}

	jti, err := session.NewRawID()
	if err != nil {
		h.logger.ErrorContext(r.Context(), "token: generate jti", "error", err)
		h.writeError(w, http.StatusInternalServerError, "server_error")
		return
	}

	now := h.now()
	scope := strings.Join(issued.Scope, " ")
	claims := accessTokenClaims{
		Issuer:    h.issuer,
		Subject:   issued.Subject,
		Audience:  client.Audiences,
		ClientID:  client.ID,
		Scope:     scope,
		ExpiresAt: now.Add(h.accessTokenTTL).Unix(),
		NotBefore: now.Unix(),
		IssuedAt:  now.Unix(),
		JTI:       jti,
	}

	accessToken, err := signAccessToken(key, claims)
	if err != nil {
		h.logger.ErrorContext(r.Context(), "token: sign access token", "error", err)
		h.writeError(w, http.StatusInternalServerError, "server_error")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(tokenSuccessBody{
		AccessToken: string(accessToken),
		TokenType:   "Bearer",
		ExpiresIn:   int(h.accessTokenTTL.Seconds()),
		Scope:       scope,
	}); err != nil {
		h.logger.ErrorContext(r.Context(), "token: encode response", "error", err)
	}
}

// authenticateClient is RS-16: client_secret_basic or client_secret_post,
// compared via Client.AuthenticateSecret's constant-time secret.Value
// comparison (RS-15) — never both methods in the same request (RFC 6749
// §2.3.1). A public client authenticates with neither; PKCE is what
// stands in for a secret there (RS-16's own wording). Every failure
// collapses to the same "invalid_client" regardless of which check
// failed — an unknown client_id and a wrong secret are indistinguishable
// to the caller, the same ambiguity RS-25 already requires of
// invalid_grant, applied here to client lookup instead of code
// consumption.
func (h *tokenHandler) authenticateClient(r *http.Request) (client identity.Client, errCode string) {
	basicID, basicSecret, hasBasic := r.BasicAuth()
	postSecret := r.PostForm.Get("client_secret")
	if hasBasic && postSecret != "" {
		return identity.Client{}, "invalid_request"
	}

	clientID := r.PostForm.Get("client_id")
	secret := postSecret
	if hasBasic {
		clientID, secret = basicID, basicSecret
	}

	client, ok := lookupClient(h.clients, clientID)
	if !ok {
		return identity.Client{}, "invalid_client"
	}
	if client.Confidential && !client.AuthenticateSecret(secret) {
		return identity.Client{}, "invalid_client"
	}
	return client, ""
}

// writeError writes RFC 6749 §5.2's fixed error shape with no
// error_description (RS-25: no internal detail) — every call site in
// this file passes the same nothing, so the field exists on the wire
// type for spec completeness without a parameter here that would always
// carry one value.
func (h *tokenHandler) writeError(w http.ResponseWriter, status int, errCode string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(tokenErrorBody{Error: errCode}); err != nil {
		h.logger.Error("token: encode error response", "error", err)
	}
}

// signAccessToken builds the RS-07 claim set into a compact JWS: typ:
// at+jwt in the protected header (RFC 9068, RS-08), key's own kid carried
// automatically (RS-09, proven for this exact call shape by
// TestKey_SigningProducesKIDHeader in internal/keys).
func signAccessToken(key keys.Key, claims accessTokenClaims) ([]byte, error) {
	payload, err := json.Marshal(claims)
	if err != nil {
		return nil, fmt.Errorf("token: marshal claims: %w", err)
	}

	signingJWK, err := key.JWK()
	if err != nil {
		return nil, fmt.Errorf("token: build signing JWK: %w", err)
	}

	hdrs := jws.NewHeaders()
	if setErr := hdrs.Set(jws.TypeKey, "at+jwt"); setErr != nil {
		return nil, fmt.Errorf("token: set typ header: %w", setErr)
	}

	var alg jwa.SignatureAlgorithm
	switch key.Algorithm {
	case tokenvalidator.RS256:
		alg = jwa.RS256()
	case tokenvalidator.ES256:
		alg = jwa.ES256()
	default:
		return nil, fmt.Errorf("token: signing key %q uses unsupported algorithm %q", key.KID, key.Algorithm)
	}

	signed, err := jws.Sign(payload, jws.WithKey(alg, signingJWK, jws.WithProtectedHeaders(hdrs)))
	if err != nil {
		return nil, fmt.Errorf("token: sign access token: %w", err)
	}
	return signed, nil
}

// noFamilyStore satisfies the oauth.FamilyStore ConsumeCode's signature
// requires (#29), with none of RF-04's machinery built yet (M4). M2 never
// calls CodeStore.Tombstone — there is no refresh-token family a code
// could produce this phase — so TombstonedFamily never reports found, and
// Revoke, the only method ConsumeCode would ever reach on this value, is
// unreachable from any request this phase can produce, including a
// genuine replay (it fails on the atomic Consume alone, same as an
// unknown code — RS-25's ambiguity holds either way). Each method panics
// rather than silently succeeding if that reasoning is ever wrong, the
// same convention pkg/tokenvalidator.Validator's own not-yet-implemented
// methods use.
type noFamilyStore struct{}

func (noFamilyStore) CreateFamily(context.Context, oauth.Family, oauth.RefreshToken) error {
	panic("token: FamilyStore.CreateFamily called in M2, before RF-04 exists")
}

func (noFamilyStore) Rotate(context.Context, [32]byte, oauth.RefreshToken) (bool, error) {
	panic("token: FamilyStore.Rotate called in M2, before RF-04 exists")
}

func (noFamilyStore) Revoke(context.Context, string, string) error {
	panic("token: FamilyStore.Revoke called in M2 -- CodeStore.Tombstone is never called this phase, so this should be unreachable; see this file's doc comment")
}

func (noFamilyStore) RevokeAllForSubject(context.Context, string, string) error {
	panic("token: FamilyStore.RevokeAllForSubject called in M2, before RF-04 exists")
}

func (noFamilyStore) Lookup(context.Context, [32]byte) (oauth.Family, oauth.RefreshToken, error) {
	panic("token: FamilyStore.Lookup called in M2, before RF-04 exists")
}
