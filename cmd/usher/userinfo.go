// GET /userinfo (OIDC Core, RS-08, RS-26): the one protocol surface a
// bearer access token reaches on usher itself rather than at a resource
// server. RS-08 groups it with the gateway deliberately — "presenting an
// ID token to the gateway, or to /userinfo, must produce 401" — so this
// handler validates exactly the way internal/proxy's own gateway handler
// does: pkg/tokenvalidator.ValidateAccessToken, typ and aud checked
// together, failure is one bare 401 with no body (RS-23/RS-25's "no
// internal detail" discipline, extended here so a caller cannot tell
// "no token" from "wrong typ" from "wrong aud" from "expired" by response
// shape). It never imports internal/proxy to get there — *tokenvalidator
// .Validator is the one seam RS-18/RS-19's defense in depth already
// shares between the gateway and this binary, not a reason to import a
// package ADR-0001 keeps internal/oauth and internal/oidc away from.
//
// userinfoAudience is RS-08's "/userinfo is itself a protected resource"
// half: an access token issued for an openid-scoped request carries this
// value alongside the resource server's own audience (issueAccessToken,
// token.go) and only a token carrying it is accepted here. Derived from
// the issuer rather than a separate config field — a second, independent
// audience value would need its own justification this project has no
// operational reason to supply.
package main

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"

	"github.com/JonasBorgesLM/usher/pkg/tokenvalidator"
)

func userinfoAudience(issuer string) string {
	return issuer + "/userinfo"
}

// userinfoBody is OIDC Core's UserInfo response narrowed to the one claim
// this project's identity.User actually has anything to say about: sub.
// usher's own User model carries no name, email or other profile data —
// inventing those claims here would be fabricating data this study
// project does not model, not implementing OIDC Core more completely.
type userinfoBody struct {
	Subject string `json:"sub"`
}

type userinfoHandler struct {
	validator *tokenvalidator.Validator
	audience  string
	logger    *slog.Logger
}

func (h *userinfoHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	raw, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok || raw == "" {
		userinfoUnauthorized(w)
		return
	}

	claims, err := h.validator.ValidateAccessToken(r.Context(), raw, h.audience)
	if err != nil {
		userinfoUnauthorized(w)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if encodeErr := json.NewEncoder(w).Encode(userinfoBody{Subject: claims.Subject}); encodeErr != nil {
		h.logger.ErrorContext(r.Context(), "userinfo: encode response", "error", encodeErr)
	}
}

// userinfoUnauthorized mirrors internal/proxy's own gateway convention
// exactly (see proxy.go's unauthorized) — RS-08's sentence treats the two
// call sites as one rule, so this file's own failure response matches it
// rather than inventing a second shape for the same case.
func userinfoUnauthorized(w http.ResponseWriter) {
	w.WriteHeader(http.StatusUnauthorized)
}
