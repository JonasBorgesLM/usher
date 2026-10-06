// GET/POST /logout (RS-27, RS-31, ADR-0021): server-side session deletion
// is the mechanism, and it happens first, before anything else -- the
// cookie clear and the Clear-Site-Data header this route's own wiring
// attaches (router.go) are the browser half, defense in depth a
// non-conforming client or a non-secure origin simply does not get.
//
// Idempotent, the same reasoning revoke.go's own RFC 7009 ambiguity
// already applies: logging out with no session, or one already gone,
// succeeds exactly like a real deletion does -- there is no requirement
// here forcing a different answer, and a client probing this endpoint
// learns nothing about whether a session existed from the response
// shape.
package main

import (
	"html/template"
	"log/slog"
	"net/http"

	"github.com/JonasBorgesLM/moat/csrf"
	"github.com/JonasBorgesLM/usher/internal/session"
)

type logoutHandler struct {
	sessions session.SessionStore

	logoutTmpl    *template.Template
	loggedOutTmpl *template.Template

	logger *slog.Logger
}

type logoutPageData struct {
	CSRFToken string
}

func (h *logoutHandler) get(w http.ResponseWriter, r *http.Request) {
	data := logoutPageData{}
	if token, ok := csrf.Token(r); ok {
		data.CSRFToken = token
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := h.logoutTmpl.Execute(w, data); err != nil {
		h.logger.ErrorContext(r.Context(), "logout: render form", "error", err)
	}
}

// post is RS-31 itself: delete the server-side session before writing
// anything to the response -- a crash or a slow client between the
// delete and the reply still leaves the session gone, which is the
// property a cookie-clear-only logout would not have.
func (h *logoutHandler) post(w http.ResponseWriter, r *http.Request) {
	if rawID, err := session.RawSessionID(r); err == nil {
		if delErr := h.sessions.Delete(r.Context(), rawID); delErr != nil {
			h.logger.ErrorContext(r.Context(), "logout: delete session", "error", delErr)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
	}

	http.SetCookie(w, session.ExpiredSessionCookie())

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := h.loggedOutTmpl.Execute(w, nil); err != nil {
		h.logger.ErrorContext(r.Context(), "logout: render confirmation", "error", err)
	}
}
