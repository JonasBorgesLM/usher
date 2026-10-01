package session

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/JonasBorgesLM/moat/csrf"
)

// RotateLogin performs RS-12b's two rotations together, in the order that
// makes a partial failure safe: moat's CSRF token first — csrf.Rotate
// itself refuses, rather than silently doing nothing, once the response
// has begun (ErrHeadersAlreadySent) — then this project's own session id.
// Calling only Rotate "looks like it solves both" and solves only the
// first; moat's own documentation says so precisely because that is the
// mistake this function exists to prevent.
//
// oldRawID is the session cookie's value before login, if the request
// carried one — an anonymous or stale session planted before login — or ""
// if none. When non-empty, that session is deleted: login must not let a
// pre-existing id become a logged-in session merely by continuing to
// exist once the user authenticates under it.
//
// Both halves write to w. Call RotateLogin before writing anything else to
// the response, for the same reason csrf.Rotate itself documents: once
// anything has been written, net/http has serialized the header block, and
// a Set-Cookie added afterward is discarded without complaint.
func RotateLogin(
	ctx context.Context,
	w http.ResponseWriter,
	r *http.Request,
	protector *csrf.Protector,
	store SessionStore,
	oldRawID, subject string,
	authTime time.Time,
	idleTTL, absoluteTTL time.Duration,
) (BrowserSession, error) {
	if _, err := protector.Rotate(w, r); err != nil {
		return BrowserSession{}, fmt.Errorf("session: rotate CSRF token: %w", err)
	}

	if oldRawID != "" {
		if err := store.Delete(ctx, oldRawID); err != nil {
			return BrowserSession{}, fmt.Errorf("session: delete pre-login session: %w", err)
		}
	}

	rawID, err := NewRawID()
	if err != nil {
		return BrowserSession{}, err
	}
	sess := BrowserSession{
		ID:        rawID,
		Subject:   subject,
		AuthTime:  authTime,
		IdleUntil: authTime.Add(idleTTL),
		ExpiresAt: authTime.Add(absoluteTTL),
	}
	if err := store.Save(ctx, sess); err != nil {
		return BrowserSession{}, fmt.Errorf("session: save new session: %w", err)
	}

	http.SetCookie(w, NewSessionCookie(rawID, absoluteTTL))
	return sess, nil
}
