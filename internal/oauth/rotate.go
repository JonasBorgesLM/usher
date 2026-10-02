// RotateRefreshToken is RF-04 Flow 3's steps 5-6 (docs/ARCHITECTURE.md
// §12), pulled out as its own function so #37's /token handler can call
// it unchanged, the same way #29's ConsumeCode and #30's /token handler
// already established for authorization codes.

package oauth

import (
	"context"
	"fmt"
	"time"

	"github.com/JonasBorgesLM/usher/internal/audit"
)

// RotateRefreshToken attempts FamilyStore.Rotate's atomic compare-and-set
// (RS-11) and, on reuse (consumed == false — the presented token was
// already consumed, or lost a race against a concurrent caller that
// ADR-0012 treats identically, by design), revokes the family and emits
// a high-severity audit event before returning ErrInvalidGrant — the
// same sentinel ConsumeCode's own failures already use, RS-25's
// ambiguity held here too.
//
// next must already carry the FamilyID the caller resolved (RS-34's
// binding checks, #37) — this function does not look it up itself.
func RotateRefreshToken(ctx context.Context, families FamilyStore, emitter audit.Emitter, hash [32]byte, next RefreshToken) error {
	consumed, err := families.Rotate(ctx, hash, next)
	if err != nil {
		return fmt.Errorf("oauth: rotate refresh token: %w", err)
	}
	if !consumed {
		if revokeErr := families.Revoke(ctx, next.FamilyID, "reuse_detected"); revokeErr != nil {
			return fmt.Errorf("oauth: revoke reused family: %w", revokeErr)
		}
		emitter.Emit(ctx, audit.Event{
			Type:    audit.EventRefreshReuse,
			Outcome: audit.OutcomeFailure,
			At:      time.Now(),
		})
		return ErrInvalidGrant
	}
	return nil
}
