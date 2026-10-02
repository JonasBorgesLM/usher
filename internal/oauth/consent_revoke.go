// consent_revoke.go holds RF-13's own orchestration, pulled out ahead of
// any HTTP caller the same way #29's ConsumeCode and #36's
// RotateRefreshToken already were — REQUIREMENTS §1.1 rules out an admin
// UI or API for this study project ("no rich user management beyond what
// authentication requires"), so RevokeConsent's only caller for now is
// whatever operational tooling invokes it directly; what it must
// guarantee does not depend on one existing yet.

package oauth

import (
	"context"
	"fmt"
)

// RevokeConsent is RF-13: revoking a (subject, clientID) consent grant
// also revokes every refresh family issued under it. Families are
// revoked first, the consent row second — the opposite order fails
// unsafe: a crash between the two would leave the consent row gone (so
// the user believes nothing is granted) while a family it produced is
// still live, exactly the drift RF-13 exists to prevent. This order
// instead leaves every token this consent produced already unusable
// even if the second call never runs; ConsentStore.Revoke's own
// idempotency ("revoking a grant that does not exist is a no-op")
// covers the retry a partial failure here invites.
func RevokeConsent(ctx context.Context, consents ConsentStore, families FamilyStore, subject, clientID string) error {
	if err := families.RevokeForSubjectAndClient(ctx, subject, clientID, "consent_revoked"); err != nil {
		return fmt.Errorf("oauth: revoke families for consent: %w", err)
	}
	if err := consents.Revoke(ctx, subject, clientID); err != nil {
		return fmt.Errorf("oauth: revoke consent: %w", err)
	}
	return nil
}
