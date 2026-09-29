// Command resource-server is the demo protected service behind usher's
// gateway (RI-05, ADR-0013). It re-validates tokens itself against the
// published JWKS (RS-18): its future implementation imports
// pkg/tokenvalidator and nothing under internal/, so it validates exactly as
// an outside consumer would — the same way task-api or any other resource
// server behind the gateway eventually would. check-boundaries.sh enforces
// that this binary never imports internal/.
package main

import (
	"fmt"
	"os"
)

func main() {
	fmt.Fprintln(os.Stderr, "resource-server: not implemented yet — see REQUIREMENTS.md §11 for the phase plan")
	os.Exit(1)
}
