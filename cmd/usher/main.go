// Command usher runs the OAuth 2.1 / OpenID Connect authorization server and
// the reverse-proxy gateway in one process, with rigid package boundaries
// between them (ADR-0001). See REQUIREMENTS.md §11 for the phase plan this
// binary is wired up incrementally against.
package main

import (
	"fmt"
	"os"
)

func main() {
	fmt.Fprintln(os.Stderr, "usher: not implemented yet — see REQUIREMENTS.md §11 for the phase plan")
	os.Exit(1)
}
