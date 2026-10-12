#!/usr/bin/env bash
#
# Package boundaries (ADR-0001), asserted by reachability rather than trusted.
#
# The authorization server and the gateway share one binary. What keeps a later
# split a deployment change instead of a rewrite is that the protocol packages
# and the proxy package never reach each other -- directly or through anything
# they import. A reviewer cannot see a transitive import; `go list -deps` can.
#
#   ./.github/scripts/check-boundaries.sh
#
# Each rule is "FROM TO": no package at or under FROM may depend, at any depth,
# on a package at or under TO. Paths are relative to the module.
RULES='
internal/oauth           internal/proxy
internal/proxy           internal/oauth
pkg                      internal
cmd/resource-server      internal
'
# There is no internal/oidc rule: the package held no code and was removed
# (ADR-0001's amendment, #122). OIDC's handlers live in cmd/usher, the
# composition root, which imports everything by design.
#
# Why the last two:
#   pkg/tokenvalidator is the candidate for extraction into moat (REQUIREMENTS
#   §7.4); a dependency on usher's internals would make that impossible.
#   The demo resource server holds no private key (REQUIREMENTS §2) and must
#   validate exactly as an outside consumer would: through pkg/ only.
#
# Not covered: imports made only from _test.go files. `.Deps` is the build
# graph; a test reaching across a boundary is a smell for review, not a split
# blocker, so it is left out rather than half-checked.

set -uo pipefail
cd "$(dirname "$0")/../.."

# Resolve into variables first: piped straight into a loop, a crashed `go list`
# and a clean tree with no violations look identical.
module=$(go list -m) || { echo "FAIL  go list -m failed"; exit 1; }
# -e and an explicit error check, because `go list` exits 0 when the error is in
# a package's *dependencies*: a missing import would otherwise be reported as a
# package with no violations. Found by breaking the tree while testing this.
graph=$(go list -e -f '{{if or .Error .DepsErrors}}!ERROR {{.ImportPath}}{{else}}{{.ImportPath}} {{join .Deps " "}}{{end}}' ./...) || {
  echo "FAIL  go list ./... failed -- the tree does not load, so nothing was checked"; exit 1; }
broken=$(printf '%s\n' "$graph" | awk '$1 == "!ERROR" {print "  " $2}')
if [ -n "$broken" ]; then
  echo "FAIL  these packages do not load, so their boundaries cannot be checked:"
  printf '%s\n' "$broken"
  echo "      Run 'go build ./...' to see why."
  exit 1
fi

if [ -z "$graph" ]; then
  if [ -n "$(find . -name '*.go' -not -path './.git/*' -print -quit)" ]; then
    echo "FAIL  .go files exist but go list found no packages"; exit 1
  fi
  echo "-     no Go packages yet; boundaries have nothing to check (this goes away with the first package)"
  exit 0
fi

under() { [ "$1" = "$2" ] || case "$1" in "$2"/*) return 0 ;; *) return 1 ;; esac; }

violations=""; checked=0
while read -r pkg deps; do
  rel=${pkg#"$module"/}
  checked=$((checked + 1))
  while read -r from to; do
    [ -n "$from" ] || continue
    under "$rel" "$from" || continue
    for d in $deps; do
      case "$d" in "$module"/*) ;; *) continue ;; esac
      under "${d#"$module"/}" "$to" && violations="$violations\n  $rel -> ${d#"$module"/}   (rule: $from must not reach $to)"
    done
  done <<< "$RULES"
done <<< "$graph"

if [ -n "$violations" ]; then
  printf '\033[31mFAIL\033[0m  package boundary violated:'; printf "$violations\n"
  echo
  echo "Each rule's reason is in the comment at the top of this script: the"
  echo "protocol and the proxy never reach each other (ADR-0001); pkg/ stays"
  echo "extractable; the demo resource server validates like an outside consumer."
  echo "Move the shared piece into pkg/tokenvalidator, internal/keys or a store --"
  echo "or write an ADR amending ADR-0001 before changing a rule here."
  exit 1
fi
echo "ok    package boundaries hold ($checked packages checked)"
