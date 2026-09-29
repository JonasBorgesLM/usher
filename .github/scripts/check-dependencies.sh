#!/usr/bin/env bash
#
# Dependency allow-list (RNF-09): every direct dependency is named, with its
# justification, in .github/dependency-allowlist.txt -- and a pinned one at
# exactly its pinned version.
#
#   ./.github/scripts/check-dependencies.sh
#
# The resolver is asked, not go.mod grepped. A grep of the manifest once matched
# a comment naming a dependency and read its trailing comma as a version.

set -uo pipefail
cd "$(dirname "$0")/../.."
ALLOWLIST=".github/dependency-allowlist.txt"

[ -f "$ALLOWLIST" ] || { echo "FAIL  $ALLOWLIST is missing"; exit 1; }

direct=$(go list -m -f '{{if and (not .Main) (not .Indirect)}}{{.Path}} {{.Version}}{{end}}' all) || {
  echo "FAIL  go list -m all failed -- the module graph does not resolve, so nothing was checked"; exit 1; }

allowed=$(grep -vE '^[[:space:]]*(#|$)' "$ALLOWLIST")
failed=0

# Every justification that cites an ADR must cite one that exists.
for adr in $(printf '%s\n' "$allowed" | grep -oE 'ADR-[0-9]{4}' | sort -u); do
  ls docs/adr/"${adr#ADR-}"-*.md >/dev/null 2>&1 || { echo "FAIL  $ALLOWLIST cites $adr, which does not exist"; failed=1; }
done
# Every entry carries a justification.
while read -r mod ver why; do
  [ -n "$why" ] || { echo "FAIL  $ALLOWLIST: $mod has no justification"; failed=1; }
done <<< "$allowed"

count=0
while read -r mod ver; do
  [ -n "$mod" ] || continue
  count=$((count + 1))
  entry=$(printf '%s\n' "$allowed" | awk -v m="$mod" '$1 == m')
  if [ -z "$entry" ]; then
    echo "FAIL  $mod $ver is a direct dependency not on the allow-list"
    echo "      RNF-02: each dependency is justified by an ADR. Write it, then add"
    echo "      '$mod  *  ADR-nnnn  reason' to $ALLOWLIST."
    failed=1; continue
  fi
  pinned=$(printf '%s\n' "$entry" | awk '{print $2}')
  if [ "$pinned" != "*" ] && [ "$pinned" != "$ver" ]; then
    echo "FAIL  $mod is at $ver but pinned to $pinned"
    echo "      Pinned dependencies are upgraded by hand, verified from a clean"
    echo "      directory with GOWORK=off (ADR-0011). Change the pin in the same PR."
    failed=1
  fi
done <<< "$direct"

[ "$failed" -eq 0 ] || exit 1
echo "ok    $count direct dependencies, all allow-listed"
