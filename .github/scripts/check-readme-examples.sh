#!/usr/bin/env bash
#
# README examples run in CI (REQUIREMENTS §10, #51): the first commands a
# visitor copies out of the "## Testing" section must actually work. Extracted
# from the file itself, not a second, hand-typed copy of the same lines --
# a hand-typed copy is exactly what goes stale the next time that section
# changes and nobody remembers this script exists.
#
#   ./.github/scripts/check-readme-examples.sh
#
# Comment lines and blank lines inside the fenced block are skipped; every
# other line is run verbatim, in order, from the repository root. The first
# one that fails is reported with its own exit code -- not swallowed into a
# generic "something broke."

set -uo pipefail
cd "$(dirname "$0")/../.."

README="README.md"
[ -f "$README" ] || { echo "FAIL  $README is missing"; exit 1; }

# Pull the fenced bash block that immediately follows the "## Testing"
# heading: from the first ```bash line after it to the next closing ```.
block=$(awk '
  /^## Testing$/ { intesting = 1; next }
  intesting && /^## / { exit }
  intesting && /^```bash$/ { infence = 1; next }
  infence && /^```$/ { exit }
  infence { print }
' "$README")

if [ -z "$block" ]; then
  echo "FAIL  no \`\`\`bash block found under '## Testing' in $README"
  exit 1
fi

commands=$(printf '%s\n' "$block" | grep -vE '^[[:space:]]*(#|$)')
if [ -z "$commands" ]; then
  echo "FAIL  the '## Testing' block in $README has no runnable lines"
  exit 1
fi

count=0
while IFS= read -r line; do
  count=$((count + 1))
  echo "+ $line"
  # status captured on its own line, before anything else runs: `if ! cmd`
  # re-evaluates the condition's own (negated) truth value into $?, not
  # cmd's real exit code -- `status=$?` inside that branch is 0 every
  # time, regardless of what cmd actually returned. Found by this
  # script's own first negative-control run (#51): the FAIL line printed
  # "(exit 0)" for a command that had very much not exited 0.
  bash -c "$line"
  status=$?
  if [ "$status" -ne 0 ]; then
    echo "FAIL  README.md's own Testing example failed (exit $status): $line"
    echo "      Either the command is wrong, or the README drifted from what this project actually runs."
    exit 1
  fi
done <<< "$commands"

echo "ok    $count README testing example(s) ran successfully"
