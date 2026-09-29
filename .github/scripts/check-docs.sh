#!/usr/bin/env bash
#
# Documentation freshness checks.
#
# A file rather than inline YAML on purpose: a CI check nobody can run locally
# is one people meet for the first time on a red pull request, and then learn to
# resent. Run it before pushing:
#
#   ./.github/scripts/check-docs.sh
#
# Each check answers a way documentation has actually rotted, not a style
# preference. Every failure prints what to do, because a checker that only says
# "no" gets disabled.
#
# ---------------------------------------------------------------------------
# usher's documents. Ids are Portuguese-derived, as in cistern: RF functional,
# RS security, RNF non-functional, RI integration.
REQUIREMENTS_FILE="REQUIREMENTS.md"
THREAT_MODEL_FILE="docs/THREAT-MODEL.md"
ADR_DIR="docs/adr"
ID_PREFIXES="RF|RS|RNF|RI"
# ---------------------------------------------------------------------------

set -uo pipefail
cd "$(dirname "$0")/../.."

FAILED=0
fail() { printf '\n\033[31mFAIL\033[0m  %s\n' "$1"; FAILED=1; }
pass() { printf '\033[32mok\033[0m    %s\n' "$1"; }
note() { printf '        %s\n' "$1"; }
skip() { printf '\033[33m-\033[0m     %s\n' "$1"; }

# --- 1. The ADR index and the ADR files agree, in both directions -----------
#
# A new ADR nobody indexed is invisible; an indexed ADR whose file was renamed
# is a dead link in the one document that is supposed to be the map.
if [ -n "$ADR_DIR" ] && [ -d "$ADR_DIR" ]; then
  missing_index=""; missing_file=""
  for f in "$ADR_DIR"/[0-9]*.md; do
    [ -e "$f" ] || continue
    grep -q "($(basename "$f"))" "$ADR_DIR/README.md" 2>/dev/null || missing_index="$missing_index $(basename "$f")"
  done
  for l in $(grep -oE '\(([0-9]{4}-[a-z0-9-]+\.md)\)' "$ADR_DIR/README.md" 2>/dev/null | tr -d '()'); do
    [ -f "$ADR_DIR/$l" ] || missing_file="$missing_file $l"
  done
  if [ -n "$missing_index" ]; then
    fail "ADR files with no row in $ADR_DIR/README.md:$missing_index"
    note "An unindexed ADR is one nobody finds."
  elif [ -n "$missing_file" ]; then
    fail "$ADR_DIR/README.md links to files that do not exist:$missing_file"
  else
    pass "ADR index matches the ADR files ($(ls "$ADR_DIR"/[0-9]*.md 2>/dev/null | wc -l | tr -d ' ') records)"
  fi
else
  skip "no ADR directory configured"
fi

# --- 2. Every cited requirement id resolves --------------------------------
#
# Ids are cited from ADRs, code comments, tests and commit messages. A citation
# of a renumbered requirement is a reader following a reference to nothing.
#
# Cross-project citations are written qualified -- `other/IR-06` -- and skipped
# here; unqualified they would be checked against this project's numbering.
if [ -n "$REQUIREMENTS_FILE" ] && [ -f "$REQUIREMENTS_FILE" ]; then
  defined=$(grep -oE "\*\*($ID_PREFIXES)-[0-9]{2}" "$REQUIREMENTS_FILE" | tr -d '*' | sort -u)
  referenced=$(grep -rhoE "(^|[^/[:alnum:]])($ID_PREFIXES)-[0-9]{2}\b" \
                 --include='*.md' --include='*.go' --include='*.ts' --include='*.tsx' \
                 --include='*.js' --include='*.py' --include='*.yml' \
                 . 2>/dev/null | grep -oE "($ID_PREFIXES)-[0-9]{2}" | sort -u)
  dangling=""
  for id in $referenced; do printf '%s\n' "$defined" | grep -qx "$id" || dangling="$dangling $id"; done
  if [ -n "$dangling" ]; then
    fail "citations to requirement ids that $REQUIREMENTS_FILE does not define:$dangling"
    note "Either the requirement was renumbered, or the citation is a typo."
    note "A cross-project citation must be qualified, e.g. otherproject/IR-06."
  else
    pass "every requirement citation resolves ($(printf '%s\n' "$defined" | grep -c . ) defined)"
  fi
else
  skip "no requirements file configured"
fi

# --- 3. Every cited threat id resolves -------------------------------------
if [ -n "$THREAT_MODEL_FILE" ] && [ -f "$THREAT_MODEL_FILE" ]; then
  threats=$(grep -oE '^### T-[0-9]{2}' "$THREAT_MODEL_FILE" | awk '{print $2}' | sort -u)
  refs=$(grep -rhoE '\bT-[0-9]{2}\b' --include='*.md' --include='*.go' --include='*.ts' . 2>/dev/null | sort -u)
  dangling=""
  for id in $refs; do printf '%s\n' "$threats" | grep -qx "$id" || dangling="$dangling $id"; done
  if [ -n "$dangling" ]; then
    fail "citations to threat ids that $THREAT_MODEL_FILE does not define:$dangling"
  else
    pass "every threat citation resolves ($(printf '%s\n' "$threats" | grep -c . ) defined)"
  fi
else
  skip "no threat model configured"
fi

# --- 4. Every relative link between documents resolves ---------------------
#
# The cheapest kind of rot: a document moves and six links go stale in silence.
# External URLs are deliberately not checked -- a network check that fails on a
# transient outage teaches people to ignore the job.
#
# Skill and agent instruction files are skipped: they are prompts, and the paths
# in them are illustrative ("write to artifacts/entities.md"), not links to
# files that exist. Checking them produces noise, and a checker that cries wolf
# gets disabled -- which was found by running this against a real .claude/ tree.
broken=""
while IFS= read -r doc; do
  dir=$(dirname "$doc")
  for target in $(grep -oE '\]\([^)#][^)]*\)' "$doc" | sed 's/^](//; s/)$//' | grep -v '^https\?://' | grep -v '^mailto:'); do
    clean=${target%%#*}; [ -z "$clean" ] && continue
    [ -e "$dir/$clean" ] || broken="$broken\n  $doc -> $target"
  done
done < <(find . -name '*.md' -not -path './.git/*' -not -path '*/node_modules/*' \
             -not -path './graphify-out/*' -not -path '*/skills/*' -not -path '*/agents/*')

if [ -n "$broken" ]; then
  fail "broken relative links:"; printf "$broken\n"
else
  pass "every relative document link resolves"
fi

echo
if [ "$FAILED" -ne 0 ]; then echo "Documentation checks failed."; exit 1; fi
echo "Documentation checks passed."
