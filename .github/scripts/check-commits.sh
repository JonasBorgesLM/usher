#!/usr/bin/env bash
#
# Conventional Commits (RNF-08) on every commit since BASE, and on a PR title.
#
#   ./.github/scripts/check-commits.sh origin/develop
#   ./.github/scripts/check-commits.sh origin/develop "feat(oauth): ..."
#
# The title is checked because a squash merge uses it as the subject: a
# convention enforced on commits and not on the thing that replaces them is
# enforced nowhere.

set -uo pipefail
base=${1:?usage: check-commits.sh BASE [PR_TITLE]}
title=${2:-}

types='feat|fix|docs|test|refactor|perf|build|ci|chore|revert'
# This project's packages and documents. The list is a contract; CONTRIBUTING.md
# carries the same one.
scopes='oauth|oidc|keys|session|identity|rbac|proxy|audit|store|tokenvalidator|rs|config|requirements|threats|adr|docs|deps|ci|security|claude'
pattern="^($types)(\\(($scopes)\\))?!?: .+"

bad=0
check() { # $1 = subject, $2 = where it came from
  if ! printf '%s' "$1" | grep -qE "$pattern"; then
    echo "::error::not a conventional commit ($2): $1"; bad=1; return
  fi
  [ ${#1} -le 72 ] || { echo "::error::subject over 72 characters (${#1}, $2): $1"; bad=1; }
  case "$1" in *.) echo "::error::subject ends with a period ($2): $1"; bad=1 ;; esac
}

shas=$(git rev-list --no-merges "$base"..HEAD) || { echo "::error::git rev-list $base..HEAD failed"; exit 1; }
n=0
for sha in $shas; do
  check "$(git log -1 --format=%s "$sha")" "${sha:0:7}"; n=$((n + 1))
done
[ -z "$title" ] || check "$title" "PR title"

if [ "$bad" -ne 0 ]; then
  echo
  echo "Format:  <type>(<scope>)!: <subject>"
  echo "Types:   $types"
  echo "Scopes:  $scopes"
  echo "Explain WHY in the body and cite the id: Refs RS-04, Closes #33."
  exit 1
fi
echo "ok    $n commits${title:+ and the PR title} follow the convention"
