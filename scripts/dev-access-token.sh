#!/usr/bin/env bash
#
# Prints one real access token from the local compose stack, minted through
# the full authorization_code + PKCE flow (/authorize -> /login -> /consent
# -> /token) as the seeded admin user, scope "openid widgets:read" — the
# token GET /api/widgets accepts. Requires `docker compose up` and
# `go run ./cmd/seed` (the seeded password is a fixed local-dev value).
#
#   ACCESS_TOKEN=$(./scripts/dev-access-token.sh)
#
# Progress goes to stderr, the token alone to stdout. The token lives for
# the AS's access-token TTL (5 minutes by default): mint one per run.

set -euo pipefail

BASE="${USHER_BASE:-http://localhost:8080}"
CLIENT_ID="demo-client"
CLIENT_SECRET="demo-client-secret-dev-only" # clients.dev.json's own dev-only value
REDIRECT_URI="http://localhost:9999/callback"
USER_ID="admin@example.com"
USER_PASS="usher-local-dev-only" # cmd/seed's fixed local-dev password

jar=$(mktemp -d)
trap 'rm -rf "$jar"' EXIT

url_encode() { python3 -c 'import sys, urllib.parse; print(urllib.parse.quote(sys.argv[1], safe=""))' "$1"; }
location() { awk -F': ' 'tolower($1) == "location" {print $2}' | tr -d '\r'; }
csrf_from() { grep -o 'name="moat.csrf" value="[^"]*"' "$1" | sed 's/.*value="//;s/"$//'; }
fail() { echo "dev-access-token: $*" >&2; exit 1; }

verifier=$(openssl rand -hex 32)
challenge=$(printf '%s' "$verifier" | openssl dgst -binary -sha256 | openssl base64 -A | tr '+/' '-_' | tr -d '=')

qs="response_type=code&client_id=${CLIENT_ID}&redirect_uri=$(url_encode "$REDIRECT_URI")&state=dev-token&scope=$(url_encode "openid widgets:read")&code_challenge=${challenge}&code_challenge_method=S256"
loc=$(curl -s -o /dev/null -D - "${BASE}/authorize?${qs}" -b "$jar/c" -c "$jar/c" | location)
case "$loc" in /login\?login_challenge=*) ;; *) fail "unexpected /authorize redirect: ${loc:-none}" ;; esac
login_challenge="${loc#/login?login_challenge=}"

# A fresh cookie jar never has a session, so /login always renders its form.
curl -s -o "$jar/login.html" "${BASE}/login?login_challenge=${login_challenge}" -b "$jar/c" -c "$jar/c"
loc=$(curl -s -o /dev/null -D - "${BASE}/login" -b "$jar/c" -c "$jar/c" -H "Origin: ${BASE}" \
  --data-urlencode "login_challenge=${login_challenge}" \
  --data-urlencode "identifier=${USER_ID}" \
  --data-urlencode "password=${USER_PASS}" \
  --data-urlencode "moat.csrf=$(csrf_from "$jar/login.html")" | location)
case "$loc" in /consent\?login_challenge=*) ;; *) fail "login did not hand off to /consent (wrong seed?): ${loc:-none}" ;; esac

# Consent persists server-side per user and client, so only the first run
# against a database renders the form; later runs are redirected straight on.
loc=$(curl -s -o "$jar/consent.html" -D - "${BASE}/consent?login_challenge=${login_challenge}" -b "$jar/c" -c "$jar/c" | location)
if [ -z "$loc" ]; then
  loc=$(curl -s -o /dev/null -D - "${BASE}/consent" -b "$jar/c" -c "$jar/c" -H "Origin: ${BASE}" \
    --data-urlencode "login_challenge=${login_challenge}" \
    --data-urlencode "decision=allow" \
    --data-urlencode "moat.csrf=$(csrf_from "$jar/consent.html")" | location)
fi
code=$(printf '%s' "$loc" | sed -n 's/.*[?&]code=\([^&]*\).*/\1/p')
[ -n "$code" ] || fail "no code in the consent redirect: ${loc:-none}"

resp=$(curl -s -X POST "${BASE}/token" -u "${CLIENT_ID}:${CLIENT_SECRET}" \
  --data-urlencode "grant_type=authorization_code" \
  --data-urlencode "code=${code}" \
  --data-urlencode "redirect_uri=${REDIRECT_URI}" \
  --data-urlencode "code_verifier=${verifier}")
token=$(printf '%s' "$resp" | sed -n 's/.*"access_token":"\([^"]*\)".*/\1/p')
[ -n "$token" ] || fail "no access_token in the /token response"
echo "dev-access-token: minted for ${USER_ID}" >&2
printf '%s\n' "$token"
