#!/usr/bin/env bash
#
# One probe per T-nn in docs/THREAT-MODEL.md, run against the real compose
# stack from outside -- black-box, the same vantage point every actor in
# the threat model's own §2 has. REQUIREMENTS §13's MVP acceptance and §6's
# own verification rule: every threat gets a probe or an explicit line
# saying why it cannot be probed from outside, never silence.
#
#   docker compose up -d
#   go run ./cmd/seed
#   ./scripts/probe-threats.sh | tee docs/security/threat-probes.txt
#
# Needs: bash, curl, openssl, sed, grep, awk -- nothing this repository
# does not already assume elsewhere. No jq dependency: every response body
# probed here is usher's own flat JSON (no nesting), so a small sed-based
# field extractor is enough and keeps this script's own dependency list
# short.
#
# The shared setup below drives exactly one real, fresh authorization_code
# exchange; almost every probe reuses its ACCESS_TOKEN/REFRESH_TOKEN/ID_TOKEN
# or its CODE1 (already consumed -- T-01 replays that same code rather than
# minting a second one). The few probes that need their own session
# (T-09, T-10, T-12, T-20's growth half, T-21) open a disposable scratch
# cookie jar rather than reusing $SCRATCH/jar, so they cannot disturb the
# shared flow's own session or consent state. T-09/T-15/T-16 are the only
# probes *about* rate-limiting; they run last so an earlier probe never
# loses budget to them, and the limiter's own window is short enough
# (observed: resets within ~1s) that they do not lock out anything after.
#
# T-18 and T-19 get their own explicit "not probeable" lines (§6's own
# requirement): a black-box HTTP client cannot observe whether a mounted
# keyset stayed confined to its mount, or whether an audit event reached
# crier, by design -- there is no endpoint that answers either question.
#
# T-08, T-13 and T-17 describe the *gateway's* own behavior specifically
# (REQUIREMENTS §13's "authenticated call through the gateway" step).
# internal/proxy.NewHandler was built and unit-tested (#40-#42) but, when
# this script first wrote these probes, was never wired into
# cmd/usher/main.go -- there was no live /api/** route to probe against.
# #104 (filed from that finding) wired it in; T-08 and T-13 below now
# probe the real /api/** route directly, alongside the resource server's
# own independent defense (RS-18/RI-04) each already had. T-17 is still a
# GAP: it needs the upstream to actually fail, which a black-box HTTP
# probe cannot induce without stopping or breaking the compose stack's
# own resource-server container -- see probe_t17's own comment.

set -uo pipefail

BASE="http://localhost:8080"
RS_BASE="http://localhost:8081"
CLIENT_ID="demo-client"
CLIENT_SECRET="demo-client-secret-dev-only"
REDIRECT_URI="http://localhost:9999/callback"
USER_ID="admin@example.com"
USER_PASS="usher-local-dev-only"

SCRATCH=$(mktemp -d)
trap 'rm -rf "$SCRATCH"' EXIT

PASS=0; FAIL=0; GAP=0
pass() { PASS=$((PASS + 1)); printf '  PASS  %s\n' "$1"; }
fail() { FAIL=$((FAIL + 1)); printf '  FAIL  %s\n' "$1"; }
gap()  { GAP=$((GAP + 1));   printf '  GAP   %s\n' "$1"; }
# note prints a residual or scope boundary that is not itself a pass/fail/gap
# -- e.g. "this mitigation protects only a client that checks it". It does
# not affect the final tally.
note() { printf '  NOTE  %s\n' "$1"; }
header() { printf '\n=== %s ===\n' "$1"; }

# jf extracts one flat JSON field's value from a response body -- string,
# number or bare true/false, never an array or object. Good enough for
# every body this script reads; nothing here is nested.
jf() {
  printf '%s' "$1" | sed -n "s/.*\"$2\":\"\{0,1\}\([^\",}]*\)\"\{0,1\}.*/\1/p" | head -1
}

csrf_from() {
  grep -o 'name="moat.csrf" value="[^"]*"' "$1" | sed 's/.*value="//;s/"$//'
}

verifier_value() { printf '%s' "probe-pkce-verifier-with-enough-entropy-0123456789-$1"; }
challenge_of() { printf '%s' "$1" | openssl dgst -sha256 -binary | openssl base64 | tr '+/' '-_' | tr -d '='; }

# b64url_decode reverses challenge_of's own encoding (base64url, no padding)
# so T-05 can read a real token's header without a JWT library.
b64url_decode() {
  local s
  s=$(printf '%s' "$1" | tr '_-' '/+')
  case $(( ${#s} % 4 )) in
    2) s="${s}==" ;;
    3) s="${s}=" ;;
  esac
  printf '%s' "$s" | openssl base64 -d -A
}

# authorize_login_consent drives /authorize -> login -> consent for real,
# through the same HTTP surface a browser would use, and echoes the
# resulting authorization code. scope and prompt are the two parameters
# individual probes vary; state is fixed since nothing here checks it
# except T-03/T-04, which read it straight off /authorize's own redirects
# without ever logging in at all.
authorize_login_consent() {
  local scope="$1" verifier_suffix="$2" prompt="${3:-}"
  local verifier challenge loc login_challenge csrf code

  verifier=$(verifier_value "$verifier_suffix")
  challenge=$(challenge_of "$verifier")

  local qs="response_type=code&client_id=${CLIENT_ID}&redirect_uri=$(url_encode "$REDIRECT_URI")&state=probe-state&scope=$(url_encode "$scope")&code_challenge=${challenge}&code_challenge_method=S256"
  [ -n "$prompt" ] && qs="${qs}&prompt=${prompt}"

  loc=$(curl -s -o /dev/null -D - "${BASE}/authorize?${qs}" -b "$SCRATCH/jar" -c "$SCRATCH/jar" | awk -F': ' '/^[Ll]ocation:/{print $2}' | tr -d '\r')

  case "$loc" in
    /login\?login_challenge=*)
      login_challenge="${loc#/login?login_challenge=}"
      # GET /login skips the password form and 303s straight to /consent
      # when the browser's session cookie is already authenticated --
      # SSO reuse is decided inside /login itself (ADR-0020), not by
      # /authorize. Headers go to their own file (and are tee'd through so
      # the Location can still be extracted), body to its own file, so
      # both cases are distinguishable without guessing from the body shape.
      loc=$(curl -s -o "$SCRATCH/login.html" -D - "${BASE}/login?login_challenge=${login_challenge}" -b "$SCRATCH/jar" -c "$SCRATCH/jar" \
        | tee "$SCRATCH/login_get_headers.txt" | awk -F': ' '/^[Ll]ocation:/{print $2}' | tr -d '\r')
      if [ -z "$loc" ]; then
        csrf=$(csrf_from "$SCRATCH/login.html")
        loc=$(curl -s -o /dev/null -D - "${BASE}/login" -b "$SCRATCH/jar" -c "$SCRATCH/jar" \
          -H "Origin: ${BASE}" \
          --data-urlencode "login_challenge=${login_challenge}" \
          --data-urlencode "identifier=${USER_ID}" \
          --data-urlencode "password=${USER_PASS}" \
          --data-urlencode "moat.csrf=${csrf}" \
          | tee "$SCRATCH/login_post_headers.txt" | awk -F': ' '/^[Ll]ocation:/{print $2}' | tr -d '\r')
      fi
      ;;
    /consent\?login_challenge=*)
      login_challenge="${loc#/consent?login_challenge=}"
      ;;
    *)
      echo "ERROR:authorize_login_consent: unexpected /authorize or /login redirect: $loc" >&2
      return 1
      ;;
  esac

  case "$loc" in
    /consent\?login_challenge=*)
      login_challenge="${loc#/consent?login_challenge=}"
      # GET /consent renders a form only the first time a client asks for a
      # given scope. Once consent for that scope already exists (true on a
      # re-run of this script against a stack it already drove once -- T-20's
      # own "re-/authorize with an existing grant does not re-prompt" case),
      # usher skips the form and 302s straight to the callback with a code.
      # Headers go to stdout, body to its own file, so both cases are
      # distinguishable without guessing from the body shape.
      loc=$(curl -s -o "$SCRATCH/consent.html" -D - "${BASE}/consent?login_challenge=${login_challenge}" -b "$SCRATCH/jar" -c "$SCRATCH/jar" \
        | awk -F': ' '/^[Ll]ocation:/{print $2}' | tr -d '\r')
      if [ -z "$loc" ]; then
        csrf=$(csrf_from "$SCRATCH/consent.html")
        loc=$(curl -s -o /dev/null -D - "${BASE}/consent" -b "$SCRATCH/jar" -c "$SCRATCH/jar" \
          -H "Origin: ${BASE}" \
          --data-urlencode "login_challenge=${login_challenge}" \
          --data-urlencode "decision=allow" \
          --data-urlencode "moat.csrf=${csrf}" \
          | awk -F': ' '/^[Ll]ocation:/{print $2}' | tr -d '\r')
      fi
      ;;
  esac

  code=$(printf '%s' "$loc" | sed -n 's/.*[?&]code=\([^&]*\).*/\1/p')
  if [ -z "$code" ]; then
    echo "ERROR:authorize_login_consent: no code in final redirect: $loc" >&2
    return 1
  fi
  # Kept for T-03/T-04, which inspect the success path's own state/iss
  # without driving a second flow just to see them again.
  printf '%s' "$loc" > "$SCRATCH/final_redirect.txt"
  # Printed together, not via a side-channel global: the caller invokes
  # this through $(...), which runs in a subshell -- a variable assigned
  # in here (CODE_VERIFIER="$verifier", this function's own first
  # version) never propagates back out. Found by this script's own first
  # run: the verifier silently came back empty, and /token's own
  # code_verifier check correctly refused to exchange a code against it.
  printf '%s %s' "$code" "$verifier"
}

url_encode() {
  curl -s -o /dev/null -w '%{url_effective}' --get --data-urlencode "x=$1" "http://url-encode.invalid" 2>/dev/null | sed 's#^http://url-encode\.invalid/?x=##'
}

exchange_code() {
  local code="$1" verifier="$2"
  curl -s -X POST "${BASE}/token" \
    -u "${CLIENT_ID}:${CLIENT_SECRET}" \
    --data-urlencode "grant_type=authorization_code" \
    --data-urlencode "code=${code}" \
    --data-urlencode "redirect_uri=${REDIRECT_URI}" \
    --data-urlencode "code_verifier=${verifier}"
}

# --- T-01: authorization code interception and replay ------------------
probe_t01() {
  header "T-01 -- authorization code interception and replay (RS-01, RS-04, RS-05, RS-24)"
  local resp
  resp=$(exchange_code "$CODE1" "$VERIFIER1")
  if [ "$(jf "$resp" error)" = "invalid_grant" ]; then
    pass "replaying the shared setup's own already-consumed code returns invalid_grant, no second token issued"
  else
    fail "replaying an already-consumed code did not return invalid_grant: $resp"
  fi
  note "a replay after the tombstone expires or Redis loses it is an ordinary invalid_grant too -- only the *detection* is bounded, the code stays unusable either way (T-01's residual)"
}

# --- T-02: open redirect through redirect_uri ----------------------------
probe_t02() {
  header "T-02 -- open redirect through redirect_uri (RF-01, RS-02, RS-28)"
  local status
  status=$(curl -s -o /dev/null -w '%{http_code}' \
    "${BASE}/authorize?response_type=code&client_id=${CLIENT_ID}&redirect_uri=$(url_encode "http://attacker.example/cb")&state=x&scope=openid&code_challenge=abc&code_challenge_method=S256")
  if [ "$status" = "400" ]; then
    pass "an unregistered redirect_uri gets a local 400, never a 3xx to the attacker's own host"
  else
    fail "unregistered redirect_uri returned ${status}, expected 400"
  fi
}

# --- T-03: CSRF on the OAuth redirect (state) ----------------------------
probe_t03() {
  header "T-03 -- CSRF on the OAuth redirect / state (RS-03)"
  local err_loc ok_loc
  err_loc=$(curl -s -o /dev/null -D - \
    "${BASE}/authorize?response_type=code&client_id=${CLIENT_ID}&redirect_uri=$(url_encode "$REDIRECT_URI")&state=probe-state-t03&scope=not-a-real-scope&code_challenge=abc&code_challenge_method=S256" \
    | awk -F': ' '/^[Ll]ocation:/{print $2}' | tr -d '\r')
  ok_loc=$(cat "$SCRATCH/final_redirect.txt")
  if printf '%s' "$err_loc" | grep -q 'state=probe-state-t03' && printf '%s' "$ok_loc" | grep -q 'state=probe-state'; then
    pass "state is echoed unchanged on both the error and the success /authorize redirect"
  else
    fail "state missing from one of the redirects (error: $err_loc / success: $ok_loc)"
  fi
  note "this protects only a client that checks the state it gets back -- usher returns it unchanged and cannot enforce the check (T-03's residual)"
}

# --- T-04: mix-up between authorization servers (iss) --------------------
probe_t04() {
  header "T-04 -- mix-up between authorization servers (RS-29)"
  local err_loc ok_loc
  err_loc=$(curl -s -o /dev/null -D - \
    "${BASE}/authorize?response_type=code&client_id=${CLIENT_ID}&redirect_uri=$(url_encode "$REDIRECT_URI")&state=probe-state-t04&scope=not-a-real-scope&code_challenge=abc&code_challenge_method=S256" \
    | awk -F': ' '/^[Ll]ocation:/{print $2}' | tr -d '\r')
  ok_loc=$(cat "$SCRATCH/final_redirect.txt")
  if printf '%s' "$err_loc" | grep -q 'iss=' && printf '%s' "$ok_loc" | grep -q 'iss='; then
    pass "iss is present on both the error and the success /authorize redirect"
  else
    fail "iss missing from one of the redirects (error: $err_loc / success: $ok_loc)"
  fi
  note "same shape as T-03 -- the client must compare iss itself; usher only supplies it (T-04's residual)"
}

# --- T-05: token forgery: alg:none and key confusion ----------------------
probe_t05() {
  header "T-05 -- token forgery: alg:none and key confusion (RS-06, RS-07)"
  local header_json alg
  header_json=$(b64url_decode "$(printf '%s' "$ACCESS_TOKEN" | cut -d. -f1)")
  alg=$(printf '%s' "$header_json" | sed -n 's/.*"alg":"\([^"]*\)".*/\1/p')
  if [ "$alg" = "RS256" ]; then
    pass "a real access token's header names RS256 -- the algorithm is never left to the token to choose"
  else
    fail "real access token's alg was '${alg}', expected RS256"
  fi

  local forged_header forged_payload forged status
  forged_header=$(printf '%s' '{"alg":"none","typ":"JWT"}' | openssl base64 -A | tr '+/' '-_' | tr -d '=')
  forged_payload=$(printf '%s' '{"sub":"attacker","aud":["http://localhost:8080/userinfo"],"exp":9999999999}' | openssl base64 -A | tr '+/' '-_' | tr -d '=')
  forged="${forged_header}.${forged_payload}."
  status=$(curl -s -o /dev/null -w '%{http_code}' "${BASE}/userinfo" -H "Authorization: Bearer ${forged}")
  if [ "$status" = "401" ]; then
    pass "a hand-forged alg:none token is rejected (401) -- the allow-list is fixed at construction, never read from the token"
  else
    fail "forged alg:none token got ${status} at /userinfo, expected 401"
  fi
}

# --- T-06: wrong token in the wrong place ---------------------------------
probe_t06() {
  header "T-06 -- wrong token in the wrong place (RS-08, RS-19, RS-30)"
  local status
  status=$(curl -s -o /dev/null -w '%{http_code}' "${BASE}/userinfo" -H "Authorization: Bearer ${ID_TOKEN}")
  if [ "$status" = "401" ]; then
    pass "an ID token presented as an API credential at /userinfo is rejected (401) -- an ID token is never an API credential"
  else
    fail "ID token used as a bearer at /userinfo got ${status}, expected 401"
  fi
}

# --- T-20: scope escalation and consent abuse -----------------------------
# Runs before T-07: the refusal below does not consume REFRESH_TOKEN (proven
# by hand while writing this probe), but T-07 deliberately burns it, so
# anything that still needs it has to run first.
probe_t20() {
  header "T-20 -- scope escalation and consent abuse (RF-05, RF-13, RS-34)"

  local resp
  resp=$(curl -s -X POST "${BASE}/token" -u "${CLIENT_ID}:${CLIENT_SECRET}" \
    --data-urlencode "grant_type=refresh_token" \
    --data-urlencode "refresh_token=${REFRESH_TOKEN}" \
    --data-urlencode "scope=openid profile offline_access a_scope_never_granted")
  if [ "$(jf "$resp" error)" = "invalid_scope" ]; then
    pass "a refresh requesting more scope than the original grant covered is refused (invalid_scope), not silently widened"
  else
    fail "refresh with an ungranted wider scope did not return invalid_scope: $resp"
  fi

  # Second half: a client asking for genuinely MORE than it has consent for
  # must re-prompt. Uses the second seeded user (whose consent was cleared
  # above) so the first grant here starts from nothing, not from the shared
  # flow's already-maximal grant -- demo-client+admin has nothing wider left
  # to ask for by this point.
  local scratch2 verifier challenge loc login_challenge csrf
  scratch2=$(mktemp -d)
  verifier=$(verifier_value "t20")
  challenge=$(challenge_of "$verifier")

  loc=$(curl -s -o /dev/null -D - \
    "${BASE}/authorize?response_type=code&client_id=${CLIENT_ID}&redirect_uri=$(url_encode "$REDIRECT_URI")&state=t20-narrow&scope=openid&code_challenge=${challenge}&code_challenge_method=S256" \
    -b "$scratch2/jar" -c "$scratch2/jar" | awk -F': ' '/^[Ll]ocation:/{print $2}' | tr -d '\r')
  login_challenge="${loc#/login?login_challenge=}"
  curl -s "${BASE}/login?login_challenge=${login_challenge}" -b "$scratch2/jar" -c "$scratch2/jar" -o "$scratch2/login.html"
  csrf=$(csrf_from "$scratch2/login.html")
  loc=$(curl -s -o /dev/null -D - "${BASE}/login" -b "$scratch2/jar" -c "$scratch2/jar" -H "Origin: ${BASE}" \
    --data-urlencode "login_challenge=${login_challenge}" --data-urlencode "identifier=user@example.com" \
    --data-urlencode "password=${USER_PASS}" --data-urlencode "moat.csrf=${csrf}" \
    | awk -F': ' '/^[Ll]ocation:/{print $2}' | tr -d '\r')
  login_challenge="${loc#/consent?login_challenge=}"
  curl -s "${BASE}/consent?login_challenge=${login_challenge}" -b "$scratch2/jar" -c "$scratch2/jar" -o "$scratch2/consent.html"
  csrf=$(csrf_from "$scratch2/consent.html")
  curl -s -o /dev/null "${BASE}/consent" -b "$scratch2/jar" -c "$scratch2/jar" -H "Origin: ${BASE}" \
    --data-urlencode "login_challenge=${login_challenge}" --data-urlencode "decision=allow" --data-urlencode "moat.csrf=${csrf}"

  loc=$(curl -s -o /dev/null -D - \
    "${BASE}/authorize?response_type=code&client_id=${CLIENT_ID}&redirect_uri=$(url_encode "$REDIRECT_URI")&state=t20-wide&scope=$(url_encode "openid profile")&code_challenge=${challenge}&code_challenge_method=S256" \
    -b "$scratch2/jar" -c "$scratch2/jar" | awk -F': ' '/^[Ll]ocation:/{print $2}' | tr -d '\r')
  case "$loc" in
    /login\?login_challenge=*)
      login_challenge="${loc#/login?login_challenge=}"
      loc=$(curl -s -o /dev/null -D - "${BASE}/login?login_challenge=${login_challenge}" -b "$scratch2/jar" -c "$scratch2/jar" \
        | awk -F': ' '/^[Ll]ocation:/{print $2}' | tr -d '\r')
      ;;
  esac
  if printf '%s' "$loc" | grep -q '^/consent?login_challenge='; then
    pass "re-/authorize for a wider scope with an existing session re-prompts for consent, it is not silently widened"
  else
    fail "wider-scope re-/authorize did not land back on /consent as expected: $loc"
  fi
  rm -rf "$scratch2"
  note "a user who clicks allow on an honest-looking consent screen has consented -- the screen's wording is the only defence and it is not a requirement (T-20's residual)"
}

# --- T-07: stolen refresh token -------------------------------------------
probe_t07() {
  header "T-07 -- stolen refresh token (RF-04, RF-12, RS-10, RS-11, RS-34)"
  local resp new_rt reuse_resp family_resp
  resp=$(curl -s -X POST "${BASE}/token" -u "${CLIENT_ID}:${CLIENT_SECRET}" \
    --data-urlencode "grant_type=refresh_token" --data-urlencode "refresh_token=${REFRESH_TOKEN}")
  new_rt=$(jf "$resp" refresh_token)
  if [ -z "$new_rt" ]; then
    fail "legitimate refresh did not issue a new refresh token: $resp"
    return
  fi

  reuse_resp=$(curl -s -X POST "${BASE}/token" -u "${CLIENT_ID}:${CLIENT_SECRET}" \
    --data-urlencode "grant_type=refresh_token" --data-urlencode "refresh_token=${REFRESH_TOKEN}")
  if [ "$(jf "$reuse_resp" error)" = "invalid_grant" ]; then
    pass "reusing an already-rotated refresh token returns invalid_grant -- reuse detected"
  else
    fail "reusing a rotated refresh token did not return invalid_grant: $reuse_resp"
  fi

  family_resp=$(curl -s -X POST "${BASE}/token" -u "${CLIENT_ID}:${CLIENT_SECRET}" \
    --data-urlencode "grant_type=refresh_token" --data-urlencode "refresh_token=${new_rt}")
  if [ "$(jf "$family_resp" error)" = "invalid_grant" ]; then
    pass "reuse revoked the whole family -- the legitimately-rotated token is dead too, atomically"
  else
    fail "the legitimately-rotated refresh token still worked after reuse was detected: $family_resp"
  fi
  note "reuse detection needs the legitimate client to come back; if the attacker refreshes first and the victim never does, the attacker holds the family until it expires -- a cost ADR-0012 accepts (T-07's residual)"
}

# --- T-08: stolen access token --------------------------------------------
probe_t08() {
  header "T-08 -- stolen access token (RF-06, RF-12, RS-24, RS-26)"
  local gw_status_before revoke_status rs_status introspect_resp gw_status_after

  gw_status_before=$(curl -s -o /dev/null -w '%{http_code}' "${BASE}/api/widgets" -H "Authorization: Bearer ${ACCESS_TOKEN}")
  if [ "$gw_status_before" = "200" ]; then
    pass "the gateway's own /api/** route (#104) accepts a valid, not-yet-revoked access token"
  else
    fail "the gateway rejected a valid access token before revocation (${gw_status_before}), expected 200"
  fi

  revoke_status=$(curl -s -o /dev/null -w '%{http_code}' -X POST "${BASE}/revoke" -u "${CLIENT_ID}:${CLIENT_SECRET}" \
    --data-urlencode "token=${ACCESS_TOKEN}")
  if [ "$revoke_status" = "200" ]; then
    pass "/revoke accepts the access token (200)"
  else
    fail "/revoke returned ${revoke_status}, expected 200"
  fi

  gw_status_after=$(curl -s -o /dev/null -w '%{http_code}' "${BASE}/api/widgets" -H "Authorization: Bearer ${ACCESS_TOKEN}")
  if [ "$gw_status_after" = "401" ]; then
    pass "the gateway's OWN denylist enforcement (RF-06) now refuses the revoked token -- the mitigation this threat names, probed for real now that #104 wired /api/** in"
  else
    fail "the gateway still accepted the revoked token (${gw_status_after}), expected 401 -- RF-06's denylist enforcement is not engaging"
  fi

  rs_status=$(curl -s -o /dev/null -w '%{http_code}' "${RS_BASE}/widgets" -H "Authorization: Bearer ${ACCESS_TOKEN}")
  if [ "$rs_status" = "200" ]; then
    pass "the resource server reached DIRECTLY still accepts the revoked token -- the stated residual (ADR-0014): a direct call never consults the denylist, TTL is the only bound"
  else
    fail "resource server rejected the revoked token directly (${rs_status}) -- the stated residual no longer holds, re-check ADR-0014"
  fi

  introspect_resp=$(curl -s -X POST "${BASE}/introspect" -u "${CLIENT_ID}:${CLIENT_SECRET}" --data-urlencode "token=${ACCESS_TOKEN}")
  if printf '%s' "$introspect_resp" | grep -q '"active":true'; then
    pass "/introspect still reports active:true for the revoked access token -- introspection is purely cryptographic/claims-based and never consults the gateway's denylist either, consistent with ADR-0014 and not a separate bug"
  else
    fail "/introspect reported the revoked access token as inactive, inconsistent with ADR-0014: $introspect_resp"
  fi
}

# --- T-13: identity header spoofing ---------------------------------------
# Runs before T-08: T-08 revokes ACCESS_TOKEN, and the gateway half below
# needs it still valid -- a revoked token 401s at the gateway regardless
# of any header, which would test T-08's own property, not this one.
probe_t13() {
  header "T-13 -- identity header spoofing (RS-17, RS-18, RI-04)"
  local real_subject spoofed_subject gw_real_subject gw_spoofed_subject
  real_subject=$(jf "$(curl -s "${RS_BASE}/widgets" -H "Authorization: Bearer ${ACCESS_TOKEN}")" subject)
  spoofed_subject=$(jf "$(curl -s "${RS_BASE}/widgets" -H "Authorization: Bearer ${ACCESS_TOKEN}" -H "X-Auth-Subject: attacker-controlled-identity")" subject)
  if [ -n "$real_subject" ] && [ "$real_subject" = "$spoofed_subject" ]; then
    pass "the resource server ignores a spoofed X-Auth-Subject header and reports the real token's own subject (RS-18/RI-04's independent defense)"
  else
    fail "a spoofed X-Auth-Subject header changed the resource server's reported subject: real='${real_subject}' spoofed='${spoofed_subject}'"
  fi

  gw_real_subject=$(jf "$(curl -s "${BASE}/api/widgets" -H "Authorization: Bearer ${ACCESS_TOKEN}")" subject)
  gw_spoofed_subject=$(jf "$(curl -s "${BASE}/api/widgets" -H "Authorization: Bearer ${ACCESS_TOKEN}" -H "X-Auth-Subject: attacker-controlled-identity")" subject)
  if [ -n "$gw_real_subject" ] && [ "$gw_real_subject" = "$gw_spoofed_subject" ]; then
    pass "through the real gateway (#104), a spoofed X-Auth-Subject still has no effect on the reported subject -- RS-17's strip-before-inject and RS-18's independent defense both hold in the combined pipeline"
  else
    fail "a spoofed X-Auth-Subject header changed the subject reported through the gateway: real='${gw_real_subject}' spoofed='${gw_spoofed_subject}'"
  fi
  note "this cannot isolate the gateway's own stripping from the resource server's own independent ignoring of X-Auth-* -- RS-18's defense-in-depth makes the two indistinguishable from outside, by design"
}

# --- T-10: user enumeration -------------------------------------------------
probe_t10() {
  header "T-10 -- user enumeration (RS-14, RS-25, RS-33)"
  local scratch2 loc lc csrf1 csrf2 wrong_pw_status nonexist_status
  scratch2=$(mktemp -d)

  loc=$(curl -s -o /dev/null -D - \
    "${BASE}/authorize?response_type=code&client_id=${CLIENT_ID}&redirect_uri=$(url_encode "$REDIRECT_URI")&state=t10a&scope=openid&code_challenge=abc&code_challenge_method=S256" \
    -b "$scratch2/jar" -c "$scratch2/jar" | awk -F': ' '/^[Ll]ocation:/{print $2}' | tr -d '\r')
  lc="${loc#/login?login_challenge=}"
  curl -s "${BASE}/login?login_challenge=${lc}" -b "$scratch2/jar" -c "$scratch2/jar" -o "$scratch2/login1.html"
  csrf1=$(csrf_from "$scratch2/login1.html")
  wrong_pw_status=$(curl -s -o /dev/null -w '%{http_code}' "${BASE}/login" -b "$scratch2/jar" -c "$scratch2/jar" -H "Origin: ${BASE}" \
    --data-urlencode "login_challenge=${lc}" --data-urlencode "identifier=${USER_ID}" --data-urlencode "password=definitely-the-wrong-password" --data-urlencode "moat.csrf=${csrf1}")

  loc=$(curl -s -o /dev/null -D - \
    "${BASE}/authorize?response_type=code&client_id=${CLIENT_ID}&redirect_uri=$(url_encode "$REDIRECT_URI")&state=t10b&scope=openid&code_challenge=abc&code_challenge_method=S256" \
    -b "$scratch2/jar" -c "$scratch2/jar" | awk -F': ' '/^[Ll]ocation:/{print $2}' | tr -d '\r')
  lc="${loc#/login?login_challenge=}"
  curl -s "${BASE}/login?login_challenge=${lc}" -b "$scratch2/jar" -c "$scratch2/jar" -o "$scratch2/login2.html"
  csrf2=$(csrf_from "$scratch2/login2.html")
  nonexist_status=$(curl -s -o /dev/null -w '%{http_code}' "${BASE}/login" -b "$scratch2/jar" -c "$scratch2/jar" -H "Origin: ${BASE}" \
    --data-urlencode "login_challenge=${lc}" --data-urlencode "identifier=does-not-exist@example.com" --data-urlencode "password=whatever" --data-urlencode "moat.csrf=${csrf2}")

  if [ -n "$wrong_pw_status" ] && [ "$wrong_pw_status" = "$nonexist_status" ]; then
    pass "existing-user-wrong-password and non-existent-identifier return the identical status (${wrong_pw_status})"
  else
    fail "status differs between wrong-password (${wrong_pw_status}) and non-existent identifier (${nonexist_status}) -- an enumeration oracle"
  fi
  rm -rf "$scratch2"
  note "the timing half of RS-14 is a statistical property measured outside this script -- see scripts/timing-login and docs/security/timing-login-baseline.txt"
}

# --- T-11: session fixation and hijacking at the AS -------------------------
probe_t11() {
  header "T-11 -- session fixation and hijacking at the AS (RS-12b, RS-27, RS-31)"
  local pre_csrf post_csrf session_line
  pre_csrf=$(grep -i '^Set-Cookie: __Host-moat.csrf=' "$SCRATCH/login_get_headers.txt" | sed 's/.*csrf=\([^;]*\);.*/\1/')
  post_csrf=$(grep -i '^Set-Cookie: __Host-moat.csrf=' "$SCRATCH/login_post_headers.txt" | sed 's/.*csrf=\([^;]*\);.*/\1/')
  session_line=$(grep -i '^Set-Cookie: __Host-usher-session=' "$SCRATCH/login_post_headers.txt")
  if [ -n "$pre_csrf" ] && [ -n "$post_csrf" ] && [ "$pre_csrf" != "$post_csrf" ] && [ -n "$session_line" ]; then
    pass "login rotates both the CSRF cookie and issues a new session cookie (RS-12b's two rotations)"
  else
    fail "login did not rotate both cookies as expected (pre_csrf='${pre_csrf}' post_csrf='${post_csrf}' session_line='${session_line}')"
  fi
  note "an XSS on the AS origin (T-21) can act within the session without ever reading the cookie -- rotation does not defend against that (T-11's residual)"
}

# --- T-12: forged form submissions and clickjacking --------------------------
probe_t12() {
  header "T-12 -- forged form submissions and clickjacking (RS-12a, RS-32)"
  local frame_hdr csp_hdr
  frame_hdr=$(grep -i '^X-Frame-Options:' "$SCRATCH/login_get_headers.txt")
  csp_hdr=$(grep -i '^Content-Security-Policy:' "$SCRATCH/login_get_headers.txt")
  if printf '%s' "$frame_hdr" | grep -qi 'DENY' && printf '%s' "$csp_hdr" | grep -q "frame-ancestors 'none'"; then
    pass "X-Frame-Options: DENY and CSP frame-ancestors 'none' are both present on the login page"
  else
    fail "framing protection missing or incomplete: frame_hdr='${frame_hdr}' csp_hdr='${csp_hdr}'"
  fi

  local scratch2 loc lc status
  scratch2=$(mktemp -d)
  loc=$(curl -s -o /dev/null -D - \
    "${BASE}/authorize?response_type=code&client_id=${CLIENT_ID}&redirect_uri=$(url_encode "$REDIRECT_URI")&state=t12&scope=openid&code_challenge=abc&code_challenge_method=S256" \
    -b "$scratch2/jar" -c "$scratch2/jar" | awk -F': ' '/^[Ll]ocation:/{print $2}' | tr -d '\r')
  lc="${loc#/login?login_challenge=}"
  curl -s "${BASE}/login?login_challenge=${lc}" -b "$scratch2/jar" -c "$scratch2/jar" -o /dev/null
  status=$(curl -s -o /dev/null -w '%{http_code}' "${BASE}/login" -b "$scratch2/jar" -c "$scratch2/jar" -H "Origin: ${BASE}" \
    --data-urlencode "login_challenge=${lc}" --data-urlencode "identifier=${USER_ID}" --data-urlencode "password=${USER_PASS}" --data-urlencode "moat.csrf=totally-wrong-csrf-value")
  if [ "$status" = "403" ]; then
    pass "/login without a valid CSRF token is rejected (403), never accepted"
  else
    fail "/login accepted or mishandled a request with an invalid CSRF token (${status}, expected 403)"
  fi
  rm -rf "$scratch2"
}

# --- T-14: credential leakage through side channels ---------------------------
probe_t14() {
  header "T-14 -- credential leakage through side channels (RS-10, RS-15, RS-16, RS-23, RS-24, RS-25, RS-26)"
  local all_ok=1 cc

  cc=$(curl -s -o /dev/null -D - -X POST "${BASE}/token" -u "${CLIENT_ID}:${CLIENT_SECRET}" \
    --data-urlencode "grant_type=refresh_token" --data-urlencode "refresh_token=x" | grep -i '^Cache-Control:')
  printf '%s' "$cc" | grep -qi 'no-store' || { all_ok=0; fail "/token missing Cache-Control: no-store"; }

  cc=$(curl -s -o /dev/null -D - -X POST "${BASE}/revoke" -u "${CLIENT_ID}:${CLIENT_SECRET}" \
    --data-urlencode "token=x" | grep -i '^Cache-Control:')
  printf '%s' "$cc" | grep -qi 'no-store' || { all_ok=0; fail "/revoke missing Cache-Control: no-store"; }

  cc=$(curl -s -o /dev/null -D - -X POST "${BASE}/introspect" -u "${CLIENT_ID}:${CLIENT_SECRET}" \
    --data-urlencode "token=x" | grep -i '^Cache-Control:')
  printf '%s' "$cc" | grep -qi 'no-store' || { all_ok=0; fail "/introspect missing Cache-Control: no-store"; }

  cc=$(curl -s -o /dev/null -D - "${BASE}/userinfo" -H "Authorization: Bearer x" | grep -i '^Cache-Control:')
  printf '%s' "$cc" | grep -qi 'no-store' || { all_ok=0; fail "/userinfo missing Cache-Control: no-store"; }

  [ "$all_ok" = "1" ] && pass "every credential-bearing endpoint (/token, /revoke, /introspect, /userinfo) responds with Cache-Control: no-store"

  local err_body
  err_body=$(curl -s -X POST "${BASE}/token" -u "${CLIENT_ID}:${CLIENT_SECRET}" \
    --data-urlencode "grant_type=refresh_token" --data-urlencode "refresh_token=garbage-token-value-xyz")
  if printf '%s' "$err_body" | grep -qi "${CLIENT_SECRET}"; then
    fail "an error response echoed back the client secret: $err_body"
  else
    pass "a failed grant's error body carries no internal detail -- RFC 6749 §5.2's fixed codes (RS-25)"
  fi
}

# --- T-17/T-18/T-19: not probeable from outside, by design or by #104 ----------
probe_t17() {
  header "T-17 -- upstream failure cascading into the gateway, or leaking through it (RS-20, RS-21, RI-02)"
  gap "#104 wired the gateway's own /api/** route in, but this threat needs the upstream to actually fail -- a black-box HTTP probe cannot induce that without stopping or breaking the compose stack's own resource-server container, which is a different, more invasive kind of probe than this script runs. sapper's own fault injector (found while working #54) has no CLI-driven scenario yet either -- see #54's own report for the exact citation."
}

probe_t18() {
  header "T-18 -- signing key compromise"
  gap "not probeable from outside by design: no endpoint can reveal whether the mounted keyset stayed confined to its mount. Custody and rotation are process controls (ADR-0015), verified by review, not an HTTP probe."
}

probe_t19() {
  header "T-19 -- loss or forgery of the audit trail"
  gap "not probeable from outside by design: no endpoint confirms delivery to or tampering with crier. The one fact that must survive -- a family revoked for reuse -- is also recorded on the family row in Postgres (ADR-0017); T-07's probe above exercises exactly that path."
}

# --- T-21: script injection in the login and consent pages ---------------------
probe_t21() {
  header "T-21 -- script injection in the login and consent pages (RS-32, RS-36)"
  local scratch2 loc lc csp_nonce script_nonce script_count
  scratch2=$(mktemp -d)
  loc=$(curl -s -o /dev/null -D - \
    "${BASE}/authorize?response_type=code&client_id=${CLIENT_ID}&redirect_uri=$(url_encode "$REDIRECT_URI")&state=t21&scope=openid&code_challenge=abc&code_challenge_method=S256" \
    -b "$scratch2/jar" -c "$scratch2/jar" | awk -F': ' '/^[Ll]ocation:/{print $2}' | tr -d '\r')
  lc="${loc#/login?login_challenge=}"
  curl -s -D "$scratch2/h.txt" "${BASE}/login?login_challenge=${lc}" -b "$scratch2/jar" -c "$scratch2/jar" -o "$scratch2/login.html"
  csp_nonce=$(grep -o 'nonce-[A-Za-z0-9+/=]*' "$scratch2/h.txt" | sed 's/^nonce-//')
  # html/template escapes a base64 nonce's own '+' as &#43; in an attribute
  # value (correct: a browser decodes it back before comparing against the
  # CSP header) -- undo that one entity so this probe compares the same
  # value a browser would, not raw HTML source bytes.
  script_nonce=$(grep -o 'nonce="[^"]*"' "$scratch2/login.html" | sed 's/nonce="//;s/"$//;s/&#43;/+/g')
  script_count=$(grep -c '<script' "$scratch2/login.html")

  if [ -n "$csp_nonce" ] && [ "$csp_nonce" = "$script_nonce" ] && [ "$script_count" = "1" ]; then
    pass "the login page's one inline script carries the exact per-request nonce the CSP header names"
  else
    fail "CSP nonce ('${csp_nonce}') / script nonce ('${script_nonce}') mismatch or unexpected script count (${script_count})"
  fi
  rm -rf "$scratch2"
  note "html/template's own escaping (RS-36) is exercised by usher's Go test suite with a negative control; a black-box probe cannot inject through client_id or scope here without registering a malicious client, which is out of this script's scope"
}

# --- T-09/T-15/T-16: rate limiting -- run last, deliberately exhaust it --------
probe_t09() {
  header "T-09 -- credential stuffing and password guessing (RS-13, RS-22, RS-35)"
  local scratch2 loc lc csrf status hit_429=0 attempts=0 i
  scratch2=$(mktemp -d)
  loc=$(curl -s -o /dev/null -D - \
    "${BASE}/authorize?response_type=code&client_id=${CLIENT_ID}&redirect_uri=$(url_encode "$REDIRECT_URI")&state=t09&scope=openid&code_challenge=abc&code_challenge_method=S256" \
    -b "$scratch2/jar" -c "$scratch2/jar" | awk -F': ' '/^[Ll]ocation:/{print $2}' | tr -d '\r')
  lc="${loc#/login?login_challenge=}"
  curl -s "${BASE}/login?login_challenge=${lc}" -b "$scratch2/jar" -c "$scratch2/jar" -o "$scratch2/login.html"
  csrf=$(csrf_from "$scratch2/login.html")
  for i in 1 2 3 4 5 6 7 8 9 10; do
    attempts="$i"
    status=$(curl -s -o /dev/null -w '%{http_code}' "${BASE}/login" -b "$scratch2/jar" -c "$scratch2/jar" -H "Origin: ${BASE}" \
      --data-urlencode "login_challenge=${lc}" --data-urlencode "identifier=${USER_ID}" --data-urlencode "password=guess-${i}" --data-urlencode "moat.csrf=${csrf}")
    if [ "$status" = "429" ]; then hit_429=1; break; fi
  done
  if [ "$hit_429" = "1" ]; then
    pass "repeated wrong-password guesses against one account get rate-limited (429) after ${attempts} attempts"
  else
    fail "${attempts} rapid failed login attempts never triggered a 429 -- rate limiting did not engage"
  fi
  rm -rf "$scratch2"
  note "a slow, distributed attack under both the IP and account thresholds still succeeds against a weak password; without MFA that is this design's stated ceiling (T-09's residual, §1.1)"
}

probe_t15() {
  header "T-15 -- denial of service against the AS (RF-07, RS-09, RS-21, RS-22, RS-33)"
  local code retry_after healthz i
  for i in 1 2 3 4 5 6 7; do
    code=$(curl -s -o /dev/null -w '%{http_code}' "${BASE}/login?login_challenge=whatever")
    [ "$code" = "429" ] && break
  done
  if [ "$code" = "429" ]; then
    retry_after=$(curl -s -o /dev/null -D - "${BASE}/login?login_challenge=whatever" | awk -F': ' '/^[Rr]etry-[Aa]fter:/{print $2}' | tr -d '\r')
    pass "the rate limiter answers with 429 and Retry-After: ${retry_after} before anything downstream is touched"
  else
    fail "could not reach 429 on /login within 7 requests"
  fi
  healthz=$(curl -s -o /dev/null -w '%{http_code}' "${BASE}/healthz")
  if [ "$healthz" = "200" ]; then
    pass "the AS process still answers /healthz normally while a client is being rate-limited elsewhere"
  else
    fail "/healthz returned ${healthz} while under rate-limit load, expected 200"
  fi
  note "a volumetric L3/L4 flood is the infrastructure's problem, not usher's (threat model §7) -- this script only exercises the application-layer limiter"
}

probe_t16() {
  header "T-16 -- rate-limit bypass (RS-22 realip/ADR-0010, RNF-04, RNF-05, RNF-07)"
  local r1 r2 r3
  r1=$(curl -s -o /dev/null -D - "${BASE}/login?login_challenge=whatever" -H "X-Forwarded-For: 1.1.1.1" | awk -F': ' '/^Ratelimit-Remaining:/{print $2}' | tr -d '\r')
  r2=$(curl -s -o /dev/null -D - "${BASE}/login?login_challenge=whatever" -H "X-Forwarded-For: 2.2.2.2" | awk -F': ' '/^Ratelimit-Remaining:/{print $2}' | tr -d '\r')
  r3=$(curl -s -o /dev/null -D - "${BASE}/login?login_challenge=whatever" -H "X-Forwarded-For: 3.3.3.3" | awk -F': ' '/^Ratelimit-Remaining:/{print $2}' | tr -d '\r')
  if [ -n "$r1" ] && [ -n "$r2" ] && [ -n "$r3" ] && [ "$r1" -gt "$r2" ] && [ "$r2" -gt "$r3" ]; then
    pass "spoofing X-Forwarded-For with different values does not split the rate-limit bucket -- remaining keeps decreasing (${r1} -> ${r2} -> ${r3}); the key derives from the real peer (ADR-0010)"
  else
    fail "the rate limit bucket appears to split by spoofed X-Forwarded-For (remaining: ${r1}, ${r2}, ${r3})"
  fi
  note "the eviction check (RNF-07) is a startup snapshot and, in cluster mode, sees only the masters reachable then (T-16's residual)"
}

echo "usher threat probes -- $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "against ${BASE} (AS/gateway) and ${RS_BASE} (demo resource server)"

if ! curl -sf -o /dev/null "${BASE}/healthz"; then
  echo "FATAL: ${BASE}/healthz did not respond -- is 'docker compose up -d' running?" >&2
  exit 1
fi

# --- shared golden-path flow, reused by most probes below -------------
header "shared setup: one real authorization_code exchange"
read -r CODE1 VERIFIER1 <<< "$(authorize_login_consent "openid profile offline_access" "shared")"
TOKEN_JSON=$(exchange_code "$CODE1" "$VERIFIER1")
ACCESS_TOKEN=$(jf "$TOKEN_JSON" access_token)
REFRESH_TOKEN=$(jf "$TOKEN_JSON" refresh_token)
ID_TOKEN=$(jf "$TOKEN_JSON" id_token)
if [ -z "$ACCESS_TOKEN" ] || [ -z "$REFRESH_TOKEN" ] || [ -z "$ID_TOKEN" ]; then
  echo "FATAL: shared setup did not produce a full token set: $TOKEN_JSON" >&2
  exit 1
fi
echo "  access_token, refresh_token, id_token obtained for ${USER_ID} via ${CLIENT_ID}"

probe_t02
probe_t03
probe_t04
probe_t05
probe_t06

# loginLimiter (burst=5, refills 1/s) covers /login and /consent together,
# by design (RS-22's IP axis) -- the shared setup above already spent most
# of that burst on its own real login+consent. T-20's own dedicated flow
# needs close to a full burst again, so it gets the budget back first,
# rather than racing a limiter that is correctly strict. Found by watching
# T-20 fail with 429s where a real browser, pacing itself, never would.
sleep 6
probe_t20
probe_t07
# T-01 replays the shared setup's own already-consumed code, which revokes
# the whole refresh-token family it minted (RS-04's own "replay revokes").
# It must run after T-20 and T-07, the only other probes that still needed
# REFRESH_TOKEN from that same grant -- found the hard way, by watching
# T-20 and T-07 fail with invalid_grant when T-01 ran first.
probe_t01
# T-13 before T-08: T-08 revokes ACCESS_TOKEN, and T-13's own gateway
# half needs it still valid (see probe_t13's own comment).
probe_t13
probe_t08
sleep 5
probe_t10
probe_t11
sleep 3
probe_t12
probe_t14
probe_t17
probe_t18
probe_t19
sleep 2
probe_t21
probe_t09
probe_t15
sleep 6
probe_t16

header "summary"
echo "  PASS=${PASS}  FAIL=${FAIL}  GAP=${GAP}"
if [ "$FAIL" -gt 0 ]; then
  exit 1
fi
