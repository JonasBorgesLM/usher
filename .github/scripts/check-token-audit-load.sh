#!/usr/bin/env bash
#
# /token under sustained load with the tally audit log in the path (ADR-0023,
# JonasBorgesLM/tally#54, #171): sapper loads client_credentials issuances,
# each recorded durably before the token is returned, and asserts the p99 in
# docs/security/sapper-token-audit.yaml. Then usher is stopped, which logs
# the audit log's own batch fsync p50/p99, the log's share of that latency;
# and the log, now holding every issuance, is verified against its spool.
#
#   SAPPER=/path/to/sapper ./.github/scripts/check-token-audit-load.sh
#
# Needs Docker, Go and python3. It writes its own .env and
# docker-compose.override.yml and removes both on exit, with the stack and
# its volumes, so it refuses to start if either file already exists. Results
# land in $OUT_DIR (default: a temporary directory, printed).

set -euo pipefail
cd "$(dirname "$0")/../.."

: "${SAPPER:?set SAPPER to a built sapper binary}"
for f in .env docker-compose.override.yml; do
  if [ -e "$f" ]; then
    echo "FAIL  $f already exists; this check writes and deletes its own -- move it aside first"
    exit 1
  fi
done

out="${OUT_DIR:-$(mktemp -d)}"
mkdir -p "$out"
work=$(mktemp -d)

cleanup() {
  docker compose down -v >/dev/null 2>&1 || true
  rm -f .env docker-compose.override.yml
  rm -rf "$work"
}
trap cleanup EXIT

umask 077
cat > .env <<EOF
POSTGRES_PASSWORD=$(openssl rand -hex 16)
REDIS_PASSWORD=$(openssl rand -hex 16)
USHER_ISSUER=http://localhost:8080
USHER_CSRF_SECRET=$(openssl rand -hex 32)
EOF

# A registry with the dev client and the load client: sapper-load can only
# use client_credentials, and exists only for this run.
python3 - "$work/clients.json" <<'EOF'
import hashlib, json, sys
clients = json.load(open("clients.dev.json"))
clients.append({
    "client_id": "sapper-load",
    "confidential": True,
    "secret_hash": hashlib.sha256(b"sapper-load-secret-dev-only").hexdigest(),
    "redirect_uris": ["http://localhost:9999/unused"],  # the registry requires one
    "grant_types": ["client_credentials"],
    "scopes": ["widgets:read"],
    "audiences": ["https://resource-server.usher.local"],
    "require_consent": False,
})
json.dump(clients, open(sys.argv[1], "w"), indent=2)
EOF
chmod 0644 "$work/clients.json"
cat > docker-compose.override.yml <<EOF
services:
  usher:
    volumes:
      - ${work}/clients.json:/etc/usher/clients.json:ro
EOF

echo "--- bringing the stack up ---"
docker compose up -d --build --wait

echo "--- sapper: /token under load ---"
status=0
"$SAPPER" run --config docs/security/sapper-config.yaml \
  --scenario docs/security/sapper-token-audit.yaml --out "$out/token-audit.json" | tee "$out/token-audit-run.txt"
"$SAPPER" report --in "$out/token-audit.json" --out "$out/token-audit-report.html" >/dev/null
"$SAPPER" assert --in "$out/token-audit.json" || status=1

echo "--- the audit log's own share: batch fsync, logged at close ---"
docker compose stop usher >/dev/null
docker compose logs --no-log-prefix usher | grep '"audit log closed"' | tee "$out/audit-sync.txt"
if [ ! -s "$out/audit-sync.txt" ]; then
  echo "FAIL  usher logged no audit-log statistics at close"
  status=1
fi

echo "--- the log under that load verifies against its spool ---"
docker run --rm -v usher_usher-audit:/audit:ro -v usher_usher-audit-keys:/k:ro -v "$work":/out \
  alpine sh -c 'cp -r /audit/log /audit/anchor /out/ && cp /k/signer.pub /out/'
if go run github.com/JonasBorgesLM/tally/cmd/tally verify --dir "$work/log" \
  --key "$(cat "$work/signer.pub")" --anchor "$work/anchor" --require-fully-attested | tee "$out/verify.txt"; then
  echo "ok    the audit log verifies"
else
  echo "FAIL  the audit log written under load does not verify"
  status=1
fi

echo "results in $out"
exit "$status"
