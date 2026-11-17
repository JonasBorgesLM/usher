#!/usr/bin/env bash
#
# Tampering with a replica's audit log is detected (ADR-0023,
# JonasBorgesLM/tally#54, #171): the stack runs a real login, consent and
# token flow, usher is stopped, and copies of its log are altered and
# truncated the way someone holding the host would, CRC recomputed so that
# the hash chain and the checkpoints are what catch it, not the CRC. tally
# verify, against the spool, must exit 0 on the untouched copy and 1 on each
# tampered one.
#
#   ./.github/scripts/check-audit-tamper.sh
#
# The spool sits beside the log here, so this shows the verifier, not an
# anchor: a host that also rewrote the spool would pass (tally's T-21). The
# anchor's off-host half is the deployment's.
#
# Needs Docker, Go, openssl, curl and python3. It writes its own .env and
# removes it on exit, with the stack and its volumes, so it refuses to start
# if one already exists.

set -euo pipefail
cd "$(dirname "$0")/../.."

if [ -e .env ]; then
  echo "FAIL  .env already exists; this check writes and deletes its own -- move it aside first"
  exit 1
fi
work=$(mktemp -d)
cleanup() {
  docker compose down -v >/dev/null 2>&1 || true
  rm -f .env
  rm -rf "$work"
}
trap cleanup EXIT

umask 077
pg_pw=$(openssl rand -hex 16)
redis_pw=$(openssl rand -hex 16)
cat > .env <<EOF
POSTGRES_PASSWORD=${pg_pw}
REDIS_PASSWORD=${redis_pw}
USHER_ISSUER=http://localhost:8080
USHER_CSRF_SECRET=$(openssl rand -hex 32)
EOF

echo "--- bringing the stack up and running a real flow ---"
docker compose up -d --build --wait
GOEXPERIMENT=jsonv2 \
  USHER_DATABASE_URL="postgres://usher:${pg_pw}@localhost:5432/usher" \
  USHER_REDIS_ADDR=localhost:6379 USHER_REDIS_PASSWORD="${redis_pw}" \
  USHER_ISSUER=http://localhost:8080 USHER_CSRF_SECRET=$(openssl rand -hex 32) \
  USHER_CLIENTS_PATH=./clients.dev.json USHER_KEYS_DIR=/nonexistent USHER_DIRECTLY_EXPOSED=true \
  USHER_TALLY_LOG_DIR=/nonexistent USHER_TALLY_SIGNER_KEY_FILE=/nonexistent \
  USHER_TALLY_VAULT_DIR=/nonexistent USHER_TALLY_KEK_FILE=/nonexistent \
  USHER_TALLY_ANCHOR_DIR=/nonexistent \
  go run ./cmd/seed >/dev/null
./scripts/dev-access-token.sh >/dev/null
docker compose stop usher >/dev/null # its closing checkpoint covers the whole log

docker run --rm -e OWNER="$(id -u):$(id -g)" -v usher_usher-audit:/audit:ro -v usher_usher-audit-keys:/k:ro -v "$work":/out \
  alpine sh -c 'mkdir /out/intact && cp -r /audit/log /audit/anchor /out/intact/ && cp /k/signer.pub /out/ && chown -R "$OWNER" /out'
key=$(cat "$work/signer.pub")

# tamper rewrites the segment in $2: "alter" changes one byte inside the last
# record's resource, "truncate" keeps only the first two records. Either way
# every frame left has a correct CRC (SPEC §3.2: anyone rewriting a file
# recomputes it).
tamper() {
  python3 - "$1" "$2" <<'EOF'
import struct, sys

def crc32c(data):
    crc = 0xFFFFFFFF
    for b in data:
        crc ^= b
        for _ in range(8):
            crc = (crc >> 1) ^ (0x82F63B78 if crc & 1 else 0)
    return crc ^ 0xFFFFFFFF

how, path = sys.argv[1], sys.argv[2]
raw = open(path, "rb").read()
header, off, frames = raw[:65], 65, []
while off < len(raw):
    (n,) = struct.unpack(">I", raw[off:off + 4])
    frames.append(raw[off + 4:off + 4 + n])
    off += 8 + n
assert len(frames) >= 4, f"{len(frames)} records; the flow wrote fewer than expected"
if how == "alter":
    body = frames[-1]
    i = body.rindex(b"client/demo-client")
    frames[-1] = body[:i] + b"client/demo-clienX" + body[i + len(b"client/demo-client"):]
elif how == "truncate":
    frames = frames[:2]
out = header + b"".join(struct.pack(">I", len(f)) + f + struct.pack(">I", crc32c(f)) for f in frames)
open(path, "wb").write(out)
print(f"{how}: {len(frames)} records written back, CRCs recomputed")
EOF
}

verify() {
  go run github.com/JonasBorgesLM/tally/cmd/tally verify --dir "$1/log" --key "$key" \
    --anchor "$1/anchor" --require-fully-attested
}

failed=0
expect() { # expect <want-status> <name> <dir> [<violation kind>]
  local got=0 output
  output=$(verify "$3") || got=$?
  printf '%s\n' "$output" | sed 's/^/      /'
  if [ "$got" -ne "$1" ]; then
    echo "FAIL  $2: tally verify exited $got, want $1"
    failed=1
  elif [ -n "${4:-}" ] && ! printf '%s\n' "$output" | grep -q "violation $4"; then
    echo "FAIL  $2: exit $got, but no $4 reported"
    failed=1
  else
    echo "ok    $2: tally verify exited $got"
  fi
}

seg() { local f; for f in "$1"/log/*.tlog; do printf "%s\n" "$f"; return; done; }

echo "--- the untouched log ---"
expect 0 "untouched" "$work/intact"

echo "--- one byte of a record altered ---"
cp -r "$work/intact" "$work/altered"
tamper alter "$(seg "$work/altered")"
expect 1 "altered" "$work/altered" CheckpointMismatch

echo "--- the last records removed ---"
cp -r "$work/intact" "$work/truncated"
tamper truncate "$(seg "$work/truncated")"
expect 1 "truncated" "$work/truncated" TruncatedBelowCheckpoint

exit "$failed"
