#!/usr/bin/env bash
#
# End to end, the audit log and its anchor (ADR-0023, #173,
# JonasBorgesLM/tally#55): usher records real flows in its tally log, an
# anchor pulls the checkpoints off the host's spool, and someone with root on
# the host rolls the log back. The host's own spool still says the log is
# intact; the anchor's copy says it is not.
#
#   ./scripts/demo-audit.sh
#
# From a clean checkout. Needs Docker, Go, openssl, ssh-keygen, curl and
# python3. It writes its own .env and removes it on exit, with the stack and
# its volumes, so it refuses to start if one already exists. KEEP=1 leaves
# the stack running afterwards.
#
# The anchor here is a container on the same machine (docker-compose.demo.yml
# says what that does and does not show), unless ANCHOR_SSH names a second
# machine (JonasBorgesLM/tally#125):
#
#   ANCHOR_SSH=pi@raspberrypi.local ANCHOR_SPOOL_HOST=192.168.10.18 ./scripts/demo-audit.sh
#
# ANCHOR_SSH is the operator's own login to the anchor machine, used to start
# each pull and to fetch the copy for the auditor; it is not part of the usher
# host. On that machine, a user `anchor` owns ~/copy (0700) and the key
# ~/.ssh/usher-pull, and pulls as itself. ANCHOR_SPOOL_HOST is this machine's
# address as the anchor machine reaches it; the spool listens on port 2222
# (docker-compose.pi.yml). The README's "End to end" section gives the setup.

set -euo pipefail
cd "$(dirname "$0")/.."

if [ -e .env ]; then
  echo "demo: .env already exists; this demo writes and deletes its own -- move it aside first" >&2
  exit 1
fi

work=$(mktemp -d)
export DEMO_SSH_DIR="$work/ssh"
overlays=(-f docker-compose.yml -f docker-compose.demo.yml)
if [ -n "${ANCHOR_SSH:-}" ]; then
  : "${ANCHOR_SPOOL_HOST:?set ANCHOR_SPOOL_HOST to the address the anchor machine reaches this one at}"
  overlays+=(-f docker-compose.pi.yml)
  anchor_dir="copy/usher-demo-$(date -u +%Y%m%dT%H%M%SZ)"
fi
compose() { docker compose "${overlays[@]}" "$@"; }
cleanup() {
  if [ "${KEEP:-}" != 1 ]; then
    compose down -v >/dev/null 2>&1 || true
    rm -f .env
  fi
  rm -rf "$work"
}
trap cleanup EXIT

step() { printf '\n=== %s\n' "$*"; }
tally() { go run github.com/JonasBorgesLM/tally/cmd/tally "$@"; }

# copy_out <volume> <path in volume> <dest>: a copy of a volume's directory,
# handed to whoever runs this script (on Linux a bind mount keeps the
# container's owner).
copy_out() {
  docker run --rm -e OWNER="$(id -u):$(id -g)" -v "$1":/v:ro -v "$work":/out alpine:3.20 \
    sh -c "mkdir -p /out/$3 && cp -r /v/$2/. /out/$3/ && chown -R \"\$OWNER\" /out"
}

umask 077
pg_pw=$(openssl rand -hex 16)
redis_pw=$(openssl rand -hex 16)
cat > .env <<EOF
POSTGRES_PASSWORD=${pg_pw}
REDIS_PASSWORD=${redis_pw}
USHER_ISSUER=http://localhost:8080
USHER_CSRF_SECRET=$(openssl rand -hex 32)
EOF
mkdir -p "$DEMO_SSH_DIR"
ssh-keygen -q -t ed25519 -N '' -C anchor -f "$DEMO_SSH_DIR/anchor"
if [ -n "${ANCHOR_SSH:-}" ]; then
  # The spool authorizes the anchor machine's key instead; its private half
  # stays there.
  ssh "$ANCHOR_SSH" 'sudo cat ~anchor/.ssh/usher-pull.pub' > "$DEMO_SSH_DIR/anchor.pub"
fi
chmod 0644 "$DEMO_SSH_DIR/anchor.pub"

step "1. Bring up usher, its audit log, the host's spool server and the anchor"
compose up -d --build --wait
GOEXPERIMENT=jsonv2 \
  USHER_DATABASE_URL="postgres://usher:${pg_pw}@localhost:5432/usher" \
  USHER_REDIS_ADDR=localhost:6379 USHER_REDIS_PASSWORD="${redis_pw}" \
  USHER_ISSUER=http://localhost:8080 USHER_CSRF_SECRET=$(openssl rand -hex 32) \
  USHER_CLIENTS_PATH=./clients.dev.json USHER_KEYS_DIR=/nonexistent USHER_DIRECTLY_EXPOSED=true \
  USHER_TALLY_LOG_DIR=/nonexistent USHER_TALLY_SIGNER_KEY_FILE=/nonexistent \
  USHER_TALLY_VAULT_DIR=/nonexistent USHER_TALLY_KEK_FILE=/nonexistent \
  USHER_TALLY_ANCHOR_DIR=/nonexistent \
  go run ./cmd/seed >/dev/null
copy_out usher_usher-audit-keys . keys
key=$(cat "$work/keys/signer.pub")
echo "the replica's verifier key: $key"

pull() {
  if [ -n "${ANCHOR_SSH:-}" ]; then
    # Run by the anchor machine's own user, with its own key, into its own
    # directory; the operator's login only starts it.
    # shellcheck disable=SC2029 # expanded here on purpose: a date, and the operator's address
    ssh "$ANCHOR_SSH" "sudo -u anchor sh -s -- '$anchor_dir' '$ANCHOR_SPOOL_HOST'" <<'REMOTE'
set -e
cd
mkdir -p "$1"
rsync -r --ignore-existing \
  -e "ssh -i .ssh/usher-pull -p 2222 -o StrictHostKeyChecking=accept-new -o UserKnownHostsFile=.ssh/demo_known_hosts" \
  "puller@$2:." "$1/"
echo "the anchor machine holds $(ls "$1" | wc -l) checkpoint notes"
REMOTE
    return
  fi
  compose exec -T anchor rsync -r --ignore-existing \
    -e "ssh -i /keys/anchor -o StrictHostKeyChecking=accept-new -o UserKnownHostsFile=/tmp/known_hosts" \
    puller@spool:. /anchor/
  echo "the anchor holds $(compose exec -T anchor sh -c 'ls /anchor | wc -l' | tr -d ' ') checkpoint notes"
}

# anchor_copy <dest>: the anchor's copy, for the auditor.
anchor_copy() {
  if [ -n "${ANCHOR_SSH:-}" ]; then
    mkdir -p "$work/$1"
    # shellcheck disable=SC2029 # expanded here on purpose: a date, and the operator's address
    ssh "$ANCHOR_SSH" "sudo tar -C ~anchor/$anchor_dir -cf - ." | tar -C "$work/$1" -xf -
    return
  fi
  copy_out usher_anchor-copy . "$1"
}

step "2. A login, consent and token flow; usher stops, signing a closing checkpoint"
./scripts/dev-access-token.sh >/dev/null
compose stop usher >/dev/null
echo "what the host will later roll back to: a snapshot of its log and spool"
docker run --rm -v usher_usher-audit:/audit:ro -v "$work":/out alpine:3.20 tar -C /audit -cf /out/earlier.tar log anchor

step "3. A second flow, and the anchor pulls over SSH (read-only key, rrsync -ro)"
compose up -d --wait usher >/dev/null
./scripts/dev-access-token.sh >/dev/null
compose stop usher >/dev/null
pull

step "4. The auditor verifies the log against the anchor's copy"
copy_out usher_usher-audit log honest/log
anchor_copy honest/anchor
tally verify --dir "$work/honest/log" --key "$key" --anchor "$work/honest/anchor" --require-fully-attested

step "5. Root on the host rolls the log and its spool back to step 2"
docker run --rm -v usher_usher-audit:/audit -v "$work":/in alpine:3.20 \
  sh -c 'rm -rf /audit/log /audit/anchor && tar -C /audit -xpf /in/earlier.tar'
copy_out usher_usher-audit log rolled/log
copy_out usher_usher-audit anchor rolled/host-spool
anchor_copy rolled/anchor

step "6a. Against the host's own spool, the rollback is invisible (tally's T-08, T-21)"
if tally verify --dir "$work/rolled/log" --key "$key" --anchor "$work/rolled/host-spool" --require-fully-attested; then
  echo "=> intact: a spool the host can write proves nothing"
else
  echo "demo: expected the host's spool to accept the rollback" >&2
  exit 1
fi

step "6b. Against the anchor's copy, it is detected"
if tally verify --dir "$work/rolled/log" --key "$key" --anchor "$work/rolled/anchor" --require-fully-attested; then
  echo "demo: the anchor's copy did not detect the rollback" >&2
  exit 1
else
  echo "=> violated (exit $?): the anchor holds a checkpoint the rolled-back log no longer reaches"
fi

if [ -n "${ANCHOR_SSH:-}" ]; then
  step "7. From the usher host, nothing can write to the anchor machine"
  # By address: a container does not resolve mDNS names, and a login that
  # fails to resolve proves nothing. Each attempt must reach the machine and
  # be refused there.
  anchor_addr=$(python3 -c 'import socket, sys; print(socket.gethostbyname(sys.argv[1]))' "${ANCHOR_SSH#*@}")
  echo "the only private SSH key in the stack is the unused demo key in the anchor container;"
  echo "the spool holds host keys and the anchor machine's public key"
  for who in anchor pi root; do
    out=$(compose exec -T anchor ssh -i /keys/anchor -o BatchMode=yes -o ConnectTimeout=5 \
      -o StrictHostKeyChecking=accept-new -o UserKnownHostsFile=/tmp/known_hosts \
      "$who@$anchor_addr" true 2>&1) && {
      echo "demo: the usher stack logged in to the anchor machine as $who" >&2
      exit 1
    }
    case "$out" in
      *"Permission denied"*) echo "=> refused by the anchor machine: $who@$anchor_addr" ;;
      *)
        echo "demo: $who@$anchor_addr was not refused by the machine, it failed otherwise: $out" >&2
        exit 1
        ;;
    esac
  done
fi

step "Done"
echo "The anchor, not the host, is what made the rollback detectable. On real hardware it is another"
echo "machine the host holds no credential to; see the README's \"End to end\" section."
