#!/usr/bin/env bash
#
# T-17's live check (RI-02, RNF-04, RI-06): sapper's fault injector between
# the real gateway and the real resource server, asserting the breaker opens,
# sheds and recovers. Automates the procedure in
# docs/security/sapper-fault-injection-report.txt (#124).
#
#   SAPPER=/path/to/sapper ./.github/scripts/check-fault-injection.sh
#
# Runs every docs/security/sapper-fault-injection*.yaml scenario (the
# -config.yaml is the shared safety config, not a scenario), each against a
# freshly recreated usher container so every run starts with a closed
# breaker. Needs Docker, Go, openssl and python3.
#
# It writes its own .env and docker-compose.override.yml and removes both on
# exit, together with the stack and its volumes — so it refuses to start if
# either file already exists rather than overwrite a developer's real ones.
# Results land in $OUT_DIR (default: a temporary directory, printed).

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
keys_dir=$(mktemp -d)

cleanup() {
  docker compose down -v >/dev/null 2>&1 || true
  rm -f .env docker-compose.override.yml
  rm -rf "$keys_dir"
}
trap cleanup EXIT

# clocks records the host's and the usher container's clocks next to the
# token's exp claim (not secret: a timestamp). #145 saw two stacks out of nine
# where every request turned 401 partway through a run and stayed there; a
# jump in the Docker VM's clock expiring the 5-minute token is the leading
# hypothesis, and this is what would confirm or rule it out next time.
clocks() {
  local vm exp
  vm=$(docker compose exec -T usher date -u +%s 2>/dev/null || echo unknown)
  exp=$(printf '%s' "${ACCESS_TOKEN:-}" | python3 -c 'import sys,json,base64
p=sys.stdin.read().split(".")
print(json.loads(base64.urlsafe_b64decode(p[1]+"=="*2)).get("exp","?") if len(p)==3 else "no-token")' 2>/dev/null || echo unparsable)
  echo "clocks ($1): host=$(date -u +%s) vm=$vm token_exp=$exp"
}

umask 077
pg_pw=$(openssl rand -hex 16)
redis_pw=$(openssl rand -hex 16)
cat > .env <<EOF
POSTGRES_DB=usher
POSTGRES_USER=usher
POSTGRES_PASSWORD=${pg_pw}
REDIS_PASSWORD=${redis_pw}
USHER_ISSUER=http://localhost:8080
USHER_CSRF_SECRET=$(openssl rand -hex 32)
EOF

# The scenarios' profile.listen is 0.0.0.0:19200 on this host. host-gateway
# makes host.docker.internal resolve on Linux too, where Docker does not
# define it by default.
cat > docker-compose.override.yml <<'EOF'
services:
  usher:
    extra_hosts:
      - "host.docker.internal:host-gateway"
    environment:
      USHER_API_UPSTREAM_URL: http://host.docker.internal:19200
EOF

echo "--- bringing the stack up (gateway routed through the injector) ---"
docker compose up -d --build --wait

echo "--- seeding the dev users ---"
GOEXPERIMENT=jsonv2 \
  USHER_DATABASE_URL="postgres://usher:${pg_pw}@localhost:5432/usher" \
  USHER_REDIS_ADDR=localhost:6379 \
  USHER_REDIS_PASSWORD="${redis_pw}" \
  USHER_ISSUER=http://localhost:8080 \
  USHER_CSRF_SECRET=$(openssl rand -hex 32) \
  USHER_CLIENTS_PATH=./clients.dev.json \
  USHER_KEYS_DIR="$keys_dir" \
  USHER_DIRECTLY_EXPOSED=true \
  go run ./cmd/seed

failed=0
ran=0
for scenario in docs/security/sapper-fault-injection*.yaml; do
  case "$scenario" in *-config.yaml) continue ;; esac
  name=$(basename "$scenario" .yaml)
  echo "--- ${name} ---"
  docker compose up -d --wait --force-recreate --no-deps usher
  ACCESS_TOKEN=$(./scripts/dev-access-token.sh)
  export ACCESS_TOKEN
  clocks "before ${name}" | tee "$out/${name}.clocks"
  "$SAPPER" run --config docs/security/sapper-fault-injection-config.yaml \
    --scenario "$scenario" --out "$out/${name}.json"
  if "$SAPPER" assert --in "$out/${name}.json"; then
    echo "PASS  ${name}"
  else
    echo "FAIL  ${name}"
    failed=1
    # Evidence before the next scenario recreates usher: the clocks again, and
    # every container's log (no secrets by RS-23), into OUT_DIR, which the
    # workflow uploads as an artifact.
    clocks "after ${name}" | tee -a "$out/${name}.clocks"
    # The resource server logs every request (~175k lines a run), so only its
    # tail; the rest in full.
    docker compose logs --no-color usher postgres redis > "$out/${name}.compose.log" 2>&1 || true
    docker compose logs --no-color --tail 2000 resource-server >> "$out/${name}.compose.log" 2>&1 || true
  fi
  ran=$((ran + 1))
done

if [ "$ran" -eq 0 ]; then
  echo "FAIL  no scenario found under docs/security/sapper-fault-injection*.yaml"
  exit 1
fi
echo "results: $out"
exit "$failed"
