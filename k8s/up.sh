#!/usr/bin/env bash
#
# Brings up usher's disposable validation cluster (ADR-0022) on k3d:
# builds both images, generates every secret and the signing keyset, applies
# k8s/*.yaml, and seeds the admin user. Idempotent: re-running it reuses the
# cluster, keeps the existing Secrets, and rolls the Deployments onto the
# freshly built images.
#
#   ./k8s/up.sh
#   ./k8s/rollout-test.sh
#   k3d cluster delete usher-validation      # when done
#
# Every kubectl call names its context, so this never acts on whatever
# cluster the shell happens to point at.
#
# The Secrets are base64, NOT encryption. They hold freshly generated
# random values and a dev-only keyset, are created here rather than
# committed, and die with the cluster. Nothing in this cluster is fit for
# anything real (REQUIREMENTS §1.1).

set -euo pipefail
cd "$(dirname "$0")/.."

CLUSTER=${CLUSTER:-usher-validation}
CTX="k3d-${CLUSTER}"
NS=usher
HOST_PORT=18080 # must match USHER_ISSUER in k8s/30-usher.yaml
k() { kubectl --context "$CTX" "$@"; }

for tool in k3d kubectl docker go openssl; do
  command -v "$tool" >/dev/null || { echo "up: $tool is required" >&2; exit 1; }
done
export GOEXPERIMENT=jsonv2

if k3d cluster list "$CLUSTER" >/dev/null 2>&1; then
  echo "up: reusing k3d cluster ${CLUSTER}"
  k3d cluster start "$CLUSTER" >/dev/null
else
  # k3s ships Traefik as its ingress controller and enforces NetworkPolicy
  # with its embedded controller; both are relied on, and the second is
  # verified by rollout-test.sh rather than assumed.
  k3d cluster create "$CLUSTER" -p "${HOST_PORT}:80@loadbalancer" --wait
fi

docker build -q -f Dockerfile.usher -t usher:dev . >/dev/null
docker build -q -f Dockerfile.resource-server -t resource-server:dev . >/dev/null
k3d image import usher:dev resource-server:dev -c "$CLUSTER" >/dev/null

k apply -f k8s/00-namespace.yaml >/dev/null

if ! k -n "$NS" get secret usher-secrets >/dev/null 2>&1; then
  pg_pass=$(openssl rand -hex 24)
  k -n "$NS" create secret generic usher-secrets \
    --from-literal=POSTGRES_PASSWORD="$pg_pass" \
    --from-literal=USHER_DATABASE_URL="postgres://usher:${pg_pass}@postgres:5432/usher?sslmode=disable" \
    --from-literal=REDIS_PASSWORD="$(openssl rand -hex 24)" \
    --from-literal=USHER_CSRF_SECRET="$(openssl rand -hex 32)" >/dev/null
  echo "up: generated usher-secrets"
fi

if ! k -n "$NS" get secret usher-keys >/dev/null 2>&1; then
  keydir=$(mktemp -d)
  trap 'rm -rf "$keydir"' EXIT
  # genkeys reads usher's whole configuration (config.Load has no partial
  # mode) but uses only USHER_KEYS_DIR; the rest only has to be valid.
  USHER_DATABASE_URL=postgres://unused@localhost/unused USHER_REDIS_ADDR=localhost:6379 \
    USHER_ISSUER="http://localhost:${HOST_PORT}" USHER_DIRECTLY_EXPOSED=true \
    USHER_CSRF_SECRET="$(openssl rand -hex 32)" USHER_CLIENTS_PATH=clients.dev.json \
    USHER_KEYS_DIR="$keydir" go run ./cmd/genkeys
  k -n "$NS" create secret generic usher-keys --from-file="$keydir" >/dev/null
  echo "up: generated the signing keyset into usher-keys"
fi

k -n "$NS" create configmap usher-clients --from-file=clients.json=clients.dev.json \
  --dry-run=client -o yaml | k apply -f - >/dev/null

k apply -f k8s/ >/dev/null
# imagePullPolicy Never with a fixed tag: a rebuilt image is only picked up
# by new pods.
k -n "$NS" rollout restart deployment/usher deployment/resource-server >/dev/null
for d in postgres redis usher resource-server; do
  k -n "$NS" rollout status "deployment/$d" --timeout=180s
done

# cmd/seed runs from the host against a temporary port-forward; it is
# idempotent, so a second run reports the user exists and changes nothing.
k -n "$NS" port-forward svc/postgres 15432:5432 >/dev/null 2>&1 &
pf=$!
trap '{ kill "$pf" && wait "$pf"; } 2>/dev/null || true; rm -rf "${keydir:-}"' EXIT
for _ in $(seq 1 20); do
  nc -z localhost 15432 2>/dev/null && break
  sleep 0.5
done
pg_pass=$(k -n "$NS" get secret usher-secrets -o jsonpath='{.data.POSTGRES_PASSWORD}' | base64 -d)
USHER_DATABASE_URL="postgres://usher:${pg_pass}@localhost:15432/usher?sslmode=disable" \
  USHER_REDIS_ADDR=localhost:6379 USHER_ISSUER="http://localhost:${HOST_PORT}" \
  USHER_DIRECTLY_EXPOSED=true USHER_CSRF_SECRET="$(openssl rand -hex 32)" \
  USHER_CLIENTS_PATH=clients.dev.json USHER_KEYS_DIR=/nonexistent \
  go run ./cmd/seed

echo "up: usher is at http://localhost:${HOST_PORT} (through Traefik)"
