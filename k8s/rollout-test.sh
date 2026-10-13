#!/usr/bin/env bash
#
# Measures what the manifests promise instead of reading them, on the
# cluster k8s/up.sh brought up. Two parts, in this order:
#
# 1. NetworkPolicy enforcement (ADR-0022 decision 3). The trusted-proxy
#    CIDRs cover the whole pod network, so the policies are what make them
#    safe. A probe pod that is neither Traefik nor usher must reach usher
#    through the ingress (proving the probe's own networking works) and
#    must NOT reach usher or the resource server directly. Nothing is
#    measured on a cluster that fails this: the result would be "trust
#    every pod".
#
# 2. A rolling restart of both Deployments under load. The load runs
#    inside the cluster, through Traefik, with a real access token: a
#    port-forward would attach to one pod and die with it, which is the
#    moment this test exists to observe. Every request must answer 200.
#    A token minted before the rollout validates on pods that started
#    after it, because every replica shares the keyset and Redis.
#
#   ./k8s/rollout-test.sh
#   LOAD_SECONDS=90 ./k8s/rollout-test.sh

set -euo pipefail
cd "$(dirname "$0")/.."

CLUSTER=${CLUSTER:-usher-validation}
CTX="k3d-${CLUSTER}"
NS=usher
LOAD_SECONDS=${LOAD_SECONDS:-60}
CURL_IMAGE=curlimages/curl:8.11.1
INGRESS=http://traefik.kube-system.svc.cluster.local
k() { kubectl --context "$CTX" "$@"; }

k -n "$NS" delete pod np-probe load --ignore-not-found >/dev/null
trap 'k -n "$NS" delete pod np-probe load --ignore-not-found --wait=false >/dev/null 2>&1 || true' EXIT

# --- 1. NetworkPolicy enforcement ----------------------------------------
# 000 is curl's "no HTTP answer": the policy dropped the connection, so it
# timed out. The expected line is asserted whole; a probe that never ran
# cannot produce it.
want="ingress=200 usher-direct=000 resource-server-direct=000"
got=$(k -n "$NS" run np-probe --image="$CURL_IMAGE" --restart=Never --rm -i --quiet --command -- sh -c "
  code() { curl -s -o /dev/null -w '%{http_code}' --max-time 3 \"\$1\"; }
  echo \"ingress=\$(code $INGRESS/healthz) usher-direct=\$(code http://usher:8080/healthz) resource-server-direct=\$(code http://resource-server:8081/healthz)\"
" | tr -d '\r')
if [ "$got" != "$want" ]; then
  echo "FAIL  NetworkPolicy: got '${got}', want '${want}'" >&2
  echo "      Do not trust the pod CIDR on this cluster (ADR-0022 decision 3)." >&2
  exit 1
fi
echo "ok    NetworkPolicy enforced: ${got}"

# --- 2. Rolling restart under load ---------------------------------------
token=$(USHER_BASE=http://localhost:18080 ./scripts/dev-access-token.sh 2>/dev/null) || {
  echo "FAIL  could not mint an access token (is the cluster up and seeded? run k8s/up.sh)" >&2
  exit 1
}

# The token reaches the pod through its environment: short-lived (the
# access-token TTL), in a disposable cluster, and never printed.
k -n "$NS" run load --image="$CURL_IMAGE" --restart=Never --env="TOKEN=${token}" --command -- sh -c "
  end=\$(( \$(date +%s) + $LOAD_SECONDS ))
  while [ \$(date +%s) -lt \$end ]; do
    curl -s -o /dev/null -w '%{http_code}\n' --max-time 5 -H \"Authorization: Bearer \$TOKEN\" $INGRESS/api/widgets
  done
" >/dev/null
k -n "$NS" wait --for=condition=Ready pod/load --timeout=60s >/dev/null
sleep 5 # requests flowing before anything restarts

for d in usher resource-server; do
  k -n "$NS" rollout restart "deployment/$d" >/dev/null
  k -n "$NS" rollout status "deployment/$d" --timeout=180s >/dev/null
  echo "ok    rolled deployment/$d"
done

k -n "$NS" wait --for=jsonpath='{.status.phase}'=Succeeded pod/load --timeout=$((LOAD_SECONDS + 60))s >/dev/null
counts=$(k -n "$NS" logs load | sort | uniq -c | sort -rn)
total=$(printf '%s\n' "$counts" | awk '{s += $1} END {print s+0}')
ok=$(printf '%s\n' "$counts" | awk '$2 == "200" {print $1}')
echo "      responses over ${LOAD_SECONDS}s:"
printf '%s\n' "$counts" | sed 's/^/        /'
if [ "$total" -eq 0 ] || [ "${ok:-0}" -ne "$total" ]; then
  echo "FAIL  rollout: ${ok:-0} of ${total} requests answered 200" >&2
  exit 1
fi
echo "ok    rollout lost no requests: ${ok} of ${total} answered 200"
