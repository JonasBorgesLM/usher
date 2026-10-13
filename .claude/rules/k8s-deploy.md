---
paths:
  - 'k8s/**'
  - 'Dockerfile.*'
  - 'cmd/usher/main.go'
  - 'cmd/usher/serve.go'
  - 'cmd/resource-server/main.go'
description: 'Disposable validation cluster (ADR-0022): the NetworkPolicy is trust config, probe roles, drain budget arithmetic'
---

# Kubernetes manifests

`k8s/` is a **disposable validation cluster** (ADR-0022), not a production
deployment. Postgres and Redis run in-cluster on throwaway storage, and the
`Secret`s are base64, not encryption. Do not delete the warning comment on
them, and do not treat these manifests as a template for anything real
(REQUIREMENTS §1.1).

## The NetworkPolicy is part of the trust configuration

`USHER_TRUSTED_PROXY_CIDRS` and `RESOURCE_SERVER_TRUSTED_PROXY_CIDRS` declare
the pod CIDR (k3s default `10.42.0.0/16`), which is far wider than compose's
single fixed address. Two NetworkPolicies make that range safe to trust:

- ingress to usher's pods **only** from the ingress controller;
- ingress to the resource server's pods **only** from usher's pods.

Deleting, loosening, or relabelling around either policy **widens who can
forge `X-Forwarded-For` and `X-Auth-*`**. Nothing fails when that happens:
every probe, every test and every rollout stays green. Change a policy, a pod
label it selects on, or either CIDR only together with the others.

A CNI that does not enforce NetworkPolicy turns this into "trust every pod in
the cluster". k3s's embedded controller enforces it, but that is verified on
the target cluster, by the first check `k8s/` runs, **before** anything trusts
the CIDR. Never `0.0.0.0/0` (ADR-0010).

## Probes

- `/healthz` is **liveness**: it answers `200` while the process is alive and
  checks no dependency.
- `/readyz` is **readiness**: Postgres, Redis, and a signing key valid now
  (RNF-10).
- Never swap them. Liveness on `/readyz` means a Redis blip restarts every
  pod, turning a recoverable outage into a crash loop.
- Both are the `operational` route group (`cmd/usher/chain.go`): no rate
  limit, because an orchestrator polling every few seconds is the expected
  caller. Do not move them under a limiter.
- The resource server has only `/healthz`; it serves both roles there, and
  that is fine for a demo upstream with no dependency of its own at startup.

## The shutdown budget is arithmetic, and it breaks silently

usher starts draining the instant SIGTERM arrives (`serve`,
`cmd/usher/serve.go`). Its endpoint leaves the Service asynchronously, so the
pod still receives new connections for a moment. A `preStop` sleep covers
that window **in the manifest**, so the binary does not grow a
Kubernetes-only setting (ADR-0022, decision 6):

```
terminationGracePeriodSeconds  >  preStop sleep
                                + shutdownDrainDeadline   (cmd/usher/main.go, 10 s)
                                + headroom for the request in flight
```

The resource server has the same shape with its own `shutdownTimeout`
(`cmd/resource-server/main.go`, also 10 s). Raising either constant without
raising the grace period reintroduces dropped requests during a rollout,
**silently**. Whoever changes one of the numbers updates the comment in the
manifest that states the sum.

The `preStop` hook runs `sleep` from the image, which exists because the
final stage is `alpine`. A move to `scratch` or distroless must switch to the
native `sleep` lifecycle action at the same time, or the hook fails and the
delay disappears.

`maxUnavailable: 0` and `maxSurge: 1` are a pair. Together they make the
rollout zero-downtime rather than merely fast.

## Startup

Before it listens, usher migrates the schema (under an advisory lock,
ADR-0018, so concurrent replicas wait rather than race), checks Redis for
`noeviction` (ADR-0003), and loads the keyset. During that window,
connections are refused rather than answered. A `startupProbe` on `/healthz`
owns the window, and `initialDelaySeconds` on liveness does not, because
liveness would kill a pod mid-migration.

Redis is started with `--maxmemory-policy noeviction`, and it must allow
`CONFIG GET`, because usher refuses to start when it cannot verify the
policy. That is intended (RNF-05), not a probe problem.

## Keys and identity

- The keyset is a `Secret` mounted read-only as `USHER_KEYS_DIR`. It must be
  readable by UID 65532: the images run as `USER 65532:65532`, and
  `runAsNonRoot` can only verify a numeric user. Set `fsGroup` or the
  volume's `defaultMode` accordingly; usher exits at startup with
  `permission denied` otherwise, as the compose stack proved without its
  `chown`.
- usher reads the keyset **once, at startup**. Rotation (ADR-0015) is: add the
  next key to the Secret with a future `sign_from`, then
  `kubectl rollout restart`. Updating the Secret alone changes nothing.
- Neither binary writes to its filesystem (only `cmd/genkeys` does), so
  `readOnlyRootFilesystem: true` holds for both.

## Replicas

The bastion breaker is per process. With 2 replicas, a fully failed upstream
sees up to 2 × the threshold of failing calls before every replica has opened
(ADR-0022, decision 8). That is accepted; do not "fix" it with shared breaker
state without the reopening criterion's measurement.

## Prove it, don't read it

The rollout test under `k8s/` measures a rollout with load running inside the
cluster. Run it when you change the shutdown path, the probes, the rollout
strategy, or a NetworkPolicy.
