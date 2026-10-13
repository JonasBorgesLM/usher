# ADR-0022: usher runs on Kubernetes as a disposable validation cluster, still one binary

## Status
Proposed — 2026-10-12
Accepted — 2026-10-12, as proposed; the order of work is in the Amendment below (#151)

## Context
The question came after v0.1.1: should usher become a set of microservices run
by Kubernetes? Two different questions hide in that one, and they have
different answers.

**"More services" is ADR-0001's question, and it already has a reopening
criterion.** Split the authorization server from the gateway when (a) the proxy
path needs to scale independently of `/token` under a *measured* load, or (b)
the keys need a process boundary from internet-facing proxy code. Nothing has
measured (a). (b) is a real property, since a remote-code-execution bug in the
proxy path reaches the signing keys today (ADR-0001's own largest cost, and
T-18's residual), but it is a security trade, not something Kubernetes
brings.

**"Run it on Kubernetes" is an operations question, and most of the answer is
already in the code.** Every piece of state that must be shared between
replicas already lives outside the process:

| State | Where | Shared across replicas |
| --- | --- | --- |
| Refresh families, users, consent | Postgres (ADR-0002) | yes |
| Sessions, challenges, codes, the gateway denylist, rate-limit buckets | Redis (ADR-0003, ADR-0014) | yes |
| Schema migrations | Postgres, under an advisory lock (ADR-0018) | safe to run from every replica |
| Signing keyset | a mounted directory (ADR-0015) | yes, every replica derives the JWKS and the active key from the keyset and the clock alone |

Four things do not carry over as they stand:

1. **The trusted proxy is a fixed IP.** ADR-0010's amendment pins usher at
   `172.28.0.10` in compose, and the resource server trusts exactly that
   address. Pod IPs change on every reschedule.
2. **The breaker is per process** (`cmd/usher/router.go`). N replicas are N
   independent breakers, each needing its own threshold of failures before it
   opens.
3. **The images run as root** (#121), which a `runAsNonRoot` pod refuses.
4. **Shutdown has no pre-stop delay.** `serve` starts draining (10 s,
   `shutdownDrainDeadline`) the instant SIGTERM arrives. A pod keeps receiving
   new connections until its endpoint leaves the Service, which happens
   asynchronously, so a rollout drops requests.

The ecosystem already has a precedent for the frame. `task-api`'s `k8s/` is a
**disposable validation cluster** with in-cluster Postgres, MinIO and Redis on
throwaway storage, a base64 `Secret` labelled as not encryption, and a
`rollout-test.sh`. Its `.claude/rules/k8s-deploy.md` records the probe and
shutdown-budget rules that cluster taught.

## Decision (proposed)
1. **Frame: a disposable validation cluster, not a production deployment.** A
   local k3d cluster, with Postgres and Redis in-cluster on throwaway storage,
   and secrets as base64 `Secret`s carrying the same "not encryption" warning
   as task-api's. This stays inside REQUIREMENTS §1.1: usher is a study
   project, and this studies running it, not operating it.
2. **Still one binary (ADR-0001 stands).** One `usher` Deployment (AS and
   gateway together, 2 replicas), one `resource-server` Deployment, Postgres,
   and Redis started with `--maxmemory-policy noeviction`. usher's startup
   `EvictionCheck` (ADR-0003) needs `CONFIG GET`, which a self-hosted Redis
   allows.
3. **Trust: the pod CIDR, made narrow by a NetworkPolicy.** usher declares the
   cluster's pod CIDR in `USHER_TRUSTED_PROXY_CIDRS` (k3s default
   `10.42.0.0/16`), and a NetworkPolicy admits ingress to usher's pods **only**
   from the ingress controller. The resource server declares the same CIDR, and
   a NetworkPolicy admits ingress to it only from usher's pods. ADR-0010's rule
   stands: never `0.0.0.0/0`, and always a declared range. The range is wider
   than compose's single address, and the network policy is what makes it safe
   to trust. **The policy is part of the trust configuration, not hardening
   on top of it.** A cluster whose CNI does not enforce NetworkPolicy must not
   run these manifests. k3s's embedded policy controller does enforce it; that
   has to be verified on the cluster the manifests target before they are
   trusted.
4. **Keys: a `Secret` mounted as the keyset directory**, read-only, readable by
   the container's non-root user. Rotation is ADR-0015 as implemented: add the
   next key to the Secret with a future `sign_from`, then `kubectl rollout
   restart`. usher reads the keyset once, at startup.
5. **Probes:** `/healthz` for liveness (no dependency) and `/readyz` for
   readiness (Postgres, Redis, a signing key), as task-api does. Never swapped:
   a Redis blip must take a pod out of rotation, not restart it.
6. **Shutdown budget, stated as arithmetic:**
   `terminationGracePeriodSeconds > preStop delay + shutdownDrainDeadline (10 s)
   + headroom`. The pre-stop delay is a `preStop` `sleep` hook, so usher's code
   does not grow a Kubernetes-specific setting. `maxUnavailable: 0`,
   `maxSurge: 1`.
7. **Images run as a fixed non-root UID** (`USER 65532`), the prerequisite for
   `runAsNonRoot`. This reopens what #121 deferred, and only this.
8. **The breaker stays per replica, and that is accepted.** With 2 replicas and
   a threshold of 5, a fully failed upstream sees up to 10 failing calls
   before every replica has opened, instead of 5. A shared breaker would mean
   distributed state on the request path, for a demo upstream.

## The alternative that was rejected
**Split the authorization server and the gateway into two Deployments now.**
The case for it is real: it is ADR-0001's criterion (b). The signing keys would
live only in a process that does not terminate internet-facing proxy traffic,
which closes T-18's largest residual. Kubernetes makes the topology cheap to
express: two Deployments, two Services, and a NetworkPolicy so only the
gateway reaches the AS's internal endpoints.

It is rejected *for now*, not dismissed:

- The split is not a deployment change today, whatever ADR-0001 hoped. The
  gateway's `bearerValidator` is `pkg/tokenvalidator` over an **in-process**
  key source (`deps.Keyset.AsKeySource()`, `cmd/usher/router.go`), not over
  the JWKS. A gateway in its own process would need the resource server's
  model, the same validator over the AS's published JWKS, so the gateway
  inherits the JWKS cache window and RS-09's refetch rate limit.
  That is a change in how revocation and rotation reach the gateway, and it
  deserves its own ADR and its own threat-model pass.
- Nothing measured (a), and (b) is not triggered by moving to Kubernetes.
  Usher's non-goals still hold, so it is not running anywhere that would make
  the residual unacceptable.

**A production-shaped deployment** (managed Postgres and Redis, external
secrets, TLS, HA): rejected by REQUIREMENTS §1.1. ADR-0003 also excludes the
managed Redis offerings that block `CONFIG`.

**Exposing usher directly with a NodePort** (`USHER_DIRECTLY_EXPOSED=true`, no
ingress): simpler, since the client IP is the connection peer and there is no
CIDR question. It is rejected because it studies less: the trusted-proxy path
is the one ADR-0010 exists for, and a validation cluster that skips it does
not validate it.

## Consequences
- **Before any manifest exists**, three code or image changes land, each in its
  own pull request: a non-root `USER` in both Dockerfiles (decision 7), the
  documented shutdown arithmetic (decision 6), and the k8s rules file
  (`.claude/rules/k8s-deploy.md`, as task-api has) stating which settings are
  load-bearing.
- **The trust range is wider than compose's.** It is sound only while the
  NetworkPolicy is enforced. A CNI that silently ignores policies turns
  decision 3 into "trust every pod in the cluster". That is the main way these
  manifests can be wrong without failing.
- **Up to 2× the failing calls before every breaker opens**, as above.
- Key rotation needs a restart, as it already does. A Secret update alone
  changes nothing until the rollout.

## Reopening criterion
- **Split AS and gateway:** ADR-0001's criteria, unchanged. Add a third: the
  first time usher is deployed anywhere its non-goals do not hold, (b) applies
  before that deployment, not after it.
- **Shared breaker state:** a measured case where per-replica breakers sent
  more load to a failing upstream than it could absorb.
- **Production frame:** a change to REQUIREMENTS §1.1 itself.

## Amendment — accepted (#151)

Accepted as proposed; nothing above is narrowed or superseded. The work lands
in this order, each step in its own pull request, because each is a
precondition for the next:

1. **Non-root images** (decision 7): `USER 65532` in both Dockerfiles, with the
   compose stack and the README examples still passing. This matters for the
   compose stack too, not only for Kubernetes.
2. **`.claude/rules/k8s-deploy.md`**: the load-bearing settings and their
   arithmetic (decision 6's shutdown budget, the probe split, and decision 3's
   rule that the NetworkPolicy is part of the trust configuration), stated next
   to the files they constrain, as task-api's equivalent does.
3. **`k8s/` manifests and a rollout test on k3d**, the first of which verifies
   that the target cluster enforces NetworkPolicy before anything trusts the
   pod CIDR (decision 3).


## Amendment — implemented (#152, #153, #154)

All three steps landed, in order: non-root images (#152), the rules file
(#153), and `k8s/` with its rollout test (#154). Nothing above is
superseded. Implementing the decisions settled three details they left open,
and one statement in the rules file had to be corrected:

- **The resource server fetches the JWKS through the ingress**, not from
  usher's Service. Decision 3 admits only the ingress controller to usher's
  pods; a direct fetch would have needed a second allowed source, from inside
  the trusted CIDR. The Ingress has no host rule, so any request reaching
  Traefik goes to usher.
- **The keyset Secret is mounted `0440` with `fsGroup: 65532`.** `keys.Load`
  already skips the Secret volume's `..data` entries and follows its
  per-file symlinks, so decision 4 needed no code change. The compose stack
  needed one: `genkeys` writes `0600` as root, and the keys volume is now
  chowned to 65532. Without it, usher exits at startup with
  `permission denied`.
- **What the trusted CIDR governs is `X-Forwarded-For` only**, meaning the IP
  axis of RS-22 and the logs. The rules file first also named `X-Auth-*`,
  which was wrong: usher strips inbound `X-Auth-*` (RS-17), and the resource
  server reads none. #154 corrected it.

Measured on k3d (`k8s/rollout-test.sh`):

| Check | Result |
| --- | --- |
| NetworkPolicy, a pod that is neither Traefik nor usher | reaches usher through the ingress (200), and reaches neither usher nor the resource server directly |
| The same check with both policies deleted | fails: both reached directly (200) |
| Rolling restart of both Deployments under load, two runs | 12328/12328 and 12750/12750 answered 200 |
| The same rollout with `preStop` removed | 9 of 13403 lost (8 × 502, 1 with no answer) |

Decision 6's `preStop` delay is therefore measured, not assumed. k3s's
policy controller lets kubelet probes through to pods under these policies,
so the probes needed no extra rule.

The rollout test does not run in CI, because the pipeline has no cluster.
It is a manual check, run when the shutdown path, the probes, the rollout
strategy or a NetworkPolicy changes (`.claude/rules/k8s-deploy.md`).
