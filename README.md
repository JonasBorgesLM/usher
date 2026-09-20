# usher

**An OAuth 2.1 / OpenID Connect authorization server and reverse proxy, written
from scratch in Go to study the parts of authentication that are easy to get
subtly wrong.**

> **Status: pre-code.** This repository currently holds the intent and nothing
> else — no implementation, no design records. The scope below is the target,
> not a description of what exists. Treat every unchecked box as unbuilt.

## Why write another one

Not to be used. There are good authorization servers already, and the correct
advice for production is to run one of them.

The point is that OAuth's failure modes are almost never in the happy path. An
implementation that issues a token to a well-behaved client looks finished long
before it is correct. What separates a real authorization server from a
convincing one is the set of checks nobody exercises by accident:

- Binding `redirect_uri` on exact string match, not prefix, not host.
- Making the PKCE `code_verifier` mandatory and actually comparing it, rather
  than accepting the challenge and never checking the proof.
- Treating an authorization code as single-use, and revoking the issued tokens
  when a code is replayed rather than merely rejecting the second exchange.
- Validating `state` and `nonce` as separate defenses against separate attacks,
  instead of conflating them.
- Refusing to reflect an `error` back to an unvalidated redirect target.

Reading the RFCs teaches the shape of these. Implementing them teaches which
ones you would have skipped.

## Intended scope

OAuth 2.1 consolidates OAuth 2.0 and removes what practice showed to be unsafe:
the implicit grant and the resource owner password grant are gone, PKCE is
required for the authorization code grant, and bearer tokens in query strings
are disallowed. That consolidated surface is the target here.

### Authorization server

- [ ] Authorization code grant with mandatory PKCE (`S256` only, never `plain`)
- [ ] Client credentials grant
- [ ] Refresh tokens with rotation and reuse detection
- [ ] Token introspection (RFC 7662) and revocation (RFC 7009)
- [ ] OIDC `id_token` issuance and the UserInfo endpoint
- [ ] Discovery (`/.well-known/openid-configuration`) and a JWKS endpoint with
      key rotation

### Reverse proxy

- [ ] Token validation at the edge, so upstream services receive verified
      identity rather than raw credentials
- [ ] Per-route scope requirements

### Throughout

- [ ] A documented threat model, in the spirit of the one in
      [`crier`](https://github.com/JonasBorgesLM/crier)
- [ ] Architecture decision records for anything with a defensible alternative
- [ ] Tests that assert the refusals, not only the successes — a test suite that
      only proves tokens get issued proves the wrong half

## Open decisions

These are unmade, and making them is part of the exercise:

- **Token format.** Self-contained JWTs (no lookup, no revocation) versus opaque
  handles (revocable, but a datastore read on every call).
- **Storage.** In-memory for study, or a real persistence layer behind an
  interface from the start.
- **Proxy coupling.** One binary with two modes, or two binaries sharing a
  library.

## Not for production

This is a study project by someone learning the specification, not a reviewed or
audited implementation. Use [Keycloak](https://www.keycloak.org/),
[Ory Hydra](https://www.ory.sh/hydra/), [Auth0](https://auth0.com/) or any other
maintained authorization server for anything real.

## License

[MIT](LICENSE)
