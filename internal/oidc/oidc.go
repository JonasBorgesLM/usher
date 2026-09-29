// Package oidc adds the OpenID Connect layer on top of internal/oauth:
// discovery, id_token issuance, /userinfo and logout (REQUIREMENTS §3.2,
// RF-11). Like internal/oauth, it must never import internal/proxy
// (ADR-0001).
//
// Designed and implemented in M7 (REQUIREMENTS §11); this file exists so the
// package is real for check-boundaries.sh and go build before that design is
// written.
package oidc
