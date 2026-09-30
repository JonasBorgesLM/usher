package config

import (
	"net/http"
	"testing"
)

func TestBuildKeyFunc_DirectlyExposedUsesRemoteAddr(t *testing.T) {
	cfg := Config{DirectlyExposed: true}
	keyFunc, err := cfg.BuildKeyFunc()
	if err != nil {
		t.Fatalf("BuildKeyFunc: %v", err)
	}

	r := &http.Request{RemoteAddr: "203.0.113.5:54321", Header: http.Header{}}
	key, err := keyFunc(r)
	if err != nil {
		t.Fatalf("keyFunc: %v", err)
	}
	if key != "203.0.113.5" {
		t.Errorf("key = %q, want the RemoteAddr's host, 203.0.113.5", key)
	}
}

// TestBuildKeyFunc_ForgedForwardedHeaderFromUntrustedPeerIgnored is the
// issue's own wording: "Forged X-Forwarded-For from an untrusted peer does
// not change the key." The peer here (203.0.113.5) is outside the declared
// trusted CIDR (10.0.0.0/8, usher's own load balancer range in this test),
// so the header it sent — claiming to be the real client at 1.2.3.4 — must
// be ignored entirely; the key is the peer's own address.
//
// Negative control: replacing BuildKeyFunc's realip-based KeyFunc with a
// naive one that reads X-Forwarded-For unconditionally (the exploitable
// shape realip exists to avoid) made this test fail with the forged
// address. Verified by hand, restored before committing.
//
// (An earlier attempt at this control passed realip.InsecureTrustEveryPeer()
// instead, expecting it to trust the forged header. It did not fail: that
// option only widens what counts as an acceptable *default-route* CIDR
// entry — "0.0.0.0/0" — and has no effect when the configured CIDR is
// already a specific, non-default range like 10.0.0.0/8. Recorded here
// rather than silently swapped for a control that actually works, since
// this is the second time in this codebase a plausible-looking mutation
// turned out to prove nothing — worth being able to find again.)
func TestBuildKeyFunc_ForgedForwardedHeaderFromUntrustedPeerIgnored(t *testing.T) {
	cfg := Config{TrustedProxyCIDRs: []string{"10.0.0.0/8"}}
	keyFunc, err := cfg.BuildKeyFunc()
	if err != nil {
		t.Fatalf("BuildKeyFunc: %v", err)
	}

	r := &http.Request{
		RemoteAddr: "203.0.113.5:54321", // not in 10.0.0.0/8 -- an untrusted peer
		Header:     http.Header{"X-Forwarded-For": []string{"1.2.3.4"}},
	}
	key, err := keyFunc(r)
	if err != nil {
		t.Fatalf("keyFunc: %v", err)
	}
	if key != "203.0.113.5" {
		t.Errorf("key = %q, want the untrusted peer's own address (203.0.113.5), not the forged header (1.2.3.4)", key)
	}
}

// TestBuildKeyFunc_ForwardedHeaderFromTrustedPeerIsUsed is the other half:
// a peer that IS the declared proxy gets its header believed. Without this
// case, a version of BuildKeyFunc that ignored every forwarded header
// unconditionally would pass the negative-control test above for the wrong
// reason.
func TestBuildKeyFunc_ForwardedHeaderFromTrustedPeerIsUsed(t *testing.T) {
	cfg := Config{TrustedProxyCIDRs: []string{"10.0.0.0/8"}}
	keyFunc, err := cfg.BuildKeyFunc()
	if err != nil {
		t.Fatalf("BuildKeyFunc: %v", err)
	}

	r := &http.Request{
		RemoteAddr: "10.0.0.1:54321", // inside 10.0.0.0/8 -- the trusted proxy
		Header:     http.Header{"X-Forwarded-For": []string{"198.51.100.9"}},
	}
	key, err := keyFunc(r)
	if err != nil {
		t.Fatalf("keyFunc: %v", err)
	}
	if key != "198.51.100.9" {
		t.Errorf("key = %q, want the forwarded address from the trusted proxy (198.51.100.9)", key)
	}
}
