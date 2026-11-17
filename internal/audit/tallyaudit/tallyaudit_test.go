package tallyaudit

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/JonasBorgesLM/tally"
	"github.com/JonasBorgesLM/tally/filestore"
	"github.com/JonasBorgesLM/tally/seal"
	"github.com/JonasBorgesLM/tally/tallytest"

	"github.com/JonasBorgesLM/usher/internal/audit"
)

// testConfig lays out a replica's files in a temporary directory, with
// tally's test signer key and a random KEK.
func testConfig(t *testing.T) Config {
	t.Helper()
	root := t.TempDir()
	cfg := Config{
		LogDir:        filepath.Join(root, "log"),
		SignerKeyFile: filepath.Join(root, "signer.key"),
		VaultDir:      filepath.Join(root, "vault"),
		KEKFile:       filepath.Join(root, "kek"),
		AnchorDir:     filepath.Join(root, "anchor"),
	}
	if err := os.WriteFile(cfg.SignerKeyFile, []byte(tallytest.TestSignerKey+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	kek := make([]byte, 32)
	_, _ = rand.Read(kek)
	if err := os.WriteFile(cfg.KEKFile, kek, 0o600); err != nil {
		t.Fatal(err)
	}
	return cfg
}

func login(subject, client, addr string) audit.Record {
	return audit.Record{ID: audit.NewRecordID(), Type: audit.EventLoginAttempt, Outcome: audit.OutcomeSuccess,
		Subject: subject, ClientID: client, SourceAddr: addr, At: time.Unix(1_700_000_000, 0)}
}

// readBack decodes every entry of the log in dir, after checking that it
// verifies fully attested under tally's test key.
func readBack(t *testing.T, dir string) []tally.RecordView {
	t.Helper()
	ctx := context.Background()
	keys, err := tally.NewVerifiers(tallytest.TestVerifierKey)
	if err != nil {
		t.Fatal(err)
	}
	rd, err := filestore.OpenReader(dir)
	if err != nil {
		t.Fatal(err)
	}
	rep, err := tally.Verify(ctx, rd, keys, tally.WithRequireFullyAttested())
	if err != nil || !rep.OK() {
		t.Fatalf("the audit log does not verify: %v, %+v", err, rep)
	}
	var out []tally.RecordView
	for r, rerr := range rd.Records(ctx, 1) {
		if rerr != nil {
			t.Fatal(rerr)
		}
		v, derr := tally.DecodeRecord(r.Body)
		if derr != nil {
			t.Fatal(derr)
		}
		out = append(out, v)
	}
	return out
}

// A person enters the log only as a SubjectRef, and the source address only
// sealed under that subject's key: neither is in clear in any file the
// adapter writes, the log verifies, and the sealed details open (ADR-0023,
// Decision 3).
//
// Seen failing with the subject and the address written as a plain payload
// beside the sealed one: the scan named both, in the segment.
func TestNoPersonInClear(t *testing.T) {
	ctx := context.Background()
	cfg := testConfig(t)
	r, err := Open(ctx, cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	const who, addr = "alice@example.com", "203.0.113.7"
	if err = r.Record(ctx, login(who, "web-app", addr)); err != nil {
		t.Fatal(err)
	}
	if err = r.Close(); err != nil {
		t.Fatal(err)
	}

	scanned := 0
	for _, dir := range []string{cfg.LogDir, cfg.AnchorDir, cfg.VaultDir} {
		err = filepath.WalkDir(dir, func(path string, d fs.DirEntry, werr error) error {
			if werr != nil || d.IsDir() {
				return werr
			}
			b, rerr := os.ReadFile(path) // #nosec G304 G122 -- a test's own temporary directory
			if rerr != nil {
				return rerr
			}
			for _, s := range []string{who, addr} {
				if bytes.Contains(b, []byte(s)) {
					t.Errorf("%s holds %q in clear", path, s)
				}
			}
			scanned++
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	if scanned < 4 {
		t.Fatalf("scanned %d files; the scan is looking at the wrong place", scanned)
	}

	entries := readBack(t, cfg.LogDir)
	if len(entries) != 1 {
		t.Fatalf("%d entries, want 1", len(entries))
	}
	e := entries[0]
	if e.ActorKind != "subject" || e.Action != "auth.login_attempt" || e.Resource != "client/web-app" || e.PayloadKind != "sealed" {
		t.Fatalf("entry = actor %s, action %s, resource %s, payload %s", e.ActorKind, e.Action, e.Resource, e.PayloadKind)
	}

	kek, err := loadKEK(cfg.KEKFile)
	if err != nil {
		t.Fatal(err)
	}
	v, err := seal.OpenFileVault(ctx, cfg.VaultDir, kek)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = v.Close() }()
	ref, err := v.Resolve(ctx, []byte(who))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(e.ActorID, ref[:]) {
		t.Fatal("the actor is not the subject's ref from this replica's vault")
	}
	aad, err := seal.AAD(e.LogID, tally.EventID(e.EventID), ref)
	if err != nil {
		t.Fatal(err)
	}
	plain, err := v.Open(ctx, ref, e.Payload, aad)
	if err != nil {
		t.Fatal(err)
	}
	var got sealedDetails
	if err = json.Unmarshal(plain, &got); err != nil || got.SourceAddr != addr {
		t.Fatalf("sealed details = %s, %v", plain, err)
	}
}

// Without a subject, the actor is the client, or the system; and a source
// address with nobody to seal it for is dropped, not stored in clear.
func TestActorsWithoutASubject(t *testing.T) {
	ctx := context.Background()
	cfg := testConfig(t)
	r, err := Open(ctx, cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err = r.Record(ctx, login("", "billing-svc", "203.0.113.9")); err != nil {
		t.Fatal(err)
	}
	if err = r.Record(ctx, login("", "", "")); err != nil {
		t.Fatal(err)
	}
	if err = r.Record(ctx, login("", "has space", "")); err == nil {
		t.Fatal("a client id tally refuses as a service name was recorded")
	}
	if err = r.Record(ctx, audit.Record{Type: audit.EventTokenIssued, Outcome: audit.OutcomeSuccess}); err == nil {
		t.Fatal("a record with no ID was accepted")
	}
	if err = r.Close(); err != nil {
		t.Fatal(err)
	}
	entries := readBack(t, cfg.LogDir)
	if len(entries) != 2 {
		t.Fatalf("%d entries, want 2", len(entries))
	}
	if e := entries[0]; e.ActorKind != "service" || string(e.ActorID) != "billing-svc" || e.PayloadKind != "none" {
		t.Fatalf("client entry = %s %q, payload %s", e.ActorKind, e.ActorID, e.PayloadKind)
	}
	if e := entries[1]; e.ActorKind != "system" {
		t.Fatalf("system entry = %s", e.ActorKind)
	}
}

// Once a write fails, Record fails and Ready reports the log poisoned, so
// /readyz takes the replica out (ADR-0023, Decision 4).
//
// Seen failing with the observer's poisoned flag never set.
func TestReadyReportsAPoisonedLog(t *testing.T) {
	ctx := context.Background()
	cfg := testConfig(t)
	errDisk := errors.New("disk refused the write")
	// The genesis is the first AppendBatch; the first Record is the second.
	store := tallytest.NewFaultyStore(tallytest.NewMemStore(), tallytest.FailAppend(2, errDisk))
	r, err := open(ctx, cfg, store, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = r.Close() }()
	if err = r.Ready(ctx); err != nil {
		t.Fatalf("Ready before any failure = %v", err)
	}
	if err = r.Record(ctx, login("bob@example.com", "web-app", "")); !errors.Is(err, errDisk) {
		t.Fatalf("the failing Record = %v, want the store's error", err)
	}
	if err = r.Ready(ctx); !errors.Is(err, ErrPoisoned) {
		t.Fatalf("Ready after the failure = %v, want ErrPoisoned", err)
	}
	if err = r.Record(ctx, login("bob@example.com", "web-app", "")); !errors.Is(err, tally.ErrPoisoned) || !errors.Is(err, audit.ErrRecorderDown) {
		t.Fatalf("the next Record = %v, want tally.ErrPoisoned as audit.ErrRecorderDown", err)
	}
}

// Open refuses, before writing anything, a signer key or a KEK it cannot use.
func TestOpenRefusesBadKeys(t *testing.T) {
	ctx := context.Background()
	cases := map[string]func(c *Config){
		"no signer key":   func(c *Config) { c.SignerKeyFile = filepath.Join(t.TempDir(), "missing") },
		"a malformed key": func(c *Config) { writeFile(t, c.SignerKeyFile, []byte("PRIVATE+KEY+nonsense")) },
		"a short KEK":     func(c *Config) { writeFile(t, c.KEKFile, make([]byte, 16)) },
		"no KEK":          func(c *Config) { c.KEKFile = filepath.Join(t.TempDir(), "missing") },
		"a different KEK": func(c *Config) { writeFile(t, c.KEKFile, bytes.Repeat([]byte{7}, 32)) },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			cfg := testConfig(t)
			if name == "a different KEK" {
				// A vault created under one KEK, reopened under another.
				r, err := Open(ctx, cfg, nil)
				if err != nil {
					t.Fatal(err)
				}
				if err = r.Record(ctx, login("carol@example.com", "", "")); err != nil {
					t.Fatal(err)
				}
				if err = r.Close(); err != nil {
					t.Fatal(err)
				}
			}
			mutate(&cfg)
			r, err := Open(ctx, cfg, nil)
			if err == nil {
				_ = r.Close()
				t.Fatal("Open accepted it")
			}
		})
	}
}

func writeFile(t *testing.T, path string, b []byte) {
	t.Helper()
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
}

// replicaKey builds a signer and verifier key pair named name, in SPEC
// §5.3's encoding, from a fixed seed: tally exports no key generator, and
// tests need a second replica's key.
func replicaKey(t *testing.T, name string, seed byte) (skey, vkey string) {
	t.Helper()
	priv := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{seed}, ed25519.SeedSize))
	pub := priv.Public().(ed25519.PublicKey)
	h := sha256.Sum256(append([]byte(name+"\n\x01"), pub...))
	id := fmt.Sprintf("%08x", binary.BigEndian.Uint32(h[:4]))
	skey = "PRIVATE+KEY+" + name + "+" + id + "+" + base64.StdEncoding.EncodeToString(append([]byte{1}, priv.Seed()...))
	vkey = name + "+" + id + "+" + base64.StdEncoding.EncodeToString(append([]byte{1}, pub...))
	return skey, vkey
}

// Two replicas, each with its own log, key and vault (ADR-0023's amendment,
// #165): each log verifies under its own key and fails as UnknownKey under
// the other's, and the same person has a different ref on each.
//
// Seen failing with both replicas given the same signer key: each log then
// verified under the other's key.
func TestReplicasAreSeparate(t *testing.T) {
	ctx := context.Background()
	type replica struct {
		cfg  Config
		vkey string
	}
	var reps []replica
	for i, name := range []string{"usher.test/usher-0", "usher.test/usher-1"} {
		cfg := testConfig(t)
		skey, vkey := replicaKey(t, name, byte(10+i))
		writeFile(t, cfg.SignerKeyFile, []byte(skey))
		r, err := Open(ctx, cfg, nil)
		if err != nil {
			t.Fatal(err)
		}
		if err = r.Record(ctx, login("user-1", "web-app", "203.0.113.7")); err != nil {
			t.Fatal(err)
		}
		if err = r.Close(); err != nil {
			t.Fatal(err)
		}
		reps = append(reps, replica{cfg, vkey})
	}
	verifyUnder := func(dir, vkey string) *tally.Report {
		t.Helper()
		keys, err := tally.NewVerifiers(vkey)
		if err != nil {
			t.Fatal(err)
		}
		rd, err := filestore.OpenReader(dir)
		if err != nil {
			t.Fatal(err)
		}
		rep, err := tally.Verify(ctx, rd, keys)
		if err != nil {
			t.Fatal(err)
		}
		return rep
	}
	refs := map[tally.SubjectRef]bool{}
	for i, own := range reps {
		other := reps[1-i]
		if rep := verifyUnder(own.cfg.LogDir, own.vkey); !rep.OK() || rep.AttestedSize != 2 {
			t.Fatalf("replica %d under its own key: %+v", i, rep)
		}
		rep := verifyUnder(own.cfg.LogDir, other.vkey)
		unknown := false
		for _, f := range rep.Failures {
			unknown = unknown || f.Kind == tally.UnknownKey
		}
		if rep.OK() || !unknown {
			t.Fatalf("replica %d under the other replica's key: %+v, want UnknownKey", i, rep)
		}
		kek, err := loadKEK(own.cfg.KEKFile)
		if err != nil {
			t.Fatal(err)
		}
		v, err := seal.OpenFileVault(ctx, own.cfg.VaultDir, kek)
		if err != nil {
			t.Fatal(err)
		}
		ref, err := v.Resolve(ctx, []byte("user-1"))
		_ = v.Close()
		if err != nil {
			t.Fatal(err)
		}
		refs[ref] = true
	}
	if len(refs) != 2 {
		t.Fatal("the same person has the same ref on both replicas")
	}
}
