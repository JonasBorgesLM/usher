// Package tallyaudit is audit.Recorder over tally, the ecosystem's
// tamper-evident log (ADR-0023). It lives in usher, not in tally: whoever
// owns the interface hosts the adapter, and tally imports nothing of usher's.
//
// Each replica has its own log, its own vault and its own signing key, whose
// name is the log's origin (ADR-0023's amendment, #165). The person behind a
// Record enters the log only as a random SubjectRef from this replica's
// vault, and the source address only sealed under that subject's key.
package tallyaudit

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/JonasBorgesLM/tally"
	"github.com/JonasBorgesLM/tally/anchor"
	"github.com/JonasBorgesLM/tally/filestore"
	"github.com/JonasBorgesLM/tally/seal"

	"github.com/JonasBorgesLM/usher/internal/audit"
)

// Config is where this replica's log, keys and vault live.
type Config struct {
	// LogDir holds the log's segments and checkpoints.
	LogDir string
	// SignerKeyFile holds the signer key tally keygen writes. Its name is
	// this replica's origin, so every replica has its own. It is never
	// usher's token keyset (ADR-0015): a separate Ed25519 key, in a
	// separate file.
	SignerKeyFile string
	// VaultDir holds this replica's vault: subject refs and their wrapped
	// keys.
	VaultDir string
	// KEKFile holds the 32-byte key that wraps the vault's keys.
	KEKFile string
	// AnchorDir is the create-only spool checkpoints are published to. It
	// protects nothing until something off the host pulls from it (tally's
	// README, "Anchoring off the host").
	AnchorDir string
	// FreeSpaceThreshold, in bytes, makes the log warn while free space on
	// its volume is below it. Zero disables the warning.
	FreeSpaceThreshold uint64
}

// ErrPoisoned is Ready's error once the log has refused a write: every later
// Record fails until the process restarts (tally's ADR-0009).
var ErrPoisoned = errors.New("tallyaudit: the audit log is poisoned; restart and verify it")

// Recorder is audit.Recorder over one tally log.
type Recorder struct {
	log      *tally.Log
	vault    *seal.FileVault
	logger   *slog.Logger
	stats    *syncStats
	poisoned *atomic.Bool
}

var _ audit.Recorder = (*Recorder)(nil)

// Open opens this replica's log, vault and spool, creating them on first
// use.
func Open(ctx context.Context, cfg Config, logger *slog.Logger) (*Recorder, error) {
	var fsOpts []filestore.Option
	if cfg.FreeSpaceThreshold > 0 {
		fsOpts = append(fsOpts, filestore.WithFreeSpaceThreshold(cfg.FreeSpaceThreshold))
	}
	store, err := filestore.Open(ctx, cfg.LogDir, fsOpts...)
	if err != nil {
		return nil, fmt.Errorf("tallyaudit: open the log: %w", err)
	}
	r, err := open(ctx, cfg, store, logger)
	if err != nil {
		return nil, errors.Join(err, store.Close())
	}
	return r, nil
}

// open is Open over any store, so a test can hand it one that fails.
func open(ctx context.Context, cfg Config, store tally.Store, logger *slog.Logger) (*Recorder, error) {
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	skey, err := os.ReadFile(cfg.SignerKeyFile) // #nosec G304 -- trusted operator config, as the keyset's path is
	if err != nil {
		return nil, fmt.Errorf("tallyaudit: read the signer key: %w", err)
	}
	signer, err := tally.NewSigner(string(bytes.TrimSpace(skey)))
	clear(skey)
	if err != nil {
		return nil, fmt.Errorf("tallyaudit: %w", err)
	}
	kek, err := loadKEK(cfg.KEKFile)
	if err != nil {
		return nil, err
	}
	spool, err := anchor.NewDir(cfg.AnchorDir)
	if err != nil {
		return nil, fmt.Errorf("tallyaudit: open the anchor spool: %w", err)
	}
	vault, err := seal.OpenFileVault(ctx, cfg.VaultDir, kek)
	if err != nil {
		return nil, fmt.Errorf("tallyaudit: open the vault: %w", err)
	}
	poisoned := &atomic.Bool{}
	stats := &syncStats{}
	log, err := tally.Open(ctx, store, signer,
		tally.WithAnchors(spool),
		tally.WithObserver(observer{logger: logger, poisoned: poisoned, stats: stats}))
	if err != nil {
		return nil, errors.Join(fmt.Errorf("tallyaudit: open the log: %w", err), vault.Close())
	}
	logger.Info("audit log open", "origin", signer.Name())
	return &Recorder{log: log, vault: vault, logger: logger, stats: stats, poisoned: poisoned}, nil
}

// loadKEK reads a 32-byte key. Its id is derived from the key, so a vault
// opened under a different key fails with seal.ErrUnknownKEK rather than
// under a reused name.
func loadKEK(path string) (seal.KEK, error) {
	key, err := os.ReadFile(path) // #nosec G304 -- trusted operator config, as the keyset's path is
	if err != nil {
		return nil, fmt.Errorf("tallyaudit: read the KEK: %w", err)
	}
	defer clear(key)
	if len(key) != 32 {
		return nil, fmt.Errorf("tallyaudit: the KEK file holds %d bytes, want 32", len(key))
	}
	sum := sha256.Sum256(key)
	kek, err := seal.NewLocalKEK("local-"+hex.EncodeToString(sum[:4]), key)
	if err != nil {
		return nil, fmt.Errorf("tallyaudit: %w", err)
	}
	return kek, nil
}

// Record appends r and returns once it is durable.
func (r *Recorder) Record(ctx context.Context, rec audit.Record) error {
	if rec.ID == "" {
		return errors.New("tallyaudit: a record needs an ID, generated before the action")
	}
	id := tally.EventID(rec.ID)
	ev := tally.Event{
		ID:         id,
		OccurredAt: rec.At,
		Action:     "auth." + string(rec.Type),
		Outcome:    outcome(rec.Outcome),
	}
	switch {
	case rec.Subject != "":
		ref, err := r.vault.Resolve(ctx, []byte(rec.Subject))
		if err != nil {
			return fmt.Errorf("tallyaudit: resolve the subject: %w", err)
		}
		ev.Actor = tally.Subject(ref)
		if rec.ClientID != "" {
			ev.Resource = "client/" + rec.ClientID
		}
		if rec.SourceAddr != "" {
			details, err := json.Marshal(sealedDetails{SourceAddr: rec.SourceAddr})
			if err != nil {
				return fmt.Errorf("tallyaudit: %w", err)
			}
			if ev.Payload, err = seal.Payload(ctx, r.vault, r.log.ID(), id, ref, details); err != nil {
				return fmt.Errorf("tallyaudit: seal the details: %w", err)
			}
		}
	case rec.ClientID != "":
		actor, err := tally.Service(rec.ClientID)
		if err != nil {
			return fmt.Errorf("tallyaudit: the client as actor: %w", err)
		}
		ev.Actor = actor
	default:
		ev.Actor = tally.System()
	}
	if _, err := r.log.Append(ctx, ev); err != nil {
		if errors.Is(err, tally.ErrPoisoned) || r.poisoned.Load() {
			// Nothing in this process can reach the log again (tally's
			// ADR-0009): say so, so a retry stops (audit.Reductions).
			return fmt.Errorf("tallyaudit: %w: %w", audit.ErrRecorderDown, err)
		}
		return fmt.Errorf("tallyaudit: %w", err)
	}
	return nil
}

// sealedDetails is what a record seals under its subject's key.
type sealedDetails struct {
	SourceAddr string `json:"source_addr"`
}

func outcome(o audit.Outcome) tally.Outcome {
	if o == audit.OutcomeSuccess {
		return tally.OutcomeSuccess
	}
	return tally.OutcomeFailure
}

// Ready is /readyz's check (ADR-0023, Decision 4): an error once the log is
// poisoned, so an orchestrator routes logins away from this replica rather
// than failing every grant on it.
func (r *Recorder) Ready(context.Context) error {
	if r.poisoned.Load() {
		return ErrPoisoned
	}
	return nil
}

// Close signs the log's closing checkpoint, publishes it, and closes the
// log and the vault.
//
// It logs the batches written since Open and the p50 and p99 of their
// fsyncs: the log's own share of a grant's latency, which ADR-0023's budget
// is about and which a load test of the HTTP endpoint cannot separate out.
func (r *Recorder) Close() error {
	err := errors.Join(r.log.Close(), r.vault.Close())
	s := r.SyncStats()
	r.logger.Info("audit log closed", "batches", s.Batches, "entries", s.Entries,
		"sync_p50_ms", ms(s.P50), "sync_p99_ms", ms(s.P99), "sync_max_ms", ms(s.Max))
	return err
}

func ms(d time.Duration) float64 { return float64(d.Microseconds()) / 1000 }

// SyncStats is what the log reported of its batches since Open: how many,
// how many entries, and the p50, p99 and maximum of the store's time to make
// one durable, fsync included. Percentiles are over the most recent
// syncSamples batches.
type SyncStats struct {
	Batches, Entries int
	P50, P99, Max    time.Duration
}

// SyncStats returns the batch statistics so far.
func (r *Recorder) SyncStats() SyncStats { return r.stats.snapshot() }

// syncSamples bounds the memory the statistics hold: the most recent
// batches, a ring.
const syncSamples = 1 << 16

// syncStats collects Observer.Batch reports. Batch is called from the log's
// writer and must not block; the lock is held for an append.
type syncStats struct {
	mu               sync.Mutex
	batches, entries int
	samples          []time.Duration
	next             int
	maxSync          time.Duration
}

func (s *syncStats) add(n int, d time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.batches++
	s.entries += n
	s.maxSync = max(s.maxSync, d)
	if len(s.samples) < syncSamples {
		s.samples = append(s.samples, d)
		return
	}
	s.samples[s.next] = d
	s.next = (s.next + 1) % syncSamples
}

func (s *syncStats) snapshot() SyncStats {
	s.mu.Lock()
	sorted := slices.Clone(s.samples)
	out := SyncStats{Batches: s.batches, Entries: s.entries, Max: s.maxSync}
	s.mu.Unlock()
	if len(sorted) == 0 {
		return out
	}
	slices.Sort(sorted)
	at := func(q float64) time.Duration { return sorted[min(len(sorted)-1, int(float64(len(sorted))*q))] }
	out.P50, out.P99 = at(0.50), at(0.99)
	return out
}

// observer reports the log's conditions to the logger. Its methods are
// called from the log's writer and must not block (tally.Observer).
type observer struct {
	logger   *slog.Logger
	poisoned *atomic.Bool
	stats    *syncStats
}

// Batch reports a durable batch and the time its store took, fsync
// included; Close logs their distribution.
func (o observer) Batch(n int, syncLatency time.Duration) { o.stats.add(n, syncLatency) }

// AnchorPublish reports a checkpoint the spool did not take.
func (o observer) AnchorPublish(err error, dropped uint64) {
	o.logger.Warn("audit log: anchor publication failed", "error", err, "dropped", dropped)
}

// DiskSpace reports free space below the configured threshold.
func (o observer) DiskSpace(free uint64) {
	o.logger.Warn("audit log: free space below the threshold", "free_bytes", free)
}

// ClockRegression reports a clock reading earlier than the last record's.
func (o observer) ClockRegression(by time.Duration) {
	o.logger.Warn("audit log: the clock went backwards", "by", by)
}

// Poisoned reports, once, the error that stopped the log, and marks the
// replica not ready.
func (o observer) Poisoned(err error) {
	o.poisoned.Store(true)
	o.logger.Error("audit log: poisoned; every privilege grant now fails closed", "error", err)
}

// Recovered reports bytes of a torn tail quarantined on open.
func (o observer) Recovered(quarantined int64) {
	o.logger.Warn("audit log: torn tail quarantined on open", "bytes", quarantined)
}
