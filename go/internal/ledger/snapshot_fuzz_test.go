package ledger

import (
	"encoding/json"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"testing"
	"unsafe"
)

// Randomized D137 equivalence (the D38 differential idea turned
// inward): random rule-valid histories, a snapshot cut at a random
// point — sometimes two, stacked — and the whole-struct comparison
// against the uncompacted fold. Seeded and deterministic; widen with
// GROUNDHOLD_FUZZ_N when touching the snapshot or the fold rules.
func TestSnapshotEquivalenceFuzz(t *testing.T) {
	n := 25
	if env := os.Getenv("GROUNDHOLD_FUZZ_N"); env != "" {
		if v, err := strconv.Atoi(env); err == nil && v > 0 {
			n = v
		}
	}
	for seed := 0; seed < n; seed++ {
		seed := seed
		t.Run(fmt.Sprintf("seed-%d", seed), func(t *testing.T) {
			rng := rand.New(rand.NewSource(int64(seed)))
			td := t.TempDir()
			full := filepath.Join(td, "full.jsonl")
			events := buildRandomHistory(t, rng, full)
			if events < 4 {
				t.Skip("history too short to cut")
			}
			fullLed, err := ReplayFile(full)
			if err != nil {
				t.Fatalf("full replay: %v", err)
			}
			cut := 1 + rng.Intn(events-1)
			cuts := []int{cut}
			// half the seeds stack a second compaction on the first
			if cut < events-1 && rng.Intn(2) == 0 {
				cuts = append(cuts, cut+1+rng.Intn(events-cut-1))
			}
			seeded := foldViaSnapshots(t, td, full, events, cuts)
			assertLedgersEquivalent(t, fullLed, seeded)
		})
	}
}

// buildRandomHistory drives the REAL Writer through a rule-valid
// random walk (leases before mutations, detected before resolved,
// terminal receipts only for pending ones) and returns the event count.
func buildRandomHistory(t *testing.T, rng *rand.Rand, path string) int {
	t.Helper()
	caps := []string{"db", "cache", "queue"}[:2+rng.Intn(2)]
	w := &Writer{Path: path, Led: New(), Env: "prod",
		Clock: 1752600000, Actor: "fuzz"}
	type capState struct {
		leased    bool
		token     int
		pendingOp string
		violated  bool
		claimed   bool
		opSeq     int
	}
	st := map[string]*capState{}
	for _, c := range caps {
		st[c] = &capState{}
	}
	events := 0
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	steps := 12 + rng.Intn(24)
	for i := 0; i < steps; i++ {
		w.Clock += 1 + rng.Intn(120)
		c := caps[rng.Intn(len(caps))]
		s := st[c]
		switch {
		case !s.leased && rng.Intn(3) == 0:
			tok, err := w.AppendLease([]string{c},
				map[string]any{"ttlSeconds": 3600})
			must(err)
			s.leased, s.token = true, tok
		case s.leased && s.pendingOp == "" && rng.Intn(2) == 0:
			s.opSeq++
			s.pendingOp = fmt.Sprintf("op-%s-%d", c, s.opSeq)
			status := []string{"pending", "unknown"}[rng.Intn(2)]
			must(w.Append("operation.receipt", []string{c}, map[string]any{
				"operationId": s.pendingOp, "status": status,
				"idempotencyKey": s.pendingOp}, s.token))
		case s.leased && s.pendingOp != "" && rng.Intn(2) == 0:
			must(w.Append("operation.receipt", []string{c}, map[string]any{
				"operationId": s.pendingOp, "status": "succeeded",
				"idempotencyKey": s.pendingOp}, s.token))
			s.pendingOp = ""
		case s.leased && rng.Intn(3) == 0:
			must(w.Append("binding.updated", []string{c}, map[string]any{
				"providerId": "fake:" + c,
				"generation": 1 + rng.Intn(3)}, s.token))
		case s.leased && s.pendingOp == "" && rng.Intn(4) == 0:
			must(w.Append("lease.released", []string{c}, nil, s.token))
			s.leased = false
		case s.violated && rng.Intn(2) == 0:
			must(w.Append("violation.resolved", []string{c}, map[string]any{
				"capability": c, "constraint": "c-z"}, 0))
			s.violated = false
		case s.leased && !s.claimed && rng.Intn(4) == 0:
			// D140 takeover authorship: lives ONLY in the claimed map (no
			// binding body), so it exercises the snapshot's Claimed field —
			// the projection D182's sibling find showed compaction dropped.
			// A mutation, so it needs the fencing token (D29).
			must(w.Append("ownership.claimed", []string{c},
				map[string]any{"note": "fuzz takeover"}, s.token))
			s.claimed = true
		case rng.Intn(4) == 0:
			must(w.Append("violation.detected", []string{c}, map[string]any{
				"capability": c, "constraint": "c-z",
				"reason": "fuzz drift"}, 0))
			s.violated = true
		case rng.Intn(3) == 0:
			// D191: emit BOTH a provider-api and a probe reading of the same
			// path, so per-source retention (ObservationsBySource) carries two
			// sources through the snapshot boundary — the projection this
			// property test exists to keep honest.
			src := "provider-api"
			if rng.Intn(2) == 0 {
				src = "probe"
			}
			must(w.Append("observation.recorded", []string{c}, map[string]any{
				"observations": []any{map[string]any{
					"path": "service.managed", "value": true,
					"observedAt": FormatTs(w.Clock),
					"ttlSeconds": 900 + rng.Intn(90000),
					"derivation": "measured", "source": src}}}, 0))
		default:
			must(w.Append("contract.published", []string{c}, map[string]any{
				"contract": c + "-contract", "version": i + 1}, 0))
		}
		events++
	}
	return events
}

// foldViaSnapshots replays prefix cuts through the REAL snapshot
// serialization boundary (JSON on disk, sidecar beside the tail),
// stacking when more than one cut is given.
func foldViaSnapshots(t *testing.T, td, full string, total int, cuts []int) *Ledger {
	t.Helper()
	raw, err := os.ReadFile(full)
	if err != nil {
		t.Fatal(err)
	}
	lines := splitLines(raw)
	write := func(path string, ls []string) {
		out := ""
		for _, l := range ls {
			out += l + "\n"
		}
		if err := os.WriteFile(path, []byte(out), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	prevCut := 0
	var snap *Snapshot
	for si, cut := range cuts {
		seg := filepath.Join(td, fmt.Sprintf("seg-%d.jsonl", si))
		write(seg, lines[prevCut:cut])
		if snap != nil {
			rawSnap, _ := json.Marshal(snap)
			if err := os.WriteFile(SnapshotPath(seg), rawSnap, 0o600); err != nil {
				t.Fatal(err)
			}
		}
		led, err := ReplayFile(seg)
		if err != nil {
			t.Fatalf("cut %d replay: %v", cut, err)
		}
		snap = BuildSnapshot(led)
		prevCut = cut
	}
	tail := filepath.Join(td, "tail.jsonl")
	write(tail, lines[prevCut:])
	rawSnap, _ := json.Marshal(snap)
	if err := os.WriteFile(SnapshotPath(tail), rawSnap, 0o600); err != nil {
		t.Fatal(err)
	}
	seeded, err := ReplayFile(tail)
	if err != nil {
		t.Fatalf("seeded replay (cuts %v of %d): %v", cuts, total, err)
	}
	return seeded
}

// assertLedgersEquivalent is the shared whole-struct comparison —
// position/identity first, then reflect.DeepEqual over everything.
func assertLedgersEquivalent(t *testing.T, full, seeded *Ledger) {
	t.Helper()
	if seeded.TotalEvents() != full.TotalEvents() ||
		seeded.headAtTip() != full.headAtTip() ||
		seeded.LedgerId() != full.LedgerId() {
		t.Fatalf("position/identity drift: total %d vs %d, tip %s vs %s, id %s vs %s",
			seeded.TotalEvents(), full.TotalEvents(),
			seeded.headAtTip(), full.headAtTip(),
			seeded.LedgerId(), full.LedgerId())
	}
	if !reflect.DeepEqual(seeded.EventHashes,
		full.EventHashes[len(full.EventHashes)-len(seeded.EventHashes):]) {
		t.Fatal("tail event hashes diverge")
	}
	fc, sc := *full, *seeded
	fc.EventHashes, sc.EventHashes = nil, nil
	fc.BaseEvents, sc.BaseEvents = 0, 0
	fc.BaseHead, sc.BaseHead = "", ""
	fc.ledgerId, sc.ledgerId = "", ""
	fc.verifiedFrom, sc.verifiedFrom = "", ""
	fc.snapshotHash, sc.snapshotHash = "", ""
	fv := reflect.ValueOf(&fc).Elem()
	sv := reflect.ValueOf(&sc).Elem()
	for i := 0; i < fv.NumField(); i++ {
		name := fv.Type().Field(i).Name
		a, b := fv.Field(i), sv.Field(i)
		// unexported fields: read via unsafe-free trick — compare
		// through the addressable copies
		af := reflect.NewAt(a.Type(), unsafePointer(fv, i)).Elem()
		bf := reflect.NewAt(b.Type(), unsafePointer(sv, i)).Elem()
		if !reflect.DeepEqual(af.Interface(), bf.Interface()) {
			t.Errorf("field %s drifts:\n  full:   %+v\n  seeded: %+v",
				name, af.Interface(), bf.Interface())
		}
	}
	if t.Failed() {
		t.Fatal("projection drift between full fold and snapshot+tail")
	}
}

func unsafePointer(v reflect.Value, field int) unsafe.Pointer {
	// v is an addressable copy made by the caller
	return unsafe.Pointer(v.Field(field).UnsafeAddr())
}
