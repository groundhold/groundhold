package restore

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"groundhold/internal/ledger"
)

// buildFakeLedger writes a 7-event ledger over TWO capabilities with one
// shared multi-capability event (the final observation lists both), using
// only the real Writer path — the fake-provider equivalent of a genuine
// history. It returns the ledger path.
//
//	1 lease.acquired   [orders-db]            <- genesis (line 1)
//	2 binding.updated  [orders-db]
//	3 lease.released   [orders-db]
//	4 lease.acquired   [cache-net]
//	5 binding.updated  [cache-net]
//	6 lease.released   [cache-net]
//	7 observation.recorded [orders-db, cache-net]   <- shared tip of both
func buildFakeLedger(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "ledger.jsonl")
	led, err := ledger.ReplayFile(path)
	if err != nil {
		t.Fatal(err)
	}
	w := &ledger.Writer{Path: path, Led: led, Env: "test", Actor: "t"}

	binding := func(pid string) map[string]any {
		return map[string]any{"resources": []any{map[string]any{
			"id": "primary", "type": "fake.thing", "providerId": pid,
			"generation": 1}}}
	}

	w.Clock = 1000
	tok1, err := w.AppendLease([]string{"orders-db"},
		map[string]any{"ttlSeconds": 300})
	if err != nil {
		t.Fatal(err)
	}
	w.Clock = 1001
	if err := w.Append("binding.updated", []string{"orders-db"},
		binding("fake:orders-1"), tok1); err != nil {
		t.Fatal(err)
	}
	w.Clock = 1002
	if err := w.Append("lease.released", []string{"orders-db"}, nil, tok1); err != nil {
		t.Fatal(err)
	}

	w.Clock = 1003
	tok2, err := w.AppendLease([]string{"cache-net"},
		map[string]any{"ttlSeconds": 300})
	if err != nil {
		t.Fatal(err)
	}
	w.Clock = 1004
	if err := w.Append("binding.updated", []string{"cache-net"},
		binding("fake:cache-1"), tok2); err != nil {
		t.Fatal(err)
	}
	w.Clock = 1005
	if err := w.Append("lease.released", []string{"cache-net"}, nil, tok2); err != nil {
		t.Fatal(err)
	}

	w.Clock = 1006
	if err := w.Append("observation.recorded",
		[]string{"orders-db", "cache-net"},
		map[string]any{"observations": []any{map[string]any{
			"path": "network.publicExposure", "value": false,
			"observedAt": "2026-07-15T08:06:00Z", "source": "provider-api"}}},
		0); err != nil {
		t.Fatal(err)
	}
	return path
}

// emitAnchorAndCapsules replays the ledger, writes a fresh anchor next to
// out/anchor.json and one capsule per capability into out/. Returns the
// anchor path and the capsule paths (sorted by capability).
func emitAnchorAndCapsules(t *testing.T, ledgerPath, outDir string,
	caps ...string) (string, []string) {
	t.Helper()
	if err := os.MkdirAll(outDir, 0o700); err != nil {
		t.Fatal(err)
	}
	led, err := ledger.ReplayFile(ledgerPath)
	if err != nil {
		t.Fatal(err)
	}
	anchor := ledger.BuildAnchor(led)
	anchorPath := filepath.Join(outDir, "anchor.json")
	writeJSON(t, anchorPath, anchor)

	var capsulePaths []string
	for _, cap := range caps {
		c, err := ledger.EmitCapsule(ledgerPath, cap)
		if err != nil {
			t.Fatalf("emit capsule %q: %v", cap, err)
		}
		p := filepath.Join(outDir, cap+".capsule.json")
		writeJSON(t, p, c)
		capsulePaths = append(capsulePaths, p)
	}
	return anchorPath, capsulePaths
}

func writeJSON(t *testing.T, path string, v any) {
	t.Helper()
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
}

func loadCapsuleFile(t *testing.T, path string) *ledger.Capsule {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var c ledger.Capsule
	if err := json.Unmarshal(raw, &c); err != nil {
		t.Fatal(err)
	}
	return &c
}

// TestRestoreEquivalence is the feature's core property: restoring from a
// complete, verified capsule set rebuilds a ledger whose fold is
// per-capability identical to the original — Heads, Bindings, Observations.
func TestRestoreEquivalence(t *testing.T) {
	ledger.ResetSigning()
	ledgerPath := buildFakeLedger(t)
	orig, err := ledger.ReplayFile(ledgerPath)
	if err != nil {
		t.Fatal(err)
	}

	outDir := t.TempDir()
	anchorPath, capsules := emitAnchorAndCapsules(t, ledgerPath, outDir,
		"orders-db", "cache-net")

	// the disaster: the original ledger is gone.
	if err := os.Remove(ledgerPath); err != nil {
		t.Fatal(err)
	}
	restoredPath := filepath.Join(t.TempDir(), "restored.jsonl")

	rep, code := Run(Options{Out: restoredPath, AnchorPath: anchorPath,
		CapsulePaths: capsules})
	if code != ExitOK {
		t.Fatalf("restore refused a good set (code %d): %v", code, rep.Reasons)
	}
	if rep.Status != "restored" {
		t.Fatalf("status = %q, want restored", rep.Status)
	}

	restored, err := ledger.ReplayFile(restoredPath)
	if err != nil {
		t.Fatalf("restored ledger does not replay: %v", err)
	}

	for _, cap := range []string{"orders-db", "cache-net"} {
		if orig.Heads[cap] != restored.Heads[cap] {
			t.Errorf("head[%s]: orig %s != restored %s",
				cap, orig.Heads[cap], restored.Heads[cap])
		}
		if !reflect.DeepEqual(orig.Bindings[cap], restored.Bindings[cap]) {
			t.Errorf("binding[%s] diverged:\n orig %v\n rest %v",
				cap, orig.Bindings[cap], restored.Bindings[cap])
		}
		if !reflect.DeepEqual(orig.Observations[cap], restored.Observations[cap]) {
			t.Errorf("observations[%s] diverged:\n orig %v\n rest %v",
				cap, orig.Observations[cap], restored.Observations[cap])
		}
	}
	if orig.LedgerId() != restored.LedgerId() {
		t.Errorf("ledger identity changed: %s -> %s",
			orig.LedgerId(), restored.LedgerId())
	}
	if restored.TotalEvents() != orig.TotalEvents() {
		t.Errorf("event count: orig %d != restored %d",
			orig.TotalEvents(), restored.TotalEvents())
	}
	// a fresh anchor was cut and it verifies the restored ledger.
	fresh, err := ledger.LoadAnchorFile(ledger.AnchorPath(restoredPath))
	if err != nil {
		t.Fatalf("no fresh anchor: %v", err)
	}
	if chk := ledger.CheckAnchor(restored, fresh); chk.Status != "verified" {
		t.Errorf("fresh anchor does not verify restore: %s", chk.Status)
	}
}

// TestRefuseMissingCapability: a capability the anchor names but no
// capsule covers is an incomplete backup — refuse, never partial.
func TestRefuseMissingCapability(t *testing.T) {
	ledger.ResetSigning()
	ledgerPath := buildFakeLedger(t)
	outDir := t.TempDir()
	// emit the anchor over BOTH caps but only the orders-db capsule.
	anchorPath, capsules := emitAnchorAndCapsules(t, ledgerPath, outDir,
		"orders-db")

	rep, code := Run(Options{Out: filepath.Join(t.TempDir(), "r.jsonl"),
		AnchorPath: anchorPath, CapsulePaths: capsules})
	if code != ExitRefused {
		t.Fatalf("expected refusal (5), got %d: %v", code, rep.Reasons)
	}
	if !containsSubstr(rep.Reasons, "cache-net") {
		t.Errorf("refusal should name the missing capability: %v", rep.Reasons)
	}
}

// TestRefuseDroppedEvent: dropping a middle event from a capsule breaks
// its prev-linkage; dropping the tip changes its recomputed head. Either
// way VerifyCapsule refuses before restore can weave a partial history.
func TestRefuseDroppedEvent(t *testing.T) {
	ledger.ResetSigning()
	ledgerPath := buildFakeLedger(t)
	outDir := t.TempDir()
	anchorPath, capsules := emitAnchorAndCapsules(t, ledgerPath, outDir,
		"orders-db", "cache-net")

	// drop a middle event from the orders-db capsule (event 2 of its 4).
	c := loadCapsuleFile(t, capsules[0])
	if len(c.Events) < 3 {
		t.Fatalf("need >=3 events to drop a middle one, have %d", len(c.Events))
	}
	c.Events = append(c.Events[:1], c.Events[2:]...)
	writeJSON(t, capsules[0], c)

	rep, code := Run(Options{Out: filepath.Join(t.TempDir(), "r.jsonl"),
		AnchorPath: anchorPath, CapsulePaths: capsules})
	if code != ExitRefused {
		t.Fatalf("expected refusal (5), got %d: %v", code, rep.Reasons)
	}
}

// TestRefuseByteFlip: a single mutated body value changes the event's
// canonical hash — the chain no longer links and the head no longer
// matches. Corruption cannot be laundered through restore.
func TestRefuseByteFlip(t *testing.T) {
	ledger.ResetSigning()
	ledgerPath := buildFakeLedger(t)
	outDir := t.TempDir()
	anchorPath, capsules := emitAnchorAndCapsules(t, ledgerPath, outDir,
		"orders-db", "cache-net")

	c := loadCapsuleFile(t, capsules[0])
	// flip a value inside a non-tip event so the FLIP is what refuses,
	// not merely the head check: rewrite the binding's providerId.
	flipped := false
	for _, doc := range c.Events {
		ev, _ := doc["event"].(map[string]any)
		if ev["type"] != "binding.updated" {
			continue
		}
		body, _ := ev["body"].(map[string]any)
		res, _ := body["resources"].([]any)
		r0, _ := res[0].(map[string]any)
		r0["providerId"] = "fake:TAMPERED"
		flipped = true
	}
	if !flipped {
		t.Fatal("found no event to flip")
	}
	writeJSON(t, capsules[0], c)

	rep, code := Run(Options{Out: filepath.Join(t.TempDir(), "r.jsonl"),
		AnchorPath: anchorPath, CapsulePaths: capsules})
	if code != ExitRefused {
		t.Fatalf("expected refusal (5), got %d: %v", code, rep.Reasons)
	}
}

// TestRefuseStaleCapsule: a capsule cut before history advanced is stale
// against a FRESH anchor — the anchor's head has moved past the capsule's.
func TestRefuseStaleCapsule(t *testing.T) {
	ledger.ResetSigning()
	ledgerPath := buildFakeLedger(t)
	outDir := t.TempDir()

	// cut the capsules NOW (they capture the current tips).
	_, capsules := emitAnchorAndCapsules(t, ledgerPath, outDir,
		"orders-db", "cache-net")

	// history advances on orders-db: a fresh observation.
	led, err := ledger.ReplayFile(ledgerPath)
	if err != nil {
		t.Fatal(err)
	}
	w := &ledger.Writer{Path: ledgerPath, Led: led, Env: "test",
		Actor: "t", Clock: 2000}
	if err := w.Append("observation.recorded", []string{"orders-db"},
		map[string]any{"observations": []any{map[string]any{
			"path": "network.publicExposure", "value": true,
			"observedAt": "2026-07-16T00:00:00Z", "source": "probe"}}},
		0); err != nil {
		t.Fatal(err)
	}
	// a FRESH anchor now pins the advanced head.
	freshLed, err := ledger.ReplayFile(ledgerPath)
	if err != nil {
		t.Fatal(err)
	}
	freshAnchorPath := filepath.Join(outDir, "fresh-anchor.json")
	writeJSON(t, freshAnchorPath, ledger.BuildAnchor(freshLed))

	rep, code := Run(Options{Out: filepath.Join(t.TempDir(), "r.jsonl"),
		AnchorPath: freshAnchorPath, CapsulePaths: capsules})
	if code != ExitRefused {
		t.Fatalf("expected refusal (5) for a stale capsule, got %d: %v",
			code, rep.Reasons)
	}
}

// TestRefuseOverwrite: restore never clobbers an existing ledger.
func TestRefuseOverwrite(t *testing.T) {
	ledger.ResetSigning()
	ledgerPath := buildFakeLedger(t)
	outDir := t.TempDir()
	anchorPath, capsules := emitAnchorAndCapsules(t, ledgerPath, outDir,
		"orders-db", "cache-net")

	existing := filepath.Join(t.TempDir(), "already.jsonl")
	if err := os.WriteFile(existing, []byte("x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	rep, code := Run(Options{Out: existing, AnchorPath: anchorPath,
		CapsulePaths: capsules})
	if code != ExitOperator {
		t.Fatalf("expected operator error (1), got %d: %v", code, rep.Reasons)
	}
}

// TestRefuseDuplicateCapsule: two capsules for one capability is a merge
// input — a later slice, refused loudly in slice 1.
// TestMergeIdenticalDedupes: the same capsule supplied twice is now DEDUPED and
// restored (slice 2 supersedes slice 1's single-source refusal); the duplicate
// is recorded as a merged alternate, never a conflict.
func TestMergeIdenticalDedupes(t *testing.T) {
	ledger.ResetSigning()
	ledgerPath := buildFakeLedger(t)
	outDir := t.TempDir()
	anchorPath, capsules := emitAnchorAndCapsules(t, ledgerPath, outDir,
		"orders-db", "cache-net")

	dup := append(append([]string{}, capsules...), capsules[0]) // orders-db twice
	rep, code := Run(Options{Out: filepath.Join(t.TempDir(), "r.jsonl"),
		AnchorPath: anchorPath, CapsulePaths: dup})
	if code != ExitOK {
		t.Fatalf("an identical duplicate must dedupe+restore, got %d: %v", code, rep.Reasons)
	}
	if len(rep.Merged["orders-db"]) != 1 {
		t.Fatalf("the duplicate must be recorded as a merged alternate, got %v", rep.Merged)
	}
}

// TestMergePrefixExtendsLongerWins: an OLD prefix capsule + a NEW capsule that
// extends it merge to the longer chain — decided by set CONTAINMENT (every old
// event rides in the new), never by trust — and the restore equals the full
// ledger the fresh anchor pins.
func TestMergePrefixExtendsLongerWins(t *testing.T) {
	ledger.ResetSigning()
	full := buildLinearLedger(t, "orders-db", 5)
	fullLed, err := ledger.ReplayFile(full)
	if err != nil {
		t.Fatal(err)
	}
	outDir := t.TempDir()

	newCap, err := ledger.EmitCapsule(full, "orders-db")
	if err != nil {
		t.Fatal(err)
	}
	newPath := filepath.Join(outDir, "new.capsule.json")
	writeJSON(t, newPath, newCap)
	anchorPath := filepath.Join(outDir, "anchor.json")
	writeJSON(t, anchorPath, ledger.BuildAnchor(fullLed))

	prefix := truncateLedger(t, full, 3) // lease + first binding + one more
	oldCap, err := ledger.EmitCapsule(prefix, "orders-db")
	if err != nil {
		t.Fatal(err)
	}
	oldPath := filepath.Join(outDir, "old.capsule.json")
	writeJSON(t, oldPath, oldCap)

	restoredPath := filepath.Join(t.TempDir(), "restored.jsonl")
	rep, code := Run(Options{Out: restoredPath, AnchorPath: anchorPath,
		CapsulePaths: []string{oldPath, newPath}})
	if code != ExitOK {
		t.Fatalf("prefix+extension must merge (longer wins), got %d: %v", code, rep.Reasons)
	}
	restored, err := ledger.ReplayFile(restoredPath)
	if err != nil {
		t.Fatal(err)
	}
	if restored.Heads["orders-db"] != fullLed.Heads["orders-db"] {
		t.Fatalf("winner must be the full chain: %s != %s",
			restored.Heads["orders-db"], fullLed.Heads["orders-db"])
	}
	if restored.TotalEvents() != fullLed.TotalEvents() {
		t.Fatalf("restored %d events, full %d", restored.TotalEvents(), fullLed.TotalEvents())
	}
	if len(rep.Merged["orders-db"]) != 1 {
		t.Fatalf("the old prefix must be a merged alternate, got %v", rep.Merged)
	}
}

// TestMergeForkRefuses: two capsules sharing a genesis but DIVERGING at the next
// event are a fork — restore refuses rather than guess which branch is real.
func TestMergeForkRefuses(t *testing.T) {
	ledger.ResetSigning()
	branchA := buildForkBranch(t, "orders-db", "alpha")
	branchB := buildForkBranch(t, "orders-db", "beta")
	ledA, err := ledger.ReplayFile(branchA)
	if err != nil {
		t.Fatal(err)
	}
	outDir := t.TempDir()

	capA, err := ledger.EmitCapsule(branchA, "orders-db")
	if err != nil {
		t.Fatal(err)
	}
	capB, err := ledger.EmitCapsule(branchB, "orders-db")
	if err != nil {
		t.Fatal(err)
	}
	pA := filepath.Join(outDir, "a.capsule.json")
	pB := filepath.Join(outDir, "b.capsule.json")
	writeJSON(t, pA, capA)
	writeJSON(t, pB, capB)
	// anchor over branch A; its ledgerId is the shared genesis, so branch B is
	// not foreign — the FORK is what must refuse, not a ledger mismatch.
	anchorPath := filepath.Join(outDir, "anchor.json")
	writeJSON(t, anchorPath, ledger.BuildAnchor(ledA))

	rep, code := Run(Options{Out: filepath.Join(t.TempDir(), "r.jsonl"),
		AnchorPath: anchorPath, CapsulePaths: []string{pA, pB}})
	if code != ExitRefused {
		t.Fatalf("a fork must refuse (5), got %d: %v", code, rep.Reasons)
	}
	if !containsSubstr(rep.Reasons, "FORK") {
		t.Fatalf("refusal must name the fork: %v", rep.Reasons)
	}
}

func containsSubstr(reasons []string, sub string) bool {
	for _, r := range reasons {
		for i := 0; i+len(sub) <= len(r); i++ {
			if r[i:i+len(sub)] == sub {
				return true
			}
		}
	}
	return false
}

// buildLinearLedger writes n sequential single-capability events (a lease, then
// binding.updated events, then a release) — a clean linear chain to slice into
// prefixes for the merge tests. Clocks are deterministic (occurredAt=FormatTs).
func buildLinearLedger(t *testing.T, cap string, n int) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "ledger.jsonl")
	led, err := ledger.ReplayFile(path)
	if err != nil {
		t.Fatal(err)
	}
	w := &ledger.Writer{Path: path, Led: led, Env: "test", Actor: "t"}
	w.Clock = 1000
	tok, err := w.AppendLease([]string{cap}, map[string]any{"ttlSeconds": 100000})
	if err != nil {
		t.Fatal(err)
	}
	for i := 1; i <= n-2; i++ {
		w.Clock = 1000 + i
		if err := w.Append("binding.updated", []string{cap},
			map[string]any{"resources": []any{map[string]any{
				"id": "primary", "type": "fake.thing",
				"providerId": fmt.Sprintf("fake:%s-%d", cap, i), "generation": 1}}}, tok); err != nil {
			t.Fatal(err)
		}
	}
	w.Clock = 1000 + n
	if err := w.Append("lease.released", []string{cap}, nil, tok); err != nil {
		t.Fatal(err)
	}
	return path
}

// truncateLedger writes the first keep lines of a ledger to a fresh file — a
// replay-valid prefix (a prefix of a valid chain is itself valid).
func truncateLedger(t *testing.T, src string, keep int) string {
	t.Helper()
	raw, err := os.ReadFile(src)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimRight(string(raw), "\n"), "\n")
	if keep > len(lines) {
		keep = len(lines)
	}
	out := filepath.Join(t.TempDir(), "prefix.jsonl")
	if err := os.WriteFile(out, []byte(strings.Join(lines[:keep], "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return out
}

// buildForkBranch writes a two-event branch sharing a byte-identical genesis
// (same lease params + clock -> same ledgerId) but a variant-specific second
// event — so two branches with different variants FORK at event 2.
func buildForkBranch(t *testing.T, cap, variant string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "branch.jsonl")
	led, err := ledger.ReplayFile(path)
	if err != nil {
		t.Fatal(err)
	}
	w := &ledger.Writer{Path: path, Led: led, Env: "test", Actor: "t"}
	w.Clock = 1000
	tok, err := w.AppendLease([]string{cap}, map[string]any{"ttlSeconds": 100000})
	if err != nil {
		t.Fatal(err)
	}
	w.Clock = 1001
	if err := w.Append("binding.updated", []string{cap},
		map[string]any{"resources": []any{map[string]any{
			"id": "primary", "type": "fake.thing",
			"providerId": "fake:" + cap + "-" + variant, "generation": 1}}}, tok); err != nil {
		t.Fatal(err)
	}
	return path
}

// buildIndependentLedger writes two capabilities with NO shared event, so
// dropping one restores the other cleanly (no coupling).
func buildIndependentLedger(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "ledger.jsonl")
	led, err := ledger.ReplayFile(path)
	if err != nil {
		t.Fatal(err)
	}
	w := &ledger.Writer{Path: path, Led: led, Env: "test", Actor: "t"}
	bind := func(pid string) map[string]any {
		return map[string]any{"resources": []any{map[string]any{
			"id": "primary", "type": "fake.thing", "providerId": pid, "generation": 1}}}
	}
	step := func(clock int, cap, pid string) {
		w.Clock = clock
		tok, err := w.AppendLease([]string{cap}, map[string]any{"ttlSeconds": 100000})
		if err != nil {
			t.Fatal(err)
		}
		w.Clock = clock + 1
		if err := w.Append("binding.updated", []string{cap}, bind(pid), tok); err != nil {
			t.Fatal(err)
		}
		w.Clock = clock + 2
		if err := w.Append("lease.released", []string{cap}, nil, tok); err != nil {
			t.Fatal(err)
		}
	}
	step(1000, "orders-db", "fake:orders-1")
	step(1100, "cache-net", "fake:cache-1")
	return path
}

// TestPartialMissingCapabilityRestoresRest: with --partial, a capability whose
// capsule is absent is recorded unknown (capsule-missing) while the sound
// capability still restores — and the restored ledger holds ONLY the sound one.
func TestPartialMissingCapabilityRestoresRest(t *testing.T) {
	ledger.ResetSigning()
	ledgerPath := buildIndependentLedger(t)
	outDir := t.TempDir()
	// anchor over BOTH, but emit only the orders-db capsule.
	anchorPath, capsules := emitAnchorAndCapsules(t, ledgerPath, outDir, "orders-db")
	// re-cut the anchor over both capabilities (emitAnchorAndCapsules anchored
	// the whole ledger already, which lists both — good).

	orig, err := ledger.ReplayFile(ledgerPath)
	if err != nil {
		t.Fatal(err)
	}
	restoredPath := filepath.Join(t.TempDir(), "restored.jsonl")
	rep, code := Run(Options{Out: restoredPath, AnchorPath: anchorPath,
		CapsulePaths: capsules, Partial: true})
	// D1082: a partial that left a capability unprovable exits NON-ZERO (the
	// set does not hold together) even though the recovered subset is still written
	// — automation must not read a knowingly-incomplete estate as a whole recovery.
	if code != ExitRefused {
		t.Fatalf("a partial restore with an unprovable capability must exit non-zero, got %d: %v", code, rep.Reasons)
	}
	if rep.Status != "partial" {
		t.Fatalf("status = %q, want partial", rep.Status)
	}
	if !hasCapStatus(rep.Partial, "cache-net", "unknown", "capsule-missing") {
		t.Fatalf("cache-net must be unknown/capsule-missing: %+v", rep.Partial)
	}
	if !hasCapStatus(rep.Partial, "orders-db", "restored", "") {
		t.Fatalf("orders-db must be restored: %+v", rep.Partial)
	}
	restored, err := ledger.ReplayFile(restoredPath)
	if err != nil {
		t.Fatal(err)
	}
	if restored.Heads["orders-db"] != orig.Heads["orders-db"] {
		t.Fatalf("orders-db head not restored")
	}
	if _, ok := restored.Heads["cache-net"]; ok {
		t.Fatalf("cache-net must be ABSENT from a partial restore, not fabricated")
	}
	// D1082: the recovered LEDGER is kept (--partial's deliverable, replayed above), but
	// its fresh anchor must be REMOVED — a self-verifying anchor over the recovered subset
	// would let `anchor --check`/`attest` promote a partial as a whole recovered estate.
	if _, err := os.Stat(ledger.AnchorPath(restoredPath)); !os.IsNotExist(err) {
		t.Fatalf("a partial restore must remove the fresh anchor (it would falsely verify a subset as whole), stat err=%v", err)
	}
}

// TestPartialTamperedIsUnknown: a byte-flipped capsule is recorded unknown
// (capsule-tampered) under --partial; the sound capability still restores.
func TestPartialTamperedIsUnknown(t *testing.T) {
	ledger.ResetSigning()
	ledgerPath := buildIndependentLedger(t)
	outDir := t.TempDir()
	anchorPath, capsules := emitAnchorAndCapsules(t, ledgerPath, outDir,
		"orders-db", "cache-net")

	// tamper the cache-net capsule (capsules[1]).
	c := loadCapsuleFile(t, capsules[1])
	for _, doc := range c.Events {
		ev, _ := doc["event"].(map[string]any)
		if ev["type"] != "binding.updated" {
			continue
		}
		body, _ := ev["body"].(map[string]any)
		res, _ := body["resources"].([]any)
		r0, _ := res[0].(map[string]any)
		r0["providerId"] = "fake:TAMPERED"
	}
	writeJSON(t, capsules[1], c)

	restoredPath := filepath.Join(t.TempDir(), "restored.jsonl")
	rep, code := Run(Options{Out: restoredPath, AnchorPath: anchorPath,
		CapsulePaths: capsules, Partial: true})
	// D1082: a tampered capsule leaves cache-net unprovable — a partial that did
	// not fully hold together exits non-zero, though the sound capability is written.
	if code != ExitRefused {
		t.Fatalf("a partial restore with a tampered capsule must exit non-zero, got %d: %v", code, rep.Reasons)
	}
	if !hasCapStatus(rep.Partial, "cache-net", "unknown", "capsule-tampered") {
		t.Fatalf("cache-net must be unknown/capsule-tampered: %+v", rep.Partial)
	}
	restored, err := ledger.ReplayFile(restoredPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := restored.Heads["cache-net"]; ok {
		t.Fatalf("a tampered capability must not be restored")
	}
	if _, ok := restored.Heads["orders-db"]; !ok {
		t.Fatalf("the sound capability must still restore")
	}
}

// TestPartialCouplingDemotes: buildFakeLedger's tip event lists BOTH capabilities.
// With cache-net missing, orders-db shares that event and cannot reach its anchor
// tip without fabricating cache-net's history — so it is demoted capsule-coupled.
func TestPartialCouplingDemotes(t *testing.T) {
	ledger.ResetSigning()
	ledgerPath := buildFakeLedger(t) // event 7 lists orders-db AND cache-net
	outDir := t.TempDir()
	anchorPath, capsules := emitAnchorAndCapsules(t, ledgerPath, outDir, "orders-db")

	restoredPath := filepath.Join(t.TempDir(), "restored.jsonl")
	rep, code := Run(Options{Out: restoredPath, AnchorPath: anchorPath,
		CapsulePaths: capsules, Partial: true})

	// D618 supersedes this case's original expectation, deliberately and in writing.
	// It used to require ExitOK plus an empty restored ledger on disk: --partial had
	// reported honestly per capability, so exiting 0 read as consistent. What changed
	// is what happens NEXT to that empty file. D613 shows the zero-event anchor
	// beside it verifies any ledger it is later checked against, and D617 shows the
	// integrity verbs answered "healthy" over an absent history — so the artefacts a
	// zero-recovery left behind were being certified as a recovered estate. A restore
	// that recovered NOTHING is a failed restore; the per-capability honesty stays in
	// the report, and the run refuses instead of leaving something to bless.
	if code == ExitOK {
		t.Fatalf("a partial restore that recovered zero events must refuse: %v", rep.Reasons)
	}
	if !hasCapStatus(rep.Partial, "cache-net", "unknown", "capsule-missing") {
		t.Fatalf("cache-net must be capsule-missing: %+v", rep.Partial)
	}
	if !hasCapStatus(rep.Partial, "orders-db", "unknown", "capsule-coupled") {
		t.Fatalf("orders-db must be demoted capsule-coupled (shares the tip): %+v", rep.Partial)
	}
	if rep.Events != 0 {
		t.Fatalf("both capabilities unknown -> zero events, got %d", rep.Events)
	}
	for _, leftover := range []string{restoredPath, restoredPath + ".anchor"} {
		if _, err := os.Stat(leftover); err == nil {
			t.Fatalf("%s survived a failed restore — D313: a refused run leaves no "+
				"plausible artefact", leftover)
		}
	}
}

func hasCapStatus(list []CapStatus, cap, status, code string) bool {
	for _, s := range list {
		if s.Capability == cap && s.Status == status && s.Code == code {
			return true
		}
	}
	return false
}
