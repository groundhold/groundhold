package restore

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"groundhold/internal/ledger"
)

// D312 (adversarial audit of restore): an anchor whose ledgerId is EMPTY silently
// disables three of restore's identity guards.
//
// Restore reads the anchor as the off-host manifest — the thing that proves the
// capsule set is complete AND is this ledger's. Three separate checks are written
// `if anchor.LedgerId != "" { ... }`:
//
//	classifyCapability — a capsule signed for ANOTHER ledger is capsule-foreign
//	Run                — the genesis event must be present in the set
//	Run                — the restored ledger's identity must match the anchor's
//
// LoadAnchorFile accepts any document whose kind is LedgerAnchor, so an anchor
// with no ledgerId loads happily and all three go quiet. The result is a
// `status: restored`, exit 0 artifact assembled from capsules that were never
// checked for belonging to the same history — precisely the claim restore exists
// to make. Nothing groundhold WRITES has an empty ledgerId (BuildAnchor always
// sets it); this is malformed input, and malformed input must be refused at the
// gate like every other operator error, not silently weaken the proof.
func TestAnchorWithoutLedgerIdIsRefused(t *testing.T) {
	ledger.ResetSigning()
	dir := t.TempDir()
	src := buildFakeLedger(t)
	anchorPath, capsules := emitAnchorAndCapsules(t, src, filepath.Join(dir, "backup"),
		"orders-db", "cache-net")

	// strip the ledgerId — everything else stays byte-identical
	var a ledger.Anchor
	readJSON(t, anchorPath, &a)
	a.LedgerId = ""
	writeJSON(t, anchorPath, a)

	rep, code := Run(Options{
		Out:          filepath.Join(dir, "restored.jsonl"),
		AnchorPath:   anchorPath,
		CapsulePaths: capsules,
	})
	if code == ExitOK {
		t.Fatalf("an anchor with no ledgerId must not produce a restored ledger — "+
			"the foreign-capsule, genesis and identity checks are all keyed on it; "+
			"got status=%q code=%d", rep.Status, code)
	}
	if code != ExitOperator {
		t.Errorf("a malformed anchor is an operator error (exit %d), got %d: %v",
			ExitOperator, code, rep.Reasons)
	}
	if _, err := os.Stat(filepath.Join(dir, "restored.jsonl")); err == nil {
		t.Error("nothing may be written when the anchor cannot identify the ledger")
	}
}

// The same hole seen from the direction that matters most: with the ledgerId
// stripped, a capsule from a DIFFERENT ledger is no longer recognised as foreign.
// The capsule-foreign check exists exactly to stop someone re-weaving one history
// out of another's parts; keyed on an empty string it never fires.
func TestForeignCapsuleStillCaughtWithoutLedgerId(t *testing.T) {
	ledger.ResetSigning()
	dir := t.TempDir()
	src := buildFakeLedger(t)
	anchorPath, capsules := emitAnchorAndCapsules(t, src, filepath.Join(dir, "backup"),
		"orders-db", "cache-net")

	// a capsule from an entirely separate ledger, standing in for one of ours
	foreign := buildIndependentLedger(t)
	fc, err := ledger.EmitCapsule(foreign, "orders-db")
	if err != nil {
		t.Fatal(err)
	}
	foreignPath := filepath.Join(dir, "backup", "foreign.capsule.json")
	writeJSON(t, foreignPath, fc)
	capsules[0] = foreignPath

	var a ledger.Anchor
	readJSON(t, anchorPath, &a)
	a.LedgerId = ""
	writeJSON(t, anchorPath, a)

	rep, code := Run(Options{
		Out:          filepath.Join(dir, "restored.jsonl"),
		AnchorPath:   anchorPath,
		CapsulePaths: capsules,
	})
	if code == ExitOK {
		t.Fatalf("a foreign capsule must never restore, with or without a "+
			"ledgerId on the anchor; got status=%q reasons=%v", rep.Status, rep.Reasons)
	}
}

func readJSON(t *testing.T, path string, v any) {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, v); err != nil {
		t.Fatal(err)
	}
}
