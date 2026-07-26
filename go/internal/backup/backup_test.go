package backup

import (
	"os"
	"path/filepath"
	"testing"

	"groundhold/internal/canonical"
	"groundhold/internal/contract"
	"groundhold/internal/ledger"
	"groundhold/internal/restore"
)

const exampleContract = "../../../spec/examples/orders-production.contract.yaml"

// buildLedger writes two independent single-capability chains via the real
// Writer path, returning the ledger file.
func buildLedger(t *testing.T) string {
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

// TestBackupRoundTrips: `backup` output feeds `restore` with no manual assembly.
func TestBackupRoundTrips(t *testing.T) {
	ledger.ResetSigning()
	lp := buildLedger(t)
	out := filepath.Join(t.TempDir(), "backup")

	rep, code := Run(Options{LedgerPath: lp, Out: out})
	if code != ExitOK {
		t.Fatalf("backup refused (%d): %v", code, rep.Reasons)
	}
	if rep.Status != "backed-up" || len(rep.Capsules) != 2 {
		t.Fatalf("unexpected report: %+v", rep)
	}
	if _, err := os.Stat(filepath.Join(out, "anchor.json")); err != nil {
		t.Fatalf("no anchor written: %v", err)
	}

	var capsulePaths []string
	for _, name := range rep.Capsules {
		p := filepath.Join(out, "capsules", name)
		if _, err := os.Stat(p); err != nil {
			t.Fatalf("capsule %s missing: %v", name, err)
		}
		capsulePaths = append(capsulePaths, p)
	}

	restored := filepath.Join(t.TempDir(), "restored.jsonl")
	rrep, rcode := restore.Run(restore.Options{Out: restored,
		AnchorPath: filepath.Join(out, "anchor.json"), CapsulePaths: capsulePaths})
	if rcode != restore.ExitOK {
		t.Fatalf("backup output must restore cleanly: %v", rrep.Reasons)
	}
}

// TestBackupRefusesExistingOut: backup writes a FRESH directory.
func TestBackupRefusesExistingOut(t *testing.T) {
	ledger.ResetSigning()
	lp := buildLedger(t)
	out := t.TempDir() // already exists
	_, code := Run(Options{LedgerPath: lp, Out: out})
	if code != ExitOperator {
		t.Fatalf("expected operator refusal on existing out, got %d", code)
	}
}

// TestBackupDocumentsCopyVerifyTamper: a ledger that pins a contractHash, backed
// up with --documents, copies the contract blob; VerifyDocuments confirms it and
// a byte-flip is caught as tampered.
func TestBackupDocumentsCopyVerifyTamper(t *testing.T) {
	ledger.ResetSigning()
	c, err := contract.LoadContract(exampleContract)
	if err != nil {
		t.Skipf("example contract not loadable in this tree: %v", err)
	}
	h, err := canonical.HashContract(c)
	if err != nil {
		t.Fatal(err)
	}

	// a ledger whose only event pins that contract's hash.
	lp := filepath.Join(t.TempDir(), "ledger.jsonl")
	led, err := ledger.ReplayFile(lp)
	if err != nil {
		t.Fatal(err)
	}
	w := &ledger.Writer{Path: lp, Led: led, Env: "test", Actor: "t", Clock: 1000}
	if err := w.Append("contract.published", []string{"orders-db"},
		map[string]any{"contract": "orders", "version": "1", "contractHash": h}, 0); err != nil {
		t.Fatal(err)
	}

	// a store holding the contract file.
	store := t.TempDir()
	rawC, _ := os.ReadFile(exampleContract)
	if err := os.WriteFile(filepath.Join(store, "orders.contract.yaml"), rawC, 0o600); err != nil {
		t.Fatal(err)
	}

	out := filepath.Join(t.TempDir(), "backup")
	rep, code := Run(Options{LedgerPath: lp, Out: out, DocumentsStore: store})
	if code != ExitOK {
		t.Fatalf("backup refused (%d): %v", code, rep.Reasons)
	}
	// the contract document must be recorded present and copied.
	found := false
	for _, d := range rep.Documents {
		if d.Hash == h && d.Kind == "contract" && d.Present {
			found = true
		}
	}
	if !found {
		t.Fatalf("the pinned contract must be copied: %+v", rep.Documents)
	}
	docsDir := filepath.Join(out, "documents")
	if _, err := os.Stat(filepath.Join(docsDir, h)); err != nil {
		t.Fatalf("blob not written: %v", err)
	}

	// verify: clean.
	vrep, vcode := VerifyDocuments(docsDir)
	if vcode != ExitOK || vrep.Status != "verified" {
		t.Fatalf("clean documents must verify: %d %+v", vcode, vrep)
	}

	// tamper: swap the blob for a DIFFERENT contract (a comment-only edit would
	// legitimately still match — the canonical hash is representation-stable, so
	// the tamper must change the contract's SEMANTICS to be caught).
	other, oerr := os.ReadFile("../../../spec/examples/workforce-sso.contract.yaml")
	if oerr != nil {
		t.Skipf("no second example contract to tamper with: %v", oerr)
	}
	if err := os.WriteFile(filepath.Join(docsDir, h), other, 0o600); err != nil {
		t.Fatal(err)
	}
	_, tcode := VerifyDocuments(docsDir)
	if tcode != ExitRefused {
		t.Fatalf("a swapped document blob must refuse (5), got %d", tcode)
	}
}
