package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"groundhold/internal/ledger"
)

// TestAttestDispatchExitsNonZeroOnATamperedAnchor is the end-to-end pin for D1020: the
// `attest` CLI must exit non-zero when its off-host witness is tampered, matching
// `anchor --check`. A genuine anchor exits 0; a foreign ledgerId (the exact off-host
// attack) must not read all-clear.
func TestAttestDispatchExitsNonZeroOnATamperedAnchor(t *testing.T) {
	dir := t.TempDir()
	lp := filepath.Join(dir, "l.jsonl")
	if err := os.WriteFile(lp, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	led := ledger.New()
	w := &ledger.Writer{Path: lp, Led: led, Env: "test", Clock: 1752566400, Actor: "t"}
	tok, err := w.AppendLease([]string{"db"}, map[string]any{"ttlSeconds": 900})
	if err != nil {
		t.Fatal(err)
	}
	if err := w.Append("binding.updated", []string{"db"},
		map[string]any{"providerId": "fake:db"}, tok); err != nil {
		t.Fatal(err)
	}
	// A GENUINE anchor sidecar, built from the REPLAYED ledger (the Writer's in-memory
	// state is not the replayed state — attest reads the file, so the anchor must too).
	reLed, err := ledger.ReplayExisting(lp)
	if err != nil {
		t.Fatal(err)
	}
	genuine, _ := json.MarshalIndent(ledger.BuildAnchor(reLed), "", "  ")
	if err := os.WriteFile(ledger.AnchorPath(lp), genuine, 0o600); err != nil {
		t.Fatal(err)
	}
	at := "2026-01-01T00:00:00Z"
	if code := runQuietly(t, "attest", "--ledger", lp, "--at", at); code != 0 {
		t.Fatalf("attest over a genuine anchor must exit 0, got %d", code)
	}
	// Swap the ledgerId to a foreign one — a rewritten off-host witness.
	var a map[string]any
	if err := json.Unmarshal(genuine, &a); err != nil {
		t.Fatal(err)
	}
	a["ledgerId"] = "sha256:0000000000000000000000000000000000000000000000000000000000000000"
	tampered, _ := json.MarshalIndent(a, "", "  ")
	if err := os.WriteFile(ledger.AnchorPath(lp), tampered, 0o600); err != nil {
		t.Fatal(err)
	}
	if code := runQuietly(t, "attest", "--ledger", lp, "--at", at); code == 0 {
		t.Fatal("attest over a FOREIGN anchor exited 0 — the off-host witness diverged and " +
			"a cron/CI reading the exit code saw all-clear over a rewritten history (D1020)")
	}
}

// TestAttestIntegrityHealthyGatesTamper pins D1020: attest's exit code must reflect the
// off-host-witness integrity it reports. A verified/absent anchor and a nil/clean
// snapshot are healthy (exit 0); a diverged/truncated/unverifiable/unreadable anchor, a
// snapshot that does not self-verify or names another ledger, or a
// mismatched/missing/misnamed/unreadable archive is a corrupted witness (exit 5) — never
// read as all-clear.
func TestAttestIntegrityHealthyGatesTamper(t *testing.T) {
	okSnap := &ledger.SnapshotFacts{SignatureSelfVerifies: true, LedgerIdMatches: true,
		Archive: ledger.ArchiveIntegrity{Status: "matched"}}
	cases := []struct {
		name    string
		rep     *ledger.IntegrityReport
		healthy bool
	}{
		{"no anchor, no snapshot", &ledger.IntegrityReport{}, true},
		{"anchor verified", &ledger.IntegrityReport{Anchor: &ledger.AnchorFacts{Status: "verified"}}, true},
		{"anchor absent", &ledger.IntegrityReport{Anchor: &ledger.AnchorFacts{Status: "absent"}}, true},
		{"anchor diverged (foreign)", &ledger.IntegrityReport{Anchor: &ledger.AnchorFacts{Status: "diverged"}}, false},
		{"anchor truncated (cut tail)", &ledger.IntegrityReport{Anchor: &ledger.AnchorFacts{Status: "truncated"}}, false},
		{"anchor unverifiable (neutralized)", &ledger.IntegrityReport{Anchor: &ledger.AnchorFacts{Status: "unverifiable"}}, false},
		{"anchor unreadable", &ledger.IntegrityReport{Anchor: &ledger.AnchorFacts{Status: "unreadable"}}, false},
		{"snapshot clean", &ledger.IntegrityReport{Snapshot: okSnap}, true},
		{"snapshot archive not-claimed", &ledger.IntegrityReport{Snapshot: &ledger.SnapshotFacts{
			SignatureSelfVerifies: true, LedgerIdMatches: true, Archive: ledger.ArchiveIntegrity{Status: "not-claimed"}}}, true},
		{"snapshot unreadable", &ledger.IntegrityReport{Snapshot: &ledger.SnapshotFacts{Unreadable: true}}, false},
		{"snapshot signature does not self-verify", &ledger.IntegrityReport{Snapshot: &ledger.SnapshotFacts{
			SignatureSelfVerifies: false, LedgerIdMatches: true, Archive: ledger.ArchiveIntegrity{Status: "matched"}}}, false},
		{"snapshot names another ledger", &ledger.IntegrityReport{Snapshot: &ledger.SnapshotFacts{
			SignatureSelfVerifies: true, LedgerIdMatches: false, Archive: ledger.ArchiveIntegrity{Status: "matched"}}}, false},
		{"snapshot archive mismatched (swapped)", &ledger.IntegrityReport{Snapshot: &ledger.SnapshotFacts{
			SignatureSelfVerifies: true, LedgerIdMatches: true, Archive: ledger.ArchiveIntegrity{Status: "mismatched"}}}, false},
	}
	for _, c := range cases {
		if got := attestIntegrityHealthy(c.rep); got != c.healthy {
			t.Errorf("%s: attestIntegrityHealthy=%v, want %v — attest exit code must not read "+
				"a corrupted off-host witness as all-clear", c.name, got, c.healthy)
		}
	}
}
