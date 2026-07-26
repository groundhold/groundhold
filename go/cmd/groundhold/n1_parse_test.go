package main

import (
	"path/filepath"
	"strings"
	"testing"

	"groundhold/internal/ledger"
)

// D323: the N1 gate checked that --at was PRESENT, never that it PARSES.
//
// Its own refusal message promises "(RFC3339 timestamp)" and explains that "a
// safety clock must not default to the epoch and make stale observations look
// fresh". `--at not-a-time` sailed through it, and every downstream site parses
// with the error discarded:
//
//	classifyPosture   atSec, _ := ledger.ParseTs(at)   -> 0
//	runStatus/runs    nowClock, _ := ledger.ParseTs(at) -> 0
//
// With atSec == 0 the decay test `observedAt + ttl <= atSec` is false for every
// real observation, so NOTHING is ever decayed and a capability whose evidence
// expired years ago reports managed-ok. That is precisely the failure N1 exists to
// prevent, reached by malforming the flag instead of omitting it — the gate that
// refuses the empty clock waved through a broken one.
func TestMalformedAtIsRefused(t *testing.T) {
	dir := t.TempDir()
	ledgerPath := filepath.Join(dir, "ledger.ndjson")
	w := &ledger.Writer{Path: ledgerPath, Led: ledger.New(), Env: "dev",
		Clock: 1752600000, Actor: "t"}
	if err := w.Append("contract.published", []string{"store"},
		map[string]any{"contract": "t", "version": 1}, 0); err != nil {
		t.Fatal(err)
	}

	for _, bad := range []string{"not-a-time", "2026-07-25", "yesterday", "1752600000"} {
		code := run([]string{"posture", "--ledger", ledgerPath, "--at", bad})
		if code == 0 {
			t.Errorf("--at %q was accepted by the N1 gate — an unparseable clock "+
				"becomes epoch downstream, and epoch makes every stale proof look "+
				"fresh (nothing is ever decayed)", bad)
		}
	}
}

// A well-formed clock must still pass — the gate must reject malformed input, not
// tighten what a legal timestamp looks like.
func TestWellFormedAtStillPasses(t *testing.T) {
	dir := t.TempDir()
	ledgerPath := filepath.Join(dir, "ledger.ndjson")
	w := &ledger.Writer{Path: ledgerPath, Led: ledger.New(), Env: "dev",
		Clock: 1752600000, Actor: "t"}
	if err := w.Append("contract.published", []string{"store"},
		map[string]any{"contract": "t", "version": 1}, 0); err != nil {
		t.Fatal(err)
	}
	out := captureStderr(t, func() {
		if code := run([]string{"posture", "--ledger", ledgerPath,
			"--at", "2026-07-25T10:00:00Z"}); code != 0 {
			t.Errorf("a valid RFC3339 --at must not be refused (exit %d)", code)
		}
	})
	if strings.Contains(out, "RFC3339") {
		t.Errorf("a valid clock was refused as malformed: %s", out)
	}
}
