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
		// a malformed --at must be REFUSED (exit 1). Since D958 a run that PROCEEDS returns
		// posture's own code (0/2), so `!= 0` no longer proves refusal — assert exit 1:
		// anything else means the clock sailed through and posture ran on the epoch.
		if code != 1 {
			t.Errorf("--at %q was accepted by the N1 gate (exit %d, not the refusal 1) — an "+
				"unparseable clock becomes epoch downstream, and epoch makes every stale "+
				"proof look fresh (nothing is ever decayed)", bad, code)
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
		// a well-formed --at must PARSE, not be refused as malformed (the refusal is
		// exit 1 + the "RFC3339" message). posture then runs and returns its OWN verdict
		// code — 2 here, because a no-crawl sweep swept nothing and cannot claim all-clear
		// (D650/D958); that is a verdict, not a refusal. The parse-success assertion is
		// exit != 1 (below) and the absence of the "RFC3339" refusal message.
		if code := run([]string{"posture", "--ledger", ledgerPath,
			"--at", "2026-07-25T10:00:00Z"}); code == 1 {
			t.Errorf("a valid RFC3339 --at was refused (exit %d)", code)
		}
	})
	if strings.Contains(out, "RFC3339") {
		t.Errorf("a valid clock was refused as malformed: %s", out)
	}
}
