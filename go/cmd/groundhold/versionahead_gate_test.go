package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"groundhold/internal/canonical"
	"groundhold/internal/state"
)

// D1154. The event-type registry is ADDITIVE-ONLY, which is what makes an unknown type
// diagnosable: a build that meets one is almost certainly older than the build that
// wrote it. Nothing acted on that. Replay returned the condition as an ordinary error,
// every call site answered any replay error with exit 5, and exit 5's banner is the
// single word CORRUPTED.
//
// So the sequence a version bump invites — upgrade, write one event of the new type,
// go back to the previous binary — ended with the tool declaring an intact ledger
// corrupt. That is the D716 shape exactly: a person acting on what the tool said is
// worse off than if it had said nothing, because the published remediation for
// ledger-corrupted is `repair --quarantine`, and the ledger is the one artefact here
// that nothing else can reconstruct. `repair` was the worst of the three paths: it
// named the file corrupt AND would cut it at the offending line on a matching
// fingerprint, discarding precisely the history the newer build can still read.
//
// What this gate holds is the DISTINCTION, in both directions. Refusing is correct and
// stays; the fix is that the refusal names the right condition. Every case below has a
// sibling in the other direction, because a fix that made real corruption quieter
// would be a worse defect than the one it replaced.
func TestAnUnknownEventTypeIsNotCorruption(t *testing.T) {
	dir := t.TempDir()

	// The vacuity floor (D328). This whole gate is about a type OUTSIDE the registry,
	// so if the registry ever grew to contain it, every case below would still pass
	// while testing nothing at all.
	const future = "observation.telepathic"
	if state.EventTypes[future] {
		t.Fatalf("%q is a registered event type — this gate's fixture no longer "+
			"models an unknown one and every case in it is vacuous", future)
	}
	if len(state.EventTypes) < 20 {
		t.Fatalf("the event-type registry has %d entries — it did not load, and "+
			"membership checks here mean nothing", len(state.EventTypes))
	}

	// chain builds a ledger whose prev pointers are genuinely correct, so a refusal
	// cannot be blamed on a broken chain we accidentally wrote. A hand-written prev
	// would make the intact-chain cases untestable (D-rule: a synthetic ledger must
	// respect the hash chain).
	chain := func(t *testing.T, types ...string) string {
		t.Helper()
		head := "genesis"
		var b strings.Builder
		for i, ty := range types {
			doc := map[string]any{
				"apiVersion": "state/v0", "kind": "LedgerEvent",
				"event": map[string]any{
					"type": ty, "environment": "test",
					"capabilities": []any{"cap.storage"},
					"occurredAt":   "2026-01-0" + string(rune('1'+i)) + "T00:00:00Z",
					"actor":        map[string]any{"id": "r", "type": "runtime"},
					"prev":         map[string]any{"cap.storage": head},
					"body":         map[string]any{},
				},
			}
			h, err := canonical.HashEvent(doc)
			if err != nil {
				t.Fatalf("hashing the fixture: %v", err)
			}
			head = h
			raw, err := json.Marshal(doc)
			if err != nil {
				t.Fatal(err)
			}
			b.Write(raw)
			b.WriteString("\n")
		}
		return b.String()
	}
	write := func(name, body string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}

	known := "observation.recorded"
	if !state.EventTypes[known] {
		t.Fatalf("%q is not a registered type — the control fixture is wrong", known)
	}

	ahead := write("ahead.jsonl", chain(t, known, future))
	healthy := write("healthy.jsonl", chain(t, known, known))
	// Real corruption, with a type this build knows: the line does not parse as an
	// event at all. This is the fixture that must keep exiting 5.
	corrupt := write("corrupt.jsonl", chain(t, known)+"{\"this\":\"is not an event\"}\n")
	// Both conditions at once. Independent, so a file can have them together.
	bothBody := chain(t, known, future) + "{\"this\":\"is not an event\"}\n"
	both := write("both.jsonl", bothBody)

	const at = "2026-02-01T00:00:00Z"
	// The verbs that fold the ledger, plus one that derives run state through a
	// different reader entirely (D611's family) — the defect lived in both.
	for _, tc := range []struct {
		name string
		argv func(string) []string
		// folds is true for a verb that REPLAYS the ledger, and so learns whether
		// the hash chain verifies. `runs` derives run state through a reader that
		// deliberately does not fold (D229), so it can name the type it cannot
		// read and nothing more. That is a real difference in what the verb KNOWS,
		// and the cases below hold each one to what it can honestly say rather
		// than demanding the same answer from both.
		folds bool
	}{
		{"posture", func(l string) []string { return []string{"posture", "--ledger", l, "--at", at} }, true},
		{"attest", func(l string) []string { return []string{"attest", "--ledger", l, "--at", at} }, true},
		{"runs", func(l string) []string { return []string{"runs", "--ledger", l, "--at", at} }, false},
	} {
		t.Run(tc.name+" does not call a newer ledger corrupt", func(t *testing.T) {
			var stderr string
			var code int
			stderr = captureStderr(t, func() { code = run(tc.argv(ahead)) })
			if code == 5 {
				t.Errorf("exit 5 over a ledger whose only problem is an event type "+
					"this build does not know. Exit 5 banners as CORRUPTED and its "+
					"published remediation is `repair --quarantine`, which would cut "+
					"away intact history.\n%s", stderr)
			}
			if code == 0 {
				t.Errorf("exit 0 over a ledger this build cannot fully read — "+
					"refusing is correct, only the WORD was wrong. Reporting over "+
					"events we cannot interpret is how `runs` answered \"0 runs\" "+
					"for a ledger that may hold a live one.\n%s", stderr)
			}
			if !strings.Contains(stderr, future) {
				t.Errorf("the refusal does not name %q. A reader who is not told "+
					"WHICH type is unreadable cannot tell a version gap from "+
					"damage:\n%s", future, stderr)
			}
		})

		// The sibling. Without it, "never exit 5 on this path" would pass.
		t.Run(tc.name+" still calls real corruption corruption", func(t *testing.T) {
			if got := run(tc.argv(corrupt)); got != 5 {
				t.Errorf("exit %d over a line that is not an event, want 5 — the "+
					"version-ahead distinction must not have widened into a general "+
					"softening of the corruption channel", got)
			}
		})

		t.Run(tc.name+" never understates damage", func(t *testing.T) {
			var stderr string
			var code int
			stderr = captureStderr(t, func() { code = run(tc.argv(both)) })
			if tc.folds {
				// It replayed, so it KNOWS the chain is broken, and must say the
				// stronger of the two things. spec/presentation.md ranks corruption
				// above every other banner because under-reporting damage is the
				// dangerous direction: told only to upgrade, nobody looks further.
				if code != 5 {
					t.Errorf("exit %d over a ledger that is BOTH ahead and damaged, "+
						"want 5 — this verb folded the chain and found it broken:\n%s",
						code, stderr)
				}
				return
			}
			// It did not replay. Refusing is right and naming the type is right;
			// what it must NOT do is imply the rest of the file is sound, which is
			// the claim that would stop someone from looking.
			if code == 0 {
				t.Errorf("exit 0 over a ledger that is ahead AND damaged:\n%s", stderr)
			}
			for _, forbidden := range []string{"NOT damaged", "nothing wrong with the file"} {
				if strings.Contains(stderr, forbidden) {
					t.Errorf("a verb that does not fold the chain claimed %q. It "+
						"cannot know that, and here it is false — the file is also "+
						"corrupt:\n%s", forbidden, stderr)
				}
			}
		})

		t.Run(tc.name+" leaves a healthy ledger alone", func(t *testing.T) {
			var stderr string
			var code int
			stderr = captureStderr(t, func() { code = run(tc.argv(healthy)) })
			// Not a blanket "exit 0": these verbs answer about an estate, and a
			// ledger with no contract behind it legitimately refuses for reasons
			// that have nothing to do with this change. The property under test is
			// narrower and is the one that would break — that the NEW check does
			// not fire on a ledger of registered types with an intact chain.
			if code == 5 {
				t.Errorf("exit 5 over a healthy ledger:\n%s", stderr)
			}
			if strings.Contains(stderr, "not known to this build") ||
				strings.Contains(stderr, "unknown event type") {
				t.Errorf("the version-ahead refusal fired on a ledger whose every "+
					"type is registered — the membership check is inverted or is "+
					"reading the wrong field:\n%s", stderr)
			}
		})
	}
}

// `repair` is the verb the corrupted code's remediation NAMES, so it is the one that
// turns a wrong diagnosis into lost history. Two things must hold: it must not call
// the file corrupt, and — the part that actually protects anything — it must refuse
// to cut, even when handed the matching fingerprint that is otherwise full consent.
func TestRepairWillNotQuarantineALedgerItMerelyCannotRead(t *testing.T) {
	dir := t.TempDir()
	const future = "observation.telepathic"
	if state.EventTypes[future] {
		t.Fatalf("%q is registered now — this gate is vacuous", future)
	}

	head := "genesis"
	line := func(t *testing.T, ty, when string) string {
		t.Helper()
		doc := map[string]any{
			"apiVersion": "state/v0", "kind": "LedgerEvent",
			"event": map[string]any{
				"type": ty, "environment": "test",
				"capabilities": []any{"cap.storage"},
				"occurredAt":   when,
				"actor":        map[string]any{"id": "r", "type": "runtime"},
				"prev":         map[string]any{"cap.storage": head},
				"body":         map[string]any{},
			},
		}
		h, err := canonical.HashEvent(doc)
		if err != nil {
			t.Fatal(err)
		}
		head = h
		raw, err := json.Marshal(doc)
		if err != nil {
			t.Fatal(err)
		}
		return string(raw) + "\n"
	}
	body := line(t, "observation.recorded", "2026-01-01T00:00:00Z") +
		line(t, future, "2026-01-02T00:00:00Z")
	p := filepath.Join(dir, "l.jsonl")
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}

	// Diagnose. The code and the finding's kind are what a caller routes on.
	var diag map[string]any
	out := captureStdout(t, func() { run([]string{"repair", "--ledger", p}) })
	if err := json.Unmarshal([]byte(out), &diag); err != nil {
		t.Fatalf("repair's diagnosis does not parse (%v):\n%s", err, out)
	}
	if got, _ := diag["code"].(string); got != "ledger-version-ahead" {
		t.Errorf("repair diagnosed code %q, want ledger-version-ahead. This verb's "+
			"own remediation for ledger-corrupted is --quarantine, so a wrong code "+
			"here is an instruction to delete undamaged history.", got)
	}
	if got, _ := diag["status"].(string); got == "corrupt" {
		t.Error("repair reports status \"corrupt\" for a ledger that is not damaged")
	}
	fp, _ := diag["fingerprint"].(string)
	if fp == "" {
		t.Fatal("no fingerprint in the diagnosis — the quarantine case below cannot run")
	}

	// The consent is real and it is still refused: the fingerprint matches, so
	// nothing but the diagnosis itself stands between this file and the cut.
	before, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	var res map[string]any
	out = captureStdout(t, func() {
		run([]string{"repair", "--ledger", p, "--quarantine", "--fingerprint", fp})
	})
	if err := json.Unmarshal([]byte(out), &res); err != nil {
		t.Fatalf("repair's quarantine result does not parse (%v):\n%s", err, out)
	}
	if got, _ := res["status"].(string); got != "refused" {
		t.Errorf("quarantine status %q on a version-ahead ledger, want refused — a "+
			"matching fingerprint is consent to remove CORRUPTION, and there is none "+
			"here", got)
	}
	after, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Errorf("the ledger file CHANGED. It held %d bytes and now holds %d — this "+
			"is the irreversible half of the defect: the cut discards exactly the "+
			"events a newer build can read.", len(before), len(after))
	}

	// The sibling, and the one my own mutation run said was missing: everything
	// above would still pass if `repair` had simply stopped calling ANYTHING
	// corrupt. A guard that refuses every cut protects nothing — it just breaks the
	// verb. So the same file plus one line that is genuinely not an event must
	// diagnose as corruption and must still be cuttable.
	head = "genesis"
	dmg := filepath.Join(dir, "damaged.jsonl")
	dmgBody := line(t, "observation.recorded", "2026-01-01T00:00:00Z") +
		"{\"this\":\"is not an event\"}\n"
	if err := os.WriteFile(dmg, []byte(dmgBody), 0o644); err != nil {
		t.Fatal(err)
	}
	var dd map[string]any
	out = captureStdout(t, func() { run([]string{"repair", "--ledger", dmg}) })
	if err := json.Unmarshal([]byte(out), &dd); err != nil {
		t.Fatalf("diagnosis of the damaged ledger does not parse (%v):\n%s", err, out)
	}
	if got, _ := dd["code"].(string); got != "ledger-corrupted" {
		t.Fatalf("repair diagnosed real damage as %q, want ledger-corrupted — the "+
			"version-ahead carve-out has swallowed the corruption channel", got)
	}
	dfp, _ := dd["fingerprint"].(string)
	sizeBefore := len(dmgBody)
	out = captureStdout(t, func() {
		run([]string{"repair", "--ledger", dmg, "--quarantine", "--fingerprint", dfp})
	})
	var dres map[string]any
	if err := json.Unmarshal([]byte(out), &dres); err != nil {
		t.Fatalf("quarantine of the damaged ledger does not parse (%v):\n%s", err, out)
	}
	if got, _ := dres["status"].(string); got == "refused" {
		t.Errorf("quarantine REFUSED a genuinely corrupt ledger with a matching " +
			"fingerprint — the guard is too wide and the verb no longer does its job")
	}
	cut, err := os.ReadFile(dmg)
	if err != nil {
		t.Fatal(err)
	}
	if len(cut) >= sizeBefore {
		t.Errorf("the corrupt ledger was not cut (%d bytes before, %d after) — "+
			"repair must still remove damage on confirmed consent", sizeBefore, len(cut))
	}
}
