package main

import (
	"path/filepath"
	"testing"

	"groundhold/internal/ledger"
)

// D567. The flag switch's `default:` arm appends anything it does not recognise to
// the POSITIONAL list, so an unknown flag is not an error — it is silently absorbed,
// along with its value.
//
// Found by making the mistake. Onboarding a real cluster, I ran
//
//	groundhold posture --ledger <l> --at <ts> --discovery discovery.json
//
// because `--discovery` exists on other verbs and posture's OWN remediation steps
// tell an operator to run `discover`. Posture does not take it. The run printed
// `"shadow": 0` and a postureHash over a cluster holding 169 unmanaged objects — a
// confident, hashed answer to a question it was never asked. `--zupelnie-wymyslona-flaga`
// gets the same treatment and the same hash.
//
// This is D530's class — a declaration nobody reads — on the command line rather than
// in the candidate. The compiler now refuses an operand no driver consumes; the CLI
// accepted a flag no verb consumes and answered anyway. And it is D323's shape
// exactly: the N1 gate checked a flag was PRESENT and not that it PARSED, one layer
// up.
func TestUnknownFlagIsRefused(t *testing.T) {
	dir := t.TempDir()
	ledgerPath := filepath.Join(dir, "ledger.ndjson")
	w := &ledger.Writer{Path: ledgerPath, Led: ledger.New(), Env: "dev",
		Clock: 1752600000, Actor: "t"}
	if err := w.Append("contract.published", []string{"store"},
		map[string]any{"contract": "t", "version": 1}, 0); err != nil {
		t.Fatal(err)
	}
	for _, bad := range [][]string{
		{"posture", "--ledger", ledgerPath, "--at", "2026-07-25T10:00:00Z", "--discovery", "d.json"},
		{"posture", "--ledger", ledgerPath, "--at", "2026-07-25T10:00:00Z", "--not-a-flag", "x"},
		{"posture", "--ledger", ledgerPath, "--at", "2026-07-25T10:00:00Z", "-x"},
	} {
		// an unknown flag must be REFUSED (exit 1), not absorbed and run. Since D958 a run
		// that PROCEEDS returns posture's own code (0 clean / 2 findings), so `!= 0` no
		// longer proves refusal — assert the refusal code itself: anything but 1 means the
		// flag was absorbed and the run answered a question the operator did not ask.
		if code := run(bad); code != 1 {
			t.Errorf("%v was accepted (exit %d, not the refusal 1) — an unknown flag is "+
				"absorbed as a positional, so the run answers a question the operator did "+
				"not ask and the answer looks authoritative", bad[4:], code)
		}
	}
}

// A legal invocation must still pass, and a lone "-" (stdin by convention) must not
// be mistaken for a flag.
func TestKnownFlagsStillPass(t *testing.T) {
	dir := t.TempDir()
	ledgerPath := filepath.Join(dir, "ledger.ndjson")
	w := &ledger.Writer{Path: ledgerPath, Led: ledger.New(), Env: "dev",
		Clock: 1752600000, Actor: "t"}
	if err := w.Append("contract.published", []string{"store"},
		map[string]any{"contract": "t", "version": 1}, 0); err != nil {
		t.Fatal(err)
	}
	// a legal invocation (known flags) must not be REFUSED (unknown-flag refusal is exit 1).
	// posture then returns its own verdict code — 2 here, a no-crawl sweep is a lower bound
	// (D958) — which is NOT a refusal; exit != 1 is the parse-success signal.
	if code := run([]string{"posture", "--ledger", ledgerPath, "--at", "2026-07-25T10:00:00Z"}); code == 1 {
		t.Errorf("a legal posture invocation was refused (exit %d)", code)
	}
	_ = filepath.Join
}
