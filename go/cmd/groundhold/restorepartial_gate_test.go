package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// D618. `restore --partial` returned ExitOK however much it had failed to restore,
// including all of it. A run where every capability came back `unknown` wrote a
// zero-byte ledger, wrote a FRESH anchor beside it, and exited 0 — and from that moment
// `anchor --check` and `attest` both certified the empty file as the recovered history.
// The truth lived only inside the `partial[]` block of a report nobody re-reads after a
// green exit.
//
// `--partial` means "give me what can be proven and tell me what cannot", not "call an
// empty recovery a success". D313 had already established the rule this breaks: a
// refused run must not leave a plausible artefact behind.
//
// This test also gives `backup` and `restore` their first automated coverage. The
// adversarial audit of the evidence chain found four of its six defects in exactly
// these two verbs, and the reason they went unexamined is visible in the suite: the
// conformance harness has no step DSL for either, so nobody could have written a case.
func TestPartialRestoreThatRecoveredNothingIsRefused(t *testing.T) {
	dir := t.TempDir()
	contract := filepath.Join(dir, "c.yaml")
	candidate := filepath.Join(dir, "k.yaml")
	ledgerPath := filepath.Join(dir, "l.jsonl")

	if err := os.WriteFile(contract, []byte(`apiVersion: contract/v0.1
kind: InfrastructureContract
meta: { id: dr, environment: test, version: 1 }
capabilities:
  - id: db
    type: capability.database.relational
constraints:
  hard:
    - { id: c1, subject: db, path: service.managed, op: equals, value: true,
        verify: { method: static } }
`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(candidate, []byte(`apiVersion: candidate/v0.1
kind: ImplementationCandidate
contract: dr
capabilities:
  db:
    provider: fake
    service: fakedb
    attributes:
      service.managed: true
`), 0o644); err != nil {
		t.Fatal(err)
	}

	const at = "2026-01-01T00:00:00Z"
	// plan + apply rather than converge: converge spawns ITSELF as a child process,
	// and inside a test binary that argv is the test.
	buildHistory(t, dir, contract, candidate, ledgerPath, at)
	backupDir := filepath.Join(dir, "bkp")
	if code := run([]string{"backup", "--ledger", ledgerPath, "--out", backupDir}); code != 0 {
		t.Fatalf("fixture: backup exited %d", code)
	}

	capsules, err := filepath.Glob(filepath.Join(backupDir, "capsules", "*.capsule.json"))
	if err != nil || len(capsules) == 0 {
		t.Fatalf("fixture: no capsules in the backup (%v)", err)
	}
	// Tamper EVERY capsule: nothing is provable, so a --partial restore recovers
	// nothing at all — the state that used to exit 0.
	for _, c := range capsules {
		raw, err := os.ReadFile(c)
		if err != nil {
			t.Fatal(err)
		}
		var doc map[string]any
		if err := json.Unmarshal(raw, &doc); err != nil {
			t.Fatal(err)
		}
		evs, _ := doc["events"].([]any)
		if len(evs) == 0 {
			t.Fatalf("fixture: capsule %s carries no events", c)
		}
		ev, _ := evs[0].(map[string]any)
		inner, _ := ev["event"].(map[string]any)
		if inner == nil {
			t.Fatalf("fixture: unexpected capsule shape in %s", c)
		}
		inner["environment"] = "tampered"
		out, _ := json.Marshal(doc)
		if err := os.WriteFile(c, out, 0o644); err != nil {
			t.Fatal(err)
		}
	}

	outLedger := filepath.Join(dir, "recovered.jsonl")
	argv := append([]string{"restore", "--out", outLedger, "--partial",
		"--check", filepath.Join(backupDir, "anchor.json")}, capsules...)
	code := run(argv)

	if code == 0 {
		t.Error("a --partial restore that recovered NOTHING exited 0 — an empty " +
			"recovery is a failed recovery, and the artefacts it leaves get certified " +
			"by every later check")
	}
	for _, leftover := range []string{outLedger, outLedger + ".anchor"} {
		if _, err := os.Stat(leftover); err == nil {
			t.Errorf("%s was left behind by a failed restore — D313: a refused run "+
				"must not leave a plausible artefact", filepath.Base(leftover))
		}
	}
}

// The control: an untampered backup still restores, so the refusal above is about
// recovering nothing rather than about being stricter.
func TestAnIntactBackupStillRestores(t *testing.T) {
	dir := t.TempDir()
	contract := filepath.Join(dir, "c.yaml")
	candidate := filepath.Join(dir, "k.yaml")
	ledgerPath := filepath.Join(dir, "l.jsonl")
	if err := os.WriteFile(contract, []byte(`apiVersion: contract/v0.1
kind: InfrastructureContract
meta: { id: dr2, environment: test, version: 1 }
capabilities:
  - id: db
    type: capability.database.relational
constraints:
  hard:
    - { id: c1, subject: db, path: service.managed, op: equals, value: true,
        verify: { method: static } }
`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(candidate, []byte(`apiVersion: candidate/v0.1
kind: ImplementationCandidate
contract: dr2
capabilities:
  db:
    provider: fake
    service: fakedb
    attributes:
      service.managed: true
`), 0o644); err != nil {
		t.Fatal(err)
	}
	buildHistory(t, dir, contract, candidate, ledgerPath, "2026-01-01T00:00:00Z")
	backupDir := filepath.Join(dir, "bkp")
	if code := run([]string{"backup", "--ledger", ledgerPath, "--out", backupDir}); code != 0 {
		t.Fatalf("fixture: backup exited %d", code)
	}
	capsules, _ := filepath.Glob(filepath.Join(backupDir, "capsules", "*.capsule.json"))
	out := filepath.Join(dir, "ok.jsonl")
	argv := append([]string{"restore", "--out", out,
		"--check", filepath.Join(backupDir, "anchor.json")}, capsules...)
	if code := run(argv); code != 0 {
		t.Fatalf("an intact backup must restore, got exit %d", code)
	}
	body, err := os.ReadFile(out)
	if err != nil || len(strings.TrimSpace(string(body))) == 0 {
		t.Fatalf("the restored ledger is empty or missing: %v", err)
	}
}

// buildHistory seals a plan and applies it against the fake driver, producing a real
// ledger with a binding — the smallest history a backup can be taken from.
func buildHistory(t *testing.T, dir, contract, candidate, ledgerPath, at string) {
	t.Helper()
	out := captureStdout(t, func() {
		if rc := run([]string{"plan", contract, candidate, "--provider", "fake",
			"--at", at, "--ledger", ledgerPath}); rc != 0 {
			t.Fatalf("fixture: plan exited %d", rc)
		}
	})
	planFile := filepath.Join(dir, "plan.json")
	if err := os.WriteFile(planFile, []byte(out), 0o644); err != nil {
		t.Fatal(err)
	}
	if rc := run([]string{"apply", contract, candidate, planFile, "--provider", "fake",
		"--at", at, "--ledger", ledgerPath}); rc != 0 {
		t.Fatalf("fixture: apply exited %d", rc)
	}
}
