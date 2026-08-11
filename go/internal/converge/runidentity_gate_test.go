package converge

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// D656. Two defects with one shape: a run's identity did not include everything
// that distinguishes one run from another.
//
// The handle was `sha256("converge:" + sha256(contract) + "|" + at)` — the
// CANDIDATE, which is the file an operator edits to fix an implementation, was not
// in it. Re-running at the same `--at` after an edit reused the handle, and the
// ledger then held `converge.finished{exitCode:0}` followed by
// `converge.failed{exitCode:2}` under one id. Measured:
//
//	status <h> --json   exit 0   "state":"done","code":"run-done","exitCode":2
//	wait   <h>          exit 0
//
// A CI gate running `converge --detach` and then `wait` got a green light for a
// deploy that had been REFUSED.
func TestTheRunHandleIncludesTheCandidate(t *testing.T) {
	dir := t.TempDir()
	contract := filepath.Join(dir, "c.yaml")
	if err := os.WriteFile(contract, []byte(`apiVersion: contract/v0.1
kind: InfrastructureContract
meta: { id: p, owner: o@e.test, environment: test, version: 1 }
capabilities:
  - id: db
    type: capability.database.relational
`), 0o600); err != nil {
		t.Fatal(err)
	}
	candA := filepath.Join(dir, "a.yaml")
	candB := filepath.Join(dir, "b.yaml")
	if err := os.WriteFile(candA, []byte("apiVersion: candidate/v0.1\nkind: ImplementationCandidate\ncontract: p\ncapabilities: {}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(candB, []byte("apiVersion: candidate/v0.1\nkind: ImplementationCandidate\ncontract: p\ncapabilities: {}\n# edited\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	const at = "2026-07-15T09:00:00Z"
	idA, _, _, err := RunID(contract, candA, at, "")
	if err != nil {
		t.Fatal(err)
	}
	idB, _, _, err := RunID(contract, candB, at, "")
	if err != nil {
		t.Fatal(err)
	}
	if idA == idB {
		t.Errorf("editing the candidate and re-running at the same --at reuses the "+
			"handle %s — the ledger then carries two terminal events for one run, "+
			"and status reports the FIRST one", idA)
	}
	// The project selects WHERE the run acts; two runs into different projects are
	// not the same run either.
	idP, _, _, err := RunID(contract, candA, at, "other-project")
	if err != nil {
		t.Fatal(err)
	}
	if idP == idA {
		t.Errorf("the handle ignores --project, so two runs against different "+
			"projects share it: %s", idA)
	}
	// The control: identical inputs must still give the identical handle, or the
	// detach launcher cannot precompute what Converge will write.
	again, _, _, err := RunID(contract, candA, at, "")
	if err != nil {
		t.Fatal(err)
	}
	if again != idA {
		t.Errorf("the handle is not deterministic: %s != %s", again, idA)
	}
}

// The plan file was a FIXED path under the working directory. Two converges in one
// directory clobbered it and applied each other's plan — measured 8 times out of 8,
// with the two plans differing only in `project`, which is not in the read-set, so
// apply's own mismatch check was structurally blind. One run created resources in
// the other's project and reported success.
func TestThePlanFileIsPerRun(t *testing.T) {
	a := planPathFor("aaaaaaaaaaaa")
	b := planPathFor("bbbbbbbbbbbb")
	if a == b {
		t.Fatalf("two runs share the plan file %s — whichever writes last is the "+
			"plan BOTH apply", a)
	}
	for _, p := range []string{a, b} {
		if !strings.HasPrefix(p, ".groundhold") {
			t.Errorf("the plan escaped the run directory: %s", p)
		}
	}
	if !strings.Contains(a, "aaaaaaaaaaaa") {
		t.Errorf("the plan file does not name its run: %s", a)
	}
}

// D665. converge must read apply's `nothing-to-change` the way it already reads
// plan's: a converged world is the GOAL, not a refusal. Before the apply-side guard
// existed this path produced `lease-conflict` (exit 3) and an internal validator
// string; the guard alone would have turned it into `REFUSED nothing-to-change`
// (exit 2), which is still wrong for the porcelain. The gate reads the mapping
// because driving two converges needs a provider and a ledger the package cannot
// reach.
func TestConvergeReadsNothingToChangeAsConverged(t *testing.T) {
	raw, err := os.ReadFile("converge.go")
	if err != nil {
		t.Fatal(err)
	}
	body := string(raw)
	// The plan phase's mapping, which has always been there.
	if !strings.Contains(body, "a converged world is the GOAL") {
		t.Error("the plan phase no longer maps nothing-to-change to converged")
	}
	// The apply phase's, added by D665.
	if !strings.Contains(body, "nothing to apply") {
		t.Error("the apply phase no longer maps nothing-to-change to converged — a " +
			"second converge over a capability with an unobservable attribute then " +
			"reads as a refusal")
	}
	if strings.Count(body, "childCode(stdout) == perr.NothingToChange") == 0 {
		t.Error("the apply-side mapping is gone")
	}
}
