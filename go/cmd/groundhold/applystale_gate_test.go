package main

import (
	"os"
	"path/filepath"
	"testing"
)

// D632, second half. The unit test for `changeStaleReason` calls it DIRECTLY, so the
// mutation meter walked straight through a mutant that deleted its CALL SITE: the
// helper was proven, and nothing proved that anything invoked it. That is D564
// verbatim — a passing assertion is a claim about what was EXECUTED — and it is the
// second appearance of that exact shape in this record.
//
// This drives the real CLI end to end, on a ledger the product itself wrote (a
// hand-built one has no hash chain and `plan` refuses it, which is how the first
// attempt at this test ended up SKIPPING — and a test that skips is not a gate):
//
//	publish -> plan -> apply           (a bound resource)
//	observe --record                    (evidence with a ttl)
//	plan at 01:00:01Z                   (an update, sealed while the evidence is live)
//	apply at 01:30:00Z  -> 0            (the control: inside the ttl it applies)
//	apply at 2030-…     -> 3 STALE      (the refusal: the proof died years ago)
func TestApplyRefusesAStalePlanEndToEnd(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}
	ledgerPath := filepath.Join(dir, "l.jsonl")

	contract := func(want string) string {
		return `apiVersion: contract/v0.1
kind: InfrastructureContract
meta: { id: st, environment: test, version: 1 }
capabilities:
  - id: db
    type: capability.database.relational
constraints:
  hard:
    - { id: c-managed, subject: db, path: service.managed, op: equals, value: ` + want + `,
        verify: { method: static } }
`
	}
	candidate := func(v string) string {
		return `apiVersion: candidate/v0.1
kind: ImplementationCandidate
contract: st
capabilities:
  db:
    provider: fake
    service: fakedb
    attributes:
      service.managed: ` + v + `
`
	}

	c1, k1 := write("c.yaml", contract("true")), write("k.yaml", candidate("true"))
	if code := run([]string{"publish", c1, "--ledger", ledgerPath,
		"--at", "2026-01-01T00:00:00Z", "--actor", "ops"}); code != 0 {
		t.Fatalf("fixture: publish exited %d", code)
	}
	planOut := captureStdout(t, func() {
		if code := run([]string{"plan", c1, k1, "--ledger", ledgerPath,
			"--provider", "fake", "--at", "2026-01-01T00:10:00Z"}); code != 0 {
			t.Fatalf("fixture: plan exited %d", code)
		}
	})
	p1 := write("p1.json", planOut)
	if code := run([]string{"apply", c1, k1, p1, "--ledger", ledgerPath,
		"--provider", "fake", "--at", "2026-01-01T00:11:00Z", "--yes",
		"--no-reachability"}); code != 0 {
		t.Fatalf("fixture: apply exited %d", code)
	}
	if code := run([]string{"observe", "--ledger", ledgerPath, "--provider", "fake",
		"--at", "2026-01-01T01:00:00Z", "--record"}); code != 0 {
		t.Fatalf("fixture: observe exited %d", code)
	}

	// Seal an UPDATE one second after the observation, while its evidence is live.
	c2, k2 := write("c2.yaml", contract("false")), write("k2.yaml", candidate("false"))
	updateOut := captureStdout(t, func() {
		if code := run([]string{"plan", c2, k2, "--ledger", ledgerPath,
			"--provider", "fake", "--at", "2026-01-01T01:00:01Z"}); code != 0 {
			t.Fatalf("fixture: the update plan exited %d", code)
		}
	})
	p2 := write("p2.json", updateOut)

	// The two applies must be INDEPENDENT. Applying the plan once mutates the ledger,
	// which moves the decision heads it pinned — so a second apply of the same plan
	// would be refused for staleness of a completely different kind, and the test
	// would pass while proving nothing. (It did: the mutation meter caught it by
	// deleting the freshness call and watching this test stay green.) Each apply runs
	// against its own copy of the same pristine ledger.
	pristine, err := os.ReadFile(ledgerPath)
	if err != nil {
		t.Fatal(err)
	}
	copyLedger := func(name string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, pristine, 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}

	if code := run([]string{"apply", c2, k2, p2, "--ledger", copyLedger("fresh.jsonl"),
		"--provider", "fake", "--at", "2026-01-01T01:30:00Z", "--yes",
		"--no-reachability"}); code != 0 {
		t.Fatalf("the CONTROL failed: applying inside the ttl exited %d. Without it "+
			"the refusal below proves only that apply refuses everything", code)
	}

	if code := run([]string{"apply", c2, k2, p2, "--ledger", copyLedger("late.jsonl"),
		"--provider", "fake", "--at", "2030-01-01T00:00:00Z", "--yes",
		"--no-reachability"}); code == 0 {
		t.Error("apply executed a change set four years after the observation that " +
			"justifies it expired — `plan` refuses that world, and apply is the verb " +
			"that re-derives rather than trusts")
	}
}
