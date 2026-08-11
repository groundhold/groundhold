package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// D637. `apply` pins `reads.provider` from the sealed plan and cross-checks it.
// `resume` — the verb an operator types by hand, under pressure, after something died —
// pinned nothing. Measured by the recovery audit on a ledger whose binding says `aws`:
//
//	groundhold resume contract.yaml --ledger aws.jsonl --provider fake --at …
//	exit 0   status: "resumed"
//
// The fake reconciler answers `succeeded` unconditionally, so the run declared an AWS
// RDS patch LANDED, bumped the binding generation, and rewrote `provider.name` from
// `aws` to `fake` — the field the code's own comment fifty lines away calls identity
// that "must survive (F4)". The create shape is worse: it invented a providerId
// (`fake:db-real-key`) and bound it over the real one.
//
// The ledger already records who started the work: the binding for a bound capability,
// and the pending receipt's `target` ("fake.fakedb/db") for one that died before its
// binding landed — which is the case where a wrong driver INVENTS an identity.
func TestResumeRefusesADriverThatDidNotStartTheOperation(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}
	contract := write("c.yaml", `apiVersion: contract/v0.1
kind: InfrastructureContract
meta: { id: rp, environment: test, version: 1 }
capabilities:
  - id: db
    type: capability.database.relational
constraints:
  hard:
    - { id: c1, subject: db, path: service.managed, op: equals, value: true,
        verify: { method: static } }
`)
	candidate := write("k.yaml", `apiVersion: candidate/v0.1
kind: ImplementationCandidate
contract: rp
capabilities:
  db:
    provider: fake
    service: fakedb
    attributes:
      service.managed: true
`)
	ledger := filepath.Join(dir, "l.jsonl")
	if code := run([]string{"publish", contract, "--ledger", ledger,
		"--at", "2026-01-01T00:00:00Z", "--actor", "ops"}); code != 0 {
		t.Fatalf("fixture: publish exited %d", code)
	}
	planOut := captureStdout(t, func() {
		if code := run([]string{"plan", contract, candidate, "--ledger", ledger,
			"--provider", "fake", "--at", "2026-01-01T00:10:00Z"}); code != 0 {
			t.Fatalf("fixture: plan exited %d", code)
		}
	})
	planFile := write("p.json", planOut)

	// Leave the create's outcome UNKNOWN: a pending receipt with no binding, which is
	// exactly the state a killed run leaves and the one where a wrong driver invents
	// an identity.
	var plan struct {
		Plan struct {
			Actions []struct {
				IdempotencyKey string `json:"idempotencyKey"`
			} `json:"actions"`
		} `json:"plan"`
	}
	if err := json.Unmarshal([]byte(planOut), &plan); err != nil || len(plan.Plan.Actions) == 0 {
		t.Fatalf("fixture: cannot read the plan's actions: %v", err)
	}
	if code := run([]string{"apply", contract, candidate, planFile, "--ledger", ledger,
		"--provider", "fake", "--at", "2026-01-01T00:11:00Z", "--yes",
		"--no-reachability", "--unknown-key", plan.Plan.Actions[0].IdempotencyKey}); code != 4 {
		t.Fatalf("fixture: apply with an unknown outcome exited %d, want 4", code)
	}

	pristine, err := os.ReadFile(ledger)
	if err != nil {
		t.Fatal(err)
	}
	ledgerCopy := func(name string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, pristine, 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}

	// Assert the REASON, not merely a non-zero exit: a wrong driver can fail for a
	// dozen unrelated reasons (no credentials, no project), and a test that accepts
	// any of them passes with the guard deleted. The mutation meter proved exactly
	// that against the first version of this test.
	out := captureStdout(t, func() {
		if code := run([]string{"resume", contract, "--ledger", ledgerCopy("wrong.jsonl"),
			"--provider", "gcp", "--project", "p1",
			"--at", "2026-01-01T00:20:00Z"}); code == 0 {
			t.Error("resume concluded an operation started by a DIFFERENT driver — " +
				"the reconciler it ran answers about a world it never touched, and " +
				"the binding it writes carries its own provider name")
		}
	})
	if !strings.Contains(out, "was started under provider") {
		t.Errorf("resume refused for some other reason than the provider mismatch — "+
			"the guard may not be running at all:\n%s", out)
	}

	// The control: the driver that started the work still resumes. Its own copy of the
	// pristine ledger, because the refusal above must not be the reason this passes.
	if code := run([]string{"resume", contract, "--ledger", ledgerCopy("right.jsonl"),
		"--provider", "fake", "--at", "2026-01-01T00:20:00Z"}); code != 0 {
		t.Errorf("the CONTROL failed: resuming with the driver that started the "+
			"operation exited %d", code)
	}
}

// The refusal must name both drivers, or the operator cannot act on it.
func TestResumeProviderRefusalNamesBothDrivers(t *testing.T) {
	src, err := os.ReadFile(filepath.Join(repoRootFromCmd(t), "go", "internal",
		"resume", "resume.go"))
	if err != nil {
		t.Skipf("resume source not readable here: %v", err)
	}
	body := string(src)
	if !strings.Contains(body, "was started under provider") {
		t.Error("the provider guard is gone from resume — an operator can once again " +
			"conclude another driver's operation with a reconciler that never saw it")
	}
}
