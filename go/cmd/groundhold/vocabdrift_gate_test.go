package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// D634. The vocabulary decides `stateful:`, and `stateful:` decides whether a delete
// is refused by the contract's own `autonomy.forbidden: delete_stateful`. A plan pinned
// the vocabulary's VERSION STRING, and `apply` compared neither that nor anything else
// — `spec/sealed-plan.md` step 3 says it re-checks "toolchain, vocab versions, provider
// identity" and it checked none of the three.
//
// Measured by the compiler audit: two vocabulary trees differing by one line
// (`stateful: true` -> `false` in capability.monitoring.logs.yaml, `version:` untouched)
//
//	plan --vocab vocabA   exit 2  "retiring applogs destroys a stateful capability and
//	                               the contract forbids delete_stateful"
//	plan --vocab vocabB   exit 0  a-delete-applogs, dataLoss: none
//	apply … --vocab vocabB          exit 0  APPLIED — the resource is destroyed
//
// byte-identical in everything the plan pins. The pin is now
// "<version> <canonical-hash-of-the-model>" — hashing what the RUNTIME reads
// (capability, version, attributes, stateful), so a comment or a reordering does not
// invalidate a sealed plan while any change the runtime can act on does.
func TestApplyRefusesAVocabularyItWasNotCompiledAgainst(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}
	repo := repoRootFromCmd(t)

	// Two vocabulary trees, one line apart, same declared version.
	vocabA := filepath.Join(dir, "vocabA")
	vocabB := filepath.Join(dir, "vocabB")
	for _, dst := range []string{vocabA, vocabB} {
		if err := os.MkdirAll(dst, 0o755); err != nil {
			t.Fatal(err)
		}
		srcs, err := filepath.Glob(filepath.Join(repo, "spec", "vocab", "*.yaml"))
		if err != nil || len(srcs) == 0 {
			t.Skipf("no vocabulary here: %v", err)
		}
		for _, s := range srcs {
			body, err := os.ReadFile(s)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dst, filepath.Base(s)), body, 0o644); err != nil {
				t.Fatal(err)
			}
		}
	}
	logsFile := filepath.Join(vocabB, "capability.monitoring.logs.yaml")
	body, err := os.ReadFile(logsFile)
	if err != nil {
		t.Skipf("the logs vocabulary is not where this test expects: %v", err)
	}
	edited := strings.Replace(string(body), "stateful: true", "stateful: false", 1)
	if edited == string(body) {
		t.Skip("capability.monitoring.logs is no longer stateful: true — re-target this test")
	}
	if err := os.WriteFile(logsFile, []byte(edited), 0o644); err != nil {
		t.Fatal(err)
	}

	contract := write("c.yaml", `apiVersion: contract/v0.1
kind: InfrastructureContract
meta: { id: vd, environment: test, version: 1 }
autonomy:
  forbidden:
    - delete_stateful: true
capabilities:
  - id: logs
    type: capability.monitoring.logs
constraints:
  hard:
    - { id: c1, subject: logs, path: service.managed, op: equals, value: true,
        verify: { method: static } }
`)
	candidate := write("k.yaml", `apiVersion: candidate/v0.1
kind: ImplementationCandidate
contract: vd
capabilities:
  logs:
    provider: fake
    service: fakelogs
    attributes:
      service.managed: true
`)

	ledger := filepath.Join(dir, "l.jsonl")
	if code := run([]string{"publish", contract, "--ledger", ledger,
		"--at", "2026-01-01T00:00:00Z", "--actor", "ops"}); code != 0 {
		t.Fatalf("fixture: publish exited %d", code)
	}
	planOut := captureStdout(t, func() {
		if code := run([]string{"plan", contract, candidate, "--vocab", vocabA,
			"--ledger", ledger, "--provider", "fake",
			"--at", "2026-01-01T00:10:00Z"}); code != 0 {
			t.Fatalf("fixture: plan exited %d", code)
		}
	})
	planFile := write("p.json", planOut)

	// Independent ledgers: applying once moves the decision heads, and a second apply
	// of the same plan would then refuse for a completely different staleness — which
	// would make this test pass while proving nothing. (That mistake has now been made
	// three times in this repo; see D632.)
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

	if code := run([]string{"apply", contract, candidate, planFile, "--vocab", vocabA,
		"--ledger", ledgerCopy("la.jsonl"), "--provider", "fake",
		"--at", "2026-01-01T00:11:00Z", "--yes", "--no-reachability"}); code != 0 {
		t.Fatalf("the CONTROL failed: applying against the vocabulary the plan was "+
			"compiled with exited %d", code)
	}

	code := run([]string{"apply", contract, candidate, planFile, "--vocab", vocabB,
		"--ledger", ledgerCopy("lb.jsonl"), "--provider", "fake",
		"--at", "2026-01-01T00:11:00Z", "--yes", "--no-reachability"})
	if code == 0 {
		t.Error("apply executed a sealed plan against a DIFFERENT vocabulary than the " +
			"one it was compiled against — one line there decides whether a delete is " +
			"forbidden, and the version string it pinned did not change")
	}
}
