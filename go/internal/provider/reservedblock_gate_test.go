package provider_test

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// D1163. `outcomes` is published in `spec/contract.schema.json`, parsed and shape-gated
// by both loaders, folded into the contract's hash — and read by nothing. `probe` derives
// what to measure from the ledger's bindings and reads the contract only for the
// intrusive-probe consent (D59), so no verb behaves differently because the block is
// there. It appears in a shipped example, so a reader learning the language writes it and
// gets a different hash and nothing else.
//
// Saying so in the schema is half the job; the half that lasts is this. The gate is
// BEHAVIOURAL rather than a search for readers, because the first draft grepped for the
// field name and flagged `apply.go` and `converge.go` — which carry an unrelated
// `Outcomes` (per-action results). A name two concepts share cannot answer "is this block
// read", and narrowing the regex until it agreed with what I already believed would have
// been a gate written to pass.
//
// What is asserted instead is the property itself: adding the block changes the contract
// HASH and nothing else. Implement `outcomes` — make any verb act on it — and this fails
// until the marker comes off the schema, which is the point of marking it.
func TestAReservedBlockChangesNothingButTheHash(t *testing.T) {
	skipIfExported(t, "the CLI")
	root := repoRoot(t)
	bin := buildCLI(t, root)

	const base = `apiVersion: contract/v0.1
kind: InfrastructureContract
meta: { id: reserved-probe, environment: test, version: 1 }
capabilities:
  - id: db
    type: capability.database.relational
constraints:
  hard:
    - { id: c-managed, subject: db, path: service.managed, op: equals, value: true }
`
	// Each block exactly as the shipped example writes it — the shape a reader copies.
	// D1164 added the second: `auto_execute` names a spending and reversibility cap on
	// what may run automatically, is shape-gated as a mapping, and is read by nothing.
	// A name that promises a safety limit is the worse of the two to leave unlabelled.
	blocks := map[string]string{
		"outcomes": `outcomes:
  - id: o-reachable
    probe: tcp-connect
    target: db
    expect: reachable
`,
		"autonomy.auto_execute": `autonomy:
  auto_execute:
    max_reversibility: R1
    max_cost_delta: { amount: 100, currency: EUR }
`,
	}
	const candidate = `apiVersion: candidate/v0.1
kind: ImplementationCandidate
contract: reserved-probe
capabilities:
  db:
    attributes:
      service.managed: true
    provider: fake
    service: sql
`
	dir := t.TempDir()
	write := func(name, body string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}
	plain := write("plain.contract.yaml", base)
	cand := write("c.candidate.yaml", candidate)

	run := func(t *testing.T, contract string) map[string]any {
		t.Helper()
		cmd := exec.Command(bin, "verify", contract, cand, "--json")
		cmd.Dir = root
		out, _ := cmd.CombinedOutput() // exit 2 on a blocked verdict is a real answer
		var doc map[string]any
		dec := json.NewDecoder(strings.NewReader(string(out)))
		if err := dec.Decode(&doc); err != nil {
			t.Fatalf("verify did not print one JSON object (%v):\n%s", err, out)
		}
		return doc
	}

	names := make([]string, 0, len(blocks))
	for n := range blocks {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, name := range names {
		t.Run(name, func(t *testing.T) { assertOnlyHashMoves(t, run, plain, write, base, blocks[name], name) })
	}
}

func assertOnlyHashMoves(t *testing.T, run func(*testing.T, string) map[string]any,
	plain string, write func(string, string) string, base, block, name string) {
	t.Helper()
	withB := write(strings.ReplaceAll(name, ".", "-")+".contract.yaml", base+block)
	a, b := run(t, plain), run(t, withB)

	// The hash MUST differ: the block is part of the document, and a contract that
	// says something extra is not the same contract. That is the vacuity floor here —
	// if the two hashed identically, the comparison below would be trivially equal
	// and this gate would pass over a block the loader had stopped reading at all.
	if a["contractHash"] == b["contractHash"] {
		t.Fatal("the two contracts hash IDENTICALLY — the block is not reaching the " +
			"canonical form, so this gate is comparing a document with itself (D683 " +
			"is the same failure: a dropped block hashing as though it were never there)")
	}

	// Everything else must be equal. A verdict, an exit, a blocking reason that moves
	// because `outcomes` is present means the block decides something, and the schema
	// is telling a reader it does not.
	for _, k := range []string{"executable", "code", "verdicts", "summary",
		"blockingReasons", "candidateHash"} {
		x, _ := json.Marshal(a[k])
		y, _ := json.Marshal(b[k])
		if string(x) != string(y) {
			t.Errorf("%s changed %q:\n  without: %s\n  with:    %s\n"+
				"The schema publishes this block as reserved in v0. Either it is not "+
				"reserved any more — take the marker off, and say in the schema what "+
				"it does — or something started reading a block readers are told is "+
				"inert.", name, k, x, y)
		}
	}
}

// buildCLI compiles the binary once for this test.
func buildCLI(t *testing.T, root string) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "groundhold")
	cmd := exec.Command("go", "build", "-o", bin, "./cmd/groundhold")
	cmd.Dir = filepath.Join(root, "go")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("building the CLI: %v\n%s", err, out)
	}
	return bin
}
