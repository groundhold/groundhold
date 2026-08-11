package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// D624. `spec/errors.md` states the coverage rule in one line: "every JSON-emitting
// verb carries `code`". Three did not.
//
//	audit  … --at …            exit 2  {"status":"violations-found", …}   grep -c '"code"' = 0
//	backup --ledger corrupt …  exit 5  {"status":"refused","reasons":[…]}  no code
//	repair --ledger corrupt …  exit 5  {"status":"corrupt", …}             no code
//
// Every one of those conditions HAS a published code. Without it the caller is pushed
// back to matching on prose — which the same document declares unparseable, and which
// D330 built a four-artefact registry to make unnecessary.
//
// The audit case is the interesting one: the code depends on WHY it blocks. An
// `unknown` hard verdict means the evidence is missing or stale and the next step is
// `observe --record` — which is exactly what `observation-required` publishes — while a
// genuinely failing constraint is `not-executable`. A single code for both would have
// satisfied the letter of the rule and told the caller nothing.
func TestJSONRefusalsCarryTheirCode(t *testing.T) {
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
meta: { id: cov, environment: test, version: 1 }
capabilities:
  - id: db
    type: capability.database.relational
constraints:
  hard:
    - { id: c-managed, subject: db, path: service.managed, op: equals, value: true,
        verify: { method: static } }
`)
	// A ledger whose line 2 parses as JSON and is not an event.
	corrupt := write("corrupt.ndjson",
		`{"apiVersion":"state/v0","kind":"LedgerEvent","event":{"type":"contract.published","environment":"test","capabilities":["db"],"occurredAt":"2026-01-01T00:00:00Z","actor":{"id":"ops","type":"human"}}}`+
			"\n{\"not\":\"an event\"}\n")
	empty := write("empty.ndjson", "")

	codeOf := func(t *testing.T, out string) string {
		t.Helper()
		var doc map[string]any
		if err := json.Unmarshal([]byte(out), &doc); err != nil {
			t.Fatalf("output is not a JSON document:\n%s", out)
		}
		code, _ := doc["code"].(string)
		return code
	}

	t.Run("audit names why it blocks", func(t *testing.T) {
		out := captureStdout(t, func() {
			run([]string{"audit", contract, "--ledger", empty,
				"--at", "2026-02-01T00:00:00Z"})
		})
		got := codeOf(t, out)
		if got == "" {
			t.Fatalf("audit refused with no code:\n%s", out)
		}
		if got != "observation-required" {
			t.Errorf("audit blocked on an unknown verdict and named %q — the operator's "+
				"next step is `observe --record`, which observation-required publishes",
				got)
		}
	})

	t.Run("backup names a corrupt ledger", func(t *testing.T) {
		out := captureStdout(t, func() {
			run([]string{"backup", "--ledger", corrupt,
				"--out", filepath.Join(dir, "bk")})
		})
		if got := codeOf(t, out); got != "ledger-corrupted" {
			t.Errorf("backup refused with code %q, want ledger-corrupted:\n%s", got, out)
		}
	})

	t.Run("repair names what it diagnosed", func(t *testing.T) {
		out := captureStdout(t, func() {
			run([]string{"repair", "--ledger", corrupt})
		})
		if got := codeOf(t, out); got != "ledger-corrupted" {
			t.Errorf("repair reported corruption with code %q:\n%s", got, out)
		}
	})

	t.Run("a clean run carries no refusal code", func(t *testing.T) {
		// A REAL ledger, written by publish: a hand-rolled event has no `prev`, which
		// repair correctly calls corruption — the control has to be genuinely healthy
		// or it proves the opposite of what it claims.
		healthy := filepath.Join(dir, "healthy.ndjson")
		if code := run([]string{"publish", contract, "--ledger", healthy,
			"--at", "2026-01-01T00:00:00Z", "--actor", "ops"}); code != 0 {
			t.Fatalf("fixture: publish exited %d", code)
		}
		out := captureStdout(t, func() {
			run([]string{"repair", "--ledger", healthy})
		})
		if got := codeOf(t, out); got != "" {
			t.Errorf("a healthy ledger carried code %q — a code on a clean run is a "+
				"signal that is always on, which is no signal (D556)", got)
		}
		if !strings.Contains(out, "healthy") {
			t.Errorf("expected a healthy diagnosis:\n%s", out)
		}
	})
}
