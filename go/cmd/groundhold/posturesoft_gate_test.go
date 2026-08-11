package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"groundhold/internal/ledger"
)

// D755. `posture` folds the audit's verdicts into one class per capability, and the fold
// read EVERY verdict — hard and soft alike. `audit` returns both, each carrying its
// severity, and the exit-code path filters on it; this fold did not.
//
// Two ways that lies, in opposite directions:
//
//	a SOFT violation      -> class "drifted", reason "a hard constraint is violated",
//	                         with a converge recipe, for something advisory
//	only SOFT constraints -> class "managed-ok", whose published meaning is "bound,
//	                         every HARD verdict satisfied" — green with nothing hard proven
//
// The default arm exists precisely to refuse the second: "no audit verdict at <at> —
// cannot claim ok without a proof". A soft verdict walked straight past it.
func TestPostureClassifiesOnHardVerdictsOnly(t *testing.T) {
	classFor := func(t *testing.T, observed bool, constraints string) (string, string) {
		t.Helper()
		dir := t.TempDir()
		ledgerPath := filepath.Join(dir, "l.jsonl")
		if err := os.WriteFile(ledgerPath, nil, 0o600); err != nil {
			t.Fatal(err)
		}
		led := ledger.New()
		w := &ledger.Writer{Path: ledgerPath, Led: led, Env: "test",
			Clock: 1752566400, Actor: "t"} // 2025-07-15T08:00:00Z
		tok, err := w.AppendLease([]string{"db"}, map[string]any{"ttlSeconds": 900})
		if err != nil {
			t.Fatal(err)
		}
		if err := w.Append("binding.updated", []string{"db"}, map[string]any{
			"providerId": "fake:db-1",
			"resources": []any{map[string]any{"providerId": "fake:db-1",
				"type": "capability.database.relational"}}}, tok); err != nil {
			t.Fatal(err)
		}
		if err := w.Append("observation.recorded", []string{"db"}, map[string]any{
			"observations": []any{
				map[string]any{"path": "service.managed", "value": observed,
					"observedAt": "2025-07-15T08:00:00Z", "ttlSeconds": 86400,
					"derivation": "measured", "source": "provider-api"}}}, tok); err != nil {
			t.Fatal(err)
		}
		contractPath := filepath.Join(dir, "c.yaml")
		if err := os.WriteFile(contractPath, []byte(`apiVersion: contract/v0.1
kind: InfrastructureContract
meta: { id: p, owner: o@e.test, environment: test, version: 1 }
capabilities:
  - id: db
    type: capability.database.relational
constraints:
`+constraints), 0o600); err != nil {
			t.Fatal(err)
		}
		out := captureStdout(t, func() {
			run([]string{"posture", "--ledger", ledgerPath, "--contract", contractPath,
				"--at", "2025-07-15T09:00:00Z"})
		})
		var doc map[string]any
		if err := json.Unmarshal([]byte(out), &doc); err != nil {
			t.Fatalf("posture output is not JSON:\n%s", out)
		}
		rows, _ := doc["rows"].([]any)
		for _, r := range rows {
			m, _ := r.(map[string]any)
			if pid, _ := m["providerId"].(string); pid == "fake:db-1" {
				cl, _ := m["class"].(string)
				rs, _ := m["reason"].(string)
				return cl, rs
			}
		}
		t.Fatalf("no row for the bound capability:\n%s", out)
		return "", ""
	}

	const softOnly = `  soft:
    - { id: s-managed, subject: db, path: service.managed, op: equals, value: true }
`
	const hardOnly = `  hard:
    - { id: c-managed, subject: db, path: service.managed, op: equals, value: true,
        verify: { method: static } }
`

	t.Run("a violated SOFT constraint is not drift", func(t *testing.T) {
		class, reason := classFor(t, false, softOnly)
		if class == "drifted" {
			t.Fatalf("an advisory constraint made posture report drift, with the reason "+
				"%q — the word `hard` in that sentence is false, and the recipe sends an "+
				"operator to converge over something the contract marked as not blocking "+
				"(D755)", reason)
		}
	})

	t.Run("a satisfied SOFT constraint is not a proof", func(t *testing.T) {
		class, _ := classFor(t, true, softOnly)
		if class == "managed-ok" {
			t.Fatal("green from an advisory check alone: managed-ok publishes as \"bound, " +
				"every HARD verdict satisfied\", and nothing hard was verified here. The " +
				"default arm refuses exactly this — `cannot claim ok without a proof` — " +
				"and a soft verdict walked past it (D755)")
		}
	})

	// The controls, or the fix would be indistinguishable from deleting the fold.
	t.Run("a violated HARD constraint is still drift", func(t *testing.T) {
		if class, _ := classFor(t, false, hardOnly); class != "drifted" {
			t.Fatalf("class = %q, want drifted", class)
		}
	})

	t.Run("a satisfied HARD constraint is still green", func(t *testing.T) {
		if class, _ := classFor(t, true, hardOnly); class != "managed-ok" {
			t.Fatalf("class = %q, want managed-ok", class)
		}
	})
}
