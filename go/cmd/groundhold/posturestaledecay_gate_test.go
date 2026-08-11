package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"groundhold/internal/ledger"
)

// TestPostureStaleHardConstraintBlocks pins D965 end to end (the accumulator +
// the capRow fold): a bound capability whose HARD constraint has only a STALE
// proof audits `unknown` and audit exits 2 — posture must classify it `unknown`
// (blocking), not mask it as a benign `decayed` refresh (exit 0). Before the fix
// the accumulator left the audit `unknown` unset, so a coincident decayed marker
// won the capRow precedence and posture read exit 0 on a stale non-negotiable.
func TestPostureStaleHardConstraintBlocks(t *testing.T) {
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
	// the ONLY proof of the hard constraint, with a 15-minute ttl
	if err := w.Append("observation.recorded", []string{"db"}, map[string]any{
		"observations": []any{
			map[string]any{"path": "service.managed", "value": true,
				"observedAt": "2025-07-15T08:00:00Z", "ttlSeconds": 900,
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
  hard:
    - { id: c-managed, subject: db, path: service.managed, op: equals, value: true,
        verify: { method: static } }
`), 0o600); err != nil {
		t.Fatal(err)
	}
	// --at is one hour past the observation, well beyond its 900s ttl → the proof
	// is stale: audit returns unknown, and the decayed marker is also set.
	out := captureStdout(t, func() {
		run([]string{"posture", "--ledger", ledgerPath, "--contract", contractPath,
			"--at", "2025-07-15T09:00:00Z"})
	})
	var doc map[string]any
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatalf("posture output is not JSON:\n%s", out)
	}
	rows, _ := doc["rows"].([]any)
	var class string
	for _, r := range rows {
		m, _ := r.(map[string]any)
		if pid, _ := m["providerId"].(string); pid == "fake:db-1" {
			class, _ = m["class"].(string)
		}
	}
	if class != "unknown" {
		t.Fatalf("a stale HARD-constraint proof must classify unknown (blocking, audit exits 2 "+
			"on the same evidence), got %q — a decayed marker masked a stale non-negotiable as exit 0", class)
	}
}
