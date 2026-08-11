package main

import (
	"os"
	"path/filepath"
	"testing"

	"groundhold/internal/ledger"
)

// TestReactExitHonorsUnknown pins D966: `react` — the unattended, event-driven
// real-time path — built its posture document through the SAME fold as `posture`
// but computed its own exit code (shadow||drifted), dropping the Unknown and
// ShadowLowerBound arms that posture.Summary.ExitCode() carries. So react returned
// 0 ("handled, nothing to do", a stream-consumer's all-clear) over an estate whose
// HARD compliance is unknown — where posture and audit both exit 2 (invariant #1).
// Here a bound resource has a hard constraint backed only by a STALE proof: no
// shadow, no drift, Unknown>0.
func TestReactExitHonorsUnknown(t *testing.T) {
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
	// bind the resource the Fake discoverer returns, so it is NOT a shadow
	if err := w.Append("binding.updated", []string{"db"}, map[string]any{
		"providerId": "fake:existing-db",
		"resources": []any{map[string]any{"providerId": "fake:existing-db",
			"type": "capability.database.relational"}}}, tok); err != nil {
		t.Fatal(err)
	}
	// its ONLY proof, with a 15-minute ttl — stale at the react --at below
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
	pairingsPath := filepath.Join(dir, "pairings.yaml")
	if err := os.WriteFile(pairingsPath,
		[]byte("pairings:\n  - provider: fake\n    pairedAt: \"2025-07-15T08:00:00Z\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	eventPath := filepath.Join(dir, "event.json")
	if err := os.WriteFile(eventPath,
		[]byte(`{"kind":"groundhold/test-event/v0","provider":"fake","scope":"demo","hint":"created"}`), 0o600); err != nil {
		t.Fatal(err)
	}

	var code int
	_ = captureStdout(t, func() {
		code = run([]string{"react", "--provider", "fake", "--event", eventPath, "--ledger", ledgerPath,
			"--contract", contractPath, "--pairings", pairingsPath,
			"--at", "2025-07-15T09:00:00Z"})
	})
	if code != 2 {
		t.Fatalf("react must exit 2 when a hard constraint is unknown (its proof is stale) — "+
			"posture and audit both do on the identical evidence; got %d (react dropped the Unknown "+
			"arm from its bespoke exit code)", code)
	}
}
