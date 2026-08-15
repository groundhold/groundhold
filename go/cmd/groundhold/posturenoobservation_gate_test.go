package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"groundhold/internal/ledger"
)

// TestPostureNeverObservedIsUnknownNotDecayed pins D1102: a bound capability with NO
// observation at all is `unknown` (exit 2), never `decayed` (exit 0). classifyPosture
// used to mark a zero-record capability decayed — putting "we have never had any
// evidence" into the benign class with a reason that lies ("the backing proof outlived
// its own ttl") when no proof ever existed. It also inverted monotonicity: a bound
// capability with a fresh-but-unaudited observation lands in `unknown` (exit 2), so the
// capability we know LESS about must not be greener. posture's own ExitCode docstring
// calls exit 0 over an unknown estate the unverifiable-as-success inversion audit refuses.
func TestPostureNeverObservedIsUnknownNotDecayed(t *testing.T) {
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
	// a binding, and DELIBERATELY no observation.recorded — the capability is bound
	// (e.g. just created by apply) but has never been observed.
	if err := w.Append("binding.updated", []string{"db"}, map[string]any{
		"providerId": "fake:db-1",
		"resources": []any{map[string]any{"providerId": "fake:db-1",
			"type": "capability.database.relational"}}}, tok); err != nil {
		t.Fatal(err)
	}
	// no --contract: there is no verdict either, so this is purely "bound, no evidence".
	code := run([]string{"posture", "--ledger", ledgerPath,
		"--at", "2025-07-15T09:00:00Z"})
	out := captureStdout(t, func() {
		run([]string{"posture", "--ledger", ledgerPath, "--at", "2025-07-15T09:00:00Z"})
	})
	var doc map[string]any
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatalf("posture output is not JSON:\n%s", out)
	}
	rows, _ := doc["rows"].([]any)
	var class, reason string
	for _, r := range rows {
		m, _ := r.(map[string]any)
		if pid, _ := m["providerId"].(string); pid == "fake:db-1" {
			class, _ = m["class"].(string)
			reason, _ = m["reason"].(string)
		}
	}
	if class != "unknown" {
		t.Fatalf("a bound-but-never-observed capability must classify `unknown` (exit 2), got %q "+
			"— decayed/exit 0 reads 'all clear' over a capability we have no evidence about", class)
	}
	if class == "decayed" || reason == "the backing proof outlived its own ttl — we no longer know" {
		t.Fatalf("the decayed reason lies when no proof ever existed: %q", reason)
	}
	if code != 2 {
		t.Fatalf("posture over a bound-but-unobserved capability must exit 2 (unknown), got %d", code)
	}
}
