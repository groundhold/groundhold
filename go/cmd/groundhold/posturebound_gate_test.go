package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"groundhold/internal/ledger"
)

// D650. The classifier is unit-tested; this pins the WIRING, which is where the
// defect lived — `classifyPosture` copied completeness onto each discovered
// resource and nowhere else, so a scope that listed nothing could not carry it.
// A test aimed at Classify alone would stay green with the builder deleted.
func TestPostureReportsALowerBoundThroughTheCLI(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	ledgerPath := write("l.jsonl", "")
	crawlDoc := func(status string, resources string) string {
		return `{"apiVersion":"crawl/v0.1","kind":"ContextDocument",
		  "at":"2026-07-15T12:05:00Z","providers":[{"provider":"fake","scopes":[
		    {"scope":"proj-a","status":"` + status + `","reason":"crawl request budget ` +
			`exhausted: fake","resources":[` + resources + `]}]}]}`
	}

	summaryOf := func(t *testing.T, args []string) map[string]any {
		t.Helper()
		out := captureStdout(t, func() { run(args) })
		var doc map[string]any
		if err := json.Unmarshal([]byte(out), &doc); err != nil {
			t.Fatalf("posture output is not JSON:\n%s", out)
		}
		s, _ := doc["summary"].(map[string]any)
		if s == nil {
			t.Fatalf("no summary in:\n%s", out)
		}
		return s
	}

	t.Run("a scope that listed nothing lowers the bound", func(t *testing.T) {
		s := summaryOf(t, []string{"posture", "--ledger", ledgerPath,
			"--crawl", write("truncated.json", crawlDoc("incomplete", "")),
			"--at", "2026-07-15T12:05:00Z"})
		if lb, _ := s["shadowLowerBound"].(bool); !lb {
			t.Errorf("shadow=%v reported as exact over a scope the crawl never "+
				"listed — expired credentials on one project render as \"no "+
				"unmanaged resources here\": %+v", s["shadow"], s)
		}
	})

	t.Run("no crawl at all lowers the bound", func(t *testing.T) {
		s := summaryOf(t, []string{"posture", "--ledger", ledgerPath,
			"--at", "2026-07-15T12:05:00Z"})
		if lb, _ := s["shadowLowerBound"].(bool); !lb {
			t.Errorf("posture with nothing swept claims an exact shadow count: %+v", s)
		}
	})

	// The control: a complete sweep still earns the exact claim through the same
	// path, or the field has stopped carrying information.
	t.Run("a complete sweep is still exact", func(t *testing.T) {
		s := summaryOf(t, []string{"posture", "--ledger", ledgerPath,
			"--crawl", write("complete.json", crawlDoc("complete",
				`{"providerId":"fake:orphan-1","resourceType":"capability.database.relational"}`)),
			"--at", "2026-07-15T12:05:00Z"})
		if lb, _ := s["shadowLowerBound"].(bool); lb {
			t.Errorf("a complete sweep must report an exact count: %+v", s)
		}
		if n, _ := s["shadow"].(float64); int(n) != 1 {
			t.Errorf("shadow = %v, want 1: %+v", s["shadow"], s)
		}
	})
}

// D652. The wiring, again: the classifier is unit-tested, but `classifyPosture` is
// where the marker had to be READ from the ledger and judged for freshness. A test
// aimed at Classify alone stays green with that block deleted.
func TestPostureReadsTheAbsenceMarkerThroughTheCLI(t *testing.T) {
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
	// A fresh observation that SATISFIES the contract's hard constraint, standing
	// beside a fresh absence marker. This is the shape the defect lives in:
	// observations are latest-per-path, so the audit still says satisfied.
	if err := w.Append("observation.recorded", []string{"db"}, map[string]any{
		"observations": []any{
			map[string]any{"path": "service.managed", "value": true,
				"observedAt": "2025-07-15T08:00:00Z", "ttlSeconds": 86400,
				"derivation": "measured", "source": "provider-api"},
			map[string]any{"path": "resource.absent", "value": true,
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
  hard:
    - { id: c-managed, subject: db, path: service.managed, op: equals, value: true,
        verify: { method: static } }
`), 0o600); err != nil {
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
	var class string
	for _, r := range rows {
		m, _ := r.(map[string]any)
		if pid, _ := m["providerId"].(string); pid == "fake:db-1" {
			class, _ = m["class"].(string)
		}
	}
	if class != "drifted" {
		t.Errorf("a resource the provider reports GONE is classified %q while its "+
			"hard constraint still reads satisfied from an observation recorded "+
			"beside the 404 — the marker is in the ledger and posture never read "+
			"it:\n%s", class, out)
	}
}

// D653. `--out` is how a scheduled run hands its document to whatever reads it
// next. Both writers swallowed every failure: `if err := os.MkdirAll(dir); err ==
// nil { _ = os.WriteFile(...) }`. Measured with a plain FILE sitting where the
// directory should be — exit 2 (the findings code), no error, no message, and
// nothing written. A cron then reads the previous run's document forever.
func TestOutDirectoryFailuresAreNotSwallowed(t *testing.T) {
	dir := t.TempDir()
	ledgerPath := filepath.Join(dir, "l.jsonl")
	if err := os.WriteFile(ledgerPath, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	// A regular file where --out names a directory: MkdirAll fails.
	blocker := filepath.Join(dir, "blocked")
	if err := os.WriteFile(blocker, []byte("in the way"), 0o600); err != nil {
		t.Fatal(err)
	}

	for _, verb := range []string{"posture", "react"} {
		t.Run(verb, func(t *testing.T) {
			args := []string{verb, "--ledger", ledgerPath, "--out", blocker,
				"--at", "2026-07-15T09:00:00Z"}
			if verb == "react" {
				args = append(args, "--provider", "fake")
			}
			var code int
			captureStdout(t, func() { code = run(args) })
			if code == 0 || code == 2 {
				t.Errorf("%s exited %d with --out unwritable: the document the "+
					"caller asked for does not exist and nothing said so", verb, code)
			}
		})
	}

	// The control: a writable --out still produces the file, or the check above is
	// satisfied by refusing every --out.
	t.Run("a writable out still writes", func(t *testing.T) {
		out := filepath.Join(dir, "good")
		captureStdout(t, func() {
			run([]string{"posture", "--ledger", ledgerPath, "--out", out,
				"--at", "2026-07-15T09:00:00Z"})
		})
		if _, err := os.Stat(filepath.Join(out, "posture.json")); err != nil {
			t.Errorf("posture.json was not written to a writable --out: %v", err)
		}
	})
}
