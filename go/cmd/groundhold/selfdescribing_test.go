package main

import (
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"testing"
)

// captureStdout runs fn with os.Stdout redirected to a pipe and returns what
// it wrote. The self-describing verbs print their machine payload to stdout
// (banners go to stderr), so this isolates the JSON contract the console reads.
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	orig := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	os.Stdout = w
	done := make(chan string, 1)
	go func() {
		b, _ := io.ReadAll(r)
		done <- string(b)
	}()
	fn()
	w.Close()
	os.Stdout = orig
	return <-done
}

func writeFile(t *testing.T, dir, name, body string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
	return p
}

// TestDiffJSONIsSelfDescribing pins that `groundhold diff --json` carries the
// identity the console keys on (specVersion + contract + both environments)
// alongside the DiffResult delta. Without it a dashboard cannot attribute a
// diff to a contract/environment without re-deriving identity.
func TestDiffJSONIsSelfDescribing(t *testing.T) {
	dir := t.TempDir()
	a := writeFile(t, dir, "a.yaml", `apiVersion: contract/v0.1
kind: InfrastructureContract
meta: { id: orders, environment: dev, version: 1 }
constraints:
  hard:
    - { id: c-private }
capabilities:
  - { id: db }
`)
	b := writeFile(t, dir, "b.yaml", `apiVersion: contract/v0.1
kind: InfrastructureContract
meta: { id: orders, environment: prod, version: 1 }
constraints:
  hard:
    - { id: c-private }
    - { id: c-encrypted }
capabilities:
  - { id: db }
`)

	out := captureStdout(t, func() {
		if rc := runDiff([]string{"diff", a, b}, true); rc != 0 {
			t.Fatalf("runDiff rc=%d", rc)
		}
	})

	var got map[string]any
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("diff output is not JSON: %v\n%s", err, out)
	}
	if got["specVersion"] != "contract/v0.1" {
		t.Errorf("specVersion: got %v, want contract/v0.1", got["specVersion"])
	}
	if got["contract"] != "orders" {
		t.Errorf("contract: got %v, want orders", got["contract"])
	}
	// same meta.id in both -> contractB omitted
	if _, ok := got["contractB"]; ok {
		t.Errorf("contractB should be omitted when ids match, got %v", got["contractB"])
	}
	if got["environmentA"] != "dev" {
		t.Errorf("environmentA: got %v, want dev", got["environmentA"])
	}
	if got["environmentB"] != "prod" {
		t.Errorf("environmentB: got %v, want prod", got["environmentB"])
	}
	// the DiffResult delta must still be present and unchanged
	if _, ok := got["aSubsetOfB"]; !ok {
		t.Error("aSubsetOfB (DiffResult field) missing from wrapped output")
	}
	if _, ok := got["hardOnlyInB"]; !ok {
		t.Error("hardOnlyInB (DiffResult field) missing from wrapped output")
	}
}

// TestDiffJSONEmitsContractBWhenIdsDiffer pins that a diff across two
// differently-named contracts carries both ids.
func TestDiffJSONEmitsContractBWhenIdsDiffer(t *testing.T) {
	dir := t.TempDir()
	a := writeFile(t, dir, "a.yaml", `apiVersion: contract/v0.1
kind: InfrastructureContract
meta: { id: orders, environment: prod }
`)
	b := writeFile(t, dir, "b.yaml", `apiVersion: contract/v0.1
kind: InfrastructureContract
meta: { id: workforce, environment: prod }
`)

	out := captureStdout(t, func() {
		if rc := runDiff([]string{"diff", a, b}, true); rc != 0 {
			t.Fatalf("runDiff rc=%d", rc)
		}
	})
	var got map[string]any
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("not JSON: %v\n%s", err, out)
	}
	if got["contract"] != "orders" || got["contractB"] != "workforce" {
		t.Errorf("expected contract=orders contractB=workforce, got %v / %v",
			got["contract"], got["contractB"])
	}
}

// TestForecastJSONIsSelfDescribing pins that `groundhold forecast --json` carries
// specVersion + environment at the top level (mirrors cost/diff) while keeping
// its predictive body intact.
func TestForecastJSONIsSelfDescribing(t *testing.T) {
	dir := t.TempDir()
	// Plan + candidate lifted from conformance/cases/forecast.yaml
	// (forecast-will-create-with-provenance); the candidateHash is pinned.
	plan := writeFile(t, dir, "plan.yaml", `apiVersion: plan/v0
kind: SealedPlan
plan:
  contract: h1
  environment: test
  reads:
    contractHash: "sha256:bfff9f8d1d7ec677f64bfff6ee56531855dcdc1be576ab4cb306fb6ff719275c"
    candidateHash: "sha256:eb5959117c0065812904b828078b0b1672bf6e99e7d2b724529b8ff61a1df2b8"
    heads: { db: genesis }
    toolchain: { compiler: groundhold-ref/0.1, spec: contract/v0.1 }
  writes: [db]
  actions:
    - id: a-create
      capability: db
      operation: create
      target: cloudsql.instance/primary
      idempotencyKey: db-create-1
      risk:
        reversibility: R2
        dataLoss: none
        downtime: none
        securityExposure: none
        costDelta: { amount: 100, currency: EUR }
        identityReplacement: false
  preconditions:
    - type: report-executable
`)
	cand := writeFile(t, dir, "candidate.yaml", `apiVersion: candidate/v0.1
kind: ImplementationCandidate
contract: h1
capabilities:
  db:
    attributes:
      engine.protocol: postgresql/16.4
      recovery.rpo: 5m
`)

	out := captureStdout(t, func() {
		if rc := runForecast(plan, cand, "", "", "", "",
			"2026-07-11T12:00:00Z"); rc != 0 {
			t.Fatalf("runForecast rc=%d", rc)
		}
	})

	var got map[string]any
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("forecast output is not JSON: %v\n%s", err, out)
	}
	if got["specVersion"] != "contract/v0.1" {
		t.Errorf("specVersion: got %v, want contract/v0.1", got["specVersion"])
	}
	if got["environment"] != "test" {
		t.Errorf("environment: got %v, want test", got["environment"])
	}
	// the predictive body must be untouched
	body, ok := got["forecast"].(map[string]any)
	if !ok {
		t.Fatalf("forecast body missing/typed wrong: %v", got["forecast"])
	}
	if body["contract"] != "h1" {
		t.Errorf("forecast.contract: got %v, want h1", body["contract"])
	}
	if _, ok := body["actions"]; !ok {
		t.Error("forecast.actions missing — predictive body was altered")
	}
}
