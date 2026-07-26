package main

import (
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// captureStderr runs fn with os.Stderr redirected to a pipe and returns what it
// wrote. Provider-branch refusals and banners land on stderr.
func captureStderr(t *testing.T, fn func()) string {
	t.Helper()
	orig := os.Stderr
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	os.Stderr = w
	done := make(chan string, 1)
	go func() {
		b, _ := io.ReadAll(r)
		done <- string(b)
	}()
	fn()
	w.Close()
	os.Stderr = orig
	return <-done
}

const azQueueContract = `apiVersion: contract/v0.1
kind: InfrastructureContract
meta: { id: azq, environment: dev, version: 1 }
capabilities: [{ id: q, type: capability.messaging.queue }]
constraints:
  hard:
    - { id: r, subject: q, path: location.region, op: equals, value: eastus, verify: { method: static } }
`

const azQueueCandidate = `apiVersion: candidate/v0.1
kind: ImplementationCandidate
contract: azq
capabilities:
  q:
    provider: azure
    service: servicebusqueue
    attributes: { location.region: eastus, service.managed: true }
    implementation: { resource_group: rg1 }
`

// TestApplyReachesAzureBranch pins the executor wiring for Azure: `apply
// --provider azure` must REACH the azure driver branch, not fall through the
// inner switch to "unknown provider". We prove it ARM-free by compiling a plan
// WITHOUT a pinned subscription (no --project) so the azure branch refuses at its
// own D28 identity check — a message only the azure branch emits — before any
// network call. A regression that drops azure from the apply switch turns this
// into "unknown provider" and fails the test.
func TestApplyReachesAzureBranch(t *testing.T) {
	dir := t.TempDir()
	at := "2026-07-23T00:00:00Z"
	c := writeFile(t, dir, "c.yaml", azQueueContract)
	cand := writeFile(t, dir, "cand.yaml", azQueueCandidate)

	// compile WITHOUT --project -> reads.provider.project is empty.
	out := captureStdout(t, func() {
		if rc := run([]string{"plan", c, cand, "--provider", "azure", "--at", at}); rc != 0 {
			t.Fatalf("plan --provider azure exited %d", rc)
		}
	})
	if !json.Valid([]byte(out)) {
		t.Fatalf("plan stdout is not pure JSON (cannot pin apply):\n%s", out)
	}
	planFile := writeFile(t, dir, "plan.json", out)

	var code int
	stderr := captureStderr(t, func() {
		code = run([]string{"apply", c, cand, planFile, "--provider", "azure",
			"--at", at, "--yes", "--ledger", filepath.Join(dir, "l")})
	})
	if strings.Contains(stderr, "unknown provider") {
		t.Fatalf("apply dropped azure to the inner default (executor not wired):\n%s", stderr)
	}
	if code != 1 || !strings.Contains(stderr, "the azure subscription") {
		t.Fatalf("apply did not reach the azure D28 identity check: exit=%d\n%s", code, stderr)
	}
}

// TestObserveAcceptsAzure pins that `observe --provider azure` constructs the
// azure driver rather than refusing with "unknown provider". observe needs no
// pinned subscription (the providerId carries it), so an empty ledger reaches the
// driver and returns cleanly without touching ARM.
func TestObserveAcceptsAzure(t *testing.T) {
	dir := t.TempDir()
	at := "2026-07-23T00:00:00Z"
	led := filepath.Join(dir, "led.ndjson")
	if err := os.WriteFile(led, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	stderr := captureStderr(t, func() {
		run([]string{"observe", "--provider", "azure", "--ledger", led, "--at", at})
	})
	if strings.Contains(stderr, "unknown provider") {
		t.Fatalf("observe dropped azure to the inner default:\n%s", stderr)
	}
}
