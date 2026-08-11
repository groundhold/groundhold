package provider_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// D606. The three canaries are the only thing that runs against real clouds on a
// schedule, and their contract is that every assertion produces a VERDICT — ok,
// provider-drift, groundhold-regression or infra-flake. An assertion that cannot find
// its subject emits infra-flake; that is how "we could not ask" stays distinguishable
// from "we asked and it was fine".
//
// One assertion broke the contract by omission. `canary-gcp.sh` reads a Cloud Run
// service id out of the ledger with a regex and then does
//
//	if [ -n "${SVC:-}" ]; then …verdict… fi
//
// with no `else`. When the providerId spelling drifts, SVC is empty, the getIamPolicy
// route is never asked about, NO verdict line is written, and the canary exits all
// green. Reproduced by the audit with the same injected provider fault and only the
// ledger spelling changed: exit 10 and a drift verdict with one spelling, exit 0 and
// six verdicts (no drift-C) with the other.
//
// The gate is structural because the failure is an ABSENCE of code: a guard that wraps
// a verdict must have an else. Anything else is a check that can disappear.
func TestNoCanaryAssertionCanVanish(t *testing.T) {
	// The canaries spend real money against real accounts and are stripped from the
	// public export (export-public.sh removes their workflows for exactly that
	// reason), so in an exported tree there is nothing here to check. Written without
	// this the gate failed `make export-check` — the D583 lesson, in a gate I wrote
	// while citing D583.
	skipIfExported(t, "the cloud canaries")
	root := repoRoot(t)
	scripts, err := filepath.Glob(filepath.Join(root, "scripts", "canary-*.sh"))
	if err != nil {
		t.Fatal(err)
	}
	if len(scripts) < 3 {
		t.Fatalf("found %d canary scripts, expected at least 3 — the scope broke, not "+
			"the canaries (D328)", len(scripts))
	}

	guard := regexp.MustCompile(`^(\s*)if \[ -n "\$\{[A-Za-z_][A-Za-z0-9_]*:-\}" \]; then\s*$`)
	for _, path := range scripts {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		lines := strings.Split(string(raw), "\n")
		name := filepath.Base(path)
		guards := 0

		for i, line := range lines {
			m := guard.FindStringSubmatch(line)
			if m == nil {
				continue
			}
			indent := m[1]
			guards++

			hasVerdict, hasElse := false, false
			for j := i + 1; j < len(lines); j++ {
				cur := lines[j]
				if cur == indent+"fi" {
					break
				}
				if cur == indent+"else" {
					hasElse = true
				}
				if strings.Contains(cur, "verdict ") {
					hasVerdict = true
				}
			}
			if hasVerdict && !hasElse {
				t.Errorf("%s:%d — a guarded block emits a verdict but has no `else`.\n"+
					"When the guard is false the assertion produces NOTHING: no verdict, "+
					"no counter, and the run exits green having never asked. Emit "+
					"infra-flake instead, the way every other assertion here does.",
					name, i+1)
			}
		}
		if guards == 0 && name == "canary-gcp.sh" {
			t.Errorf("%s no longer contains a `-n` guard — either the shape changed and "+
				"this gate must be re-taught, or it is now checking nothing", name)
		}
	}
}

// D606. `scripts/adopt-candidate.sh` generates a contract from what discover OBSERVED
// and its header promises adoption "confirms every declared attribute against the same
// reality groundhold measured". With an empty observation list it generated a contract
// with zero constraints, adopted it, and printed `adopted` — a confirmation of
// nothing, in confident words. `discover` appends a resource with whatever the driver
// returned, empty included, so this input is reachable by construction.
func TestAdoptCandidateRefusesAnEmptyObservationSet(t *testing.T) {
	root := repoRoot(t)
	script := filepath.Join(root, "scripts", "adopt-candidate.sh")
	if _, err := os.Stat(script); err != nil {
		t.Skipf("no adopt-candidate script here: %v", err)
	}

	dir := t.TempDir()
	disc := filepath.Join(dir, "discovery.json")
	if err := os.WriteFile(disc, []byte(`{"apiVersion":"discovery/v0",
	  "kind":"DiscoveryDocument","at":"2026-07-31T08:00:00Z",
	  "resources":[{"providerId":"sql:eu-central-1:widgets",
	                "resourceType":"database","observations":[]}]}`), 0o644); err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command("bash", script,
		"--discovery", disc, "--resource", "sql:eu-central-1:widgets",
		"--contract", "widgets", "--capability", "db",
		"--ledger", filepath.Join(dir, "l.ndjson"), "--at", "2026-07-15T08:00:00Z")
	// The guard must fire before anything is executed, so the binary is never needed.
	cmd.Env = append(os.Environ(), "GROUNDHOLD=/bin/false")
	out, err := cmd.CombinedOutput()

	if err == nil {
		t.Fatalf("the script accepted a resource with no observed attributes and "+
			"reported success:\n%s", out)
	}
	if !strings.Contains(string(out), "NO observed attributes") {
		t.Errorf("the refusal does not say what is missing:\n%s", out)
	}
	if strings.Contains(string(out), "adopted:") {
		t.Errorf("the script still printed an adoption:\n%s", out)
	}
}
