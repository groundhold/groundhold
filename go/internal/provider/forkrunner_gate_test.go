package provider_test

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// D713: a workflow a FORK can trigger must not run on the self-hosted fleet.
//
// `ci.yml`, `lint.yml` and `security.yml` all trigger on `pull_request` and every job
// in them ran on the private self-hosted pool — a persistent machine with our network
// and our disk. On a PUBLIC repository that means a stranger's first PR executes their
// code there. The repo is private today, so nothing was exposed; the point is that
// opening it would have been one settings flip, with no line of code changing and
// nothing saying a word.
//
// D383 moved this pool to self-hosted deliberately (the org's Actions budget hit 100%),
// which is right for a private repo and wrong for a public one — and GitHub-hosted
// runners are free for public repositories, so the fix costs nothing exactly where it
// is needed.
//
// The pool's LABEL is never written here. This file is exported; the exporter is not,
// so a gate that spelled the label out would be the disclosure it exists to prevent —
// which the export audit said, about this very file, on its first run. The pattern is
// read from the exporter's own denylist, the same way the neighbouring estate gate
// does it.
//
// The rule: in a workflow reachable by `pull_request`, every `runs-on` is either a
// GitHub-hosted label or the guard expression that routes FORK pull requests to a
// hosted runner and keeps the fleet for same-repo pushes.
func TestNoForkTriggerableWorkflowRunsOnTheSelfHostedFleet(t *testing.T) {
	root := repoRoot(t)
	dir := filepath.Join(root, ".github", "workflows")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Skip("no workflows in this tree")
	}

	// The one spelling of the guard. Repeated per job by design — a `needs` edge on
	// every job to share one output would reshape the DAG for a five-second lookup —
	// so this gate is what keeps the copies honest.
	const guard = "github.event.pull_request.head.repo.full_name != github.repository"
	pool := buildEstatePatterns(t, root) // the labels, read from the exporter
	runsOn := regexp.MustCompile(`runs-on:\s*(.+)`)

	checked, prTriggered := 0, 0
	var bad []string
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".yml") {
			continue
		}
		raw, rerr := os.ReadFile(filepath.Join(dir, e.Name()))
		if rerr != nil {
			t.Fatal(rerr)
		}
		body := string(raw)
		checked++
		// `pull_request:` at the trigger level — not `pull_request_target`, which is a
		// different (and worse) thing this project does not use.
		if !regexp.MustCompile(`(?m)^\s{2}pull_request:\s*$`).MatchString(body) {
			continue
		}
		prTriggered++
		for _, m := range runsOn.FindAllStringSubmatch(body, -1) {
			line := strings.TrimSpace(m[1])
			if !pool.MatchString(line) {
				continue // a hosted label is fine
			}
			if !strings.Contains(line, guard) {
				bad = append(bad, e.Name()+": runs-on "+line)
			}
		}
	}
	if checked < 5 || prTriggered < 2 {
		t.Fatalf("scanned %d workflows, %d fork-triggerable — the scan broke and this "+
			"gate would pass over an exposed one (D328)", checked, prTriggered)
	}
	if len(bad) > 0 {
		t.Errorf("workflows a fork PR can trigger, running on the self-hosted fleet:\n  %s\n"+
			"A stranger's PR would execute on that machine the moment this repository "+
			"becomes public. Select the runner instead:\n"+
			"  runs-on: ${{ (github.event_name == 'pull_request' && %s) && 'ubuntu-latest' "+
			"|| '<the pool label from the exporter denylist>' }}",
			strings.Join(bad, "\n  "), guard)
	}
}
