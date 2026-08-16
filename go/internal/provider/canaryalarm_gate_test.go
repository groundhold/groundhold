package provider_test

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// D1133. The canaries are the only thing that can see a provider change its mind,
// and each has a triage step that classifies a red run and opens an issue. The
// condition on that step was `failure() && steps.canary.outcome == 'failure'`.
//
// It never matched what actually went wrong. When a SETUP step dies — authentication,
// a repository variable that was never set — the canary step is SKIPPED, and a skipped
// step's outcome is not 'failure'. So across 739 scheduled runs on three clouds, not
// one of which has ever succeeded, triage did not run once and no issue was ever
// opened. The alarm was blind to precisely the state in which we are blind.
//
// The property is not "handle skipped" — that is the bug restated. It is that the
// alarm covers every way the canary can fail to produce a verdict, so the condition
// must be written against SUCCESS, the one outcome that needs no alarm.
func TestTheCanaryAlarmCoversEveryWayItCanFailToRun(t *testing.T) {
	skipIfExported(t, "the cloud canaries")
	root := repoRoot(t)

	found, err := filepath.Glob(filepath.Join(root, ".github", "workflows", "canary-*.yml"))
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(found)
	// Named, not derived: a glob that matched nothing would satisfy every assertion
	// below (D328), and the set of clouds we canary is a fact worth stating.
	want := []string{"canary-aws.yml", "canary-azure.yml", "canary-gcp.yml"}
	var got []string
	for _, f := range found {
		got = append(got, filepath.Base(f))
	}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("canary workflows are %v, expected %v — the set changed and this gate "+
			"is measuring something other than what it names", got, want)
	}

	for _, f := range found {
		raw, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		name := filepath.Base(f)
		cond, body := triageStep(string(raw))
		if cond == "" {
			t.Errorf("%s has no Triage step with a condition — a canary that goes red "+
				"with nothing watching is the state this gate exists to prevent", name)
			continue
		}
		if !strings.Contains(cond, "!= 'success'") {
			t.Errorf("%s triages on %q. Written against one failure shape, it misses the "+
				"others: a setup step dying leaves the canary SKIPPED, which is not "+
				"'failure', and that is the state in which we learn nothing at all. "+
				"Condition on success, the only outcome needing no alarm.", name, cond)
		}
		if strings.Contains(cond, "== 'failure'") {
			t.Errorf("%s triages only when the canary itself failed: %q", name, cond)
		}
		// Reaching the step is not the same as the step knowing what to do there.
		if !strings.Contains(body, `!= "failure"`) {
			t.Errorf("%s runs triage for a canary that never ran, but has no branch for "+
				"it — it would fall through to a classifier reading a result file that "+
				"was never written, and report the absence as unclassified", name)
		}
	}
}

// triageStep returns the `if:` condition and the run body of the Triage step.
// It anchors on the step NAME rather than searching the file, because these
// workflows carry several conditions and several run blocks.
func triageStep(body string) (cond, run string) {
	lines := strings.Split(body, "\n")
	for i, line := range lines {
		if strings.TrimSpace(line) != "- name: Triage" {
			continue
		}
		for _, l := range lines[i+1:] {
			trimmed := strings.TrimSpace(l)
			if strings.HasPrefix(trimmed, "if:") {
				cond = strings.TrimSpace(strings.TrimPrefix(trimmed, "if:"))
			}
			// The next step at the same indentation ends this one.
			if strings.HasPrefix(trimmed, "- name:") {
				break
			}
			run += l + "\n"
		}
		return cond, run
	}
	return "", ""
}
