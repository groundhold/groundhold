package provider_test

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// D386. The directive is that this repository buys no GitHub-hosted CI minutes.
// That is a property of every job in every workflow, and it was true only because
// someone had checked each one by hand — which is exactly how it stops being true.
//
// A hosted `runs-on:` is allowed here in precisely two shapes, and the point of
// each is that the job cannot consume this organisation's minutes by itself:
//
//   - GATED TO THE PUBLIC MIRROR, by owner or by repository visibility. The mirror
//     has its own healthy budget. `portability-darwin` lives here: there is no
//     self-hosted darwin, the mirror's ci.yml is EXPORTED FROM THIS ONE, and
//     deleting the job to honour the directive would have removed darwin coverage
//     from the only repository that still has it.
//   - MANUAL ONLY (`workflow_dispatch` and nothing else). Nothing fires it but a
//     person clicking, who is choosing to spend at that moment.
//
// Anything else is a job that will quietly bill on the next push.
// This is a policy of THIS repository, not of the software. The public mirror buys
// its own hosted minutes deliberately — that is the whole reason darwin still runs
// somewhere — so downstream every job is legitimately hosted and this gate would
// fail on eleven of them for doing the right thing. The exporter's presence is the
// marker for "private side", the same one D385 uses.
func TestNoWorkflowSpendsHostedMinutesUnasked(t *testing.T) {
	root := repoRoot(t)
	if _, err := os.Stat(filepath.Join(root, "scripts", "export-public.sh")); os.IsNotExist(err) {
		t.Skip("hosted-minutes policy is private-side only; the mirror buys its own")
	}
	files, err := filepath.Glob(filepath.Join(root, ".github", "workflows", "*.yml"))
	if err != nil {
		t.Fatalf("glob workflows: %v", err)
	}
	if len(files) < 5 {
		t.Fatalf("only %d workflows found — the scope broke, not the workflows", len(files))
	}

	type job struct {
		RunsOn any    `yaml:"runs-on"`
		If     string `yaml:"if"`
	}
	type workflow struct {
		On   any            `yaml:"on"`
		Jobs map[string]job `yaml:"jobs"`
	}

	// A hosted label is anything GitHub provides. Self-hosted pool names are
	// deliberately NOT listed (D385: this file is exported); the test is written
	// the other way round — it recognises the hosted labels, which are public
	// knowledge, and treats everything else as the fleet.
	hosted := func(v any) bool {
		s, ok := v.(string)
		if !ok {
			return false // a matrix expression: read the label out of the matrix
		}
		return strings.HasPrefix(s, "ubuntu-") || strings.HasPrefix(s, "macos-") ||
			strings.HasPrefix(s, "windows-")
	}

	var offenders []string
	for _, f := range files {
		raw, err := os.ReadFile(f)
		if err != nil {
			t.Fatalf("read %s: %v", f, err)
		}
		var wf workflow
		if err := yaml.Unmarshal(raw, &wf); err != nil {
			t.Fatalf("parse %s: %v", filepath.Base(f), err)
		}

		// Manual-only: `on:` is exactly workflow_dispatch, however it is spelled.
		manualOnly := false
		switch on := wf.On.(type) {
		case string:
			manualOnly = on == "workflow_dispatch"
		case []any:
			manualOnly = len(on) == 1 && on[0] == "workflow_dispatch"
		case map[string]any:
			_, ok := on["workflow_dispatch"]
			manualOnly = ok && len(on) == 1
		}

		for name, j := range wf.Jobs {
			if !hosted(j.RunsOn) {
				continue
			}
			if manualOnly {
				continue
			}
			// Gated to the mirror: by owner, or by the repository being public.
			cond := j.If
			if strings.Contains(cond, "repository_owner") ||
				strings.Contains(cond, "repository.visibility") ||
				strings.Contains(cond, "repository_visibility") {
				continue
			}
			offenders = append(offenders,
				filepath.Base(f)+": job "+name+" (runs-on: "+j.RunsOn.(string)+")")
		}
	}
	if len(offenders) > 0 {
		sort.Strings(offenders)
		t.Errorf("%d job(s) can spend this organisation's GitHub-hosted minutes on an "+
			"ordinary push — gate them to the public mirror or make them manual:\n  %s",
			len(offenders), strings.Join(offenders, "\n  "))
	}
}
