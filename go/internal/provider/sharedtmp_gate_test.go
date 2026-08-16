package provider_test

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// D1146. Jobs on the self-hosted pool share a machine with other repositories — the
// install step in the release says so itself, which is why it puts the binary it
// installs under the runner's own temp directory rather than somewhere global.
//
// The same reasoning had not been applied to where things are FETCHED. The release
// downloaded a pinned tool to `/tmp` at a name derived from the version, checksummed it
// there, extracted it there and installed from there. The pin and the SHA-256 are the
// control; verifying a file at an address another tenant can rewrite between the check
// and the use is the one arrangement that makes both decorative. A rebuild used for the
// reproducibility comparison sat at a predictable `/tmp` path too — plant bytes there
// after the build and a non-reproducible release compares equal to itself.
//
// The rule: a step that does not run on a GitHub-hosted runner writes under RUNNER_TEMP.
// Hosted runners are single-tenant and disposable, so the rule is about the fleet; the
// hosted labels are public knowledge and named here, and everything else is treated as
// shared — the same direction the fork-runner gate reads it (D713), and for the same
// reason: this file is exported and the pool's label is not ours to publish.
func TestNoSharedPoolStepWritesToAFixedTempPath(t *testing.T) {
	skipIfExported(t, "the CI recipes")
	root := repoRoot(t)
	files, err := filepath.Glob(filepath.Join(root, ".github", "workflows", "*.yml"))
	if err != nil {
		t.Fatal(err)
	}
	if len(files) < 5 {
		t.Fatalf("only %d workflows found — the scan broke (D328)", len(files))
	}

	hosted := func(s string) bool {
		return strings.Contains(s, "ubuntu-") || strings.Contains(s, "macos-") ||
			strings.Contains(s, "windows-")
	}
	// `/tmp/` in a command, not in a comment: prose about temp paths is not a write.
	writesTmp := regexp.MustCompile(`(^|[^#\n])[^#\n]*[\s"']/tmp/`)

	checked := 0
	var bad []string
	for _, f := range files {
		raw, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		var doc struct {
			Jobs map[string]struct {
				RunsOn string `yaml:"runs-on"`
				Steps  []struct {
					Name string `yaml:"name"`
					Run  string `yaml:"run"`
				} `yaml:"steps"`
			} `yaml:"jobs"`
		}
		if err := yaml.Unmarshal(raw, &doc); err != nil {
			continue // a matrix expression this shape cannot hold; the fleet gate reads those
		}
		for job, spec := range doc.Jobs {
			if spec.RunsOn == "" || hosted(spec.RunsOn) {
				continue
			}
			checked++
			for _, st := range spec.Steps {
				for _, line := range strings.Split(st.Run, "\n") {
					if strings.HasPrefix(strings.TrimSpace(line), "#") {
						continue
					}
					if writesTmp.MatchString(line) {
						bad = append(bad, filepath.Base(f)+" / "+job+" / "+st.Name+
							": "+strings.TrimSpace(line))
					}
				}
			}
		}
	}
	if checked == 0 {
		t.Fatal("no job on the shared fleet found — either every job moved to hosted " +
			"runners, or the scan stopped understanding `runs-on` and this gate is " +
			"measuring nothing (D328)")
	}
	sort.Strings(bad)
	if len(bad) > 0 {
		t.Errorf("steps on the shared fleet writing to a fixed /tmp path:\n  %s\n"+
			"That machine is shared with other repositories. A predictable path is one "+
			"another tenant can create, replace or read — and where the path holds "+
			"something that was just verified, it separates the check from the use. "+
			"Use ${RUNNER_TEMP}, which is per-job.", strings.Join(bad, "\n  "))
	}
}
