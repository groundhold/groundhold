package provider_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// D581. Running every Makefile target that `make check` does NOT (D580's lesson:
// verify the tip with all the instruments, not the default one), `make cover` left
// `go/cover.out` behind — 2.1 MB, untracked, and not in `.gitignore`. `git add -A`
// commits it, permanently, and the memory of this project already records that
// `-A` sweeps up files nobody meant to include.
//
// Nothing was broken; this is the kind of thing that becomes permanent quietly, in
// one careless commit, and cannot be removed from history afterwards.
//
// The rule is derived rather than restated: every path the Makefile writes with
// `-coverprofile=` or `-o` must be ignored, or live under a temp directory. A target
// added later with a new artifact fails this until its output is declared (D550 —
// a list beside a generator falls behind the generator).
func TestMakefileArtifactsAreIgnored(t *testing.T) {
	skipIfExported(t, "git check-ignore and the full Makefile")
	root := repoRoot(t)
	raw, err := os.ReadFile(filepath.Join(root, "Makefile"))
	if err != nil {
		t.Fatal(err)
	}
	re := regexp.MustCompile(`(?:-coverprofile=|-o )([^\s'"$]+)`)
	seen := map[string]bool{}
	for _, m := range re.FindAllStringSubmatch(string(raw), -1) {
		p := m[1]
		if strings.HasPrefix(p, "/tmp/") || strings.HasPrefix(p, "$") {
			continue // a temp path is nobody's working tree
		}
		seen[p] = true
	}
	if len(seen) < 2 {
		t.Fatalf("found %d artifact paths in the Makefile — the probe broke and this "+
			"gate would pass on anything", len(seen))
	}
	for p := range seen {
		// paths are written relative to go/ (the Makefile cds there)
		rel := filepath.Clean(filepath.Join("go", p))
		cmd := exec.Command("git", "-C", root, "check-ignore", "-q", rel)
		if err := cmd.Run(); err != nil {
			t.Errorf("`make` writes %s and .gitignore does not cover it — `git add -A` "+
				"commits a build artifact, and history keeps it", rel)
		}
	}
}
