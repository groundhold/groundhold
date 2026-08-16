package provider_test

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// D1141. The release cross-builds four platforms and publishes a binary for each; the
// README tells the reader to swap one name for another. CI compiled ONE of them —
// darwin/arm64 — so linux/arm64 and darwin/amd64 were built nowhere until a tag was
// pushed, and a compile break on either would surface as a failed release rather than a
// failed pull request.
//
// The same closed set, in two workflow files, with nothing comparing them. It is named
// here rather than derived from either side, because a set taken from both would agree
// with itself no matter what either did — the shape D1130 found in the checksums and
// D1140 in the tool list.
func TestCIAndTheReleaseAgreeOnThePublishedPlatforms(t *testing.T) {
	skipIfExported(t, "the CI recipes")
	root := repoRoot(t)

	// What we publish. Changing this is a decision about what ships, and it has to be
	// made in three places at once — here, and in both workflows the gate checks.
	want := []string{"darwin/amd64", "darwin/arm64", "linux/amd64", "linux/arm64"}

	for _, f := range []struct{ file, what string }{
		{filepath.Join(".github", "workflows", "release.yml"), "the release cross-build"},
		{filepath.Join(".github", "workflows", "ci.yml"), "the CI cross-compile"},
	} {
		raw, err := os.ReadFile(filepath.Join(root, f.file))
		if err != nil {
			t.Fatal(err)
		}
		got := platformLoop(string(raw))
		if len(got) == 0 {
			t.Errorf("%s: no `for t in <os/arch> ...` loop found — the scan broke, or the "+
				"platform set moved somewhere this gate cannot see it (D328)", f.file)
			continue
		}
		if strings.Join(got, ",") != strings.Join(want, ",") {
			t.Errorf("%s (%s) builds %v; the published set is %v.\nA platform missing from "+
				"the release is one the README tells people to download and nobody produced; "+
				"a platform missing from CI is one whose first build attempt is the release "+
				"itself.", f.file, f.what, got, want)
		}
	}
}

// platformLoop returns the os/arch pairs of the first `for t in ...` loop, sorted.
// Anchored on the loop rather than on any os/arch text in the file: both workflows
// mention platform names in prose, and a substring scan would collect those too.
var platformLoopRe = regexp.MustCompile(`for t in ((?:[a-z0-9]+/[a-z0-9]+\s*)+);`)

func platformLoop(body string) []string {
	m := platformLoopRe.FindStringSubmatch(body)
	if m == nil {
		return nil
	}
	out := strings.Fields(m[1])
	sort.Strings(out)
	return out
}
