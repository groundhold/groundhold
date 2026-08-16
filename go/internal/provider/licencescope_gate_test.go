package provider_test

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// D1124. The project is dual-licensed and says so in three prose places: the README,
// the published versioning page, and the open-source plan. Apache 2.0 for `spec/`,
// `conformance/` and `ref/` — the trust interface anyone may implement against — and
// MPL 2.0 for `go/`, the runtime, whose file-level copyleft is the whole point of
// choosing it.
//
// Nothing in the TREE carried that split. The root held `LICENSE` (Apache, verbatim)
// and `LICENSE-runtime` (MPL, verbatim); neither states what it covers, and there were
// no SPDX headers. The mapping existed only in sentences.
//
// The consequence is measurable rather than theoretical: GitHub reports the repository
// as Apache-2.0, because that is the root licence and GitHub reports exactly one.
// Dependency scanners read that API. Someone embedding the runtime on the strength of
// the badge takes MPL-covered code believing it is Apache — a mistake the reader cannot
// discover from the artefact they consulted.
//
// The fix is conventional and small: the MPL text now sits at `go/LICENSE`, beside the
// code it covers, where a directory-walking tool finds it. The badge still says
// Apache-2.0 and always will; the versioning page now says why, because a lossy summary
// is only safe when the reader knows it is one.
func TestEveryLicensedTreeCarriesItsLicence(t *testing.T) {
	root := repoRoot(t)

	// The two licences, identified by their own first line rather than by filename.
	for _, c := range []struct{ path, want string }{
		{"LICENSE", "Apache License"},
		{"LICENSE-runtime", "Mozilla Public License"},
		{filepath.Join("go", "LICENSE"), "Mozilla Public License"},
	} {
		raw, err := os.ReadFile(filepath.Join(root, c.path))
		if err != nil {
			t.Errorf("%s is missing: %v\n\nThe runtime tree must carry its own licence — "+
				"the root badge reports one licence for a dual-licensed repository, and "+
				"a consumer walking directories has nothing else to go on.", c.path, err)
			continue
		}
		if !strings.Contains(string(raw), c.want) {
			t.Errorf("%s does not contain %q — the file was replaced with a different "+
				"licence", c.path, c.want)
		}
	}

	// The runtime's copy must be the SAME text as the one the project publishes, not a
	// paraphrase or an older revision that quietly grants different terms.
	a, errA := os.ReadFile(filepath.Join(root, "LICENSE-runtime"))
	b, errB := os.ReadFile(filepath.Join(root, "go", "LICENSE"))
	if errA == nil && errB == nil && string(a) != string(b) {
		t.Error("go/LICENSE and LICENSE-runtime differ. Two copies of one licence that " +
			"disagree is worse than one copy: a consumer reads whichever they find first.")
	}

	// The page must keep warning that the badge is a lossy summary. Without that
	// sentence the tree is correct and the artefact most consumers read is not.
	page, err := os.ReadFile(filepath.Join(root, "website", "pages", "versioning.md"))
	if err != nil {
		t.Skipf("no versioning page here: %v", err)
	}
	if !regexp.MustCompile(`(?i)badge`).Match(page) {
		t.Error("the versioning page no longer explains that the repository badge shows " +
			"one licence for a dual-licensed tree. GitHub reports Apache-2.0; the runtime " +
			"is MPL; a dependency scanner reading the API sees only the badge.")
	}
}
