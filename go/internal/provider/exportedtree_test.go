package provider_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// D583. Three gates in a row have broken `make export-check` the same way: they read
// something the export does not ship, so they run in the public tree and fail there.
// D580 fixed the first by adding a skip to that one test. The two written the next
// two slices needed the same skip and did not get it — I fixed the instance and left
// the class, which is the mistake this project has a name for (D527, D550, D573:
// prose does not propagate, only a shared mechanism does).
//
// So this is the mechanism. A gate that reads repo-only material calls it first.
//
// D661: the signal is a MARKER the export writes, not the absence of `.git`. The
// absence test was wrong about the world: the publication target is a CLONE —
// export-public.sh explicitly keeps the destination's `.git`, and `actions/checkout`
// creates one on the mirror — so six gates ran in the public tree and failed on
// files the whitelist deliberately leaves behind, while `make export-check`
// certified a bare directory nobody ever publishes.
//
// Inferring a fact from an absence is the recurring class in this record. The
// export states it.
func isExportedTree(t *testing.T) bool {
	t.Helper()
	return exportedTreeAt(repoRoot(t))
}

// exportedTreeAt takes the root as an argument so the rule can be driven with BOTH
// shapes in one test — a marked tree that also has `.git` (the mirror) and an
// unmarked one that does not (a tarball of the private repo). The version that read
// `.git` could not be tested that way, which is why it stayed wrong.
func exportedTreeAt(root string) bool {
	_, err := os.Stat(filepath.Join(root, "PUBLIC_EXPORT"))
	return err == nil
}

// skipIfExported stops a private-tree gate from running in the published copy, and
// says which artefact it wanted, so a future reader can tell a deliberate skip from
// a silently disabled check.
func skipIfExported(t *testing.T, wants string) {
	t.Helper()
	if isExportedTree(t) {
		t.Skipf("exported tree (no .git): %s is private to the source repository, so "+
			"there is nothing here for this gate to check", wants)
	}
}

// The helper must not become a blanket "skip everywhere". The property is checked
// against a DIFFERENT signal than the one the helper uses — the presence of the
// private export script, rather than the presence of `.git` — so this is not the
// implementation restated. Where the private material IS present, the helper must
// say "not exported", or every gate calling it stops running and nothing says so.
//
// In the exported tree the script is absent and there is nothing to assert; the test
// says that rather than passing quietly, since "no private material here" is exactly
// the state a silently-disabled gate also produces.
func TestExportedTreeDetectionDoesNotSkipAPrivateTree(t *testing.T) {
	if _, err := os.Stat(filepath.Join(repoRoot(t), "scripts", "export-public.sh")); err != nil {
		t.Skip("no export script: this is the published copy, where skipping IS correct")
	}
	if isExportedTree(t) {
		t.Fatal("a tree carrying the private export script was detected as an export — " +
			"every gate calling skipIfExported would stop running, silently")
	}
}

// D661. The export used to be detected by the absence of `.git`, and the
// publication target is a CLONE — so the six gates that skip in the export ran in
// the public tree and failed on files the whitelist deliberately leaves behind,
// while `make export-check` certified a bare directory nobody publishes. This pins
// the two halves that must stay true together: a tree with the marker is the
// export, and a tree with the private script is not, WHATEVER either says about
// `.git`.
func TestExportDetectionSurvivesAGitDirectory(t *testing.T) {
	root := repoRoot(t)
	priv := filepath.Join(root, "scripts", "export-public.sh")
	if _, err := os.Stat(priv); err != nil {
		t.Skip("no export script: this is the published copy")
	}
	if _, err := os.Stat(filepath.Join(root, ".git")); err != nil {
		t.Skip("no .git here: nothing to distinguish")
	}
	// The private tree HAS .git and must not be read as an export.
	if isExportedTree(t) {
		t.Fatal("the private tree reads as an export")
	}

	// Both shapes, driven directly, because the mirror is the case that broke: a
	// marked tree WITH a repository is the export, and an unmarked tree WITHOUT one
	// is not.
	mirror := t.TempDir()
	if err := os.WriteFile(filepath.Join(mirror, "PUBLIC_EXPORT"),
		[]byte("exported"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(mirror, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	if !exportedTreeAt(mirror) {
		t.Error("a published tree that is a git clone — which every mirror is — was " +
			"not recognised as the export, so every private-only gate runs there " +
			"and fails on files the whitelist leaves behind")
	}
	tarball := t.TempDir() // the private repo copied without its history
	if exportedTreeAt(tarball) {
		t.Error("an unmarked tree with no .git was read as an export — that is the " +
			"old heuristic, and it skips every gate in a private working copy")
	}
	// And the marker is what the export writes: assert the script writes it, so a
	// published tree without one cannot appear (which would run every private gate
	// there, exactly the failure this entry fixes).
	raw, err := os.ReadFile(priv)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), "PUBLIC_EXPORT") {
		t.Error("export-public.sh no longer writes the marker — the published tree " +
			"would run every gate that reads scripts/, and fail all of them")
	}
}
