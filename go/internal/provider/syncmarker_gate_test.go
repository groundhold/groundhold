package provider_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// D714: the sync refusal rests on the marker, so the marker must be written.
//
// `scripts/sync-public.sh` protects a merged community pull request by finding the
// commit that last wrote `.github/sync-source` and refusing when the public repository
// has commits after it. Remove the line in the exporter that writes that file and the
// refusal does not fail loudly — it silently decides every public tree is a first sync
// and stops refusing anything. A guard that disarms itself quietly is the shape this
// record keeps finding, so the two ends are held together here: one path, written by
// the exporter, read by the sync.
//
// Also checked: the marker is not under a gitignored directory. The first draft wrote
// it to `.groundhold/`, which is ignored AND excluded from the export — a record that
// would have existed on disk and never in the history.
func TestExportWritesTheSyncSourceMarker(t *testing.T) {
	root := repoRoot(t)
	exporter := filepath.Join(root, "scripts", "export-public.sh")
	raw, err := os.ReadFile(exporter)
	if os.IsNotExist(err) {
		t.Skip("export-public.sh is private-side only; this gate does not apply here")
	}
	if err != nil {
		t.Fatal(err)
	}
	sync, serr := os.ReadFile(filepath.Join(root, "scripts", "sync-public.sh"))
	if serr != nil {
		t.Fatalf("sync-public.sh is missing, so the refusal it carries is gone: %v", serr)
	}

	const marker = ".github/sync-source"
	if !strings.Contains(string(raw), marker) {
		t.Errorf("the exporter does not write %s — sync-public.sh then treats every "+
			"public tree as a first sync and stops refusing to overwrite a merged "+
			"contribution", marker)
	}
	if !strings.Contains(string(sync), marker) {
		t.Errorf("sync-public.sh does not read %s — its refusal has no subject", marker)
	}

	// The marker must be committable: a path the repository ignores would be written
	// and then dropped, and the refusal would rest on a file that never arrives.
	ignores, ierr := os.ReadFile(filepath.Join(root, ".gitignore"))
	if ierr == nil {
		for _, line := range strings.Split(string(ignores), "\n") {
			pat := strings.TrimSpace(line)
			if pat == "" || strings.HasPrefix(pat, "#") {
				continue
			}
			if strings.HasPrefix(marker, strings.TrimSuffix(pat, "/")+"/") {
				t.Errorf("%s sits under the ignored path %q — it would be written and "+
					"never committed", marker, pat)
			}
		}
	}
}
