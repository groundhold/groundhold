package provider_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// D651. The export's negative-space audit is the control that keeps a client name
// out of the public tree. It ran `grep -r` over the export — which reads file
// CONTENTS. A denied term in a PATH crossed untouched:
//
//	examples/<client>-<internal-ip>/notes.md   ("A tiny note with no denied words inside.")
//	$ bash scripts/export-public.sh $DST
//	  ...  exported to …/expB          <- the deny audit PASSED
//
// A directory named after an engagement discloses the engagement; a repository
// listing shows the name before anyone opens a file.
//
// The audit is now its own script taking the denylist as an ARGUMENT, which is what
// makes this gate possible: it drives both arms with a harmless invented term, so
// it proves the control fires without a private name ever appearing in a Go test —
// and Go tests are exported, so a gate that spelled one out would itself be the
// leak (that has happened here once already, D606).
func TestTheExportDenyAuditCatchesPathsAndContents(t *testing.T) {
	skipIfExported(t, "the export scripts")
	script := filepath.Join(repoRoot(t), "scripts", "deny-audit.sh")
	if _, err := os.Stat(script); err != nil {
		t.Fatalf("the deny audit is gone: %v — the export's only negative-space "+
			"control cannot be missing", err)
	}
	const term = "zzdeniedterm" // invented here; never a real denied name

	run := func(t *testing.T, dir string) (int, string) {
		t.Helper()
		cmd := exec.Command("bash", script, dir, term)
		out, err := cmd.CombinedOutput()
		code := 0
		if ee, ok := err.(*exec.ExitError); ok {
			code = ee.ExitCode()
		} else if err != nil {
			t.Fatal(err)
		}
		return code, string(out)
	}

	t.Run("a clean tree passes", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "readme.md"),
			[]byte("nothing to see"), 0o600); err != nil {
			t.Fatal(err)
		}
		if code, out := run(t, dir); code != 0 {
			t.Errorf("a clean tree was refused (exit %d): %s", code, out)
		}
	})

	t.Run("a denied term in file contents is caught", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "readme.md"),
			[]byte("we worked with "+term+" last spring"), 0o600); err != nil {
			t.Fatal(err)
		}
		code, out := run(t, dir)
		if code == 0 {
			t.Errorf("a denied term in a file body was published: %s", out)
		}
		if !strings.Contains(out, "CONTENTS") {
			t.Errorf("the refusal does not say which arm fired: %s", out)
		}
	})

	t.Run("a denied term in a path is caught", func(t *testing.T) {
		dir := t.TempDir()
		sub := filepath.Join(dir, "examples", term+"-migration")
		if err := os.MkdirAll(sub, 0o755); err != nil {
			t.Fatal(err)
		}
		// Deliberately innocuous contents: the PATH is the whole disclosure.
		if err := os.WriteFile(filepath.Join(sub, "notes.md"),
			[]byte("A tiny note with no denied words inside."), 0o600); err != nil {
			t.Fatal(err)
		}
		code, out := run(t, dir)
		if code == 0 {
			t.Errorf("a directory named after a denied term was published with "+
				"clean contents: %s", out)
		}
		if !strings.Contains(out, "PATH") {
			t.Errorf("the refusal does not say which arm fired: %s", out)
		}
	})
}

// The audit must stay wired into the export, or the gate above proves a script
// nobody runs.
func TestTheExportStillRunsTheDenyAudit(t *testing.T) {
	skipIfExported(t, "the export scripts")
	raw, err := os.ReadFile(filepath.Join(repoRoot(t), "scripts", "export-public.sh"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), "deny-audit.sh") {
		t.Error("export-public.sh no longer calls the deny audit — the export has " +
			"no negative-space control at all")
	}
}
