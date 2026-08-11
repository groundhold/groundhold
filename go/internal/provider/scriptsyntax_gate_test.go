package provider_test

import (
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// D582. The release-critical scripts — `export-public.sh`, `preship.sh`,
// `mutation-gate.sh`, the canaries — are invoked by hand or by one Makefile target
// nobody runs before committing (D580). A syntax error in any of them surfaces at the
// worst possible moment: the release, or the publish.
//
// `bash -n` and `py_compile` cost milliseconds and catch the whole class of rot. All
// ten scripts parse today; this keeps it that way from inside the gate everyone runs,
// which is the argument D580 already made about the cheap half of a slow check.
//
// It does NOT claim the scripts WORK — only that they can be read. Saying so matters:
// a green parse over a script whose logic broke is precisely the false comfort this
// project keeps finding, and the honest limit is stated rather than implied.
func TestShippedScriptsParse(t *testing.T) {
	skipIfExported(t, "the release and publication scripts")
	root := repoRoot(t)
	sh, err := filepath.Glob(filepath.Join(root, "scripts", "*.sh"))
	if err != nil {
		t.Fatal(err)
	}
	py, err := filepath.Glob(filepath.Join(root, "scripts", "*.py"))
	if err != nil {
		t.Fatal(err)
	}
	if len(sh)+len(py) < 5 {
		t.Fatalf("found %d scripts — the probe broke and this gate would pass on "+
			"anything", len(sh)+len(py))
	}

	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skipf("no bash here — the shell scripts are UNCHECKED, not proven fine: %v", err)
	}
	checked := 0
	for _, s := range sh {
		checked++
		if out, err := exec.Command(bash, "-n", s).CombinedOutput(); err != nil {
			t.Errorf("%s does not parse: %v\n%s", filepath.Base(s), err,
				strings.TrimSpace(string(out)))
		}
	}

	py3, err := exec.LookPath("python3")
	if err != nil {
		t.Skipf("no python3 here — the python scripts are UNCHECKED: %v", err)
	}
	for _, p := range py {
		// compile() rather than py_compile: py_compile writes the .pyc NEXT TO THE
		// SOURCE regardless of the working directory, so the first version of this
		// gate reproduced D581 — a check leaving an artifact in the tree — while
		// checking for exactly that class. compile() parses and writes nothing.
		checked++
		cmd := exec.Command(py3, "-c",
			"import sys; compile(open(sys.argv[1]).read(), sys.argv[1], 'exec')", p)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Errorf("%s does not parse: %v\n%s", filepath.Base(p), err,
				strings.TrimSpace(string(out)))
		}
	}
	// D582: count what was actually PARSED, not what was found. A loop that runs
	// zero times over a healthy tree passes silently — the mutation meter proved it
	// by emptying this range and surviving. A gate must be able to fail when it
	// stops doing its work, not only when its subject is bad.
	if checked < len(sh)+len(py) {
		t.Errorf("parsed %d of %d scripts — the gate skipped some of its own subject",
			checked, len(sh)+len(py))
	}
	if checked < 5 {
		t.Errorf("parsed only %d scripts — this run proved nothing", checked)
	}
}
