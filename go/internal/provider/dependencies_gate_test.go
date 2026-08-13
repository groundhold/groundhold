package provider_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// D475: "the runtime is stdlib + yaml only" is a claim, published in the README that
// crosses the export boundary, and nothing checked it.
//
// It is true today — the Go module requires exactly one module, and the reference
// implementation imports nothing outside the standard library and PyYAML. That is the
// point: it is a load-bearing property of the design (a verifier with no third-party
// surface is a verifier nobody has to audit transitively), it is easy to lose to a
// single convenient import, and losing it would falsify a sentence in the public README
// without failing anything.
//
// Same shape as every other finding in this session: a convention the project genuinely
// holds, stated in public, asserted nowhere.

var goRequire = regexp.MustCompile(`(?m)^\s*(?:require\s+)?([a-z0-9./-]+\.[a-z]{2,}/[^\s]+)\s+v[^\s]+`)

func TestGoRuntimeHasOneDependency(t *testing.T) {
	root := repoRoot(t)
	raw, err := os.ReadFile(filepath.Join(root, "go", "go.mod"))
	if err != nil {
		t.Fatal(err)
	}
	var mods []string
	for _, m := range goRequire.FindAllStringSubmatch(string(raw), -1) {
		mods = append(mods, m[1])
	}
	sort.Strings(mods)
	want := []string{"gopkg.in/yaml.v3"}
	if strings.Join(mods, ",") != strings.Join(want, ",") {
		t.Errorf("go.mod requires %v, want exactly %v\n"+
			"The README says the runtime is stdlib + yaml only, and that sentence crosses "+
			"the export boundary. A new dependency is not forbidden — but it makes a "+
			"published claim false, so it has to be a decision, not an import (D475).",
			mods, want)
	}
	if len(mods) == 0 {
		t.Fatal("no requires parsed — the gate would be vacuous (D328)")
	}
}

// TestPythonReferenceImportsStdlibOnly asks the interpreter what the standard library
// is rather than carrying a list that would rot. python3 is REQUIRED, not skipped:
// `make check` runs the Python reference through the whole conformance suite, so an
// environment without it cannot pass the gate anyway — and a gate that skips itself is
// how a property stops being checked without anyone deciding to stop checking it.
func TestPythonReferenceImportsStdlibOnly(t *testing.T) {
	root := repoRoot(t)
	out, err := exec.Command("python3", "-c",
		"import sys; print('\\n'.join(sorted(sys.stdlib_module_names)))").Output()
	if err != nil {
		t.Fatalf("python3 is required to derive the standard library: %v", err)
	}
	stdlib := map[string]bool{}
	for _, m := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		stdlib[strings.TrimSpace(m)] = true
	}
	if len(stdlib) < 100 {
		t.Fatalf("only %d stdlib modules — the gate would be vacuous (D328)", len(stdlib))
	}

	allowed := map[string]bool{"yaml": true, "groundholdlib": true}
	importRE := regexp.MustCompile(`(?m)^\s*(?:from\s+([a-zA-Z_][\w.]*)\s+import|import\s+([a-zA-Z_][\w.]*))`)

	var foreign []string
	var scanned int
	err = filepath.Walk(filepath.Join(root, "ref"), func(p string, info os.FileInfo, err error) error {
		if err != nil || info == nil || info.IsDir() || !strings.HasSuffix(p, ".py") {
			return nil
		}
		raw, rerr := os.ReadFile(p)
		if rerr != nil {
			return nil
		}
		scanned++
		rel, _ := filepath.Rel(root, p)
		for _, m := range importRE.FindAllStringSubmatch(string(raw), -1) {
			mod := m[1]
			if mod == "" {
				mod = m[2]
			}
			top := strings.SplitN(strings.TrimPrefix(mod, "."), ".", 2)[0]
			if top == "" || stdlib[top] || allowed[top] {
				continue
			}
			foreign = append(foreign, rel+": "+top)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if scanned < 5 {
		t.Fatalf("only %d python files scanned — the gate would be vacuous (D328)", scanned)
	}
	sort.Strings(foreign)
	if len(foreign) > 0 {
		t.Errorf("the reference implementation imports outside stdlib + PyYAML: %v\n"+
			"CLAUDE.md and the README both say stdlib + PyYAML only; a third-party import "+
			"in the VERIFIER is a transitive audit surface the design exists to avoid.",
			foreign)
	}
}
