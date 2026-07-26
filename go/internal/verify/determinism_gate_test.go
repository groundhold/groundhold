package verify_test

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"groundhold/internal/scalars"
)

// D327: invariant 6 ("the verifier stays deterministic — no LLM calls, no network,
// no heuristics inside the verification core") had no machine check.
//
// It is the load-bearing claim of the whole thesis: probabilistic proposal,
// DETERMINISTIC verification. Every other invariant is about what a verdict means;
// this one is about whether a verdict is reproducible at all. It held — checked, it
// holds today in both implementations — but it held by care, and care is what the
// D306/D309/D311 debts showed erodes. A stated invariant with no gate is one
// refactor away from being false, and this is the one whose falsity would be
// hardest to notice: nothing fails, verdicts just stop being reproducible.
//
// The gate walks the verification core's import closure inside the module and
// refuses any package that can make a verdict depend on something other than its
// inputs.
var forbidden = map[string]string{
	"net":         "network access — a verdict must not depend on reachability",
	"net/http":    "network access — a verdict must not depend on reachability",
	"net/url":     "network access — a verdict must not depend on reachability",
	"os/exec":     "subprocesses — a verdict must not depend on what is installed",
	"math/rand":   "randomness — a verdict must be reproducible",
	"crypto/rand": "randomness — a verdict must be reproducible",
	"time":        "wall-clock — the evaluation clock is an INPUT (N1), never read here",
}

// coreRoots are the packages a verdict is computed from. A driver is deliberately
// absent: pulling one in would drag the network into the core by transitivity.
var coreRoots = []string{
	"groundhold/internal/verify",
	"groundhold/internal/scalars",
	"groundhold/internal/contract",
	"groundhold/internal/canonical",
	"groundhold/internal/vocab",
}

func TestVerificationCoreIsDeterministic(t *testing.T) {
	root := goRoot(t)
	seen := map[string]bool{}
	var walk func(pkg string, from string)
	walk = func(pkg, from string) {
		if seen[pkg] {
			return
		}
		seen[pkg] = true
		dir := filepath.Join(root, strings.TrimPrefix(pkg, "groundhold/"))
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatalf("%s (imported by %s): %v", pkg, from, err)
		}
		for _, e := range entries {
			if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") ||
				strings.HasSuffix(e.Name(), "_test.go") {
				continue
			}
			for _, imp := range importsOf(t, filepath.Join(dir, e.Name())) {
				if why, bad := forbidden[imp]; bad {
					t.Errorf("%s imports %q — %s\n(reached from %s; invariant 6: the "+
						"verification core must compute a verdict from its inputs alone)",
						pkg, imp, why, from)
				}
				if strings.HasPrefix(imp, "groundhold/") {
					walk(imp, pkg)
				}
			}
		}
	}
	for _, r := range coreRoots {
		walk(r, "(root)")
	}
	if len(seen) < len(coreRoots) {
		t.Fatalf("the walk visited %d packages — the closure did not resolve", len(seen))
	}
}

// The Python reference is the other half of the dual verifier, and CLAUDE.md states
// the same rule for it by name. Text-level, because the point is the same: nothing
// in the reference may reach outside its inputs.
func TestPythonReferenceIsDeterministic(t *testing.T) {
	dir := filepath.Join(filepath.Dir(goRoot(t)), "ref", "groundholdlib")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read %s: %v", dir, err)
	}
	banned := regexp.MustCompile(`^\s*(?:import|from)\s+(socket|http|urllib|requests|subprocess|random|secrets)\b`)
	found := 0
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".py") {
			continue
		}
		found++
		raw, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		for i, line := range strings.Split(string(raw), "\n") {
			if m := banned.FindStringSubmatch(line); m != nil {
				t.Errorf("ref/groundholdlib/%s:%d imports %q — the reference verifier "+
					"must be deterministic too (invariant 6)", e.Name(), i+1, m[1])
			}
		}
	}
	if found == 0 {
		t.Fatal("no .py files found — the gate would be vacuous")
	}
}

func goRoot(t *testing.T) string {
	t.Helper()
	// internal/verify -> internal -> go
	abs, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	return abs
}

func importsOf(t *testing.T, path string) []string {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	src := string(raw)
	var out []string
	if m := regexp.MustCompile(`(?s)\nimport \((.*?)\n\)`).FindStringSubmatch(src); m != nil {
		for _, line := range strings.Split(m[1], "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "//") {
				continue
			}
			if i := strings.Index(line, `"`); i >= 0 {
				if j := strings.Index(line[i+1:], `"`); j >= 0 {
					out = append(out, line[i+1:i+1+j])
				}
			}
		}
	}
	for _, m := range regexp.MustCompile(`\nimport "([^"]+)"`).FindAllStringSubmatch(src, -1) {
		out = append(out, m[1])
	}
	sort.Strings(out)
	return out
}

// D327: invariant 4 ("closed operator set") must be closed the same way in BOTH
// implementations. The Python reference derives its accepted set from the
// implemented one (`VALID_OPS = set(OPERATORS) | PRESENCE_OPERATORS`); Go used to
// hand-list a copy, whose drift mode is a crash — an operator accepted at load but
// absent from `scalars.Operators` makes the map lookup a nil function that verify
// calls directly. Go derives it now too; this pins that the two agree.
func TestOperatorSetsAgreeAcrossImplementations(t *testing.T) {
	goOps := map[string]bool{}
	for name := range scalars.Operators {
		goOps[name] = true
	}
	for _, p := range []string{"exists", "absent"} {
		goOps[p] = true
	}

	raw, err := os.ReadFile(filepath.Join(filepath.Dir(goRoot(t)), "ref", "groundholdlib", "scalars.py"))
	if err != nil {
		t.Fatal(err)
	}
	src := string(raw)
	pyOps := map[string]bool{}
	block := regexp.MustCompile(`(?s)OPERATORS\s*=\s*\{(.*?)\n\}`).FindStringSubmatch(src)
	if block == nil {
		t.Fatal("could not find OPERATORS in ref/groundholdlib/scalars.py")
	}
	for _, m := range regexp.MustCompile(`"([a-z-]+)"\s*:`).FindAllStringSubmatch(block[1], -1) {
		pyOps[m[1]] = true
	}
	pres := regexp.MustCompile(`PRESENCE_OPERATORS\s*=\s*\{([^}]*)\}`).FindStringSubmatch(src)
	if pres == nil {
		t.Fatal("could not find PRESENCE_OPERATORS in ref/groundholdlib/scalars.py")
	}
	for _, m := range regexp.MustCompile(`"([a-z-]+)"`).FindAllStringSubmatch(pres[1], -1) {
		pyOps[m[1]] = true
	}

	var onlyGo, onlyPy []string
	for op := range goOps {
		if !pyOps[op] {
			onlyGo = append(onlyGo, op)
		}
	}
	for op := range pyOps {
		if !goOps[op] {
			onlyPy = append(onlyPy, op)
		}
	}
	sort.Strings(onlyGo)
	sort.Strings(onlyPy)
	if len(onlyGo) > 0 || len(onlyPy) > 0 {
		t.Errorf("the closed operator set differs between implementations — a "+
			"contract legal in one is illegal in the other (D25)\n  Go only:     %v\n"+
			"  Python only: %v", onlyGo, onlyPy)
	}
	if len(goOps) == 0 {
		t.Fatal("no operators found — the gate would be vacuous")
	}
}
