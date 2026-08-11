package provider_test

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// D600. The conformance suite is this project's source of truth — CI says so, the
// README says so, and every delivery manifest quotes its tally. Two things were true
// of the harness that runs it:
//
//  1. `conformance/run.py` had no floor. With `conformance/cases/` moved away it
//     printed "0/0 conformance cases passed" and exited 0, so `make check` reported
//     "all gates passed" having verified nothing. That is D328 (a gate that finds
//     nothing passes) standing at the top of the pyramid rather than in a corner.
//
//  2. `run_show_case_cli` accumulated its failures into `fails` and then fell off the
//     end of the function without returning them. It is annotated `-> list[str]`; it
//     returned None, which the runner reads as "no failures". Both of its checks —
//     the byte-for-byte golden comparison and the forbidden-token scan — were dead.
//     Measured: replacing the derived plan order with input order (exactly what
//     `plan-order-is-derived-not-input-order` is named for) passed 516/516 before the
//     fix and fails after it.
//
// This gate covers the SHAPE of (2) rather than the one function: every runner that
// promises a list of failures must end by returning one. Asked of the source through
// Python's own parser, not matched with a regex — an accumulator dropped on any
// terminal path is invisible to text search.
func TestNoConformanceRunnerDropsItsFailures(t *testing.T) {
	root := repoRoot(t)
	runner := filepath.Join(root, "conformance", "run.py")
	if _, err := os.Stat(runner); err != nil {
		t.Skipf("no conformance runner here: %v", err)
	}

	out, err := exec.Command("python3", "-c", `
import ast, json, sys

tree = ast.parse(open(sys.argv[1]).read())
bad, seen = [], 0
for fn in [n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)]:
    if not fn.name.startswith("run_"):
        continue
    ann = getattr(fn, "returns", None)
    if not (ann and "str" in ast.unparse(ann)):
        continue
    seen += 1
    last = fn.body[-1]
    # A runner may end in a return, a raise, or a loop/branch whose every arm does.
    def terminal(node):
        if isinstance(node, (ast.Return, ast.Raise)):
            return True
        if isinstance(node, ast.If):
            return bool(node.orelse) and terminal(node.body[-1]) and terminal(node.orelse[-1])
        if isinstance(node, (ast.With, ast.Try)):
            return terminal(node.body[-1])
        return False
    if not terminal(last):
        bad.append(f"{fn.name} (line {fn.lineno})")
print(json.dumps({"seen": seen, "bad": bad}))
`, runner).Output()
	if err != nil {
		t.Fatalf("could not parse the conformance runner — this gate must not pass "+
			"without an answer (D565): %v", err)
	}

	var got struct {
		Seen int      `json:"seen"`
		Bad  []string `json:"bad"`
	}
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatal(err)
	}
	if got.Seen == 0 {
		t.Fatal("found no case runners to check in conformance/run.py — the gate " +
			"would be vacuous (D328)")
	}
	if len(got.Bad) > 0 {
		t.Errorf("these conformance runners can fall off the end and return None, "+
			"which the harness reads as PASS: %v\n"+
			"They are annotated as returning a failure list; every terminal path must "+
			"return one, or their assertions are decoration.", got.Bad)
	}
}

// The floor itself. Removing it is the mutation that matters, so the gate reads the
// two guards out of the runner and requires both to refuse rather than warn.
func TestConformanceRunnerRefusesAnEmptySuite(t *testing.T) {
	root := repoRoot(t)
	raw, err := os.ReadFile(filepath.Join(root, "conformance", "run.py"))
	if err != nil {
		t.Skipf("no conformance runner here: %v", err)
	}
	src := string(raw)

	for _, guard := range []struct{ name, needle string }{
		{"a floor on the number of case FILES found", "len(case_files) < MIN_CASE_FILES"},
		{"a floor on the number of cases COLLECTED", "total < MIN_CASES"},
	} {
		if !strings.Contains(src, guard.needle) {
			t.Errorf("conformance/run.py no longer carries %s (%q).\n"+
				"Without it a moved directory, a broken glob or an over-eager filter "+
				"produces a green tally over nothing, and `make check` calls that "+
				"'all gates passed'.", guard.name, guard.needle)
		}
	}
	for _, floor := range []string{"MIN_CASE_FILES", "MIN_CASES"} {
		if !strings.Contains(src, floor+" = ") {
			t.Errorf("%s is not defined in conformance/run.py", floor)
		}
	}
}

// D601. An `expect` block written one level too deep is read by nothing: the runner
// asks the step mapping for a sibling `expect`, gets nothing, and asserts only what
// remains — usually "the verb exited 0". Four attest cases were in that shape, so a
// report with forged provenance (`selfVerified: 999`, zero invalid envelopes, the
// anchor erased) passed all 518 conformance cases AND every Go test. `attest` is the
// verb the console reads and the one D139 calls the honesty core.
//
// The runner now refuses such a case at collection time. This gate asks the runner's
// own walker rather than re-implementing it, so the two cannot drift apart.
//
// D605 adds the second half: a suite may DECLARE the expectation keys its cases must
// carry (`requireExpect:`), for the field the suite exists to defend. Three
// reachability cases named "...-has-nothing-to-probe" asserted only exit and status,
// so a probe claiming "reachable" over zero derived targets passed all three.
func TestNoConformanceCaseHidesItsExpectations(t *testing.T) {
	root := repoRoot(t)
	if _, err := os.Stat(filepath.Join(root, "conformance", "run.py")); err != nil {
		t.Skipf("no conformance runner here: %v", err)
	}

	out, err := exec.Command("python3", "-c", `
import glob, importlib.util, json, os, sys, yaml

root = sys.argv[1]
spec = importlib.util.spec_from_file_location("r", os.path.join(root, "conformance", "run.py"))
mod = importlib.util.module_from_spec(spec); spec.loader.exec_module(mod)

files = sorted(glob.glob(os.path.join(root, "conformance", "cases", "*.yaml")))
hits = []
for f in files:
    doc = yaml.safe_load(open(f))
    hits += mod.find_misnested_expectations(doc, os.path.basename(f))
    hits += mod.find_missing_required_expectations(doc, os.path.basename(f))
print(json.dumps({"files": len(files), "hits": hits}))
`, root).Output()
	if err != nil {
		t.Fatalf("could not ask the runner to check its own case shapes (D565): %v", err)
	}
	var got struct {
		Files int      `json:"files"`
		Hits  []string `json:"hits"`
	}
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatal(err)
	}
	if got.Files == 0 {
		t.Fatal("no case files were walked — the gate would be vacuous (D328)")
	}
	for _, h := range got.Hits {
		t.Errorf("a case assertion is unreachable: %s", h)
	}
}
