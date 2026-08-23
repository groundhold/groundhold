package provider_test

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// D1234. `capability.cost.budget`'s vocabulary publishes a convention, in the
// attribute's own mapping text: "a timeGrain with no equivalent is named in a
// diagnostic, never coerced". It is the right rule — `budget.period` is a CLOSED enum
// of recurring periods, so a provider value outside it cannot be mapped and must not
// be guessed at.
//
// One of the three drivers honored it. AWS and GCP both wrote
//
//	if period := mapIt(raw); period != "" { emit(period) }
//
// with no else, so a value the mapping does not know produced NO observation AND NO
// diagnostic. To a reader that is indistinguishable from a budget with no period at
// all — the D513 silence, on an attribute whose whole job is to say what the limit
// recurs over. It needs no exotic input to happen: a new provider enum value, or GCP
// returning `CALENDAR_PERIOD_UNSPECIFIED` literally rather than omitting the field.
//
// WHAT THIS GATE IS AND IS NOT, stated because the first version overclaimed and a
// mutant proved it. It reads SOURCE, so it can only see that a branch is written
// beside the mapping call — `} else if false {` satisfies it, and did: the mutant that
// removed the AWS diagnostic survived this gate untouched. Structure is not behaviour.
//
// So the BEHAVIOUR is witnessed per cloud, by a test that serves an unmappable value
// and asserts the diagnostic names it:
//
//	aws    TestUnmappedBudgetTimeUnitIsDiagnosedNotDropped
//	gcp    TestUnmappedCalendarPeriodIsDiagnosedNotDropped
//	azure  TestUnmappedTimeGrainIsDiagnosedNotDropped
//
// What THIS gate adds, and the reason it stays: it is the one place that knows the
// convention applies to ALL THREE, so a fourth cloud arriving without a mapping site
// fails here rather than being noticed by nobody. It is a completeness check over the
// SET, not a proof about any member.
func TestEveryBudgetPeriodMappingDiagnosesAnUnmappedValue(t *testing.T) {
	root := filepath.Join("..", "..", "internal")
	// (package, file, the mapping function whose empty result must be diagnosed)
	sites := []struct{ pkg, file, fn string }{
		{"aws", "budgets_net.go", "budgetPeriodFromTimeUnit"},
		{"gcp", "billingbudget_net.go", "budgetPeriodFromCalendar"},
		{"azure", "consumptionbudget_net.go", "budgetPeriodFromTimeGrain"},
	}
	// D328: the subject must exist. A renamed file would otherwise make this gate
	// report a clean sweep over nothing.
	var checked int
	var bare []string
	for _, s := range sites {
		path := filepath.Join(root, s.pkg, s.file)
		blob, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v — if the file moved, move this gate with it rather than "+
				"dropping the site", path, err)
		}
		src := string(blob)
		if !strings.Contains(src, s.fn+"(") {
			t.Fatalf("%s no longer calls %s — the mapping was renamed or removed, and this "+
				"gate is now watching nothing", path, s.fn)
		}
		checked++
		// The shape: the `if period := <fn>(...)` guard must be followed by an else
		// that produces a diagnostic. Matched on the else-branch carrying the
		// not-mapped wording, so a bare `else {}` does not satisfy it.
		guard := regexp.MustCompile(`if period := ` + regexp.QuoteMeta(s.fn) +
			`\([^)]*\); period != "" \{(?s).{0,400}?\} else if`)
		if !guard.MatchString(src) {
			bare = append(bare, s.pkg+" ("+s.file+"): "+s.fn)
			continue
		}
		if !strings.Contains(src, "budget.period not mapped") {
			bare = append(bare, s.pkg+" ("+s.file+"): else-branch present but it does not "+
				"say the value was not mapped")
		}
	}
	if checked != len(sites) {
		t.Fatalf("checked %d of %d budget drivers", checked, len(sites))
	}
	sort.Strings(bare)
	if len(bare) > 0 {
		t.Errorf("%d budget driver(s) have no else-branch beside the period mapping:\n  %s\n\n"+
			"The vocabulary publishes the convention for this attribute (\"no equivalent is "+
			"named in a diagnostic, never coerced\"); silence reads as \"this budget has no "+
			"period\", a different fact. Add the branch AND a behavioural witness — this "+
			"check reads source and cannot tell a live branch from a dead one.",
			len(bare), strings.Join(bare, "\n  "))
	}

	// The behavioural witnesses are what actually hold the convention, so their absence
	// is a finding in itself: a cloud can otherwise pass the structural check above with
	// a branch nothing exercises.
	for pkg, name := range map[string]string{
		"aws":   "TestUnmappedBudgetTimeUnitIsDiagnosedNotDropped",
		"gcp":   "TestUnmappedCalendarPeriodIsDiagnosedNotDropped",
		"azure": "TestUnmappedTimeGrainIsDiagnosedNotDropped",
	} {
		if !packageDeclaresTest(t, filepath.Join(root, pkg), name) {
			t.Errorf("%s has no behavioural witness for an unmapped budget period (%s). The "+
				"structural check above is satisfied by a dead branch.", pkg, name)
		}
	}
}

// The convention this gate enforces must actually BE published — otherwise the gate is
// holding the drivers to a rule of its own invention, which is how a gate outlives the
// decision behind it.
func TestTheBudgetPeriodConventionIsPublished(t *testing.T) {
	blob, err := os.ReadFile(filepath.Join("..", "..", "..", "spec", "vocab",
		"capability.cost.budget.yaml"))
	if err != nil {
		t.Fatalf("read the budget vocabulary: %v", err)
	}
	src := string(blob)
	for _, must := range []string{"named in a diagnostic", "never coerced"} {
		if !strings.Contains(src, must) {
			t.Fatalf("the vocabulary no longer publishes %q — either restore it, or retire "+
				"the gate that enforces it; a gate must not outlive its decision", must)
		}
	}
}

// packageDeclaresTest reports whether any _test.go in dir declares the named test.
func packageDeclaresTest(t *testing.T, dir, name string) bool {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read %s: %v", dir, err)
	}
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		blob, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			t.Fatalf("read %s: %v", e.Name(), err)
		}
		if strings.Contains(string(blob), "func "+name+"(") {
			return true
		}
	}
	return false
}
