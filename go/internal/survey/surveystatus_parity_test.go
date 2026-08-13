package survey

import (
	"os"
	"regexp"
	"sort"
	"testing"
)

// TestSurveyStatusesMatchTheProducedLiterals pins CoverageStatuses() and
// OrphanStatuses() to the status literals survey.go actually emits. The two
// functions are a SECOND enumeration of the same closed set the fold assigns
// inline (row.Status = "..." / OrphanRow{Status: "..."}), and a second copy that
// nobody compares is the one that drifts (D1025): a status added to the fold but
// not the function would leave the console's parity gate — which pins to the
// function — blind to it. This asserts the union of the two functions equals the
// set of literals the code assigns to a status.
func TestSurveyStatusesMatchTheProducedLiterals(t *testing.T) {
	src, err := os.ReadFile("survey.go")
	if err != nil {
		t.Fatalf("cannot read survey.go — a gate that loses its subject must fail (D565): %v", err)
	}
	// Every string literal assigned to a Status field or a status variable.
	re := regexp.MustCompile(`(?:Status\s*[:=]\s*|status\s*:?=\s*)"([a-z-]+)"`)
	produced := map[string]bool{}
	for _, m := range re.FindAllStringSubmatch(string(src), -1) {
		produced[m[1]] = true
	}
	if len(produced) < 5 {
		t.Fatalf("scanned only %d status literals — the probe broke (D328)", len(produced))
	}

	declared := map[string]bool{}
	for _, s := range append(CoverageStatuses(), OrphanStatuses()...) {
		declared[s] = true
	}

	var missing, extra []string
	for s := range produced {
		if !declared[s] {
			missing = append(missing, s) // emitted by the fold, absent from the functions
		}
	}
	for s := range declared {
		if !produced[s] {
			extra = append(extra, s) // in a function but the fold never emits it
		}
	}
	sort.Strings(missing)
	sort.Strings(extra)
	if len(missing) > 0 {
		t.Errorf("survey.go emits status(es) %v that CoverageStatuses()/OrphanStatuses() "+
			"do not list — the console parity gate pins to the functions and would be blind "+
			"to these, silently under-reporting", missing)
	}
	if len(extra) > 0 {
		t.Errorf("CoverageStatuses()/OrphanStatuses() list %v that survey.go never emits — "+
			"dead entries that read like coverage", extra)
	}
}
