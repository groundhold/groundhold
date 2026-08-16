package survey

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// D1119. spec/survey.md was the last spec file no test opened. Unlike the four before
// it, nothing in it was wrong: the status vocabulary matches the runtime, the drift
// predicate (uncovered, and orphaned only under --complete) is asserted by the package's
// own tests, and the status literals are already pinned to the two enumerating functions
// (D1025). This gate closes the sweep rather than fixing a defect, and says so.
//
// What it adds is the one binding that was missing — the DOCUMENT to the runtime. The
// status vocabulary is written in three places: the spec's prose, CoverageStatuses(),
// and OrphanStatuses(). The existing gate pins the second and third to the literals the
// fold assigns. Nothing compared any of them to the published page a reader uses to
// interpret a report.
//
// The classification is what a reader routes on: `gap` is "a question for a human,
// never silent drift", `witnessed-by-type` is "information, never drift". A status that
// existed in the runtime and not the page would arrive in a report nobody could look
// up; one on the page and not in the runtime is a promise of a distinction that is
// never drawn.
func TestSurveyStatusVocabularyMatchesTheSpec(t *testing.T) {
	want := map[string]bool{
		"covered": true, "uncovered": true, "gap": true, "ignored": true,
		"orphaned": true, "unwitnessed": true, "witnessed-by-type": true,
	}

	runtime := map[string]bool{}
	for _, s := range append(CoverageStatuses(), OrphanStatuses()...) {
		runtime[s] = true
	}
	diffStatuses(t, "the runtime's status vocabulary", runtime, want)

	root, err := filepath.Abs(filepath.Join("..", "..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(root, "spec", "survey.md"))
	if err != nil {
		t.Skipf("no survey spec here: %v", err)
	}
	// The page marks each status in bold where it defines it. Reading the definition
	// markup rather than every lowercase word: prose around it names capabilities,
	// verbs and flags, and a word-shape match would sweep those in (D1115).
	published := map[string]bool{}
	for _, m := range regexp.MustCompile(`\*\*([a-z][a-z-]+)\*\*`).FindAllStringSubmatch(string(raw), -1) {
		published[m[1]] = true
	}
	if len(published) < 5 {
		t.Fatalf("found %d bold-defined statuses in spec/survey.md — the page changed "+
			"shape and this gate would pass on anything (D328)", len(published))
	}
	diffStatuses(t, "spec/survey.md's published vocabulary", published, want)
}

// The drift predicate, stated as the spec states it: only two statuses are drift, and
// one of them only under --complete. The package's own tests cover the behaviour; this
// asserts the SET, so adding a status cannot quietly join or leave it.
func TestOnlyTwoStatusesAreDrift(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", "..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(root, "spec", "survey.md"))
	if err != nil {
		t.Skipf("no survey spec here: %v", err)
	}
	sentence := regexp.MustCompile(`(?s)Exit 0 clean; exit 2 with .code: survey-drift. when(.*?)Exit 1`).
		FindStringSubmatch(string(raw))
	if sentence == nil {
		t.Fatal("spec/survey.md no longer states the exit contract in the form this gate " +
			"reads — the sentence that says WHICH statuses are drift is the whole claim")
	}
	for _, must := range []string{"uncovered", "orphaned", "complete"} {
		if !strings.Contains(sentence[1], must) {
			t.Errorf("the published exit contract no longer mentions %q: %q", must, sentence[1])
		}
	}
	for _, mustNot := range []string{"gap", "ignored", "witnessed-by-type", "unwitnessed"} {
		if strings.Contains(sentence[1], mustNot) {
			t.Errorf("the published exit contract now names %q as drift. Each of these is "+
				"documented as information — a question for a human, or evidence that "+
				"cannot settle which capability it witnessed. Turning one into drift "+
				"turns a clean estate red.", mustNot)
		}
	}
}

func diffStatuses(t *testing.T, what string, got, want map[string]bool) {
	t.Helper()
	var missing, extra []string
	for v := range want {
		if !got[v] {
			missing = append(missing, v)
		}
	}
	for v := range got {
		if !want[v] {
			extra = append(extra, v)
		}
	}
	sort.Strings(missing)
	sort.Strings(extra)
	if len(missing) > 0 {
		t.Errorf("%s is missing: %s", what, strings.Join(missing, ", "))
	}
	if len(extra) > 0 {
		t.Errorf("%s carries unexpected: %s", what, strings.Join(extra, ", "))
	}
}
