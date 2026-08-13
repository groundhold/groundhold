package survey

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// surveyStatusParitySHA256 pins the shared survey-status parity fixture. The SAME
// file and constant live in the console
// (proviso-console/internal/server/surveystatus_parity_test.go). The console's
// surveyDigest folds these statuses into a portfolio count and cannot import this
// package across the repo split, so it gates its handling against this fixture;
// this test proves the fixture is EXACTLY CoverageStatuses()/OrphanStatuses(), so
// a status added here fails the fixture until it is copied, which then fails the
// console build until surveyDigest classifies it (D1024).
const surveyStatusParitySHA256 = "fc1835d9fee1fb5ab083e59b1b3367f4991be99f84b4228e7ae0711922ad4108"

func TestSurveyStatusFixtureIsTheContract(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "surveystatus_parity.json"))
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(raw)
	if got := hex.EncodeToString(sum[:]); got != surveyStatusParitySHA256 {
		t.Fatalf("survey-status fixture sha256 = %s, pinned = %s — regenerate the constant "+
			"here AND in the console", got, surveyStatusParitySHA256)
	}
	var doc struct {
		Coverage []string `json:"coverage"`
		Orphan   []string `json:"orphan"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("fixture is not valid JSON: %v", err)
	}
	sameSet(t, "coverage", doc.Coverage, CoverageStatuses())
	sameSet(t, "orphan", doc.Orphan, OrphanStatuses())
}

func sameSet(t *testing.T, label string, fixture, live []string) {
	t.Helper()
	inFix := map[string]bool{}
	for _, s := range fixture {
		inFix[s] = true
	}
	inLive := map[string]bool{}
	for _, s := range live {
		inLive[s] = true
	}
	if len(inFix) == 0 || len(inLive) == 0 {
		t.Fatalf("%s: an input set is empty — the gate would be vacuous (D328)", label)
	}
	for s := range inLive {
		if !inFix[s] {
			t.Errorf("%s: the runtime produces %q but the fixture omits it — the console "+
				"would not know to classify a status the survey emits", label, s)
		}
	}
	for s := range inFix {
		if !inLive[s] {
			t.Errorf("%s: the fixture lists %q which the runtime no longer produces — stale", label, s)
		}
	}
}
