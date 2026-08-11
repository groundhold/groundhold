package provider_test

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// D666. The boundary is pinned as arithmetic in internal/ledger. This pins that
// every SITE deciding freshness goes through it — the defect was not the formula,
// it was six copies of the formula with two of them different.
//
// A source read rather than a behavioural drive, deliberately and with its limits
// stated: driving all six verbs at three clock offsets needs a ledger, a provider
// and a contract per verb, and the boundary itself is already tested as arithmetic.
// What this catches is a SEVENTH copy appearing.
func TestNoSiteReinventsTheFreshnessComparison(t *testing.T) {
	skipIfExported(t, "the source tree")
	root := repoRoot(t)

	// Any comparison of an age against a TTL that is not the shared predicate.
	handRolled := regexp.MustCompile(
		`(?:TTLSeconds\s*(?:<=|>=|<|>)|\+\s*r?e?c?\.?TTLSeconds\s*(?:<=|>=|<|>))`)
	allowed := map[string]string{
		// The predicate itself, and the two the spec grandfathers: apply's
		// change-level re-check and the compiler's operand step both carry their own
		// per-attribute skip conditions around the same comparison.
		"internal/ledger/ledger.go":     "the shared predicate",
		"internal/apply/apply.go":       "re-checks each change's own record (D632)",
		"internal/compiler/compiler.go": "stalenessRefusal + the operand step",
		"internal/audit/audit.go":       "verdict-level freshness",
		"internal/forecast/forecast.go": "prediction-level freshness",
	}
	var offenders []string
	err := filepath.Walk(filepath.Join(root, "go"), func(p string, fi os.FileInfo, err error) error {
		if err != nil || fi.IsDir() || !strings.HasSuffix(p, ".go") ||
			strings.HasSuffix(p, "_test.go") {
			return err
		}
		rel, _ := filepath.Rel(filepath.Join(root, "go"), p)
		if _, ok := allowed[rel]; ok {
			return nil
		}
		raw, rerr := os.ReadFile(p)
		if rerr != nil {
			return rerr
		}
		for i, line := range strings.Split(string(raw), "\n") {
			if strings.Contains(line, "//") {
				continue
			}
			if handRolled.MatchString(line) {
				offenders = append(offenders,
					rel+":"+strings.TrimSpace(line)+" (line "+itoa(i+1)+")")
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(allowed) < 4 {
		t.Fatal("the allow-list collapsed — this gate would flag everything or nothing")
	}
	for _, o := range offenders {
		t.Errorf("a hand-rolled freshness comparison: %s\n"+
			"Use ledger.ObservationExpired — six copies of this formula is how "+
			"posture and refresh came to disagree with audit by one second.", o)
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}
