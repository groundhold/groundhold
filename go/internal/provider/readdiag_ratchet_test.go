package provider_test

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// D297: the "unreadable" debt is a RATCHET, not a claim of completion.
//
// D295/D296 converted the read paths where the failure cause was lost on every
// branch, and D295's own scope claim had to be corrected once (the per-function
// measure flattered it; the honest unit is the per-branch expression). What is
// left is real and large — a driver can still answer "unreadable" without the
// status on hundreds of branches — and it will be paid down service by service.
//
// The risk with a long mechanical debt is not that it stays; it is that it
// GROWS while being paid down, because nothing stops a new driver from copying
// the old shape. So this gate records the count per cloud and fails when it
// goes UP. It deliberately did not fail on the current number while the debt
// was large: a gate that demands perfection today would be turned off tomorrow,
// and a turned-off gate protects nothing.
//
// The debt is now PAID: every remaining mention of the word lives in prose
// (comments explaining this very history), so the baselines are zero and the
// gate has become an invariant — a driver may no longer say "unreadable"
// without naming the status or building a typed read error.
//
// Lowering a baseline is the point. Raising one requires editing this file,
// which is exactly the conversation worth forcing.
var bareUnreadableBaseline = map[string]int{
	"aws":   0,
	"azure": 0,
	"gcp":   0,
}

// bareUnreadable matches an expression that says "unreadable" while carrying
// neither an HTTP status nor a constructed read error — the shape that leaves
// an operator with no way to tell a throttle from a permission gap.
var bareUnreadable = regexp.MustCompile(`"[^"]*unreadable[^"]*"`)

// The gate measures CODE, not commentary: a comment that describes the debt (or
// the design that ended it) is documentation, and counting it would either
// freeze the prose or force a baseline that no longer means anything.
func isComment(line string) bool {
	return strings.HasPrefix(strings.TrimSpace(line), "//")
}

func TestBareUnreadableDoesNotGrow(t *testing.T) {
	for cloud, budget := range bareUnreadableBaseline {
		dir := filepath.Join("..", cloud)
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatalf("read %s: %v", dir, err)
		}
		count, worst, scanned := 0, "", 0
		for _, e := range entries {
			if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") ||
				strings.HasSuffix(e.Name(), "_test.go") {
				continue
			}
			raw, err := os.ReadFile(filepath.Join(dir, e.Name()))
			if err != nil {
				t.Fatalf("read %s: %v", e.Name(), err)
			}
			scanned++
			for _, line := range strings.Split(string(raw), "\n") {
				if !bareUnreadable.MatchString(line) || isComment(line) {
					continue
				}
				// a line that names the status, or builds a typed read error,
				// is already diagnosable — those are the converted shapes.
				if strings.Contains(line, "%d") ||
					strings.Contains(line, "readHTTP") ||
					strings.Contains(line, "armReadError") {
					continue
				}
				count++
				if worst == "" {
					worst = e.Name() + ": " + strings.TrimSpace(line)
				}
			}
		}
		if scanned == 0 {
			// D328: zero files scanned means the ratchet is measuring nothing — it
			// would report "down to 0" and read as a debt fully paid.
			t.Fatalf("%s: scanned ZERO driver files — the ratchet measured nothing "+
				"and would report the debt as paid", cloud)
		}
		switch {
		case count > budget:
			t.Errorf("%s: %d bare \"unreadable\" expressions, budget %d — a NEW one was "+
				"added. A read that produced nothing must name its cause (status + the "+
				"provider's own code); see internal/azure/armread.go and "+
				"internal/aws/awsread.go for the shape. First offender: %s",
				cloud, count, budget, worst)
		case count < budget:
			t.Logf("%s: down to %d (budget %d) — lower the baseline in this file to lock it in",
				cloud, count, budget)
		}
	}
}
