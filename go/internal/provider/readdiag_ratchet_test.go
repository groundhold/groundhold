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
//
// D1236: it used to be `"[^"]*unreadable[^"]*"`, which is quote-NAIVE — `[^"]*`
// happily spans the gap BETWEEN two literals, so
//
//	"a message: " + strings.Join(unreadable, "; ") + " more"
//
// matched, on an identifier that is not in any string at all. The gate counted a
// variable name as a published word. It now extracts each literal and tests them
// one at a time, which is what it always meant.
var goStringLiteral = regexp.MustCompile(`"(?:[^"\\]|\\.)*"`)

func saysBareUnreadable(line string) bool {
	for _, lit := range goStringLiteral.FindAllString(line, -1) {
		if strings.Contains(lit, "unreadable") {
			return true
		}
	}
	return false
}

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
				if !saysBareUnreadable(line) || isComment(line) {
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

// D1236. Loosening a gate's matcher is the moment to prove it still catches what it
// was built for. The old regex was quote-naive and counted an IDENTIFIER between two
// string literals; the fix must not also stop seeing the real thing.
//
// Constructed rather than sampled: the tree currently holds zero bare-unreadable
// diagnostics (that is the point of the baseline), so a passing run demonstrates
// nothing about the matcher. These cases do not exist in the tree and must not.
func TestSaysBareUnreadableSeesTheStringAndNotTheIdentifier(t *testing.T) {
	for line, want := range map[string]bool{
		// the real defect: the word ships to an operator inside a message
		`diags = append(diags, "the bucket policy is unreadable")`: true,
		`return fmt.Errorf("unreadable body")`:                     true,
		`d := "x" + "unreadable" + "y"`:                            true,
		// the false positive that prompted the fix: an identifier BETWEEN literals
		`diags = append(diags, "metrics not observed: "+join(unreadable, "; ")+" more")`: false,
		`for _, u := range unreadable {`:                                                 false,
		`var unreadable []string`:                                                        false,
		// an escaped quote must not end the literal early and hide the word
		`x := "he said \"unreadable\" once"`: true,
	} {
		if got := saysBareUnreadable(line); got != want {
			t.Errorf("saysBareUnreadable(%q) = %v, want %v", line, got, want)
		}
	}
}
