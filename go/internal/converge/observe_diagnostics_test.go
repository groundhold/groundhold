package converge

import (
	"bytes"
	"strings"
	"testing"
)

// D558. D556 stopped `adopt` from discarding the driver's account of what it could
// not read. `converge` does the same thing one level up, in the verb operators
// actually run: when knowledge is stale it weaves in an `observe` child and takes
//
//	c2, _, e2 := o.Run("observe", ...)
//
// — the child's stdout, which carries `diagnostics`, goes to `_`, and its stderr is
// read only when the child FAILS. So the case that matters most is exactly the one
// dropped: observe succeeded, and while succeeding it reported that it could not
// measure something.
//
// The pattern for fixing it is three lines below the bug (D202): the plan child
// renders its cost estimate to stderr and converge surfaces it deliberately. A child
// process's report is not noise just because the child exited 0.
func TestConvergeSurfacesTheObserveChildsDiagnostics(t *testing.T) {
	planned := false
	run := func(args ...string) (int, string, string) {
		switch args[0] {
		case "verify":
			return 0, `{"executable":true}`, ""
		case "observe":
			return 0, `{"observations":[],"diagnostics":[` +
				`"platform: GitRepository \"platform\" referenced by spec.sourceRef.name ` +
				`does not exist — spec.url not represented"]}`, ""
		case "plan":
			if planned { // second plan: knowledge refreshed, nothing to do
				return 0, `{"plan":{"actions":[]}}`, ""
			}
			planned = true
			return 2, `{"code":"observation-required"}`, "stale knowledge"
		}
		return 0, "", ""
	}
	var out bytes.Buffer
	o := Options{Contract: "c", Candidate: "k", Vocab: "v", Ledger: "l.ndjson",
		Provider: "k8s", At: "2026-01-01T00:00:00Z", Run: run, Out: &out, Yes: true}
	Converge(o)

	if !strings.Contains(out.String(), "GitRepository") {
		t.Errorf("converge re-observed, the driver explained what it could not measure, "+
			"and converge printed none of it.\noutput:\n%s\n"+
			"The one verb an operator runs unattended is the one that drops the "+
			"explanation, and it drops it precisely when the run SUCCEEDS.", out.String())
	}
}
