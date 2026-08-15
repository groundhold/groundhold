package main

import (
	"path/filepath"
	"strings"
	"testing"
)

// D617. `ReplayFile` treats a missing file as an empty ledger — a bootstrap affordance
// for WRITERS, since the first append creates it. Six read-only verbs inherited it and
// answered questions about a file that was not there:
//
//	attest   exit 0, a clean IntegrityReport
//	repair   exit 0, {"status":"healthy"} and the fingerprint of the empty string
//	anchor   exit 0, and it EMITS an events:0 anchor — the document D613 shows
//	                 rubber-stamps any ledger it is later checked against
//	deposed / posture / refresh   exit 0
//
// while `export` and `snapshot` exited 1 and `backup` exited 5 on the identical input.
// A typo in a path is the ordinary way to arrive here, and "healthy" is the worst
// possible answer to it — the published remediation for a corrupt ledger is
// `groundhold repair`, so following the advice produced a false all-clear.
//
// The second half is the code. A wrong PATH and bytes that do not REPLAY are different
// operator problems, and between them they had four exit codes across sixteen verbs.
// They are now 1 and 5, separated by a sentinel rather than by which verb you happened
// to run.
func TestVerbsRefuseALedgerThatIsNotThere(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "gone.jsonl")
	const at = "2026-01-05T00:00:00Z"

	for _, tc := range []struct {
		name string
		argv []string
	}{
		{"attest", []string{"attest", "--ledger", missing, "--at", at}},
		{"repair", []string{"repair", "--ledger", missing, "--provider", "fake"}},
		{"anchor", []string{"anchor", "--ledger", missing, "--provider", "fake"}},
		{"deposed", []string{"deposed", "--ledger", missing}},
		{"posture", []string{"posture", "--ledger", missing, "--at", at}},
		{"refresh", []string{"refresh", "--ledger", missing, "--provider", "fake", "--at", at}},
		{"runs", []string{"runs", "--ledger", missing, "--at", at}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var code int
			stderr := captureStderr(t, func() { code = run(tc.argv) })
			if code == 0 {
				t.Errorf("%s answered at exit 0 about a ledger that does not exist — "+
					"an absent ledger is not an empty one, and an empty one is not a "+
					"healthy one", tc.name)
			}
			if code != 1 {
				t.Errorf("%s exits %d for a missing path, want 1: corruption (5) means "+
					"the history is damaged and sends the operator to `repair`; a wrong "+
					"path means fix the path", tc.name, code)
			}
			if !strings.Contains(stderr, "no ledger") &&
				!strings.Contains(stderr, "no such file") {
				t.Errorf("%s does not say the ledger is missing:\n%s", tc.name, stderr)
			}
		})
	}
}
