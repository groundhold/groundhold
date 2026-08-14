package runstatus

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// runstatusParitySHA256 pins the exact bytes of the shared run-status parity
// fixture. The SAME file and the SAME constant live in the console
// (the console repo, internal/server/parity_test.go). The console cannot import
// this package (it is internal, and a separate repo), so "the console mirrors
// groundhold's run-status derivation" was a hand-copied CLAIM with nothing
// enforcing it — the exact shape that produced D656/D641/D676 (a golden fixture
// that asserted parity but did not cover the hardenings). This closes it: BOTH
// repos now execute ONE declarative case set — the runtime through
// DeriveRunStatus, the console through deriveRun — and a divergence in either
// derivation fails that repo's build.
//
// The constant is the cross-repo sync anchor. If the runtime and console values
// differ, the fixture was regenerated in one repo and not copied to the other.
// To change the cases: edit this fixture, run this test (the runtime is the
// authority — it proves each expected state against the real derivation), copy
// the JSON verbatim to the console, and update BOTH constants. (D1021.)
const runstatusParitySHA256 = "6ba3a5e08c94f36388cac5da17fbf1a7317db01f7975abd24369e83e0b77cf9c"

type parityEvent struct {
	Type         string         `json:"type"`
	Clock        int            `json:"clock"`
	Capabilities []string       `json:"capabilities"`
	Body         map[string]any `json:"body"`
}

type parityCase struct {
	Name     string        `json:"name"`
	Handle   string        `json:"handle"`
	Now      int           `json:"now"`
	Expected string        `json:"expected"`
	Events   []parityEvent `json:"events"`
}

func loadParityFixture(t *testing.T) ([]byte, []parityCase) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "runstatus_parity.json"))
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Cases []parityCase `json:"cases"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("parity fixture is not valid JSON: %v", err)
	}
	return raw, doc.Cases
}

// TestRunStatusParityFixtureIsTheContract proves the shared fixture against the
// REAL runtime derivation — this side is the authority the console mirrors — and
// pins the bytes so the two repos cannot silently hold different copies.
func TestRunStatusParityFixtureIsTheContract(t *testing.T) {
	raw, cases := loadParityFixture(t)

	if got := hex.EncodeToString(sha256Sum(raw)); got != runstatusParitySHA256 {
		t.Fatalf("parity fixture sha256 = %s, pinned = %s — regenerate the constant "+
			"here AND in the console, or the two repos will drift apart", got, runstatusParitySHA256)
	}
	// A floor so a truncated fixture cannot pass by measuring almost nothing
	// (D328). Covers all six states plus the D656/D641/D241/D676 hardenings.
	if len(cases) < 15 {
		t.Fatalf("the parity fixture collapsed to %d cases", len(cases))
	}
	states := map[string]bool{}
	for _, c := range cases {
		evs := make([]RunEvent, len(c.Events))
		for i, e := range c.Events {
			evs[i] = RunEvent{Type: e.Type, Clock: e.Clock, Body: e.Body, Caps: e.Capabilities}
		}
		got := string(DeriveRunStatus(evs, c.Handle, c.Now).State)
		if got != c.Expected {
			t.Errorf("case %q: runtime DeriveRunStatus = %q, fixture expected %q",
				c.Name, got, c.Expected)
		}
		states[c.Expected] = true
	}
	for _, want := range []string{"unknown", "running", "stalled", "needs-reconcile", "done", "failed"} {
		if !states[want] {
			t.Errorf("no parity case exercises the %q state — the mirror is not exhaustive", want)
		}
	}
	// Every run state the fixture proves DeriveRunStatus produces must have an
	// error code. rs.Code = codeFor[rs.State] returns "" for a missing entry, so a
	// state added to the switch but not to codeFor would report an empty code and
	// no remediation — the independent-enumeration drift of D1025, one map over.
	// Gated here against the fixture's produced states rather than a fresh hardcoded
	// list (which would be one more copy to drift).
	for st := range states {
		if codeFor[State(st)] == "" {
			t.Errorf("DeriveRunStatus produces state %q (per the fixture) but codeFor has no "+
				"code for it — the run would report an empty code and no remediation", st)
		}
	}
}

func sha256Sum(b []byte) []byte {
	h := sha256.Sum256(b)
	return h[:]
}
