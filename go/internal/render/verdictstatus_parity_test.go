package render

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// verdictStatusParitySHA256 pins the exact bytes of the shared verdict-rollup
// parity fixture. The SAME file and constant live in the console
// (proviso-console/internal/server/verdictstatus_parity_test.go). The console's
// verdictStatus() maps a verdict slice to the pill state (proven/blocked/
// violated); the runtime derives the same banner from a rollup built in
// cmd/groundhold/main.go and Pick() here. That was a hand-mirrored precedence
// with nothing tying the two together — the same class as the run-status mirror
// (D1021). This closes it for the verdict rollup: both repos execute ONE
// declarative case set and a divergence fails that repo's build.
//
// SCOPE. The fixture covers the reachable closed four-valued verdict set, where
// the two AGREE. Two things are deliberately NOT in it, and are not divergences:
//   - the empty slice: the console reports "declared" (nothing real verified),
//     a console lifecycle state; the runtime would green a zero-verdict verify.
//   - an unrecognised hard verdict value: the console fail-closes it to "blocked"
//     (a0b608f, safer), while it never enters the runtime rollup. Non-reachable
//     (the runtime emits a closed set); the console is the more conservative side.
//
// The constant is the cross-repo sync anchor. To change the cases: edit here, run
// this test (the runtime is the authority — it proves each expected state through
// the REAL Pick), copy the JSON verbatim to the console, update BOTH constants.
// (D1022.)
const verdictStatusParitySHA256 = "da9428ae63a447c9f9d84eb09986f0347dfa879842441a1b49dfa159d402bfea"

type vsVerdict struct {
	Severity string `json:"severity"`
	Verdict  string `json:"verdict"`
}

type vsCase struct {
	Name     string      `json:"name"`
	Verdicts []vsVerdict `json:"verdicts"`
	Expected string      `json:"expected"`
}

// TestVerdictStatusParityIsTheContract proves the fixture against the REAL
// banner precedence (Pick) over a rollup built by the SAME hard-only rule the
// verify/audit CLI uses. This side is the authority the console mirrors.
func TestVerdictStatusParityIsTheContract(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "verdictstatus_parity.json"))
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(raw)
	if got := hex.EncodeToString(sum[:]); got != verdictStatusParitySHA256 {
		t.Fatalf("verdict-status parity fixture sha256 = %s, pinned = %s — regenerate "+
			"the constant here AND in the console, or the repos will drift apart", got, verdictStatusParitySHA256)
	}
	var doc struct {
		Cases []vsCase `json:"cases"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("parity fixture is not valid JSON: %v", err)
	}
	if len(doc.Cases) < 12 {
		t.Fatalf("the verdict-status parity fixture collapsed to %d cases", len(doc.Cases))
	}
	states := map[string]bool{}
	for _, c := range doc.Cases {
		// Build the rollup EXACTLY as cmd/groundhold/main.go:2455-2467 does: ONLY
		// hard verdicts, keyed by value. That loop is inline in the CLI command,
		// not a callable function, so it is mirrored here (with this pointer) — the
		// console's verdictStatus is thereby gated against the REAL Pick precedence
		// plus this documented hard-only rule.
		var r Rollup
		for _, v := range c.Verdicts {
			if v.Severity != "hard" {
				continue
			}
			switch v.Verdict {
			case "violated":
				r.Violated = append(r.Violated, c.Name)
			case "unknown":
				r.Unknown = append(r.Unknown, c.Name)
			case "unverifiable":
				r.Unverifiable = append(r.Unverifiable, c.Name)
			}
		}
		banner, _ := Pick("verify", 0, "", r)
		status := ""
		switch banner {
		case "PROVEN":
			status = "proven"
		case "VIOLATED":
			status = "violated"
		case "BLOCKED":
			status = "blocked"
		default:
			status = "unmapped:" + banner
		}
		if status != c.Expected {
			t.Errorf("case %q: rollup+Pick = %q (banner %q), fixture expected %q",
				c.Name, status, banner, c.Expected)
		}
		states[c.Expected] = true
	}
	for _, want := range []string{"proven", "blocked", "violated"} {
		if !states[want] {
			t.Errorf("no parity case exercises the %q state — the mirror is not exhaustive", want)
		}
	}
}
