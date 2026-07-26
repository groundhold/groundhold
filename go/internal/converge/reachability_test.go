package converge

import (
	"bytes"
	"strings"
	"testing"

	"groundhold/internal/reach"
)

// TestFoldReach pins the honesty core folded into the converge result: reachable
// stays clean (exit 0); a 401/403 anonymous denial and a transport failure are
// BOTH unknown -> BLOCKED (Unknown rollup, exit 2) — never a green success. A
// 403 is NEVER collapsed to a confident "denied", and it carries the multi-cause
// (never accusatory) remediation; a transport failure names its own cause.
func TestFoldReach(t *testing.T) {
	cases := []struct {
		name       string
		result     reach.CapResult
		wantExit   int
		wantReach  string
		wantUnk    int
		humanMatch string
		wantRemedy bool
	}{
		{"reachable", reach.CapResult{Verdict: reach.Reachable, Status: 200}, 0, "reachable", 0, "reachable", false},
		{"anon-403", reach.CapResult{Verdict: reach.Unknown, Status: 403}, 2, "unknown", 1, "unknown", true},
		{"anon-401", reach.CapResult{Verdict: reach.Unknown, Status: 401}, 2, "unknown", 1, "unknown", true},
		{"transport", reach.CapResult{Verdict: reach.Unknown, Status: 0}, 2, "unknown", 1, "unknown (from here)", false},
	}
	for _, tc := range cases {
		var buf bytes.Buffer
		o := &Options{Out: &buf}
		r := result{Status: "applied", Exit: 0}
		cr := tc.result
		cr.Capability, cr.URL, cr.Cause = "edge", "https://e/", "cause"
		o.foldReach(&r, []reach.CapResult{cr})
		if r.Exit != tc.wantExit {
			t.Errorf("%s: exit = %d, want %d", tc.name, r.Exit, tc.wantExit)
		}
		if r.Reachability != tc.wantReach {
			t.Errorf("%s: reachability = %q, want %q", tc.name, r.Reachability, tc.wantReach)
		}
		if len(r.Rollup.Violated) != 0 {
			t.Errorf("%s: Layer 1 never sets a VIOLATED rollup (no denied verdict), got %d",
				tc.name, len(r.Rollup.Violated))
		}
		if len(r.Rollup.Unknown) != tc.wantUnk {
			t.Errorf("%s: unknown rollup = %d, want %d", tc.name, len(r.Rollup.Unknown), tc.wantUnk)
		}
		if !strings.Contains(buf.String(), tc.humanMatch) {
			t.Errorf("%s: human output %q lacks %q", tc.name, buf.String(), tc.humanMatch)
		}
		hasRemedy := strings.Contains(buf.String(), "lambda:InvokeFunction")
		if hasRemedy != tc.wantRemedy {
			t.Errorf("%s: multi-cause remediation present=%v, want %v (%q)",
				tc.name, hasRemedy, tc.wantRemedy, buf.String())
		}
		if tc.name == "anon-403" && strings.Contains(buf.String(), "DENIED") {
			t.Errorf("a 403 must NOT be reported as a confident DENIED accusation: %q", buf.String())
		}
	}
}

// TestNoReachabilitySkipsLoudly pins that --no-reachability never skips silently:
// the human channel prints "reachability skipped" and the machine field is set.
func TestNoReachabilitySkipsLoudly(t *testing.T) {
	var buf bytes.Buffer
	o := &Options{Out: &buf, NoReachability: true}
	r := result{Status: "applied", Exit: 0}
	o.reachability(&r)
	if r.Reachability != "skipped" {
		t.Fatalf("reachability = %q, want skipped", r.Reachability)
	}
	if !strings.Contains(buf.String(), "reachability skipped") {
		t.Fatalf("skip must be LOUD on the human channel, got %q", buf.String())
	}
	if r.Exit != 0 {
		t.Errorf("a skipped probe leaves the clean apply exit alone, got %d", r.Exit)
	}
}
