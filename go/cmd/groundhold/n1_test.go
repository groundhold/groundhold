package main

import (
	"sort"
	"strings"
	"testing"
)

// TestTimeSensitiveVerbsMembership pins the EXACT set of verbs the N1 safety
// clock gates. N1 is invariant 0: a verb whose decision depends on time must
// refuse a missing --at rather than default to the epoch (which makes stale
// observations look fresh and silently disables the staleness gate). A verb
// silently dropped from this set is a fail-open regression on the most
// safety-critical invariant; a new time-sensitive verb added without gating is
// the same hole from the other side. This test forces either change to be a
// deliberate edit here — never an accident.
//
// restore is intentionally NOT gated: it linearizes events by their own
// occurredAt for ordering, it does not gate freshness against a clock. If that
// ever changes, restore must join the set AND this expectation.
func TestTimeSensitiveVerbsMembership(t *testing.T) {
	want := []string{
		"adopt", "apply", "attest", "audit", "converge", "crawl",
		"forecast", "observe", "plan", "posture", "probe", "publish",
		"react", "refresh", "resume", "runs", "status", "unadopt",
	}

	got := make([]string, 0, len(timeSensitiveVerbs))
	for v, on := range timeSensitiveVerbs {
		if on {
			got = append(got, v)
		}
	}
	sort.Strings(got)

	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("timeSensitiveVerbs drifted — N1 gating changed WITHOUT updating\n"+
			"this test. If deliberate, update `want` and confirm the verb's --at\n"+
			"refusal; if not, a safety-clock hole just opened.\n  want: %v\n  got:  %v",
			want, got)
	}
}

// TestTimeSensitiveVerbsAreNonEmpty is a floor guard: an empty or malformed set
// would silently disarm the N1 gate for every verb.
func TestTimeSensitiveVerbsAreNonEmpty(t *testing.T) {
	if len(timeSensitiveVerbs) == 0 {
		t.Fatal("timeSensitiveVerbs is empty — the N1 gate would never fire")
	}
	for v := range timeSensitiveVerbs {
		if v == "" || strings.TrimSpace(v) != v {
			t.Errorf("time-sensitive verb %q is malformed", v)
		}
	}
}
