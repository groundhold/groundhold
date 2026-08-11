package react

import (
	"errors"
	"strings"
	"testing"
)

// D591. `react` is the real-time path: one change event in, one paced re-list and a
// reclassified posture out. Run over a stream, its EXIT CODE is how a consumer knows
// what happened.
//
// Measured against the live cluster: a recognised watch event exits 2 (posture found
// drift), a BOOKMARK frame exits 0, and an unparseable envelope ALSO exits 0. The
// last two are the same outcome to a machine, and they mean opposite things — one is
// "a routine frame, nothing to react to", the other is "I could not understand this
// event and dropped it". The second means the real-time path is silently losing
// changes, which is the failure react exists to prevent.
//
// They collapse because ParseEvent returns one error for both: a BOOKMARK has no
// resource coordinate, falls past every branch, and lands on the same
// "unrecognised event envelope" as a garbage document. The package comment says
// watch BOOKMARK/ERROR frames "are ignored loudly" — loudly on stderr, and
// indistinguishably on the channel a stream consumer actually routes on.
func TestBenignWatchFrameIsNotAParseFailure(t *testing.T) {
	for _, frame := range []string{
		`{"type":"BOOKMARK","object":{"kind":"","metadata":{"resourceVersion":"84021"}}}`,
		`{"type":"ERROR","object":{"kind":"Status","metadata":{}}}`,
	} {
		_, err := ParseEvent([]byte(frame))
		if err == nil {
			t.Errorf("a %.20s… frame parsed as an actionable event", frame)
			continue
		}
		if !errors.Is(err, ErrNothingToReactTo) {
			t.Errorf("a routine watch frame reports the same failure as a malformed "+
				"document: %v\nA consumer routing on the outcome cannot tell "+
				"\"nothing to do\" from \"I dropped your event\".", err)
		}
	}
}

// A document nothing can parse must stay a real failure — the point is to separate
// the two, not to make everything benign.
func TestUnparseableEventStaysAFailure(t *testing.T) {
	for _, junk := range []string{`{"nonsense":true}`, `[]`, `{"type":"MODIFIED"}`} {
		_, err := ParseEvent([]byte(junk))
		if err == nil {
			t.Errorf("%s parsed as an event", junk)
			continue
		}
		if errors.Is(err, ErrNothingToReactTo) {
			t.Errorf("%s was called a routine frame — a malformed event would then be "+
				"dropped as if it were a bookmark", junk)
		}
	}
}

// A real event still parses, or the separation has eaten the feature.
func TestRecognisedWatchEventStillParses(t *testing.T) {
	ev, err := ParseEvent([]byte(
		`{"type":"MODIFIED","object":{"kind":"ResourceQuota",` +
			`"metadata":{"namespace":"default","name":"fc-quota"}}}`))
	if err != nil {
		t.Fatalf("a real watch event no longer parses: %v", err)
	}
	if ev.Scope != "default" || !strings.Contains(ev.Hint, "ResourceQuota") {
		t.Errorf("routing coordinates lost: %+v", ev)
	}
}
