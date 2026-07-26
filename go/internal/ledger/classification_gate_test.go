package ledger

import (
	"sort"
	"testing"

	"groundhold/internal/state"
)

// D338: `MutationTypes[etype]` is what makes an append require an active lease and
// a matching fencing token (D29). Membership is hand-maintained, and the default is
// silent: a mutating event type omitted from the map is appended with no lease and
// no token at all. That is the fail-open shape D330 found in perrnext's `next`
// coverage, except here the thing left undecided is a concurrency control.
//
// The fix is the same one that package already uses: force an explicit decision.
// Every event type must be in MutationTypes or in NonMutatingTypes, never both and
// never neither.
func TestEveryEventTypeIsClassified(t *testing.T) {
	if len(state.EventTypes) == 0 || len(MutationTypes) == 0 || len(NonMutatingTypes) == 0 {
		t.Fatal("an input set is empty — the gate would be vacuous (D328)")
	}

	var undecided, both []string
	for etype := range state.EventTypes {
		m, n := MutationTypes[etype], NonMutatingTypes[etype]
		switch {
		case m && n:
			both = append(both, etype)
		case !m && !n:
			undecided = append(undecided, etype)
		}
	}
	sort.Strings(undecided)
	sort.Strings(both)

	if len(undecided) > 0 {
		t.Errorf("event types classified neither mutating nor non-mutating: %v\n"+
			"They append with NO lease and NO fencing token — if any of them changes "+
			"the world, D29's concurrency control is silently off for it.", undecided)
	}
	if len(both) > 0 {
		t.Errorf("event types in BOTH MutationTypes and NonMutatingTypes: %v", both)
	}

	// The reverse direction: a classification naming a type the registry does not
	// know is dead weight that reads like coverage.
	for _, set := range []struct {
		name string
		m    map[string]bool
	}{{"MutationTypes", MutationTypes}, {"NonMutatingTypes", NonMutatingTypes}} {
		var unknown []string
		for etype := range set.m {
			if !state.EventTypes[etype] {
				unknown = append(unknown, etype)
			}
		}
		sort.Strings(unknown)
		if len(unknown) > 0 {
			t.Errorf("%s classifies types absent from the closed registry: %v",
				set.name, unknown)
		}
	}
}
