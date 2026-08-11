package contract

import (
	"testing"

	"groundhold/internal/scalars"
	"groundhold/internal/vocab"
)

// D532: the unit twin of the conformance case. It goes through vocabCheck — the
// WIRING — rather than calling the sorter directly, because the first version of
// this test called the helper and the mutation meter caught it: disabling the call
// site left the test green. A test that exercises the function but not the place
// it is used proves the function, not the behaviour.
func TestUnorderedListIsCanonicalized(t *testing.T) {
	sc, err := scalars.Parse([]any{"c", "a", "b"})
	if err != nil {
		t.Fatal(err)
	}
	cand := &Candidate{Capabilities: map[string]map[string]Provenanced{
		"db": {"network.zones": {Scalar: sc}},
	}}
	c := &Contract{Capabilities: map[string]map[string]any{
		"db": {"type": "capability.database.relational"},
	}}
	vocabs := map[string]vocab.Vocabulary{
		"capability.database.relational": {Attributes: map[string]map[string]any{
			"network.zones": {"kind": "list", "unordered": true},
		}},
	}
	if err := vocabCheck(cand, c, vocabs); err != nil {
		t.Fatal(err)
	}
	raw, _ := sc.Raw.([]any)
	if len(raw) != 3 || raw[0] != "a" || raw[1] != "b" || raw[2] != "c" {
		t.Fatalf("raw not canonicalized: %v — two spellings of one set would hash differently", raw)
	}
	elems, _ := sc.Value.([]*scalars.Scalar)
	for i, want := range []string{"a", "b", "c"} {
		if elems[i].Raw != want {
			t.Errorf("element %d = %v, want %s", i, elems[i].Raw, want)
		}
	}
}

// The default must not move: a list NOT marked unordered keeps its order.
func TestOrderedListKeepsItsOrder(t *testing.T) {
	sc, _ := scalars.Parse([]any{"c", "a", "b"})
	cand := &Candidate{Capabilities: map[string]map[string]Provenanced{
		"db": {"network.zones": {Scalar: sc}},
	}}
	c := &Contract{Capabilities: map[string]map[string]any{
		"db": {"type": "capability.database.relational"},
	}}
	vocabs := map[string]vocab.Vocabulary{
		"capability.database.relational": {Attributes: map[string]map[string]any{
			"network.zones": {"kind": "list"},
		}},
	}
	if err := vocabCheck(cand, c, vocabs); err != nil {
		t.Fatal(err)
	}
	if raw, _ := sc.Raw.([]any); raw[0] != "c" {
		t.Errorf("an ordered list was reordered: %v", raw)
	}
}
