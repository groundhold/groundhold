package verify_test

import (
	"sort"
	"strings"
	"testing"

	"groundhold/internal/scalars"
)

// D493: invariant 4 says the operator set is CLOSED — "do not add an expression
// language, interpolation, or logical connectives to constraints. Complexity = more
// constraints."
//
// `TestOperatorSetsAgreeAcrossImplementations` (D327) proves the two implementations
// hold the SAME set. Agreement is not closure: add an operator to both and that gate
// stays green, which is the shape of every drift this session has been about — a
// property everyone believes, checked in a way that permits its violation.
//
// So the set is pinned. Growing it is a design act with consequences the invariant
// names (an operator is a new thing every future author must reason about, in a
// language whose value is that there is nothing to reason about), and it should cost a
// deliberate edit here plus a decision entry — not a silent line in a map.
//
// Presence operators live outside scalars.Operators and are pinned with them: the
// closed set the SPEC promises is the union a contract author can actually write.
var closedOperatorSet = []string{
	"compatible-with",
	"equals",
	"gte",
	"in",
	"lte",
	"not-equals",
	"not-in",
	"subset-of",
	// presence, evaluated before a value is compared
	"absent",
	"exists",
}

func TestOperatorSetIsClosed(t *testing.T) {
	got := []string{"absent", "exists"}
	for name := range scalars.Operators {
		got = append(got, name)
	}
	sort.Strings(got)
	want := append([]string(nil), closedOperatorSet...)
	sort.Strings(want)

	if len(got) < 5 {
		t.Fatalf("only %d operators found — the gate would be vacuous (D328)", len(got))
	}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("the operator set changed.\n  have: %v\n  want: %v\n"+
			"Invariant 4 says this set is CLOSED: an expression language is what the "+
			"medium exists NOT to be, and every operator is one more thing a reader of a "+
			"contract must know. Growing it is legitimate and must be deliberate — edit "+
			"this list and write the decision entry that says why (D493).", got, want)
	}
}
