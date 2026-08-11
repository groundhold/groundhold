package vocab

import "testing"

// D787. `TestEveryDeclaredEvidenceClassIsInTheClosedSet` runs ValidateEvidence over every
// embedded vocabulary — and no vocabulary violates it, so replacing the whole validator
// with `return nil` changes nothing and no mutant aimed at that gate can bite. The same
// empty-subject shape as D784's visibility sweep and D785's forbidden-import list.
//
// The validator itself had no test at all. It gets one here, against a synthetic
// vocabulary carrying an invented class — the only shape that proves the machinery works
// on the day a typo reaches a vocabulary file, which is the failure D311 named: "a closed
// set that silently tolerates a typo is not closed, and here the typo's consequence is a
// reconcile that gates on an observation which will never arrive".
func TestValidateEvidenceRejectsAnInventedClass(t *testing.T) {
	ok := Vocabulary{Capability: "capability.test", Attributes: map[string]map[string]any{
		"a.measured":   {"kind": "bool"},
		"a.projection": {"kind": "money", "evidence": "projection"},
		"a.probe":      {"kind": "bool", "evidence": "probe"},
		"a.resource":   {"kind": "bool", "evidence": "resource"},
	}}
	if err := ok.ValidateEvidence(); err != nil {
		t.Fatalf("every declared class is in the closed set: %v", err)
	}

	for _, bad := range []string{"projections", "Probe", "measured", ""} {
		v := Vocabulary{Capability: "capability.test", Attributes: map[string]map[string]any{
			"a.x": {"kind": "bool", "evidence": bad},
		}}
		if err := v.ValidateEvidence(); err == nil {
			t.Errorf("evidence %q was accepted — a near-miss is the whole point of a "+
				"closed set, and `measured` is a DERIVATION, not an evidence class (D787)", bad)
		}
	}
}
