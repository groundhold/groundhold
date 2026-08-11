package posture

import (
	"strings"
	"testing"
)

// D568. Posture's contract with the operator, in its own usage line, is
// "managed-ok/drifted/shadow/decayed/unknown with adopt/converge/observe recipes".
// Three classes carry one: drifted → converge, decayed → observe, shadow → adopt.
// `managed-ok` needs none. `unknown` gets an empty `{"action": ""}` — and unknown is
// where an operator STARTS.
//
// Walked on a live cluster: adopt a capability, run posture, and the single row is
// `unknown — no audit verdict at <ts>` with no recipe. Then follow the decayed
// recipe's FIRST step (`refresh`) and stop, and the row moves from decayed — which
// has a recipe — to unknown, which does not. Following half of a two-step instruction
// leaves the operator with less guidance than before they started.
//
// The recipe is not a judgement call: the decayed remediation's own second step is
// `groundhold audit`, which is exactly the missing verdict.
func TestUnknownWithNoVerdictCarriesARecipe(t *testing.T) {
	doc := Classify(Input{
		At:       "2026-07-31T12:00:00Z",
		Bindings: map[string]string{"web": "cert-manager.io/v1/Certificate/default/web-cert"},
		Verdict:  map[string]string{}, // no audit has run — the state right after adopt
		Deposed:  map[string]bool{}, Decayed: map[string]bool{},
	})
	if len(doc.Rows) != 1 {
		t.Fatalf("expected one row, got %d", len(doc.Rows))
	}
	r := doc.Rows[0]
	if r.Class != "unknown" {
		t.Fatalf("setup: expected unknown, got %q", r.Class)
	}
	if r.Remediation.Action == "" {
		t.Errorf("the class an operator lands in immediately after adopting carries no "+
			"recipe: %+v\nposture's own usage promises one per class, and the missing "+
			"verb is named in the decayed recipe two lines away (`groundhold audit`).",
			r.Remediation)
	}
	if !strings.Contains(strings.Join(r.Remediation.Steps, " "), "audit") {
		t.Errorf("the recipe does not name `audit`, which is the verdict that is missing: %+v",
			r.Remediation)
	}
}

// The other unknown arm is a MODELING problem — an unverifiable verdict is not fixed
// by running anything, and saying "run audit" there would send an operator in a
// circle. It must still say what to do, because "no action" and "no advice" read the
// same in a JSON document and only one of them is true.
func TestUnverifiableUnknownSaysItIsAModelingProblem(t *testing.T) {
	doc := Classify(Input{
		At:       "2026-07-31T12:00:00Z",
		Bindings: map[string]string{"web": "x/y/Z/n"},
		Verdict:  map[string]string{"web": "unverifiable"},
		Deposed:  map[string]bool{}, Decayed: map[string]bool{},
	})
	r := doc.Rows[0]
	if r.Remediation.Action == "" {
		t.Errorf("an unverifiable verdict carries no advice at all: %+v", r.Remediation)
	}
	if strings.Contains(strings.Join(r.Remediation.Steps, " "), "audit") {
		t.Errorf("re-auditing cannot resolve an incomparable verdict — that is a loop: %+v",
			r.Remediation)
	}
}

// managed-ok must stay bare: a recipe on a healthy row is noise, and posture exits 0
// there precisely because there is nothing to do.
func TestManagedOkCarriesNoRecipe(t *testing.T) {
	doc := Classify(Input{
		At:       "2026-07-31T12:00:00Z",
		Bindings: map[string]string{"web": "x/y/Z/n"},
		Verdict:  map[string]string{"web": "satisfied"},
		Deposed:  map[string]bool{}, Decayed: map[string]bool{},
	})
	if a := doc.Rows[0].Remediation.Action; a != "" {
		t.Errorf("a healthy row carries a recipe %q — advice with nothing to fix is noise", a)
	}
}

// D568, second half, and the sharper one. Following the recipe is not enough if the
// recipe omits how to SEE that it worked. Measured on the live cluster: after
// `groundhold audit` reported PROVEN, re-running posture exactly as before still
// printed `unknown: 1` — because posture reads verdicts only when given `--contract`.
// An operator who follows the advice and re-runs the command they already know
// concludes the advice did nothing.
//
// Both recipes that end in a re-check carry the flag now. Advice that cannot be seen
// to have worked is indistinguishable from advice that did not.
func TestRecipesSayHowToSeeTheResult(t *testing.T) {
	for _, tc := range []struct {
		name string
		in   Input
	}{
		{"unknown-no-verdict", Input{At: "t", Bindings: map[string]string{"web": "p"},
			Verdict: map[string]string{}, Deposed: map[string]bool{}, Decayed: map[string]bool{}}},
		{"decayed", Input{At: "t", Bindings: map[string]string{"web": "p"},
			Verdict: map[string]string{}, Deposed: map[string]bool{},
			Decayed: map[string]bool{"web": true}}},
	} {
		steps := strings.Join(Classify(tc.in).Rows[0].Remediation.Steps, " | ")
		if !strings.Contains(steps, "posture") {
			t.Errorf("%s: the recipe never says to re-check: %s", tc.name, steps)
			continue
		}
		if !strings.Contains(steps, "--contract") {
			t.Errorf("%s: the recipe re-runs posture WITHOUT --contract, so the verdict "+
				"the previous step just produced stays invisible and the operator reads "+
				"the advice as having failed:\n  %s", tc.name, steps)
		}
	}
}
