package costproj

import (
	"bytes"
	"strings"
	"testing"
)

// D595. The cost block is careful in every way that was tested: the arithmetic is
// right, the weekly figure annualises properly (monthly × 12 ÷ 52, not monthly ÷ 4),
// a second currency is kept SEPARATE with "NOT converted" rather than run through an
// invented rate, and the coverage line states how much of the plan the figure rests
// on. Verified against a real plan before touching anything.
//
// One thing the render does not say is which DIRECTION a partial figure is wrong in.
// With "based on 1 of 2 capabilities", the missing capability costs something, so the
// true monthly cost is strictly HIGHER — the number can only be wrong one way. The
// headline reads "Estimated cost … ~ 120.50 EUR / month", and "estimate" with a
// tilde reads as a central value, which is the one thing it cannot be.
//
// This project already has the vocabulary: `shadowLowerBound` exists because a count
// from partial data is a lower bound and says so. A price deserves the same word,
// especially since the error runs toward "cheaper than it is".
func TestPartialCoverageReadsAsALowerBound(t *testing.T) {
	var b bytes.Buffer
	Projection{Basis: "declared", Currency: "EUR", Monthly: 120.50, Priced: 1, Total: 2}.Render(&b)
	out := b.String()
	if !strings.Contains(strings.ToLower(out), "at least") {
		t.Errorf("a figure covering 1 of 2 capabilities is presented as an estimate "+
			"rather than a floor:\n%s\nThe uncovered capability costs something, so the "+
			"true figure is higher — the number can only be wrong one way.", out)
	}
}

// Full coverage is not a lower bound, and calling it one would understate a complete
// answer — the mirror mistake, and noise where the caveat cannot apply (D537).
func TestFullCoverageIsNotHedged(t *testing.T) {
	var b bytes.Buffer
	Projection{Basis: "declared", Currency: "EUR", Monthly: 120.50, Priced: 2, Total: 2}.Render(&b)
	if strings.Contains(strings.ToLower(b.String()), "at least") {
		t.Errorf("a figure covering every capability was hedged as a floor:\n%s", b.String())
	}
}

// The parts that were already right must stay right: coverage stated, the second
// currency separate and unconverted.
func TestCostRenderKeepsWhatItAlreadyGotRight(t *testing.T) {
	var b bytes.Buffer
	Projection{Basis: "declared", Currency: "EUR", Monthly: 120.50, Priced: 1, Total: 2,
		Other: []currencyTotal{{Currency: "USD", Monthly: 80}}}.Render(&b)
	out := b.String()
	for _, want := range []string{"based on 1 of 2", "NOT converted", "projection, not a quote"} {
		if !strings.Contains(out, want) {
			t.Errorf("the render lost %q:\n%s", want, out)
		}
	}
}
