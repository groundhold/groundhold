package posture

import "testing"

// D650. `shadowLowerBound` is posture's whole honesty claim about the shadow
// count: false means "this number is exact", true means "at least this many". It
// was derived by walking the DISCOVERED RESOURCES and asking each one whether its
// scope had been complete — so a scope that was cut short before listing anything
// contributed no entries at all, and its incompleteness was unrepresentable.
//
// Measured on a crawl with a budget of 1:
//
//	crawl:   scope fake-project-a  status incomplete  resources 0
//	         reason "crawl request budget exhausted"
//	posture: {"shadow": 0, "shadowLowerBound": false}   exit 0   OK
//
// And an incomplete scope is USUALLY empty: crawl emits `status: incomplete,
// resources: []` for every auth error, throttle, budget stop, breaker trip and
// failed scope enumeration. So the case the field exists for is exactly the case
// it could not see: expired credentials on one project render as "no unmanaged
// resources here", at exit 0, under a banner that says OK.
func TestAnEmptyIncompleteScopeStillLowersTheBound(t *testing.T) {
	doc := Classify(Input{
		At: "2026-07-15T12:05:00Z",
		Scopes: []Scope{
			{Provider: "fake", Scope: "fake-project-a", Complete: false,
				Reason: "crawl request budget exhausted: fake"},
		},
		Bindings: map[string]string{},
	})
	if !doc.Summary.ShadowLowerBound {
		t.Errorf("a sweep that listed NOTHING and said so reports shadow=%d as an "+
			"exact count: %+v", doc.Summary.Shadow, doc.Summary)
	}
}

// The half-truncated shape, which is the one that reads most convincingly: one
// scope listed cleanly and returned a resource, the next never got off the ground.
func TestOneGoodScopeDoesNotCoverForATruncatedOne(t *testing.T) {
	doc := Classify(Input{
		At: "2026-07-15T12:05:00Z",
		Scopes: []Scope{
			{Provider: "fake", Scope: "a", Complete: true},
			{Provider: "fake", Scope: "b", Complete: false, Reason: "budget exhausted"},
		},
		Discovered: []Discovered{
			{ProviderID: "fake:orphan-1", Scope: "a", ScopeComplete: true},
		},
		Bindings: map[string]string{},
	})
	if doc.Summary.Shadow != 1 {
		t.Errorf("shadow = %d, want 1", doc.Summary.Shadow)
	}
	if !doc.Summary.ShadowLowerBound {
		t.Error("an affirmative claim that 1 is the exact count, over a sweep that " +
			"never listed the second scope")
	}
}

// No crawl at all is the strongest form of the same thing: nothing was swept, so
// zero shadow resources is a lower bound of the least informative kind. `--crawl`
// is optional in `--help`, and the flagless invocation is a published one.
func TestNoSweepAtAllIsALowerBoundToo(t *testing.T) {
	doc := Classify(Input{At: "2026-07-15T12:05:00Z",
		Bindings: map[string]string{"db": "fake:db-1"}})
	if !doc.Summary.ShadowLowerBound {
		t.Errorf("posture with nothing swept reports shadow=%d as exact: %+v",
			doc.Summary.Shadow, doc.Summary)
	}
}

// The control: a sweep that DID complete every scope earns the exact claim. Without
// this, setting the flag unconditionally passes every case above and the field
// stops carrying information.
func TestACompleteSweepStillEarnsAnExactCount(t *testing.T) {
	doc := Classify(Input{
		At: "2026-07-15T12:05:00Z",
		Scopes: []Scope{
			{Provider: "fake", Scope: "a", Complete: true},
			{Provider: "fake", Scope: "b", Complete: true},
		},
		Discovered: []Discovered{
			{ProviderID: "fake:orphan-1", Scope: "a", ScopeComplete: true},
		},
		Bindings: map[string]string{},
	})
	if doc.Summary.ShadowLowerBound {
		t.Errorf("a complete sweep must report its shadow count as exact: %+v",
			doc.Summary)
	}
	if doc.Summary.Shadow != 1 {
		t.Errorf("shadow = %d, want 1", doc.Summary.Shadow)
	}
}
