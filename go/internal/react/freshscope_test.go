package react

import (
	"testing"

	"groundhold/internal/discover"
)

// TestFreshScopeCarriesTheReListsIncompleteness is the regression fence for the react
// false-complete defect: react re-lists a scope and, if the driver truncated the listing
// (partial results, no error), the spliced scope MUST be incomplete — not a hardcoded
// "complete". A complete claim spliced over a prior honest incomplete lets posture exit 0
// over a scope where a shadow may sit on the unread page (react is the unattended stream
// path). Swapping the status back to a hardcoded "complete" fails this.
func TestFreshScopeCarriesTheReListsIncompleteness(t *testing.T) {
	inc := &discover.Result{Incomplete: true,
		IncompleteReason: "the scope is incomplete — a listing did not finish: ListPods (D803/D873)"}
	sc := FreshScope("prod", "2026-07-15T12:00:00Z", "2026-07-15T12:00:01Z", inc)
	if sc.Status != "incomplete" {
		t.Fatalf("a truncated re-list must produce an INCOMPLETE scope, got %q", sc.Status)
	}
	if sc.Reason == "" {
		t.Fatal("an incomplete scope must carry the reason a human reads")
	}
}

// A re-list the driver reported complete stays complete, and the resources it found flow
// through, each stamped at the re-list time.
func TestFreshScopeCompleteWhenTheReListWas(t *testing.T) {
	res := &discover.Result{}
	res.Discovery.Resources = []discover.Resource{{ProviderID: "sql:widgets", ResourceType: "db"}}
	sc := FreshScope("prod", "2026-07-15T12:00:00Z", "2026-07-15T12:00:01Z", res)
	if sc.Status != "complete" {
		t.Fatalf("a complete re-list stays complete, got %q", sc.Status)
	}
	if len(sc.Resources) != 1 || sc.Resources[0].ObservedAt != "2026-07-15T12:00:01Z" {
		t.Fatalf("resources must be carried and stamped at the re-list time, got %+v", sc.Resources)
	}
}
