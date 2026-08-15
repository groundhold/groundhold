package discover

import (
	"strings"
	"testing"

	"groundhold/internal/provider"
)

// truncatingDisc is a Discoverer that ALSO reports a truncated listing: List returns
// partial results with NO error (a page went unread), and TruncatedListings names the
// call — exactly what aws/azure/gcp/k8s do through provider.ListingRecord.
type truncatingDisc struct {
	*provider.Fake
	res   []provider.Discovered
	notes []provider.TruncationNote
}

func (t *truncatingDisc) Name() string { return "fake" }
func (t *truncatingDisc) List(string) ([]provider.Discovered, []string, error) {
	return t.res, nil, nil
}
func (t *truncatingDisc) TruncatedListings() []provider.TruncationNote { return t.notes }

var (
	_ provider.Provider            = (*truncatingDisc)(nil)
	_ provider.Discoverer          = (*truncatingDisc)(nil)
	_ provider.ListingCompleteness = (*truncatingDisc)(nil)
)

// TestRunSurfacesADriversTruncation pins the single-interrogation contract (D803/D873):
// discover.Run asks the completeness capability ONCE and carries the verdict on the
// Result, so a driver that listed only partially (no error) is NOT read as complete. This
// is the source both crawl and react now read, so react can no longer hardcode "complete".
func TestRunSurfacesADriversTruncation(t *testing.T) {
	prov := &truncatingDisc{Fake: &provider.Fake{},
		res:   []provider.Discovered{{ProviderID: "sql:widgets", ResourceType: "db"}},
		notes: []provider.TruncationNote{{Call: "ListInstances"}}}
	res, err := Run(prov, "p", "eu", "2026-07-15T12:00:00Z")
	if err != nil {
		t.Fatal(err)
	}
	if !res.Incomplete {
		t.Fatal("a driver that truncated its listing must set Result.Incomplete — a partial " +
			"sweep read as complete lets a shadow hide on the unread page")
	}
	if !strings.Contains(res.IncompleteReason, "ListInstances") {
		t.Fatalf("the reason must NAME the truncated call, got %q", res.IncompleteReason)
	}
	if len(res.Discovery.Resources) != 1 {
		t.Fatalf("truncation must NOT discard the partial results — the count is a lower "+
			"bound, not zero; got %d", len(res.Discovery.Resources))
	}
}

// A driver reporting NO truncation is complete — the fix must not fabricate incompleteness.
func TestRunWithoutTruncationIsComplete(t *testing.T) {
	prov := &truncatingDisc{Fake: &provider.Fake{},
		res: []provider.Discovered{{ProviderID: "sql:widgets", ResourceType: "db"}}}
	res, err := Run(prov, "p", "eu", "2026-07-15T12:00:00Z")
	if err != nil {
		t.Fatal(err)
	}
	if res.Incomplete || res.IncompleteReason != "" {
		t.Fatalf("no truncation notes must not be reported incomplete: %v / %q",
			res.Incomplete, res.IncompleteReason)
	}
}
