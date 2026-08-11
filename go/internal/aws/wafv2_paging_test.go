package aws

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// TestWAFNameSearchReadsEveryPage is the AWS half of D870.
//
// `wafListByName` searches a page of `ListWebACLs` for a name, and BOTH callers turn a
// miss into a fact. `observeWAF` emits resource-absent with derivation "measured" — a live
// security control reported gone, which the runtime answers by re-creating it. `deleteWAF`
// reports SUCCEEDED as idempotent — the ledger records the firewall retired while it
// stands and keeps filtering traffic.
//
// The listing pages. `ListWebACLsRequest` and `ListWebACLsResponse` both carry a
// `NextMarker` in the service model, and the WebACL quota per scope is the same order as
// the page size. Botocore ships NO paginator entry for this operation, which is why the
// D866 ratchet — built from paginator data — cannot see it. That is worth more than this
// one fix: paginator data is a LOWER BOUND on what paginates, and the service model is the
// fuller authority.
func TestWAFNameSearchReadsEveryPage(t *testing.T) {
	want := wafListedName(t)
	var pages int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if wafTarget2(r) != "ListWebACLs" {
			w.WriteHeader(400)
			return
		}
		pages++
		if m := readJSON3(r); m["NextMarker"] != nil {
			_, _ = w.Write([]byte(`{"WebACLs":[{"Name":"` + want +
				`","Id":"id-1","ARN":"arn:aws:wafv2::000000000000:global/webacl/x/id-1",` +
				`"LockToken":"lt-1"}]}`))
			return
		}
		// A full first page of other people's ACLs, and a marker saying there is more.
		_, _ = w.Write([]byte(`{"WebACLs":[{"Name":"someone-elses","Id":"id-9",` +
			`"ARN":"arn:aws:wafv2::000000000000:global/webacl/y/id-9","LockToken":"lt-9"}],` +
			`"NextMarker":"m2"}`))
	}))
	defer srv.Close()
	d := wafDriver(t, srv)

	s, found, err := d.wafListByName(want)
	if err != nil {
		t.Fatalf("search: %v", err)
	}
	if !found {
		t.Fatalf("the WebACL sat on page two and the search reported it absent after %d "+
			"page(s). observe publishes that as resource-absent MEASURED for a live "+
			"firewall, and delete reports success while it stands (D870).", pages)
	}
	if s.Id != "id-1" {
		t.Fatalf("matched the wrong ACL: %+v", s)
	}
}

// TestWAFNameSearchRefusesAnUnfinishedSweep: an endless chain must be an error. An
// absence is only honest once every page has been read (D860's wording, and the reason
// this bound exists rather than a partial answer).
func TestWAFNameSearchRefusesAnUnfinishedSweep(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"WebACLs":[],"NextMarker":"always-more"}`))
	}))
	defer srv.Close()
	d := wafDriver(t, srv)
	d.PollInterval = time.Millisecond

	if _, found, err := d.wafListByName("anything"); err == nil {
		t.Fatalf("an endless marker chain returned found=%v with no error — a sweep that "+
			"did not finish must not become an absence", found)
	}
}
