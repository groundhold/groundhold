package azure

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// pagedPermFake serves Microsoft.Authorization/permissions across TWO pages, the way
// ARM's own specification says the operation answers: `Permissions_ListForResource` and
// `Permissions_ListForResourceGroup` both carry `x-ms-pageable: {nextLinkName: nextLink}`.
type pagedPermFake struct {
	page1, page2 string
	endless      bool
	pages        int
}

func (f *pagedPermFake) driver(t *testing.T) *Driver {
	t.Helper()
	var base string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.pages++
		if f.endless {
			_, _ = w.Write([]byte(`{"value":[],"nextLink":"` + base +
				r.URL.Path + `?api-version=x&$skiptoken=more"}`))
			return
		}
		if strings.Contains(r.URL.RawQuery, "skiptoken") {
			_, _ = w.Write([]byte(f.page2))
			return
		}
		_, _ = w.Write([]byte(`{"value":` + f.page1 + `,"nextLink":"` + base +
			r.URL.Path + `?api-version=x&$skiptoken=2"}`))
	}))
	base = srv.URL
	t.Cleanup(srv.Close)
	d := NewDriver(testSub)
	d.BaseURL = srv.URL
	d.token = "test-token"
	d.Now = time.Now
	d.PollInterval = time.Millisecond
	return d
}

// TestAzureResourceDenialWaitsForTheLastPage is D869.
//
// `CheckResourcePermissions` is documented as the AUTHORITATIVE half of the preflight:
// "the permissions list at the resource's own scope includes every inherited assignment,
// so an ungranted action IS a real denial", and `internal/apply` turns that denial into a
// refusal that blocks the apply. It rested on ONE page of a listing ARM pages.
//
// The direction is unusual for this class and it still qualifies. The tool tells an
// operator they lack a permission they hold, and blocks work that would have succeeded —
// so a person acting on what the tool said is worse off than if it had said nothing, which
// is the test the freeze is written around. Truncation can only REMOVE grants, never add
// one, so it is a false denial and never a false permit.
//
// The other two clouds already had it right, which is what makes this an instance rather
// than a class: AWS's simulator follows its Marker and refuses past fifty pages, and GCP's
// testIamPermissions is a server-side query with no pages at all.
func TestAzureResourceDenialWaitsForTheLastPage(t *testing.T) {
	f := &pagedPermFake{
		page1: `[{"actions":["Microsoft.Storage/*/read"],"notActions":[]}]`,
		page2: `{"value":[{"actions":["Microsoft.Cache/*"],"notActions":[]}]}`,
	}
	d := f.driver(t)
	pid := redisAzureProviderID(testSub, "rg1", "cache-x")
	denied, _, err := d.CheckResourcePermissions("rediscache", pid,
		[]string{"Microsoft.Cache/Redis/write"})
	if err != nil {
		t.Fatalf("check: %v", err)
	}
	if len(denied) != 0 {
		t.Fatalf("denied %v after reading %d page(s) — the grant sat on page two, and this "+
			"denial is authoritative: internal/apply refuses the whole apply on it. The tool "+
			"would be telling an operator they lack a permission they hold (D869).",
			denied, f.pages)
	}
}

// TestAzurePermissionsEndlessPagingIsInconclusiveNotDenial: a chain that never ends must
// be an ERROR, which `internal/apply` reads as unattested. Returning the pages read so far
// would be the same lie in a helper's clothes — and here it would arrive as a refusal.
func TestAzurePermissionsEndlessPagingIsInconclusiveNotDenial(t *testing.T) {
	f := &pagedPermFake{endless: true}
	d := f.driver(t)
	pid := redisAzureProviderID(testSub, "rg1", "cache-x")
	denied, _, err := d.CheckResourcePermissions("rediscache", pid,
		[]string{"Microsoft.Cache/Redis/write"})
	if err == nil {
		t.Fatalf("an endless page chain produced a verdict (denied=%v) instead of an error", denied)
	}
	if len(denied) != 0 {
		t.Fatalf("an unfinished read reported %v as denied", denied)
	}
}
