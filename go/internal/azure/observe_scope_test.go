package azure

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// D294 regression: `observe` builds the driver with NO subscription on purpose
// (a ledger may span subscriptions; every Azure providerId carries its own).
// The read path used to build URLs from the driver's pin regardless, so an
// unpinned driver failed the guard and EVERY Azure observation came back
// "unreadable" — the whole 41-service family, invisible to the gates because
// every test constructed the driver WITH a subscription, a configuration no
// real caller performs. This pins the production construction, not the
// convenient one.
func TestObserveScopesFromProviderIDWhenDriverUnpinned(t *testing.T) {
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		fmt.Fprint(w, `{"location":"westeurope","tags":{"groundhold-capability":"net",
			"groundhold-environment":"canary"},
			"properties":{"provisioningState":"Succeeded","subnets":[{"properties":{}}]}}`)
	}))
	defer srv.Close()

	d := NewDriver("") // exactly how runObserve builds it
	d.BaseURL = srv.URL
	d.token = "test-token"

	pid := "vnet:" + testSub + ":rg1:pv-net-canary"
	obs, _, err := d.Observe("vnet", "net", pid)
	if err != nil {
		t.Fatalf("an unpinned driver must scope from the providerId, got: %v", err)
	}
	if len(obs) == 0 {
		t.Fatal("the read must yield measured observations")
	}
	if !strings.Contains(gotPath, "/subscriptions/"+testSub+"/resourceGroups/rg1/") {
		t.Fatalf("the URL must carry the providerId's subscription, got %q", gotPath)
	}
	// and the driver itself must NOT have been mutated (per-call value copy)
	if d.Subscription != "" {
		t.Fatalf("scoping must not mutate the shared driver, got %q", d.Subscription)
	}
}

// A driver WITH a pin still wins — the pin is a cross-check against reading a
// resource from a subscription the operator did not name.
func TestObserveKeepsThePinWhenSet(t *testing.T) {
	d := NewDriver(testSub)
	d.token = "test-token"
	other := "11111111-2222-3333-4444-555555555555"
	_, _, err := d.Observe("vnet", "net", "vnet:"+other+":rg1:pv-net-foreign")
	if err == nil || !strings.Contains(err.Error(), "not the driver's") {
		t.Fatalf("a pinned driver must refuse a foreign subscription, got: %v", err)
	}
}
