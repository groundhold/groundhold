package azure

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"groundhold/internal/provider"
)

// permFake serves Microsoft.Authorization/permissions with a fixed entry set, and
// records the scope path it was queried at.
type permFake struct {
	json       string
	lastScope  string
	httpStatus int
}

func (f *permFake) driver(t *testing.T) *Driver {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.URL.Path, "/providers/Microsoft.Authorization/permissions") {
			http.Error(w, "unexpected path", http.StatusBadRequest)
			return
		}
		f.lastScope = strings.TrimSuffix(r.URL.Path, "/providers/Microsoft.Authorization/permissions")
		if f.httpStatus != 0 {
			http.Error(w, `{"error":{"code":"AuthorizationFailed"}}`, f.httpStatus)
			return
		}
		_, _ = w.Write([]byte(f.json))
	}))
	t.Cleanup(srv.Close)
	d := NewDriver(testSub)
	d.BaseURL = srv.URL
	d.token = "test-token"
	d.Now = time.Now
	return d
}

// TestAzureCheckPermissions_Subscription: a granted action passes; an ungranted one
// is UNATTESTED (never denied) at subscription scope.
func TestAzureCheckPermissions_Subscription(t *testing.T) {
	f := &permFake{json: `{"value":[{"actions":["Microsoft.Cache/*"],"notActions":[]}]}`}
	d := f.driver(t)
	denied, unatt, err := d.CheckPermissions(testSub, []string{
		"Microsoft.Cache/Redis/write",                     // granted by the wildcard
		"Microsoft.DBforPostgreSQL/flexibleServers/write", // not granted
	})
	if err != nil {
		t.Fatalf("check: %v", err)
	}
	if len(denied) != 0 {
		t.Fatalf("subscription scope must never DENY (no deny-assignment signal), got %v", denied)
	}
	if strings.Join(unatt, ",") != "Microsoft.DBforPostgreSQL/flexibleServers/write" {
		t.Fatalf("ungranted action must be unattested, got %v", unatt)
	}
	if f.lastScope != "/subscriptions/"+testSub {
		t.Fatalf("must query subscription scope, got %q", f.lastScope)
	}
}

// TestAzureCheckResourcePermissions_Authoritative: at the resource scope an ungranted
// action IS a denial; a notActions match is a denial; and the resource id is built.
func TestAzureCheckResourcePermissions_Authoritative(t *testing.T) {
	f := &permFake{json: `{"value":[{"actions":["Microsoft.Cache/*"],"notActions":["Microsoft.Cache/Redis/delete"]}]}`}
	d := f.driver(t)
	pid := redisAzureProviderID(testSub, "rg1", "cache-x")
	denied, _, err := d.CheckResourcePermissions("rediscache", pid, []string{
		"Microsoft.Cache/Redis/write",  // granted
		"Microsoft.Cache/Redis/delete", // in notActions -> denied
		"Microsoft.Cache/Redis/read",   // granted by wildcard
	})
	if err != nil {
		t.Fatalf("check: %v", err)
	}
	if strings.Join(denied, ",") != "Microsoft.Cache/Redis/delete" {
		t.Fatalf("only the notActions-excluded action must be denied, got %v", denied)
	}
	want := "/subscriptions/" + testSub + "/resourceGroups/rg1/providers/Microsoft.Cache/Redis/cache-x"
	if f.lastScope != want {
		t.Fatalf("resource scope = %q, want %q", f.lastScope, want)
	}
}

// TestAzureCheckResource_NoSurface: an unmapped service falls back.
func TestAzureCheckResource_NoSurface(t *testing.T) {
	f := &permFake{json: `{"value":[]}`}
	d := f.driver(t)
	_, _, err := d.CheckResourcePermissions("metricalert", "azalert:"+testSub+":rg1:a1", []string{"Microsoft.Insights/metricAlerts/write"})
	if err != provider.ErrNoResourceSurface {
		t.Fatalf("unmapped service must return ErrNoResourceSurface, got %v", err)
	}
}

// TestAzurePreflight_Inconclusive: a non-200 permissions read is an error, never denied.
func TestAzurePreflight_Inconclusive(t *testing.T) {
	f := &permFake{httpStatus: http.StatusForbidden}
	d := f.driver(t)
	if _, _, err := d.CheckPermissions(testSub, []string{"Microsoft.Cache/Redis/write"}); err == nil {
		t.Fatal("a permissions read the caller cannot do must be an error, not a pass/denial")
	}
}

func TestAzGlob(t *testing.T) {
	cases := []struct {
		pat, act string
		want     bool
	}{
		{"Microsoft.Cache/*", "Microsoft.Cache/Redis/write", true},
		{"*", "anything/at/all", true},
		{"Microsoft.Cache/*/delete", "Microsoft.Cache/Redis/delete", true},
		{"Microsoft.Cache/Redis/read", "Microsoft.Cache/Redis/write", false},
		{"microsoft.cache/*", "Microsoft.Cache/Redis/write", true}, // case-insensitive
	}
	for _, c := range cases {
		if got := azGlob(c.pat, c.act); got != c.want {
			t.Fatalf("azGlob(%q,%q)=%v want %v", c.pat, c.act, got, c.want)
		}
	}
}
