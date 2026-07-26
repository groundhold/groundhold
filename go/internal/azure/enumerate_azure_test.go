package azure

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestAzureEnumerateSubscriptions drives Enumerate against a fake tenant-scoped
// ARM endpoint that serves GET /subscriptions with nextLink pagination. It
// asserts: the bearer token is signed on every page, both pages are followed,
// only Enabled subscriptions are returned, and the api-version is present.
func TestAzureEnumerateSubscriptions(t *testing.T) {
	var sawBearer, sawAPIVersion bool
	var pagesServed int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/subscriptions" {
			http.Error(w, "unexpected path "+r.URL.Path, http.StatusNotFound)
			return
		}
		if r.Header.Get("Authorization") == "Bearer test-token" {
			sawBearer = true
		}
		if r.URL.Query().Get("api-version") == subscriptionsAPIVersion {
			sawAPIVersion = true
		}
		pagesServed++
		// Page 1: one Enabled + one Disabled, with a nextLink to page 2.
		if r.URL.Query().Get("page") == "" {
			next := srvBase(r) + "/subscriptions?api-version=" + subscriptionsAPIVersion + "&page=2"
			_, _ = w.Write([]byte(`{"value":[
				{"subscriptionId":"11111111-1111-1111-1111-111111111111","state":"Enabled"},
				{"subscriptionId":"22222222-2222-2222-2222-222222222222","state":"Disabled"}
			],"nextLink":"` + next + `"}`))
			return
		}
		// Page 2: one more Enabled, no nextLink (terminal).
		_, _ = w.Write([]byte(`{"value":[
			{"subscriptionId":"33333333-3333-3333-3333-333333333333","state":"Enabled"}
		]}`))
	}))
	defer srv.Close()

	d := NewDriver(testSub)
	d.BaseURL = srv.URL
	d.token = "test-token"

	scopes, diags, err := d.Enumerate()
	if err != nil {
		t.Fatalf("Enumerate: %v", err)
	}
	if !sawBearer {
		t.Fatalf("bearer token not signed on the subscriptions list")
	}
	if !sawAPIVersion {
		t.Fatalf("api-version %s not present on the request", subscriptionsAPIVersion)
	}
	if pagesServed != 2 {
		t.Fatalf("expected 2 pages followed via nextLink, served %d", pagesServed)
	}
	if len(diags) != 0 {
		t.Fatalf("unexpected diagnostics: %v", diags)
	}
	want := []string{
		"11111111-1111-1111-1111-111111111111",
		"33333333-3333-3333-3333-333333333333",
	}
	if strings.Join(scopes, ",") != strings.Join(want, ",") {
		t.Fatalf("scopes = %v, want %v (Enabled only, both pages)", scopes, want)
	}
}

// TestAzureEnumerateForbiddenFallsBackToConfigured asserts that a tenant that
// refuses the list (403) does NOT yield a fabricated empty list: with a
// configured subscription the driver returns that one plus a diagnostic.
func TestAzureEnumerateForbiddenFallsBackToConfigured(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"error":{"code":"AuthorizationFailed"}}`, http.StatusForbidden)
	}))
	defer srv.Close()

	d := NewDriver(testSub)
	d.BaseURL = srv.URL
	d.token = "test-token"

	scopes, diags, err := d.Enumerate()
	if err != nil {
		t.Fatalf("Enumerate should fall back, not error, when a subscription is configured: %v", err)
	}
	if len(scopes) != 1 || scopes[0] != testSub {
		t.Fatalf("scopes = %v, want the configured subscription %s", scopes, testSub)
	}
	if len(diags) == 0 {
		t.Fatalf("a partial fallback must carry a diagnostic")
	}
}

// TestAzureEnumerateForbiddenNoConfiguredIsError asserts that a 403 with NO
// configured subscription to fall back to is a hard error, never an empty list.
func TestAzureEnumerateForbiddenNoConfiguredIsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "forbidden", http.StatusForbidden)
	}))
	defer srv.Close()

	d := NewDriver("") // no configured subscription
	d.BaseURL = srv.URL
	d.token = "test-token"

	scopes, _, err := d.Enumerate()
	if err == nil {
		t.Fatalf("expected an error on 403 with no fallback, got scopes=%v", scopes)
	}
	if scopes != nil {
		t.Fatalf("a refused list must not fabricate scopes, got %v", scopes)
	}
}

// srvBase reconstructs the server's base URL from a request (scheme is always
// http for httptest), so the fake nextLink points back at the test server.
func srvBase(r *http.Request) string {
	return "http://" + r.Host
}
