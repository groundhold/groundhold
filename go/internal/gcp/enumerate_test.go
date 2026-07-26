package gcp

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"groundhold/internal/provider"
)

// Compile-time proof the GCP driver satisfies the crawl's scope fan-out
// contract (D141): the gentle crawl fans a scopeless pairing out to a
// provider's scopes via provider.Enumerator.
var _ provider.Enumerator = (*Driver)(nil)

// A fake Cloud Resource Manager projects.list endpoint, paginated: page one
// returns two projects + a nextPageToken, page two returns the rest. Asserts
// the bearer, follows pagination, and filters lifecycleState==ACTIVE.
func TestEnumerateProjects(t *testing.T) {
	var page1, page2 bool
	srv := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			requireBearer(t, r)
			if r.URL.Path != "/projects" {
				t.Errorf("unexpected path: %s", r.URL.Path)
			}
			switch r.URL.Query().Get("pageToken") {
			case "":
				page1 = true
				w.Write([]byte(`{"projects":[
				  {"projectId":"alpha-prod","lifecycleState":"ACTIVE"},
				  {"projectId":"beta-dead","lifecycleState":"DELETE_REQUESTED"}
				],"nextPageToken":"tok2"}`))
			case "tok2":
				page2 = true
				w.Write([]byte(`{"projects":[
				  {"projectId":"gamma-staging","lifecycleState":"ACTIVE"}
				]}`))
			default:
				t.Errorf("unexpected pageToken: %q", r.URL.Query().Get("pageToken"))
			}
		}))
	defer srv.Close()
	d := testDriver(t, srv)
	d.CRMBaseURL = srv.URL

	scopes, diags, err := d.Enumerate()
	if err != nil {
		t.Fatal(err)
	}
	if !page1 || !page2 {
		t.Fatalf("both pages must be fetched: page1=%v page2=%v", page1, page2)
	}
	if len(diags) != 0 {
		t.Errorf("unexpected diags: %v", diags)
	}
	// beta-dead is DELETE_REQUESTED and must be filtered out.
	want := []string{"alpha-prod", "gamma-staging"}
	if len(scopes) != len(want) {
		t.Fatalf("scopes = %v, want %v", scopes, want)
	}
	for i, s := range want {
		if scopes[i] != s {
			t.Fatalf("scopes = %v, want %v", scopes, want)
		}
	}
}

// A 403 on projects.list with a pinned project degrades to that one project
// plus a diagnostic — never a fabricated empty list, never a hard failure.
func TestEnumerateForbiddenFallsBackToPinnedProject(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			requireBearer(t, r)
			http.Error(w, `{"error":{"code":403,"message":"denied"}}`, http.StatusForbidden)
		}))
	defer srv.Close()
	d := testDriver(t, srv) // pinned project is "acme-prod"
	d.CRMBaseURL = srv.URL

	scopes, diags, err := d.Enumerate()
	if err != nil {
		t.Fatalf("forbidden with a pinned project must not error: %v", err)
	}
	if len(scopes) != 1 || scopes[0] != "acme-prod" {
		t.Fatalf("scopes = %v, want [acme-prod]", scopes)
	}
	if len(diags) != 1 {
		t.Fatalf("a fall-back must be announced in a diagnostic, got %v", diags)
	}
}

// A 403 with NO project pinned is a real error: an incomplete enumeration is a
// fact, never a silently empty scope list.
func TestEnumerateForbiddenNoProjectIsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			requireBearer(t, r)
			http.Error(w, `denied`, http.StatusForbidden)
		}))
	defer srv.Close()
	d := testDriver(t, srv)
	d.Project = ""
	d.CRMBaseURL = srv.URL

	scopes, _, err := d.Enumerate()
	if err == nil {
		t.Fatal("403 with no pinned project must be an error")
	}
	if scopes != nil {
		t.Errorf("no scopes on error, got %v", scopes)
	}
}
