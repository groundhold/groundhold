package hetzner

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func testDriver(t *testing.T, srv *httptest.Server) *Driver {
	t.Helper()
	return &Driver{
		Token:   "test-token",
		BaseURL: srv.URL,
		HTTP:    srv.Client(),
		Now:     time.Now,
	}
}

// one-network server: GET /v1/networks returns a single network with one subnet
// in zone eu-central, pagination terminated (next_page null). Also asserts the
// Bearer header rode along (the crawl authenticates every request).
func oneNetworkServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("Authorization") != "Bearer test-token" {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			switch r.URL.Path {
			case "/networks":
				_, _ = w.Write([]byte(`{"networks":[` +
					`{"id":4711,"name":"prod-net","ip_range":"10.0.0.0/16",` +
					`"subnets":[{"type":"cloud","network_zone":"eu-central","ip_range":"10.0.0.0/24"}]}` +
					`],"meta":{"pagination":{"page":1,"per_page":50,"next_page":null}}}`))
			default:
				w.WriteHeader(http.StatusOK)
			}
		}))
}

func TestListDiscoversNetworks(t *testing.T) {
	srv := oneNetworkServer(t)
	defer srv.Close()
	d := testDriver(t, srv)

	found, diags, err := d.List("") // empty region = whole project, never refused
	if err != nil {
		t.Fatal(err)
	}
	if len(found) != 1 {
		t.Fatalf("want one network, got %d: %+v (diags %v)", len(found), found, diags)
	}
	got := found[0]
	if got.ProviderID != "hetzner:network:4711" {
		t.Fatalf("providerId = %q, want %q", got.ProviderID, "hetzner:network:4711")
	}
	if got.ResourceType != "capability.network.private" {
		t.Fatalf("resourceType = %q, want capability.network.private", got.ResourceType)
	}
	obs := map[string]any{}
	for _, o := range got.Observations {
		if o.Derivation != "measured" {
			t.Fatalf("observation %s derivation = %q, want measured", o.Path, o.Derivation)
		}
		obs[o.Path] = o.Value
	}
	if obs["location.region"] != "eu-central" {
		t.Fatalf("location.region = %v, want eu-central", obs["location.region"])
	}
	if obs["service.managed"] != true {
		t.Fatalf("service.managed = %v, want true", obs["service.managed"])
	}
}

// a scoped pairing prefixes the project label into the providerId.
func TestListScopedProviderID(t *testing.T) {
	srv := oneNetworkServer(t)
	defer srv.Close()
	d := testDriver(t, srv)
	d.Scope = "myproj"

	found, _, err := d.List("")
	if err != nil {
		t.Fatal(err)
	}
	if len(found) != 1 || found[0].ProviderID != "hetzner:myproj:network:4711" {
		t.Fatalf("scoped providerId = %+v, want hetzner:myproj:network:4711", found)
	}
}

func TestListEmptyProject(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte(`{"networks":[],"meta":{"pagination":{"page":1,"per_page":50,"next_page":null}}}`))
		}))
	defer srv.Close()
	d := testDriver(t, srv)

	found, diags, err := d.List("")
	if err != nil {
		t.Fatal(err)
	}
	if len(found) != 0 {
		t.Fatalf("empty project must discover nothing, got %d: %+v (diags %v)", len(found), found, diags)
	}
}

// pagination is honesty-critical: a network only on page 2 must be discovered.
func TestListFollowsPagination(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Query().Get("page") {
			case "", "1":
				_, _ = w.Write([]byte(`{"networks":[` +
					`{"id":1,"subnets":[{"network_zone":"eu-central"}]}` +
					`],"meta":{"pagination":{"page":1,"per_page":50,"next_page":2}}}`))
			case "2":
				_, _ = w.Write([]byte(`{"networks":[` +
					`{"id":2,"subnets":[{"network_zone":"us-east"}]}` +
					`],"meta":{"pagination":{"page":2,"per_page":50,"next_page":null}}}`))
			default:
				t.Errorf("unexpected page %q", r.URL.Query().Get("page"))
				w.WriteHeader(http.StatusInternalServerError)
			}
		}))
	defer srv.Close()
	d := testDriver(t, srv)

	found, _, err := d.List("")
	if err != nil {
		t.Fatal(err)
	}
	if len(found) != 2 {
		t.Fatalf("want two networks across two pages, got %d: %+v", len(found), found)
	}
	ids := map[string]bool{}
	for _, f := range found {
		ids[f.ProviderID] = true
	}
	if !ids["hetzner:network:1"] || !ids["hetzner:network:2"] {
		t.Fatalf("missing a paged network: %v", ids)
	}
}

func TestListRefusesWithoutToken(t *testing.T) {
	d := &Driver{HTTP: http.DefaultClient, Now: time.Now}
	if _, _, err := d.List(""); err == nil {
		t.Fatal("discovery without a token must refuse")
	}
}

func TestListSurfaces429AsRetryable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = w.Write([]byte(`{"error":{"code":"rate_limit_exceeded"}}`))
		}))
	defer srv.Close()
	d := testDriver(t, srv)

	// the sweep error is collected as a diagnostic (per-sweep isolation), and it
	// names the retryable 429 so the pace scheduler can back off.
	_, diags, err := d.List("")
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, dg := range diags {
		if strings.Contains(dg, "429") && strings.Contains(dg, "retryable") {
			found = true
		}
	}
	if !found {
		t.Fatalf("429 must surface as a retryable diagnostic, got %v", diags)
	}
}
