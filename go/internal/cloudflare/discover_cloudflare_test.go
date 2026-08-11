package cloudflare

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"groundhold/internal/provider"
)

// dnsOnly keeps just the DNS records from a discovery result, so the DNS-focused tests
// count DNS behaviour independent of the per-zone capability.security.waf added in D874.
func dnsOnly(in []provider.Discovered) []provider.Discovered {
	var out []provider.Discovered
	for _, f := range in {
		if f.ResourceType == "capability.dns.record" {
			out = append(out, f)
		}
	}
	return out
}

func testDriver(t *testing.T, srv *httptest.Server) *Driver {
	t.Helper()
	return &Driver{
		Token:   "test-token",
		BaseURL: srv.URL,
		HTTP:    srv.Client(),
		Now:     time.Now,
	}
}

// oneZoneServer: GET /zones returns a single active zone, GET
// /zones/{id}/dns_records returns a proxied CNAME and an unproxied A. Every
// response asserts the Bearer header rode along (the crawl authenticates every
// request), and terminates pagination (total_pages=1).
func oneZoneServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("Authorization") != "Bearer test-token" {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			switch r.URL.Path {
			case "/zones":
				_, _ = w.Write([]byte(`{"success":true,"errors":[],"messages":[],` +
					`"result":[{"id":"zone123","name":"connect.example.com","status":"active"}],` +
					`"result_info":{"page":1,"per_page":100,"count":1,"total_count":1,"total_pages":1}}`))
			case "/zones/zone123/dns_records":
				_, _ = w.Write([]byte(`{"success":true,"errors":[],"messages":[],"result":[` +
					`{"id":"recCNAME","type":"CNAME","name":"www.connect.example.com",` +
					`"content":"origin.example.com","proxied":true,"ttl":1},` +
					`{"id":"recA","type":"A","name":"connect.example.com",` +
					`"content":"203.0.113.10","proxied":false,"ttl":300}` +
					`],"result_info":{"page":1,"per_page":100,"count":2,"total_count":2,"total_pages":1}}`))
			default:
				w.WriteHeader(http.StatusNotFound)
			}
		}))
}

// obsMap flattens a Discovered's observations, asserting every one is `measured`.
func obsMap(t *testing.T, obs []provider.Observation) map[string]any {
	t.Helper()
	m := map[string]any{}
	for _, o := range obs {
		if o.Derivation != "measured" {
			t.Fatalf("observation %s derivation = %q, want measured", o.Path, o.Derivation)
		}
		m[o.Path] = o.Value
	}
	return m
}

func TestListDiscoversDNSRecords(t *testing.T) {
	srv := oneZoneServer(t)
	defer srv.Close()
	d := testDriver(t, srv)

	found, diags, err := d.List("") // empty region = whole account, never refused
	if err != nil {
		t.Fatal(err)
	}
	found = dnsOnly(found)
	if len(diags) != 0 {
		t.Fatalf("unexpected diags: %v", diags)
	}
	if len(found) != 2 {
		t.Fatalf("want two records, got %d: %+v", len(found), found)
	}

	byID := map[string]provider.Discovered{}
	for _, f := range found {
		if f.ResourceType != "capability.dns.record" {
			t.Fatalf("resourceType = %q, want capability.dns.record", f.ResourceType)
		}
		byID[f.ProviderID] = f
	}

	// the proxied CNAME: dns.proxied=true, target + type reverse-mapped.
	cname, ok := byID["dns:zone123:recCNAME"]
	if !ok {
		t.Fatalf("missing CNAME providerId dns:zone123:recCNAME: %v", byID)
	}
	cm := obsMap(t, cname.Observations)
	if cm["dns.type"] != "CNAME" {
		t.Fatalf("CNAME dns.type = %v, want CNAME", cm["dns.type"])
	}
	if cm["dns.target"] != "origin.example.com" {
		t.Fatalf("CNAME dns.target = %v, want origin.example.com", cm["dns.target"])
	}
	if cm["dns.proxied"] != true {
		t.Fatalf("proxied CNAME dns.proxied = %v, want true", cm["dns.proxied"])
	}
	if cm["service.managed"] != true {
		t.Fatalf("service.managed = %v, want true", cm["service.managed"])
	}

	// the unproxied A: dns.proxied=false (grey-cloud, direct to origin).
	a, ok := byID["dns:zone123:recA"]
	if !ok {
		t.Fatalf("missing A providerId dns:zone123:recA: %v", byID)
	}
	am := obsMap(t, a.Observations)
	if am["dns.type"] != "A" {
		t.Fatalf("A dns.type = %v, want A", am["dns.type"])
	}
	if am["dns.target"] != "203.0.113.10" {
		t.Fatalf("A dns.target = %v, want 203.0.113.10", am["dns.target"])
	}
	if am["dns.proxied"] != false {
		t.Fatalf("unproxied A dns.proxied = %v, want false", am["dns.proxied"])
	}
}

// region is a zone-name FILTER: a non-matching name yields nothing, never a refusal.
func TestListRegionFiltersByZoneName(t *testing.T) {
	srv := oneZoneServer(t)
	defer srv.Close()
	d := testDriver(t, srv)

	found, _, err := d.List("other.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if len(found) != 0 {
		t.Fatalf("filter to a non-matching zone must discover nothing, got %d", len(found))
	}

	found, _, err = d.List("connect.example.com")
	if err != nil {
		t.Fatal(err)
	}
	found = dnsOnly(found)
	if len(found) != 2 {
		t.Fatalf("matching zone filter must discover both records, got %d", len(found))
	}
}

// Observe reverse-maps a single bound record via GET /zones/{id}/dns_records/{id},
// sharing mapRecord with List — the proxied CNAME maps to dns.proxied=true.
func TestObserveSingleRecord(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("Authorization") != "Bearer test-token" {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			if r.URL.Path != "/zones/zone123/dns_records/recCNAME" {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			_, _ = w.Write([]byte(`{"success":true,"errors":[],"messages":[],` +
				`"result":{"id":"recCNAME","type":"CNAME","name":"www.connect.example.com",` +
				`"content":"origin.example.com","proxied":true,"ttl":1}}`))
		}))
	defer srv.Close()
	d := testDriver(t, srv)

	obs, diags, err := d.Observe("cloudflare", "capability.dns.record", "dns:zone123:recCNAME")
	if err != nil {
		t.Fatal(err)
	}
	if len(diags) != 0 {
		t.Fatalf("unexpected diags: %v", diags)
	}
	m := obsMap(t, obs)
	if m["dns.type"] != "CNAME" || m["dns.target"] != "origin.example.com" || m["dns.proxied"] != true {
		t.Fatalf("Observe reverse-map = %v, want CNAME/origin.example.com/true", m)
	}
}

func TestObserveRejectsMalformedProviderID(t *testing.T) {
	d := &Driver{Token: "test-token", HTTP: http.DefaultClient, Now: time.Now}
	if _, _, err := d.Observe("cloudflare", "capability.dns.record", "zone123/recCNAME"); err == nil {
		t.Fatal("Observe with a non-dns:<zone>:<record> providerId must refuse")
	}
}

func TestListRefusesWithoutToken(t *testing.T) {
	d := &Driver{HTTP: http.DefaultClient, Now: time.Now}
	if _, _, err := d.List(""); err == nil {
		t.Fatal("discovery without a token must refuse")
	}
}

// a zone whose record list 429s becomes a per-zone diagnostic naming the retryable
// 429 — never a hard failure that hides the rest of the crawl.
func TestListZoneRecordFailureIsDiagnostic(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/zones":
				_, _ = w.Write([]byte(`{"success":true,"result":[` +
					`{"id":"zoneOK","name":"ok.example.com"},` +
					`{"id":"zoneBusy","name":"busy.example.com"}` +
					`],"result_info":{"page":1,"total_pages":1}}`))
			case "/zones/zoneOK/dns_records":
				_, _ = w.Write([]byte(`{"success":true,"result":[` +
					`{"id":"r1","type":"A","name":"ok.example.com","content":"192.0.2.1","proxied":false}` +
					`],"result_info":{"page":1,"total_pages":1}}`))
			case "/zones/zoneBusy/dns_records":
				w.WriteHeader(http.StatusTooManyRequests)
				_, _ = w.Write([]byte(`{"success":false,"errors":[{"code":10000}]}`))
			default:
				w.WriteHeader(http.StatusNotFound)
			}
		}))
	defer srv.Close()
	d := testDriver(t, srv)

	found, diags, err := d.List("")
	if err != nil {
		t.Fatal(err)
	}
	found = dnsOnly(found)
	if len(found) != 1 || found[0].ProviderID != "dns:zoneOK:r1" {
		t.Fatalf("the healthy zone's record must still be discovered, got %+v", found)
	}
	busy := false
	for _, dg := range diags {
		if strings.Contains(dg, "busy.example.com") && strings.Contains(dg, "429") && strings.Contains(dg, "retryable") {
			busy = true
		}
	}
	if !busy {
		t.Fatalf("the busy zone's 429 must surface as a retryable diagnostic, got %v", diags)
	}
}

// pagination is honesty-critical: a record only on page 2 must be discovered.
func TestListFollowsPagination(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/zones":
				_, _ = w.Write([]byte(`{"success":true,"result":[{"id":"z1","name":"ex.com"}],` +
					`"result_info":{"page":1,"total_pages":1}}`))
			case "/zones/z1/dns_records":
				switch r.URL.Query().Get("page") {
				case "", "1":
					_, _ = w.Write([]byte(`{"success":true,"result":[` +
						`{"id":"p1","type":"A","name":"a.ex.com","content":"192.0.2.1","proxied":false}` +
						`],"result_info":{"page":1,"total_pages":2}}`))
				case "2":
					_, _ = w.Write([]byte(`{"success":true,"result":[` +
						`{"id":"p2","type":"A","name":"b.ex.com","content":"192.0.2.2","proxied":false}` +
						`],"result_info":{"page":2,"total_pages":2}}`))
				default:
					t.Errorf("unexpected page %q", r.URL.Query().Get("page"))
					w.WriteHeader(http.StatusInternalServerError)
				}
			default:
				w.WriteHeader(http.StatusNotFound)
			}
		}))
	defer srv.Close()
	d := testDriver(t, srv)

	found, _, err := d.List("")
	if err != nil {
		t.Fatal(err)
	}
	found = dnsOnly(found)
	if len(found) != 2 {
		t.Fatalf("want two records across two pages, got %d: %+v", len(found), found)
	}
	ids := map[string]bool{}
	for _, f := range found {
		ids[f.ProviderID] = true
	}
	if !ids["dns:z1:p1"] || !ids["dns:z1:p2"] {
		t.Fatalf("missing a paged record: %v", ids)
	}
}

// mutations refuse-closed: read-only pairing never provisions.
func TestMutationsRefuseClosed(t *testing.T) {
	d := &Driver{Token: "test-token", HTTP: http.DefaultClient, Now: time.Now}
	if err := d.Validate("cloudflare", "capability.dns.record", "prod", nil, nil, 1); err == nil {
		t.Fatal("Validate must refuse")
	}
	if r := d.Create("cloudflare", "capability.dns.record", "prod", nil, nil, "k", 1); r.Status != "failed" {
		t.Fatalf("Create status = %q, want failed", r.Status)
	}
	if r := d.Update("cloudflare", "capability.dns.record", "prod", "dns:z:r", nil, nil, nil, "k"); r.Status != "failed" {
		t.Fatalf("Update status = %q, want failed", r.Status)
	}
	if r := d.Delete("cloudflare", "capability.dns.record", "prod", "dns:z:r", "k"); r.Status != "failed" {
		t.Fatalf("Delete status = %q, want failed", r.Status)
	}
	if class, _ := d.ClassifyChange("cloudflare", "dns.target", "a", "b", nil); class != "unsupported" {
		t.Fatalf("ClassifyChange class = %q, want unsupported", class)
	}
}
