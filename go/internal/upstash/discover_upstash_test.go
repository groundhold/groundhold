package upstash

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"groundhold/internal/provider"
)

// compile-time proof the driver is a Discoverer (the crawl's only requirement
// beyond Name()).
var _ provider.Discoverer = (*Driver)(nil)

// testDriver points a driver at an httptest server with canned creds.
func testDriver(baseURL string, c *http.Client) *Driver {
	return &Driver{
		HTTP:    c,
		Now:     time.Now,
		email:   "me@example.com",
		apiKey:  "key-123",
		BaseURL: baseURL,
	}
}

const oneDBBody = `[{
  "database_id":"11111111-2222-3333-4444-555555555555",
  "database_name":"cache-prod",
  "region":"us-east-1",
  "tls":true,
  "eviction":true,
  "type":"pro",
  "state":"active"
}]`

func obsMap(obs []provider.Observation) map[string]provider.Observation {
	m := map[string]provider.Observation{}
	for _, o := range obs {
		m[o.Path] = o
	}
	return m
}

// TestListDiscoversOneRedisDB is the golden path: one served database, basic
// auth asserted, providerId/resourceType/observations checked.
func TestListDiscoversOneRedisDB(t *testing.T) {
	var sawAuth bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/redis/databases" {
			t.Fatalf("unexpected path %q", r.URL.Path)
		}
		if r.Method != http.MethodGet {
			t.Fatalf("unexpected method %q", r.Method)
		}
		u, p, ok := r.BasicAuth()
		if !ok || u != "me@example.com" || p != "key-123" {
			t.Fatalf("basic auth = (%q,%q,%v), want me@example.com/key-123", u, p, ok)
		}
		sawAuth = true
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(oneDBBody))
	}))
	defer srv.Close()

	d := testDriver(srv.URL, srv.Client())
	found, diags, err := d.List("")
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if !sawAuth {
		t.Fatal("server never saw an authenticated request")
	}
	if len(found) != 1 {
		t.Fatalf("found %d resources, want 1", len(found))
	}
	got := found[0]
	if got.ProviderID != "upstash:redis:11111111-2222-3333-4444-555555555555" {
		t.Errorf("providerId = %q", got.ProviderID)
	}
	if got.ResourceType != "capability.cache.keyvalue" {
		t.Errorf("resourceType = %q", got.ResourceType)
	}

	m := obsMap(got.Observations)
	wantTrue := map[string]bool{
		"service.managed":        true,
		"encryption.inTransit":   true,
		"network.publicExposure": true, // no PrivateLink/VPC addon => public
	}
	for path, want := range wantTrue {
		o, ok := m[path]
		if !ok {
			t.Errorf("missing observation %q", path)
			continue
		}
		if o.Value != want {
			t.Errorf("%s = %v, want %v", path, o.Value, want)
		}
		if o.Derivation != "measured" {
			t.Errorf("%s derivation = %q, want measured", path, o.Derivation)
		}
	}
	if o := m["location.region"]; o.Value != "us-east-1" || o.Derivation != "measured" {
		t.Errorf("location.region = %+v, want us-east-1/measured", o)
	}
	// at-rest addon absent => the bool is emitted as a MEASURED false (D1050),
	// not omitted: the list response carries the addon flag, so its absence is a
	// read false, not an unknown. Omitting it let a `true` candidate be adopted.
	if o, ok := m["encryption.atRest"]; !ok {
		t.Error("encryption.atRest must be emitted as measured false when addon absent")
	} else if o.Value != false || o.Derivation != "measured" {
		t.Errorf("encryption.atRest = %+v, want false/measured", o)
	}
	// eviction/type/state are noise — never observations.
	for _, noise := range []string{"eviction", "type", "state", "cost.monthly", "availability.class"} {
		if _, ok := m[noise]; ok {
			t.Errorf("unexpected observation %q (noise/omitted)", noise)
		}
	}
	if len(diags) != 1 {
		t.Fatalf("diags = %v, want one engine.protocol diag", diags)
	}
}

// TestListRegionFilter keeps only databases in the requested region.
func TestListRegionFilter(t *testing.T) {
	body := `[
	  {"database_id":"us-1","database_name":"a","region":"us-east-1","tls":true},
	  {"database_id":"eu-1","database_name":"b","region":"eu-west-1","tls":true}
	]`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()

	d := testDriver(srv.URL, srv.Client())
	found, _, err := d.List("eu-west-1")
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(found) != 1 {
		t.Fatalf("found %d, want 1 (region-filtered)", len(found))
	}
	if found[0].ProviderID != "upstash:redis:eu-1" {
		t.Errorf("providerId = %q, want the eu-west-1 db", found[0].ProviderID)
	}
}

// TestListEmptyArray: no databases => zero discovered, no error, no diags.
func TestListEmptyArray(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`[]`))
	}))
	defer srv.Close()

	d := testDriver(srv.URL, srv.Client())
	found, diags, err := d.List("")
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(found) != 0 {
		t.Errorf("found %d, want 0", len(found))
	}
	if len(diags) != 0 {
		t.Errorf("diags = %v, want none", diags)
	}
}

// TestListNon200Errors: a non-200 is a hard error for the whole sweep.
func TestListNon200Errors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"error":"nope"}`))
	}))
	defer srv.Close()

	d := testDriver(srv.URL, srv.Client())
	if _, _, err := d.List(""); err == nil {
		t.Fatal("List: want error on HTTP 403, got nil")
	}
}

// TestListMissingCredsRefuses: no credentials => refuse before any request.
func TestListMissingCredsRefuses(t *testing.T) {
	var hit bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hit = true
		_, _ = w.Write([]byte(`[]`))
	}))
	defer srv.Close()

	d := &Driver{HTTP: srv.Client(), Now: time.Now, BaseURL: srv.URL} // no email/apiKey
	if _, _, err := d.List(""); err == nil {
		t.Fatal("List: want error with missing creds, got nil")
	}
	if hit {
		t.Fatal("a request was sent despite missing credentials (must refuse first)")
	}
}

// TestMapRedisDB is the pure reverse-map table test.
func TestMapRedisDB(t *testing.T) {
	cases := []struct {
		name    string
		in      redisDB
		want    map[string]any // path -> value expected present
		absent  []string       // paths that must NOT be present
		diagLen int
	}{
		{
			name: "public tls db, no addons",
			in: redisDB{
				ID: "d1", Name: "n", Region: "us-east-1", TLS: true,
				Eviction: true, Type: "free", State: "active",
			},
			want: map[string]any{
				"service.managed":        true,
				"location.region":        "us-east-1",
				"encryption.inTransit":   true,
				"network.publicExposure": true,
				"encryption.atRest":      false, // D1050: addon off => measured false, not omitted
			},
			absent:  []string{"availability.class", "cost.monthly"},
			diagLen: 1,
		},
		{
			name: "no tls, private via privateLink, at-rest addon",
			in: func() redisDB {
				db := redisDB{ID: "d2", Name: "n", Region: "eu-west-1", TLS: false}
				db.SecurityAddons.PrivateLink = true
				db.SecurityAddons.EncryptionAtRest = true
				return db
			}(),
			want: map[string]any{
				"encryption.inTransit":   false,
				"network.publicExposure": false, // privateLink fronts it
				"encryption.atRest":      true,
			},
			absent:  nil,
			diagLen: 1,
		},
		{
			name: "region falls back to primary_region",
			in:   redisDB{ID: "d3", Name: "n", PrimaryRegion: "ap-northeast-1", TLS: true},
			want: map[string]any{"location.region": "ap-northeast-1"},
		},
		{
			name: "vpc peering also counts as private",
			in: func() redisDB {
				db := redisDB{ID: "d4", Name: "n", Region: "us-west-1", TLS: true}
				db.SecurityAddons.VPCPeering = true
				return db
			}(),
			want: map[string]any{"network.publicExposure": false},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			obs, diags := mapRedisDB(tc.in)
			m := obsMap(obs)
			for path, want := range tc.want {
				o, ok := m[path]
				if !ok {
					t.Errorf("missing %q", path)
					continue
				}
				if o.Value != want {
					t.Errorf("%s = %v, want %v", path, o.Value, want)
				}
				if o.Derivation != "measured" {
					t.Errorf("%s derivation = %q, want measured", path, o.Derivation)
				}
			}
			for _, path := range tc.absent {
				if _, ok := m[path]; ok {
					t.Errorf("%q present, want absent", path)
				}
			}
			if tc.diagLen != 0 && len(diags) != tc.diagLen {
				t.Errorf("diags = %v, want %d", diags, tc.diagLen)
			}
		})
	}
}
