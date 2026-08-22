package azure

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"groundhold/internal/certifynet"
	"groundhold/internal/provider"
)

func aiSearchAttrs() map[string]any {
	return map[string]any{
		"location.region":                "eastus",
		"availability.class":             "regional",
		"network.publicExposure":         false,
		"encryption.atRest":              true,
		"encryption.inTransit":           true,
		"encryption.customerManagedKeys": true,
		"service.managed":                true,
	}
}

func aiSearchImpl() map[string]any { return map[string]any{"resource_group": "rg1"} }

func TestBuildAISearchHonors(t *testing.T) {
	p, err := BuildAISearch("prod", "catalog", aiSearchAttrs(), aiSearchImpl(), 1)
	if err != nil {
		t.Fatal(err)
	}
	if p.SKU != "standard" || p.ReplicaCount != 3 || p.Public || !p.CMEK {
		t.Fatalf("plan = %+v", p)
	}
	body := p.createBody(map[string]any{})
	props := body["properties"].(map[string]any)
	if props["publicNetworkAccess"] != "disabled" || props["encryptionWithCmk"] == nil {
		t.Fatalf("body = %+v", props)
	}
}

func TestBuildAISearchRefusals(t *testing.T) {
	cases := map[string]map[string]any{
		"atrest-false":    {"encryption.atRest": false},
		"intransit-false": {"encryption.inTransit": false},
		"unmanaged":       {"service.managed": false},
		"bad-avail":       {"availability.class": "planetary"},
		"unknown-attr":    {"search.tier": "x"},
	}
	for name, extra := range cases {
		a := aiSearchAttrs()
		for k, v := range extra {
			a[k] = v
		}
		if _, err := BuildAISearch("prod", "catalog", a, aiSearchImpl(), 1); err == nil {
			t.Errorf("%s: expected refusal, got none", name)
		}
	}
	a := aiSearchAttrs()
	delete(a, "location.region")
	if _, err := BuildAISearch("prod", "catalog", a, aiSearchImpl(), 1); err == nil {
		t.Error("missing location.region must refuse")
	}
}

func aiSearchServer(t *testing.T, capLabel, sku string, replicas int, access, cmkEnf string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			switch r.Method {
			case "PUT":
				w.WriteHeader(200)
				_, _ = w.Write([]byte(`{"properties":{"provisioningState":"Succeeded"}}`))
			case "GET":
				cmk := ""
				if cmkEnf != "" {
					cmk = `,"encryptionWithCmk":{"enforcement":"` + cmkEnf + `"}`
				}
				_, _ = w.Write([]byte(`{"location":"eastus","sku":{"name":"` + sku + `"},` +
					`"tags":{"groundhold-capability":"` + capLabel + `","groundhold-environment":"prod"},` +
					`"properties":{"provisioningState":"Succeeded","publicNetworkAccess":"` + access +
					`","replicaCount":` + itoaAz(replicas) + cmk + `}}`))
			case "DELETE":
				w.WriteHeader(200)
			default:
				w.WriteHeader(404)
			}
		}))
}

func itoaAz(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

func aiSearchDriver(t *testing.T, srv *httptest.Server) *Driver {
	t.Helper()
	d := NewDriver(testSub)
	d.BaseURL = srv.URL
	d.token = "test-token"
	d.Now = time.Now
	d.PollInterval = time.Millisecond
	d.PollTimeout = 2 * time.Second
	return d
}

func TestCreateObserveDeleteAISearch(t *testing.T) {
	srv := aiSearchServer(t, "catalog", "standard", 3, "disabled", "Enabled")
	defer srv.Close()
	d := aiSearchDriver(t, srv)
	res := d.createAISearch("prod", "catalog", aiSearchAttrs(), aiSearchImpl(), 1)
	if res.Status != "succeeded" || !strings.HasPrefix(res.ProviderID, "aisearch:"+testSub+":rg1:") {
		t.Fatalf("create: %+v", res)
	}
	obs, _, err := d.observeAISearch("catalog", res.ProviderID)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]any{}
	for _, o := range obs {
		got[o.Path] = o.Value
	}
	if got["location.region"] != "eastus" || got["availability.class"] != "regional" ||
		got["network.publicExposure"] != false || got["encryption.customerManagedKeys"] != true {
		t.Fatalf("observe: %+v", got)
	}
	if del := d.deleteAISearch("catalog", "prod", res.ProviderID); del.Status != "succeeded" {
		t.Fatalf("delete: %+v", del)
	}
}

// D956: >=3 replicas distribute across zones only in a region that HAS availability zones.
// northcentralus exposes 0 AZs (field 2026-08-08), so a Standard service with 3 replicas
// there is single-zone — availability.class must be zonal, not regional off the replica
// proxy. The fake routes the subscription-locations call (regionLogicalZones) separately.
func TestObserveAISearchNonAZRegionIsZonal(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/locations") {
			_, _ = w.Write([]byte(`{"value":[{"name":"northcentralus","availabilityZoneMappings":[]}]}`))
			return
		}
		if r.Method == "GET" {
			_, _ = w.Write([]byte(`{"location":"northcentralus","sku":{"name":"standard"},` +
				`"tags":{"groundhold-capability":"catalog","groundhold-environment":"prod"},` +
				`"properties":{"provisioningState":"Succeeded","publicNetworkAccess":"enabled","replicaCount":3}}`))
			return
		}
		w.WriteHeader(200)
	}))
	defer srv.Close()
	d := aiSearchDriver(t, srv)
	obs, diags, err := d.observeAISearch("catalog", "aisearch:"+testSub+":rg1:pv-catalog-prod-abcd1234")
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]any{}
	for _, o := range obs {
		got[o.Path] = o.Value
	}
	if got["availability.class"] != "zonal" {
		t.Fatalf("3 replicas in a non-AZ region must be zonal, got %v (diags %v)", got["availability.class"], diags)
	}
	if len(diags) == 0 {
		t.Error("a downgraded availability.class should carry a diagnostic")
	}
}

func TestDeleteAISearchForeignRefused(t *testing.T) {
	srv := aiSearchServer(t, "someone-else", "basic", 1, "enabled", "")
	defer srv.Close()
	d := aiSearchDriver(t, srv)
	pid := aiSearchProviderID(testSub, "rg1", aiSearchName("prod", "catalog", 1))
	res := d.deleteAISearch("catalog", "prod", pid)
	if res.Status != "failed" || !strings.Contains(res.Reason, "not ours") {
		t.Fatalf("foreign service must refuse delete, got %+v", res)
	}
}

func TestHonestyHarnessAISearch(t *testing.T) {
	pid := aiSearchProviderID(testSub, "rg1", aiSearchName("prod", "catalog", 1))
	p := &certifynet.Probe{
		Name:            "azure/aisearch",
		Classify:        armRole,
		OwnerTagValue:   "catalog",
		AssertTransient: true, // D237
		DeterministicID: true,
		// F-LC3 (D518): migrated to the absence property.
		ObserveAbsent: func(pr provider.Provider) ([]provider.Observation, []string, error) {
			return pr.Observe("aisearch", "catalog", pid)
		},
		New: func(happyURL string, rt http.RoundTripper) provider.Provider {
			d := NewDriver(testSub)
			d.BaseURL = happyURL
			d.HTTP = &http.Client{Transport: rt}
			d.token = "test-token"
			d.Now = time.Now
			d.PollInterval = time.Millisecond
			d.PollTimeout = 2 * time.Second
			return d
		},
		Ops: []certifynet.Op{
			{
				Name:  "create",
				Happy: func() *httptest.Server { return aiSearchServer(t, "catalog", "standard", 3, "disabled", "Enabled") },
				Run: func(pr provider.Provider) provider.CreateResult {
					return pr.Create("aisearch", "catalog", "prod", aiSearchAttrs(), aiSearchImpl(), "k", 1)
				},
			},
			{
				Name:  "delete",
				Happy: func() *httptest.Server { return aiSearchServer(t, "catalog", "standard", 3, "disabled", "Enabled") },
				Run: func(pr provider.Provider) provider.CreateResult {
					return pr.Delete("aisearch", "catalog", "prod", pid, "k")
				},
			},
		},
	}
	certifynet.CertifyDriverNet(t, p)
}

// Weapon 2 (D87), the metamorphic write/read round-trip for
// capability.search.index on Azure AI Search.
func TestMetamorphicAISearchRoundTrip(t *testing.T) {
	cases := []struct {
		name      string
		regional  bool
		cmek      bool
		wantAvail string
	}{
		{"zonal-nocmek", false, false, "zonal"},
		{"regional-cmek", true, true, "regional"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var sku, cmk string
			var replicas int
			srv := httptest.NewServer(http.HandlerFunc(
				func(w http.ResponseWriter, r *http.Request) {
					switch r.Method {
					case "PUT":
						body, _ := io.ReadAll(r.Body)
						var doc struct {
							Sku        struct{ Name string } `json:"sku"`
							Properties struct {
								ReplicaCount      int `json:"replicaCount"`
								EncryptionWithCmk struct {
									Enforcement string `json:"enforcement"`
								} `json:"encryptionWithCmk"`
							} `json:"properties"`
						}
						_ = json.Unmarshal(body, &doc)
						sku, replicas, cmk = doc.Sku.Name, doc.Properties.ReplicaCount, doc.Properties.EncryptionWithCmk.Enforcement
						w.WriteHeader(200)
						_, _ = w.Write([]byte(`{"properties":{"provisioningState":"Succeeded"}}`))
					case "GET":
						cmkS := ""
						if cmk != "" {
							cmkS = `,"encryptionWithCmk":{"enforcement":"` + cmk + `"}`
						}
						_, _ = w.Write([]byte(`{"location":"eastus","sku":{"name":"` + sku + `"},` +
							`"tags":{"groundhold-capability":"catalog","groundhold-environment":"prod"},` +
							`"properties":{"provisioningState":"Succeeded","publicNetworkAccess":"disabled","replicaCount":` + itoaAz(replicas) + cmkS + `}}`))
					default:
						w.WriteHeader(200)
					}
				}))
			defer srv.Close()
			d := aiSearchDriver(t, srv)
			a := aiSearchAttrs()
			if c.regional {
				a["availability.class"] = "regional"
			} else {
				a["availability.class"] = "zonal"
			}
			a["encryption.customerManagedKeys"] = c.cmek
			res := d.createAISearch("prod", "catalog", a, aiSearchImpl(), 1)
			if res.Status != "succeeded" {
				t.Fatalf("create: %+v", res)
			}
			obs, _, err := d.observeAISearch("catalog", res.ProviderID)
			if err != nil {
				t.Fatal(err)
			}
			got := map[string]any{}
			for _, o := range obs {
				got[o.Path] = o.Value
			}
			if got["availability.class"] != c.wantAvail {
				t.Errorf("availability round-trip: want %q got %v", c.wantAvail, got["availability.class"])
			}
			if got["encryption.customerManagedKeys"] != c.cmek {
				t.Errorf("cmek round-trip: want %v got %v", c.cmek, got["encryption.customerManagedKeys"])
			}
		})
	}
}

// D1207: updateAISearch remediates network.publicExposure in place — a PATCH of the service's
// publicNetworkAccess (lowercase enabled/disabled), so a public search service is made private
// WITHOUT a replacement that would destroy every index. Ownership re-checked; foreign refused.
func TestUpdateAISearchPublicExposure(t *testing.T) {
	newSrv := func(tagCap string, seen *[]string) *httptest.Server {
		return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.Method {
			case "GET":
				_, _ = w.Write([]byte(`{"location":"eastus",` +
					`"tags":{"groundhold-capability":"` + tagCap + `","groundhold-environment":"prod"},` +
					`"properties":{"provisioningState":"succeeded","publicNetworkAccess":"enabled"}}`))
			case "PATCH":
				body, _ := io.ReadAll(r.Body)
				var d struct {
					Properties struct {
						PublicNetworkAccess string `json:"publicNetworkAccess"`
					} `json:"properties"`
				}
				_ = json.Unmarshal(body, &d)
				*seen = append(*seen, d.Properties.PublicNetworkAccess)
				w.WriteHeader(200)
				_, _ = w.Write([]byte(`{"properties":{"provisioningState":"succeeded"}}`))
			default:
				t.Errorf("unexpected %s", r.Method)
				w.WriteHeader(404)
			}
		}))
	}

	t.Run("remediate public->private (PATCH publicNetworkAccess=disabled)", func(t *testing.T) {
		var seen []string
		srv := newSrv("catalog", &seen)
		defer srv.Close()
		d := aiSearchDriver(t, srv)
		pid := aiSearchProviderID(d.Subscription, "rg1", "catalog-search")
		res := d.updateAISearch("catalog", "prod", pid,
			map[string]any{"network.publicExposure": false}, []string{"network.publicExposure"})
		if res.Status != "succeeded" {
			t.Fatalf("update: %+v", res)
		}
		if len(seen) != 1 || seen[0] != "disabled" {
			t.Fatalf("must PATCH publicNetworkAccess=disabled (lowercase), got %+v", seen)
		}
	})

	t.Run("foreign service refused, no write", func(t *testing.T) {
		var seen []string
		srv := newSrv("someone-else", &seen)
		defer srv.Close()
		d := aiSearchDriver(t, srv)
		pid := aiSearchProviderID(d.Subscription, "rg1", "catalog-search")
		res := d.updateAISearch("catalog", "prod", pid,
			map[string]any{"network.publicExposure": false}, []string{"network.publicExposure"})
		if res.Status != "failed" || !strings.Contains(res.Reason, "not ours") {
			t.Fatalf("a foreign service must be refused, got %+v", res)
		}
		if len(seen) != 0 {
			t.Fatalf("a refused update must issue NO write, got %+v", seen)
		}
	})
}

func TestClassifyAISearchChange(t *testing.T) {
	if got, _ := classifyAISearchChange("network.publicExposure"); got != "mutable" {
		t.Fatalf("network.publicExposure must be mutable (in-place), got %q", got)
	}
	for _, p := range []string{"location.region", "engine.protocol", "capacity.replicas"} {
		if got, _ := classifyAISearchChange(p); got != "immutable" {
			t.Fatalf("%s must be immutable (replacement), got %q", p, got)
		}
	}
}
