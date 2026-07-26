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
		// AssertTransient left false — D237 TODO: this driver's create/delete ladder
		// still maps 429/503/403 to terminal failed (and drops the providerId); it must
		// route through provider.MutationResult before the transient invariant can lock.
		Name:            "azure/aisearch",
		Classify:        armRole,
		OwnerTagValue:   "catalog",
		AssertTransient: true, // D237
		DeterministicID: true,
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
			if _, has := got["encryption.customerManagedKeys"]; has != c.cmek {
				t.Errorf("cmek round-trip: want present=%v got %v", c.cmek, got["encryption.customerManagedKeys"])
			}
		})
	}
}
