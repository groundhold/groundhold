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

func ehItoa(n int) string {
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

func ehAttrs() map[string]any {
	return map[string]any{
		"location.region":                "eastus",
		"retention.window":               "168h",
		"availability.class":             "regional",
		"encryption.customerManagedKeys": true,
		"service.managed":                true,
	}
}

func ehImpl() map[string]any {
	return map[string]any{
		"resource_group":         "rg1",
		"key_vault_key_uri":      "https://kv1.vault.azure.net/keys/k",
		"user_assigned_identity": "/subscriptions/x/resourceGroups/rg1/providers/Microsoft.ManagedIdentity/userAssignedIdentities/id1",
	}
}

func TestBuildEventHubsHonors(t *testing.T) {
	p, err := BuildEventHubs("prod", "events", ehAttrs(), ehImpl(), 1)
	if err != nil {
		t.Fatal(err)
	}
	if p.SKU != "Premium" || !p.ZoneRedundant || p.RetentionDays != 7 || p.KmsKeyVaultURI == "" {
		t.Fatalf("plan = %+v", p)
	}
	body := p.namespaceBody(map[string]any{})
	if body["properties"].(map[string]any)["encryption"] == nil || body["identity"] == nil {
		t.Fatalf("body = %+v", body)
	}
	if p.hubBody()["properties"].(map[string]any)["messageRetentionInDays"] != 7 {
		t.Fatalf("hub = %+v", p.hubBody())
	}
}

func TestBuildEventHubsRefusals(t *testing.T) {
	cases := map[string]map[string]any{
		"bad-avail":     {"availability.class": "planetary"},
		"unmanaged":     {"service.managed": false},
		"long-standard": {"retention.window": "720h", "encryption.customerManagedKeys": false}, // 30 days on Standard
		"unknown-attr":  {"stream.tier": "x"},
	}
	for name, extra := range cases {
		a := ehAttrs()
		for k, v := range extra {
			a[k] = v
		}
		if _, err := BuildEventHubs("prod", "events", a, ehImpl(), 1); err == nil {
			t.Errorf("%s: expected refusal, got none", name)
		}
	}
	// cmek without the impl pair must refuse.
	if _, err := BuildEventHubs("prod", "events", ehAttrs(), map[string]any{"resource_group": "rg1"}, 1); err == nil {
		t.Error("cmek without key_vault_key_uri + identity must refuse")
	}
	a := ehAttrs()
	delete(a, "location.region")
	if _, err := BuildEventHubs("prod", "events", a, ehImpl(), 1); err == nil {
		t.Error("missing location.region must refuse")
	}
}

func ehServer(t *testing.T, capLabel string, zoneRedundant, cmk bool, retentionDays int) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			isHub := strings.Contains(r.URL.Path, "/eventhubs/")
			switch r.Method {
			case "PUT":
				w.WriteHeader(200)
				_, _ = w.Write([]byte(`{"properties":{"provisioningState":"Succeeded"}}`))
			case "GET":
				if isHub {
					_, _ = w.Write([]byte(`{"properties":{"messageRetentionInDays":` + ehItoa(retentionDays) + `}}`))
					return
				}
				zr := "false"
				if zoneRedundant {
					zr = "true"
				}
				enc := ""
				if cmk {
					enc = `,"encryption":{"keySource":"Microsoft.KeyVault"}`
				}
				_, _ = w.Write([]byte(`{"location":"eastus","sku":{"name":"Premium"},` +
					`"tags":{"groundhold-capability":"` + capLabel + `","groundhold-environment":"prod"},` +
					`"properties":{"provisioningState":"Succeeded","zoneRedundant":` + zr + enc + `}}`))
			case "DELETE":
				w.WriteHeader(200)
			default:
				w.WriteHeader(404)
			}
		}))
}

func ehDriver(t *testing.T, srv *httptest.Server) *Driver {
	t.Helper()
	d := NewDriver(testSub)
	d.BaseURL = srv.URL
	d.token = "test-token"
	d.Now = time.Now
	d.PollInterval = time.Millisecond
	d.PollTimeout = 2 * time.Second
	return d
}

func TestCreateObserveDeleteEventHubs(t *testing.T) {
	srv := ehServer(t, "events", true, true, 7)
	defer srv.Close()
	d := ehDriver(t, srv)
	res := d.createEventHubs("prod", "events", ehAttrs(), ehImpl(), 1)
	if res.Status != "succeeded" || !strings.HasPrefix(res.ProviderID, "eventhubs:"+testSub+":rg1:") {
		t.Fatalf("create: %+v", res)
	}
	obs, _, err := d.observeEventHubs("events", res.ProviderID)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]any{}
	for _, o := range obs {
		got[o.Path] = o.Value
	}
	if got["location.region"] != "eastus" || got["availability.class"] != "regional" ||
		got["encryption.customerManagedKeys"] != true || got["retention.window"] != "168h" {
		t.Fatalf("observe: %+v", got)
	}
	if del := d.deleteEventHubs("events", "prod", res.ProviderID); del.Status != "succeeded" {
		t.Fatalf("delete: %+v", del)
	}
}

func TestDeleteEventHubsForeignRefused(t *testing.T) {
	srv := ehServer(t, "someone-else", false, false, 1)
	defer srv.Close()
	d := ehDriver(t, srv)
	pid := eventHubsProviderID(testSub, "rg1", eventHubsNamespaceName("prod", "events", 1), azResourceName("pv-hub", "prod", "events", 1))
	res := d.deleteEventHubs("events", "prod", pid)
	if res.Status != "failed" || !strings.Contains(res.Reason, "not ours") {
		t.Fatalf("foreign namespace must refuse delete, got %+v", res)
	}
}

func TestHonestyHarnessEventHubs(t *testing.T) {
	pid := eventHubsProviderID(testSub, "rg1", eventHubsNamespaceName("prod", "events", 1), azResourceName("pv-hub", "prod", "events", 1))
	p := &certifynet.Probe{
		Name:            "azure/eventhubs",
		Classify:        armRole,
		OwnerTagValue:   "events",
		AssertTransient: true, // D237
		DeterministicID: true,
		// F-LC3 (D518): migrated to the absence property.
		ObserveAbsent: func(pr provider.Provider) ([]provider.Observation, []string, error) {
			return pr.Observe("eventhubs", "events", pid)
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
				Happy: func() *httptest.Server { return ehServer(t, "events", true, true, 7) },
				Run: func(pr provider.Provider) provider.CreateResult {
					return pr.Create("eventhubs", "events", "prod", ehAttrs(), ehImpl(), "k", 1)
				},
			},
			{
				Name:  "delete",
				Happy: func() *httptest.Server { return ehServer(t, "events", true, true, 7) },
				Run: func(pr provider.Provider) provider.CreateResult {
					return pr.Delete("eventhubs", "events", "prod", pid, "k")
				},
			},
		},
	}
	certifynet.CertifyDriverNet(t, p)
}

// Weapon 2 (D87), the metamorphic write/read round-trip for
// capability.streaming.pipe on Azure Event Hubs.
func TestMetamorphicEventHubsRoundTrip(t *testing.T) {
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
			var zr, keySource string
			var retDays int
			srv := httptest.NewServer(http.HandlerFunc(
				func(w http.ResponseWriter, r *http.Request) {
					isHub := strings.Contains(r.URL.Path, "/eventhubs/")
					switch r.Method {
					case "PUT":
						body, _ := io.ReadAll(r.Body)
						if isHub {
							var hd struct {
								Properties struct {
									MessageRetentionInDays int `json:"messageRetentionInDays"`
								} `json:"properties"`
							}
							_ = json.Unmarshal(body, &hd)
							retDays = hd.Properties.MessageRetentionInDays
						} else {
							var nd struct {
								Properties struct {
									ZoneRedundant bool `json:"zoneRedundant"`
									Encryption    struct {
										KeySource string `json:"keySource"`
									} `json:"encryption"`
								} `json:"properties"`
							}
							_ = json.Unmarshal(body, &nd)
							if nd.Properties.ZoneRedundant {
								zr = "true"
							} else {
								zr = "false"
							}
							keySource = nd.Properties.Encryption.KeySource
						}
						w.WriteHeader(200)
						_, _ = w.Write([]byte(`{"properties":{"provisioningState":"Succeeded"}}`))
					case "GET":
						if isHub {
							_, _ = w.Write([]byte(`{"properties":{"messageRetentionInDays":` + ehItoa(retDays) + `}}`))
							return
						}
						enc := ""
						if keySource != "" {
							enc = `,"encryption":{"keySource":"` + keySource + `"}`
						}
						_, _ = w.Write([]byte(`{"location":"eastus","tags":{"groundhold-capability":"events","groundhold-environment":"prod"},` +
							`"properties":{"provisioningState":"Succeeded","zoneRedundant":` + zr + enc + `}}`))
					default:
						w.WriteHeader(200)
					}
				}))
			defer srv.Close()
			d := ehDriver(t, srv)
			a := ehAttrs()
			if c.regional {
				a["availability.class"] = "regional"
			} else {
				a["availability.class"] = "zonal"
			}
			impl := map[string]any{"resource_group": "rg1"}
			if c.cmek {
				impl["key_vault_key_uri"] = "https://kv1.vault.azure.net/keys/k"
				impl["user_assigned_identity"] = "/subscriptions/x/resourceGroups/rg1/providers/Microsoft.ManagedIdentity/userAssignedIdentities/id1"
			} else {
				delete(a, "encryption.customerManagedKeys")
			}
			res := d.createEventHubs("prod", "events", a, impl, 1)
			if res.Status != "succeeded" {
				t.Fatalf("create: %+v", res)
			}
			obs, _, err := d.observeEventHubs("events", res.ProviderID)
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

// D1212: updateEventHubs changes retention.window in place — a PUT of the hub with the new
// messageRetentionInDays, PRESERVING the partition count it read, so the retention policy
// changes WITHOUT replacing the namespace (which drops its buffered events). Ownership is the
// namespace's tags; foreign refused.
func TestUpdateEventHubsRetention(t *testing.T) {
	type put struct {
		retention  int
		partitions int
	}
	newSrv := func(capLabel string, curPartitions int, seen *[]put) *httptest.Server {
		return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			isHub := strings.Contains(r.URL.Path, "/eventhubs/")
			switch r.Method {
			case "GET":
				if isHub {
					_, _ = w.Write([]byte(`{"properties":{"messageRetentionInDays":1,"partitionCount":` + ehItoa(curPartitions) + `}}`))
					return
				}
				_, _ = w.Write([]byte(`{"location":"eastus","sku":{"name":"Premium"},` +
					`"tags":{"groundhold-capability":"` + capLabel + `","groundhold-environment":"prod"},` +
					`"properties":{"provisioningState":"Succeeded"}}`))
			case "PUT":
				if isHub {
					body, _ := io.ReadAll(r.Body)
					var d struct {
						Properties struct {
							MessageRetentionInDays int `json:"messageRetentionInDays"`
							PartitionCount         int `json:"partitionCount"`
						} `json:"properties"`
					}
					_ = json.Unmarshal(body, &d)
					*seen = append(*seen, put{retention: d.Properties.MessageRetentionInDays, partitions: d.Properties.PartitionCount})
				}
				w.WriteHeader(200)
				_, _ = w.Write([]byte(`{"properties":{"provisioningState":"Succeeded"}}`))
			default:
				t.Errorf("unexpected %s", r.Method)
				w.WriteHeader(404)
			}
		}))
	}
	pid := eventHubsProviderID(testSub, "rg1", eventHubsNamespaceName("prod", "events", 1), azResourceName("pv-hub", "prod", "events", 1))

	t.Run("change retention (168h -> 7 days), partition count preserved", func(t *testing.T) {
		var seen []put
		srv := newSrv("events", 4, &seen)
		defer srv.Close()
		d := ehDriver(t, srv)
		res := d.updateEventHubs("events", "prod", pid,
			map[string]any{"retention.window": "168h"}, []string{"retention.window"})
		if res.Status != "succeeded" {
			t.Fatalf("update: %+v", res)
		}
		if len(seen) != 1 || seen[0].retention != 7 || seen[0].partitions != 4 {
			t.Fatalf("must PUT messageRetentionInDays=7 preserving partitionCount=4, got %+v", seen)
		}
	})

	t.Run("foreign namespace refused, no PUT", func(t *testing.T) {
		var seen []put
		srv := newSrv("someone-else", 4, &seen)
		defer srv.Close()
		d := ehDriver(t, srv)
		res := d.updateEventHubs("events", "prod", pid,
			map[string]any{"retention.window": "168h"}, []string{"retention.window"})
		if res.Status != "failed" || !strings.Contains(res.Reason, "not ours") {
			t.Fatalf("a foreign namespace must be refused, got %+v", res)
		}
		if len(seen) != 0 {
			t.Fatalf("a refused update must issue NO PUT, got %+v", seen)
		}
	})
}

func TestClassifyEventHubsChange(t *testing.T) {
	if got, _ := classifyEventHubsChange("retention.window"); got != "mutable" {
		t.Fatalf("retention.window must be mutable (in-place), got %q", got)
	}
	for _, p := range []string{"location.region", "availability.class", "encryption.customerManagedKeys"} {
		if got, _ := classifyEventHubsChange(p); got != "immutable" {
			t.Fatalf("%s must be immutable (replacement), got %q", p, got)
		}
	}
}
