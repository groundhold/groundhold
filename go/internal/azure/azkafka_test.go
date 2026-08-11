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

func azKafkaAttrs() map[string]any {
	return map[string]any{
		"location.region":                "eastus",
		"engine.protocol":                "kafka/3",
		"availability.class":             "regional",
		"encryption.inTransit":           true,
		"encryption.customerManagedKeys": true,
		"service.managed":                true,
	}
}

func azKafkaImpl() map[string]any {
	return map[string]any{
		"resource_group":         "rg1",
		"key_vault_key_uri":      "https://kv1.vault.azure.net/keys/k",
		"user_assigned_identity": "/subscriptions/x/resourceGroups/rg1/providers/Microsoft.ManagedIdentity/userAssignedIdentities/id1",
	}
}

func TestBuildAzKafkaHonors(t *testing.T) {
	p, err := BuildAzKafka("prod", "bus", azKafkaAttrs(), azKafkaImpl(), 1)
	if err != nil {
		t.Fatal(err)
	}
	if p.SKU != "Premium" || !p.ZoneRedundant || !p.CMEK || p.KmsKeyVaultURI == "" {
		t.Fatalf("plan = %+v", p)
	}
	body := p.createBody(map[string]any{})
	props := body["properties"].(map[string]any)
	if props["kafkaEnabled"] != true || props["encryption"] == nil || body["identity"] == nil {
		t.Fatalf("body = %+v", body)
	}
}

func TestBuildAzKafkaRefusals(t *testing.T) {
	cases := map[string]map[string]any{
		"bad-avail":       {"availability.class": "planetary"},
		"intransit-false": {"encryption.inTransit": false},
		"bad-proto":       {"engine.protocol": "amqp/1"},
		"unmanaged":       {"service.managed": false},
		"unknown-attr":    {"kafka.tier": "x"},
	}
	for name, extra := range cases {
		a := azKafkaAttrs()
		for k, v := range extra {
			a[k] = v
		}
		if _, err := BuildAzKafka("prod", "bus", a, azKafkaImpl(), 1); err == nil {
			t.Errorf("%s: expected refusal, got none", name)
		}
	}
	// cmek without the impl pair must refuse.
	if _, err := BuildAzKafka("prod", "bus", azKafkaAttrs(), map[string]any{"resource_group": "rg1"}, 1); err == nil {
		t.Error("cmek without key_vault_key_uri + identity must refuse")
	}
	a := azKafkaAttrs()
	delete(a, "location.region")
	if _, err := BuildAzKafka("prod", "bus", a, azKafkaImpl(), 1); err == nil {
		t.Error("missing location.region must refuse")
	}
}

func azKafkaServer(t *testing.T, capLabel string, zoneRedundant, cmk bool) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			switch r.Method {
			case "PUT":
				w.WriteHeader(200)
				_, _ = w.Write([]byte(`{"properties":{"provisioningState":"Succeeded"}}`))
			case "GET":
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
					`"properties":{"provisioningState":"Succeeded","kafkaEnabled":true,"zoneRedundant":` + zr + enc + `}}`))
			case "DELETE":
				w.WriteHeader(200)
			default:
				w.WriteHeader(404)
			}
		}))
}

func azKafkaDriver(t *testing.T, srv *httptest.Server) *Driver {
	t.Helper()
	d := NewDriver(testSub)
	d.BaseURL = srv.URL
	d.token = "test-token"
	d.Now = time.Now
	d.PollInterval = time.Millisecond
	d.PollTimeout = 2 * time.Second
	return d
}

func TestCreateObserveDeleteAzKafka(t *testing.T) {
	srv := azKafkaServer(t, "bus", true, true)
	defer srv.Close()
	d := azKafkaDriver(t, srv)
	res := d.createAzKafka("prod", "bus", azKafkaAttrs(), azKafkaImpl(), 1)
	if res.Status != "succeeded" || !strings.HasPrefix(res.ProviderID, "azkafka:"+testSub+":rg1:") {
		t.Fatalf("create: %+v", res)
	}
	obs, _, err := d.observeAzKafka("bus", res.ProviderID)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]any{}
	for _, o := range obs {
		got[o.Path] = o.Value
	}
	if got["location.region"] != "eastus" || got["availability.class"] != "regional" ||
		got["engine.protocol"] != "kafka/3" || got["encryption.customerManagedKeys"] != true {
		t.Fatalf("observe: %+v", got)
	}
	if del := d.deleteAzKafka("bus", "prod", res.ProviderID); del.Status != "succeeded" {
		t.Fatalf("delete: %+v", del)
	}
}

func TestDeleteAzKafkaForeignRefused(t *testing.T) {
	srv := azKafkaServer(t, "someone-else", false, false)
	defer srv.Close()
	d := azKafkaDriver(t, srv)
	pid := azKafkaProviderID(testSub, "rg1", azKafkaNamespaceName("prod", "bus", 1))
	res := d.deleteAzKafka("bus", "prod", pid)
	if res.Status != "failed" || !strings.Contains(res.Reason, "not ours") {
		t.Fatalf("foreign namespace must refuse delete, got %+v", res)
	}
}

func TestHonestyHarnessAzKafka(t *testing.T) {
	pid := azKafkaProviderID(testSub, "rg1", azKafkaNamespaceName("prod", "bus", 1))
	p := &certifynet.Probe{
		Name:            "azure/azkafka",
		Classify:        armRole,
		OwnerTagValue:   "bus",
		AssertTransient: true, // D237
		DeterministicID: true,
		// F-LC3 (D518): migrated to the absence property.
		ObserveAbsent: func(pr provider.Provider) ([]provider.Observation, []string, error) {
			return pr.Observe("azkafka", "bus", pid)
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
				Happy: func() *httptest.Server { return azKafkaServer(t, "bus", true, true) },
				Run: func(pr provider.Provider) provider.CreateResult {
					return pr.Create("azkafka", "bus", "prod", azKafkaAttrs(), azKafkaImpl(), "k", 1)
				},
			},
			{
				Name:  "delete",
				Happy: func() *httptest.Server { return azKafkaServer(t, "bus", true, true) },
				Run: func(pr provider.Provider) provider.CreateResult {
					return pr.Delete("azkafka", "bus", "prod", pid, "k")
				},
			},
		},
	}
	certifynet.CertifyDriverNet(t, p)
}

// Weapon 2 (D87), the metamorphic write/read round-trip for
// capability.messaging.kafka on Azure Event Hubs Kafka.
func TestMetamorphicAzKafkaRoundTrip(t *testing.T) {
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
			srv := httptest.NewServer(http.HandlerFunc(
				func(w http.ResponseWriter, r *http.Request) {
					switch r.Method {
					case "PUT":
						body, _ := io.ReadAll(r.Body)
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
						w.WriteHeader(200)
						_, _ = w.Write([]byte(`{"properties":{"provisioningState":"Succeeded"}}`))
					case "GET":
						enc := ""
						if keySource != "" {
							enc = `,"encryption":{"keySource":"` + keySource + `"}`
						}
						_, _ = w.Write([]byte(`{"location":"eastus","tags":{"groundhold-capability":"bus","groundhold-environment":"prod"},` +
							`"properties":{"provisioningState":"Succeeded","kafkaEnabled":true,"zoneRedundant":` + zr + enc + `}}`))
					default:
						w.WriteHeader(200)
					}
				}))
			defer srv.Close()
			d := azKafkaDriver(t, srv)
			a := azKafkaAttrs()
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
			res := d.createAzKafka("prod", "bus", a, impl, 1)
			if res.Status != "succeeded" {
				t.Fatalf("create: %+v", res)
			}
			obs, _, err := d.observeAzKafka("bus", res.ProviderID)
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
