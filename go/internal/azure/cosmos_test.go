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

func cosmosAttrs() map[string]any {
	return map[string]any{
		"location.region":                "eastus",
		"availability.class":             "regional",
		"encryption.customerManagedKeys": true,
		"backup.pointInTimeRecovery":     true,
		"service.managed":                true,
	}
}

func cosmosImpl() map[string]any {
	return map[string]any{
		"resource_group":    "rg1",
		"key_vault_key_uri": "https://kv1.vault.azure.net/keys/k",
	}
}

func TestBuildCosmosHonors(t *testing.T) {
	p, err := BuildCosmos("prod", "sessions", cosmosAttrs(), cosmosImpl(), 1)
	if err != nil {
		t.Fatal(err)
	}
	if !p.PITR || p.KmsKeyVaultURI == "" || !cosmosNameOK.MatchString(p.Account) {
		t.Fatalf("plan = %+v", p)
	}
	body := p.createBody(map[string]any{})
	props := body["properties"].(map[string]any)
	if props["backupPolicy"].(map[string]any)["type"] != "Continuous" || props["keyVaultKeyUri"] == nil {
		t.Fatalf("body = %+v", props)
	}
}

func TestBuildCosmosRefusals(t *testing.T) {
	cases := map[string]map[string]any{
		"deletion-protection": {"deletion.protection": true}, // the honest Azure gap
		"multi-regional":      {"availability.class": "multi-regional"},
		"bad-avail":           {"availability.class": "planetary"},
		"unmanaged":           {"service.managed": false},
		"unknown-attr":        {"nosql.tier": "x"},
	}
	for name, extra := range cases {
		a := cosmosAttrs()
		for k, v := range extra {
			a[k] = v
		}
		if _, err := BuildCosmos("prod", "sessions", a, cosmosImpl(), 1); err == nil {
			t.Errorf("%s: expected refusal, got none", name)
		}
	}
	a := cosmosAttrs()
	if _, err := BuildCosmos("prod", "sessions", a, map[string]any{"resource_group": "rg1"}, 1); err == nil {
		t.Error("cmek without key_vault_key_uri must refuse")
	}
	delete(a, "location.region")
	if _, err := BuildCosmos("prod", "sessions", a, cosmosImpl(), 1); err == nil {
		t.Error("missing location.region must refuse")
	}
}

func cosmosServer(t *testing.T, capLabel, backupType, kms string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			switch r.Method {
			case "PUT":
				w.WriteHeader(200)
				_, _ = w.Write([]byte(`{"properties":{"provisioningState":"Succeeded"}}`))
			case "GET":
				kv := ""
				if kms != "" {
					kv = `,"keyVaultKeyUri":"` + kms + `"`
				}
				_, _ = w.Write([]byte(`{"location":"eastus",` +
					`"tags":{"groundhold-capability":"` + capLabel + `","groundhold-environment":"prod"},` +
					`"properties":{"provisioningState":"Succeeded","backupPolicy":{"type":"` + backupType + `"}` + kv + `}}`))
			case "DELETE":
				w.WriteHeader(200)
			default:
				w.WriteHeader(404)
			}
		}))
}

func cosmosDriver(t *testing.T, srv *httptest.Server) *Driver {
	t.Helper()
	d := NewDriver(testSub)
	d.BaseURL = srv.URL
	d.token = "test-token"
	d.Now = time.Now
	d.PollInterval = time.Millisecond
	d.PollTimeout = 2 * time.Second
	return d
}

func TestCreateObserveDeleteCosmos(t *testing.T) {
	srv := cosmosServer(t, "sessions", "Continuous", "https://kv1.vault.azure.net/keys/k")
	defer srv.Close()
	d := cosmosDriver(t, srv)
	res := d.createCosmos("prod", "sessions", cosmosAttrs(), cosmosImpl(), 1)
	if res.Status != "succeeded" || !strings.HasPrefix(res.ProviderID, "cosmos:"+testSub+":rg1:") {
		t.Fatalf("create: %+v", res)
	}
	obs, _, err := d.observeCosmos("sessions", res.ProviderID)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]any{}
	for _, o := range obs {
		got[o.Path] = o.Value
	}
	if got["location.region"] != "eastus" || got["backup.pointInTimeRecovery"] != true ||
		got["encryption.customerManagedKeys"] != true {
		t.Fatalf("observe: %+v", got)
	}
	if del := d.deleteCosmos("sessions", "prod", res.ProviderID); del.Status != "succeeded" {
		t.Fatalf("delete: %+v", del)
	}
}

func TestDeleteCosmosForeignRefused(t *testing.T) {
	srv := cosmosServer(t, "someone-else", "Periodic", "")
	defer srv.Close()
	d := cosmosDriver(t, srv)
	pid := cosmosProviderID(testSub, "rg1", cosmosAccountName("prod", "sessions", 1))
	res := d.deleteCosmos("sessions", "prod", pid)
	if res.Status != "failed" || !strings.Contains(res.Reason, "not ours") {
		t.Fatalf("foreign account must refuse delete, got %+v", res)
	}
}

func TestHonestyHarnessCosmos(t *testing.T) {
	pid := cosmosProviderID(testSub, "rg1", cosmosAccountName("prod", "sessions", 1))
	p := &certifynet.Probe{
		// AssertTransient left false — D237 TODO: this driver's create/delete ladder
		// still maps 429/503/403 to terminal failed (and drops the providerId); it must
		// route through provider.MutationResult before the transient invariant can lock.
		Name:            "azure/cosmos",
		Classify:        armRole,
		OwnerTagValue:   "sessions",
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
				Name: "create",
				Happy: func() *httptest.Server {
					return cosmosServer(t, "sessions", "Continuous", "https://kv1.vault.azure.net/keys/k")
				},
				Run: func(pr provider.Provider) provider.CreateResult {
					return pr.Create("cosmos", "sessions", "prod", cosmosAttrs(), cosmosImpl(), "k", 1)
				},
			},
			{
				Name: "delete",
				Happy: func() *httptest.Server {
					return cosmosServer(t, "sessions", "Continuous", "https://kv1.vault.azure.net/keys/k")
				},
				Run: func(pr provider.Provider) provider.CreateResult {
					return pr.Delete("cosmos", "sessions", "prod", pid, "k")
				},
			},
		},
	}
	certifynet.CertifyDriverNet(t, p)
}

// Weapon 2 (D87), the metamorphic write/read round-trip for
// capability.database.nosql on Azure Cosmos DB.
func TestMetamorphicCosmosRoundTrip(t *testing.T) {
	cases := []struct {
		name string
		pitr bool
		cmek bool
	}{
		{"bare", false, false},
		{"full", true, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var backupType, kms string
			srv := httptest.NewServer(http.HandlerFunc(
				func(w http.ResponseWriter, r *http.Request) {
					switch r.Method {
					case "PUT":
						body, _ := io.ReadAll(r.Body)
						var doc struct {
							Properties struct {
								BackupPolicy struct {
									Type string `json:"type"`
								} `json:"backupPolicy"`
								KeyVaultKeyUri string `json:"keyVaultKeyUri"`
							} `json:"properties"`
						}
						_ = json.Unmarshal(body, &doc)
						backupType, kms = doc.Properties.BackupPolicy.Type, doc.Properties.KeyVaultKeyUri
						w.WriteHeader(200)
						_, _ = w.Write([]byte(`{"properties":{"provisioningState":"Succeeded"}}`))
					case "GET":
						kv := ""
						if kms != "" {
							kv = `,"keyVaultKeyUri":"` + kms + `"`
						}
						_, _ = w.Write([]byte(`{"location":"eastus","tags":{"groundhold-capability":"sessions","groundhold-environment":"prod"},` +
							`"properties":{"provisioningState":"Succeeded","backupPolicy":{"type":"` + backupType + `"}` + kv + `}}`))
					default:
						w.WriteHeader(200)
					}
				}))
			defer srv.Close()
			d := cosmosDriver(t, srv)
			a := cosmosAttrs()
			a["backup.pointInTimeRecovery"] = c.pitr
			impl := map[string]any{"resource_group": "rg1"}
			if c.cmek {
				impl["key_vault_key_uri"] = "https://kv1.vault.azure.net/keys/k"
			} else {
				delete(a, "encryption.customerManagedKeys")
			}
			res := d.createCosmos("prod", "sessions", a, impl, 1)
			if res.Status != "succeeded" {
				t.Fatalf("create: %+v", res)
			}
			obs, _, err := d.observeCosmos("sessions", res.ProviderID)
			if err != nil {
				t.Fatal(err)
			}
			got := map[string]any{}
			for _, o := range obs {
				got[o.Path] = o.Value
			}
			if got["backup.pointInTimeRecovery"] != c.pitr {
				t.Errorf("pitr round-trip: want %v got %v", c.pitr, got["backup.pointInTimeRecovery"])
			}
			if _, has := got["encryption.customerManagedKeys"]; has != c.cmek {
				t.Errorf("cmek round-trip: want present=%v got %v", c.cmek, got["encryption.customerManagedKeys"])
			}
		})
	}
}
