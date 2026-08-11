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

// D934: the default (non-PITR) account uses a Periodic backup policy, and Azure
// rejects a bare {"type":"Periodic"} — it requires periodicModeProperties. The
// fake accepted the bare shape, so the golden path was field-dead until proven
// on the real cloud. Assert the mode properties are present and well-formed.
func TestBuildCosmosPeriodicCarriesModeProperties(t *testing.T) {
	a := cosmosAttrs()
	delete(a, "encryption.customerManagedKeys") // stay on the default Periodic path
	a["backup.pointInTimeRecovery"] = false
	p, err := BuildCosmos("prod", "sessions", a, cosmosImpl(), 1)
	if err != nil {
		t.Fatal(err)
	}
	if p.PITR {
		t.Fatalf("expected non-PITR plan, got PITR")
	}
	backup := p.createBody(map[string]any{})["properties"].(map[string]any)["backupPolicy"].(map[string]any)
	if backup["type"] != "Periodic" {
		t.Fatalf("backup type = %v, want Periodic", backup["type"])
	}
	mode, ok := backup["periodicModeProperties"].(map[string]any)
	if !ok {
		t.Fatalf("Periodic policy missing periodicModeProperties — Azure 400s this body: %+v", backup)
	}
	if mode["backupIntervalInMinutes"] == nil || mode["backupRetentionIntervalInHours"] == nil {
		t.Fatalf("periodicModeProperties incomplete: %+v", mode)
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

// cosmosLocations is the locations array the fake serves. It served NONE, so the field
// that decides availability.class could not appear in any test in either value — the
// same blind-spot fixture as preflightFake (D750), iamRoleXML (D751) and bkdrServer
// (D752). Default: what this driver now builds for `availability.class: regional`.
var cosmosLocations = `,"locations":[{"locationName":"eastus","isZoneRedundant":true}]`

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
					`"properties":{"provisioningState":"Succeeded","backupPolicy":{"type":"` + backupType + `"}` +
					cosmosLocations + kv + `}}`))
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
		Name:            "azure/cosmos",
		Classify:        armRole,
		OwnerTagValue:   "sessions",
		AssertTransient: true, // D237
		DeterministicID: true,
		// F-LC3 (D518): migrated to the absence property.
		ObserveAbsent: func(pr provider.Provider) ([]provider.Observation, []string, error) {
			return pr.Observe("cosmos", "sessions", pid)
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
			if got["encryption.customerManagedKeys"] != c.cmek {
				t.Errorf("cmek round-trip: want %v got %v", c.cmek, got["encryption.customerManagedKeys"])
			}
		})
	}
}

// D753. `availability.class` was the constant "regional" while the create sent
// `isZoneRedundant: false` — the tool built a single-zone account and reported the class
// this vocabulary defines as "replicated across zones in one region". A contract asking
// to survive a zone failure read satisfied against an account that does not.
func TestCosmosZoneRedundancyIsBuiltAndRead(t *testing.T) {
	t.Run("the create sends the redundancy it promises", func(t *testing.T) {
		p, err := BuildCosmos("prod", "sessions", cosmosAttrs(), cosmosImpl(), 1)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := json.Marshal(p.createBody(nil))
		if !strings.Contains(string(body), `"isZoneRedundant":true`) {
			t.Fatalf("availability.class: regional was declared and the create sends %s — "+
				"a single-zone account cannot survive the zone failure the declaration "+
				"claims (D753)", body)
		}
	})

	cases := []struct {
		name      string
		locations string
		want      any
		diag      string
	}{
		{"zone-redundant", `,"locations":[{"locationName":"eastus","isZoneRedundant":true}]`,
			"regional", ""},
		{"single zone — no value in this enum fits, so none is emitted",
			`,"locations":[{"locationName":"eastus","isZoneRedundant":false}]`,
			nil, "does not survive a zone failure"},
		{"no locations at all", `,"locations":[]`, nil, "reports no locations"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			old := cosmosLocations
			cosmosLocations = c.locations
			defer func() { cosmosLocations = old }()

			srv := cosmosServer(t, "sessions", "Continuous", "")
			defer srv.Close()
			d := cosmosDriver(t, srv)

			res := d.createCosmos("prod", "sessions", cosmosAttrs(), cosmosImpl(), 1)
			if res.Status != "succeeded" {
				t.Fatalf("create: %+v", res)
			}
			obs, diags, err := d.observeCosmos("sessions", res.ProviderID)
			if err != nil {
				t.Fatal(err)
			}
			var got any
			for _, o := range obs {
				if o.Path == "availability.class" {
					got = o.Value
				}
			}
			if got != c.want {
				t.Fatalf("availability.class = %v, want %v", got, c.want)
			}
			if c.diag != "" {
				found := false
				for _, dg := range diags {
					if strings.Contains(dg, c.diag) {
						found = true
					}
				}
				if !found {
					t.Fatalf("withheld the value and said nothing: %v", diags)
				}
			}
		})
	}
}
