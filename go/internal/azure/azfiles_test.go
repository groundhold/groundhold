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

func azfilesAttrs() map[string]any {
	return map[string]any{
		"location.region":                "eastus",
		"protocol":                       "nfs/4.1",
		"availability.class":             "regional",
		"encryption.atRest":              true,
		"encryption.customerManagedKeys": true,
		"service.managed":                true,
	}
}

func azfilesImpl() map[string]any {
	return map[string]any{
		"resource_group":         "rg1",
		"key_vault_key_uri":      "https://kv1.vault.azure.net/keys/k",
		"user_assigned_identity": "/subscriptions/x/resourceGroups/rg1/providers/Microsoft.ManagedIdentity/userAssignedIdentities/id1",
	}
}

func TestBuildAzFilesHonors(t *testing.T) {
	p, err := BuildAzFiles("prod", "shared", azfilesAttrs(), azfilesImpl(), 1)
	if err != nil {
		t.Fatal(err)
	}
	// NFS + regional => Premium FileStorage, Premium_ZRS, CMK present.
	if p.Protocol != "NFS" || p.Kind != "FileStorage" || p.SKU != "Premium_ZRS" || p.KmsKeyVaultURI == "" {
		t.Fatalf("plan = %+v", p)
	}
	body := p.accountBody(map[string]any{})
	if body["kind"] != "FileStorage" || body["properties"].(map[string]any)["encryption"] == nil {
		t.Fatalf("body = %+v", body)
	}
	if p.shareBody()["properties"].(map[string]any)["enabledProtocols"] != "NFS" {
		t.Fatalf("share = %+v", p.shareBody())
	}
}

func TestBuildAzFilesSMBZonal(t *testing.T) {
	a := azfilesAttrs()
	a["protocol"] = "smb/3"
	a["availability.class"] = "zonal"
	delete(a, "encryption.customerManagedKeys")
	p, err := BuildAzFiles("prod", "shared", a, map[string]any{"resource_group": "rg1"}, 1)
	if err != nil {
		t.Fatal(err)
	}
	if p.Protocol != "SMB" || p.Kind != "StorageV2" || p.SKU != "Standard_LRS" {
		t.Fatalf("smb-zonal plan = %+v", p)
	}
}

func TestBuildAzFilesRefusals(t *testing.T) {
	cases := map[string]map[string]any{
		"atrest-false": {"encryption.atRest": false},
		"unmanaged":    {"service.managed": false},
		"bad-avail":    {"availability.class": "planetary"},
		"bad-proto":    {"protocol": "afp/1"},
		"unknown-attr": {"filesystem.tier": "x"},
	}
	for name, extra := range cases {
		a := azfilesAttrs()
		for k, v := range extra {
			a[k] = v
		}
		if _, err := BuildAzFiles("prod", "shared", a, azfilesImpl(), 1); err == nil {
			t.Errorf("%s: expected refusal, got none", name)
		}
	}
	// cmek without the impl pair must refuse.
	if _, err := BuildAzFiles("prod", "shared", azfilesAttrs(), map[string]any{"resource_group": "rg1"}, 1); err == nil {
		t.Error("cmek without key_vault_key_uri + identity must refuse")
	}
	// missing region must refuse.
	a := azfilesAttrs()
	delete(a, "location.region")
	if _, err := BuildAzFiles("prod", "shared", a, azfilesImpl(), 1); err == nil {
		t.Error("missing location.region must refuse")
	}
}

// azfilesServer reflects an owned Premium FileStorage account with CMK.
func azfilesServer(t *testing.T, capLabel, kind, sku, keySource string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			switch r.Method {
			case "PUT":
				w.WriteHeader(200)
				_, _ = w.Write([]byte(`{"properties":{"provisioningState":"Succeeded"}}`))
			case "GET":
				enc := ""
				if keySource != "" {
					enc = `,"encryption":{"keySource":"` + keySource + `"}`
				}
				_, _ = w.Write([]byte(`{"location":"eastus","kind":"` + kind + `","sku":{"name":"` + sku + `"},` +
					`"tags":{"groundhold-capability":"` + capLabel + `","groundhold-environment":"prod"},` +
					`"properties":{"provisioningState":"Succeeded"` + enc + `}}`))
			case "DELETE":
				w.WriteHeader(200)
			default:
				w.WriteHeader(404)
			}
		}))
}

func azfilesDriver(t *testing.T, srv *httptest.Server) *Driver {
	t.Helper()
	d := NewDriver(testSub)
	d.BaseURL = srv.URL
	d.token = "test-token"
	d.Now = time.Now
	d.PollInterval = time.Millisecond
	d.PollTimeout = 2 * time.Second
	return d
}

func TestCreateObserveDeleteAzFiles(t *testing.T) {
	srv := azfilesServer(t, "shared", "FileStorage", "Premium_ZRS", "Microsoft.Keyvault")
	defer srv.Close()
	d := azfilesDriver(t, srv)
	res := d.createAzFiles("prod", "shared", azfilesAttrs(), azfilesImpl(), 1)
	if res.Status != "succeeded" || !strings.HasPrefix(res.ProviderID, "azfiles:"+testSub+":rg1:") {
		t.Fatalf("create: %+v", res)
	}
	obs, _, err := d.observeAzFiles("shared", res.ProviderID)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]any{}
	for _, o := range obs {
		got[o.Path] = o.Value
	}
	if got["location.region"] != "eastus" || got["availability.class"] != "regional" ||
		got["encryption.customerManagedKeys"] != true || got["protocol"] != "nfs/4.1" {
		t.Fatalf("observe: %+v", got)
	}
	if del := d.deleteAzFiles("shared", "prod", res.ProviderID); del.Status != "succeeded" {
		t.Fatalf("delete: %+v", del)
	}
}

func TestDeleteAzFilesForeignRefused(t *testing.T) {
	srv := azfilesServer(t, "someone-else", "StorageV2", "Standard_LRS", "")
	defer srv.Close()
	d := azfilesDriver(t, srv)
	pid := azFilesProviderID(testSub, "rg1", azStorageName("prod", "shared", 1), azFilesShareName("prod", "shared", 1))
	res := d.deleteAzFiles("shared", "prod", pid)
	if res.Status != "failed" || !strings.Contains(res.Reason, "not ours") {
		t.Fatalf("foreign account must refuse delete, got %+v", res)
	}
}

func TestHonestyHarnessAzureFiles(t *testing.T) {
	pid := azFilesProviderID(testSub, "rg1", azStorageName("prod", "shared", 1), azFilesShareName("prod", "shared", 1))
	p := &certifynet.Probe{
		// AssertTransient left false — D237 TODO: this driver's create/delete ladder
		// still maps 429/503/403 to terminal failed (and drops the providerId); it must
		// route through provider.MutationResult before the transient invariant can lock.
		Name:            "azure/azurefiles",
		Classify:        armRole,
		OwnerTagValue:   "shared",
		AssertTransient: true, // D237
		DeterministicID: true, // account + share names are chosen
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
					return azfilesServer(t, "shared", "FileStorage", "Premium_ZRS", "Microsoft.Keyvault")
				},
				Run: func(pr provider.Provider) provider.CreateResult {
					return pr.Create("azurefiles", "shared", "prod", azfilesAttrs(), azfilesImpl(), "k", 1)
				},
			},
			{
				Name: "delete",
				Happy: func() *httptest.Server {
					return azfilesServer(t, "shared", "FileStorage", "Premium_ZRS", "Microsoft.Keyvault")
				},
				Run: func(pr provider.Provider) provider.CreateResult {
					return pr.Delete("azurefiles", "shared", "prod", pid, "k")
				},
			},
		},
	}
	certifynet.CertifyDriverNet(t, p)
}

// Weapon 2 (D87), the metamorphic write/read round-trip for
// capability.storage.filesystem on Azure Files. A STATEFUL fake records the
// account kind, sku and CMK key source the create writes and reflects them on
// the observe read; the test varies (protocol, availability, cmek) and asserts
// observe reverse-maps what create was given.
func TestMetamorphicAzFilesRoundTrip(t *testing.T) {
	cases := []struct {
		name      string
		protocol  string
		avail     string
		cmek      bool
		wantProto string
		wantAvail string
	}{
		{"smb-zonal-nocmek", "smb/3", "zonal", false, "smb/3", "zonal"},
		{"nfs-regional-cmek", "nfs/4.1", "regional", true, "nfs/4.1", "regional"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var kind, sku, keySource string
			srv := httptest.NewServer(http.HandlerFunc(
				func(w http.ResponseWriter, r *http.Request) {
					switch r.Method {
					case "PUT":
						body, _ := io.ReadAll(r.Body)
						var doc struct {
							Kind string `json:"kind"`
							Sku  struct {
								Name string `json:"name"`
							} `json:"sku"`
							Properties struct {
								Encryption struct {
									KeySource string `json:"keySource"`
								} `json:"encryption"`
							} `json:"properties"`
						}
						_ = json.Unmarshal(body, &doc)
						if doc.Kind != "" { // the account PUT (not the share/fileservice)
							kind, sku, keySource = doc.Kind, doc.Sku.Name, doc.Properties.Encryption.KeySource
						}
						w.WriteHeader(200)
						_, _ = w.Write([]byte(`{"properties":{"provisioningState":"Succeeded"}}`))
					case "GET":
						enc := ""
						if keySource != "" {
							enc = `,"encryption":{"keySource":"` + keySource + `"}`
						}
						_, _ = w.Write([]byte(`{"location":"eastus","kind":"` + kind + `","sku":{"name":"` + sku + `"},` +
							`"tags":{"groundhold-capability":"shared","groundhold-environment":"prod"},` +
							`"properties":{"provisioningState":"Succeeded"` + enc + `}}`))
					default:
						w.WriteHeader(200)
					}
				}))
			defer srv.Close()
			d := azfilesDriver(t, srv)
			a := azfilesAttrs()
			a["protocol"] = c.protocol
			a["availability.class"] = c.avail
			impl := map[string]any{"resource_group": "rg1"}
			if c.cmek {
				impl["key_vault_key_uri"] = "https://kv1.vault.azure.net/keys/k"
				impl["user_assigned_identity"] = "/subscriptions/x/resourceGroups/rg1/providers/Microsoft.ManagedIdentity/userAssignedIdentities/id1"
			} else {
				delete(a, "encryption.customerManagedKeys")
			}
			res := d.createAzFiles("prod", "shared", a, impl, 1)
			if res.Status != "succeeded" {
				t.Fatalf("create: %+v", res)
			}
			obs, _, err := d.observeAzFiles("shared", res.ProviderID)
			if err != nil {
				t.Fatal(err)
			}
			got := map[string]any{}
			for _, o := range obs {
				got[o.Path] = o.Value
			}
			if got["protocol"] != c.wantProto {
				t.Errorf("protocol round-trip: want %q got %v", c.wantProto, got["protocol"])
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
