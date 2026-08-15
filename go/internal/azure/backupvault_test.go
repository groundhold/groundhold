package azure

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"groundhold/internal/certifynet"
	"groundhold/internal/provider"
)

func bvAttrs() map[string]any {
	return map[string]any{
		"location.region": "eastus", "service.managed": true,
		"retention.minimum": "720h", "retention.lockMode": "compliance",
	}
}
func bvImpl() map[string]any { return map[string]any{"resource_group": "rg1"} }

func backupVaultDriver(t *testing.T, srv *httptest.Server) *Driver {
	t.Helper()
	d := NewDriver(testSub)
	d.BaseURL = srv.URL
	d.token = "test-token"
	d.Now = func() time.Time { return time.Date(2026, 7, 19, 0, 0, 0, 0, time.UTC) }
	d.PollInterval = time.Millisecond
	d.PollTimeout = 2 * time.Second
	return d
}

// TestBuildBackupVaultHonors: the builder maps every attribute + honors BOTH
// lockModes (the Azure parity win) into the immutability state.
func TestBuildBackupVaultHonors(t *testing.T) {
	// compliance -> Locked
	p, err := BuildBackupVault("prod", "archive", bvAttrs(), bvImpl(), 1)
	if err != nil {
		t.Fatal(err)
	}
	if p.Region != "eastus" || p.ResourceGroup != "rg1" || p.RetentionDays != 30 || p.LockState != "Locked" {
		t.Fatalf("compliance vault wrong: %+v", p)
	}
	// governance -> Unlocked (Azure honors it, unlike GCP)
	a := bvAttrs()
	a["retention.lockMode"] = "governance"
	p, err = BuildBackupVault("prod", "archive", a, bvImpl(), 1)
	if err != nil {
		t.Fatal(err)
	}
	if p.LockState != "Unlocked" {
		t.Fatalf("governance must map to Unlocked (Azure honors it), got %q", p.LockState)
	}
	// none -> Disabled: the measured off-value builds a vault with no immutability lock.
	a["retention.lockMode"] = "none"
	p, err = BuildBackupVault("prod", "archive", a, bvImpl(), 1)
	if err != nil {
		t.Fatal(err)
	}
	if p.LockState != "Disabled" {
		t.Fatalf("none must map to Disabled (no immutability lock), got %q", p.LockState)
	}
	a["retention.lockMode"] = "compliance" // restore for the CMK cases below
	// CMK requires the key uri
	a["encryption.customerManagedKeys"] = true
	if _, err := BuildBackupVault("prod", "archive", a, bvImpl(), 1); err == nil {
		t.Error("CMK without key_vault_key_uri must refuse")
	}
	a2impl := map[string]any{"resource_group": "rg1", "key_vault_key_uri": "https://kv.vault.azure.net/keys/k/1"}
	p, err = BuildBackupVault("prod", "archive", a, a2impl, 1)
	if err != nil || !p.CMK || p.KeyVaultKeyURI == "" {
		t.Fatalf("CMK with key uri must be honored, got %+v err=%v", p, err)
	}
}

func TestBuildBackupVaultRefusals(t *testing.T) {
	merge := func(over map[string]any) map[string]any {
		m := bvAttrs()
		for k, v := range over {
			if v == nil {
				delete(m, k)
			} else {
				m[k] = v
			}
		}
		return m
	}
	cases := []struct {
		name  string
		attrs map[string]any
		impl  map[string]any
	}{
		{"unknown attr", merge(map[string]any{"network.publicExposure": true}), bvImpl()},
		{"service.managed false", merge(map[string]any{"service.managed": false}), bvImpl()},
		{"missing region", merge(map[string]any{"location.region": nil}), bvImpl()},
		{"missing resource_group", bvAttrs(), map[string]any{}},
		{"lock without retention", merge(map[string]any{"retention.minimum": nil}), bvImpl()},
		{"bad lockMode enum", merge(map[string]any{"retention.lockMode": "sometimes"}), bvImpl()},
	}
	for _, c := range cases {
		if _, err := BuildBackupVault("prod", "archive", c.attrs, c.impl, 1); err == nil {
			t.Errorf("%s: expected a refusal, got none", c.name)
		}
	}
}

// backupVaultServer serves the vault: PUT succeeds (provisioningState Succeeded),
// GET returns the doc with the given immutability/soft-delete/encryption + tags,
// DELETE 200. locked=true reports immutability Locked (compliance).
func backupVaultServer(t *testing.T, region, immState string, retDays int, cmk bool, tags map[string]string) *httptest.Server {
	t.Helper()
	if tags == nil {
		tags = map[string]string{"groundhold-capability": "archive", "groundhold-environment": "prod"}
	}
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case "PUT":
			w.WriteHeader(201)
			_, _ = w.Write([]byte(`{"properties":{"provisioningState":"Succeeded"}}`))
		case "GET":
			sec := map[string]any{
				"immutabilitySettings": map[string]any{"state": immState},
			}
			if retDays > 0 {
				// D908: Azure returns retentionDurationInDays as a JSON number WITH a
				// fraction (e.g. 30.0), not a bare int — the fake mirrors that so a struct
				// that types it as int fails to parse the whole document, exactly as it did
				// against the real service.
				sec["softDeleteSettings"] = json.RawMessage(fmt.Sprintf(`{"state":"On","retentionDurationInDays":%d.0}`, retDays))
			}
			if cmk {
				sec["encryptionSettings"] = map[string]any{"state": "Enabled"}
			}
			doc := map[string]any{"location": region, "tags": tags,
				"properties": map[string]any{"provisioningState": "Succeeded", "securitySettings": sec}}
			b, _ := json.Marshal(doc)
			_, _ = w.Write(b)
		case "DELETE":
			w.WriteHeader(200)
		default:
			w.WriteHeader(404)
		}
	}))
}

func TestCreateObserveDeleteBackupVault(t *testing.T) {
	srv := backupVaultServer(t, "eastus", "Locked", 30, false, nil)
	defer srv.Close()
	d := backupVaultDriver(t, srv)
	res := d.createBackupVault("prod", "archive", bvAttrs(), bvImpl(), 1)
	if res.Status != "succeeded" || res.ProviderID == "" {
		t.Fatalf("create must succeed with a pid, got %+v", res)
	}
	obs, _, err := d.observeBackupVault("archive", res.ProviderID)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]any{}
	for _, o := range obs {
		got[o.Path] = o.Value
	}
	if got["retention.lockMode"] != "compliance" || got["retention.minimum"] != "720h" || got["location.region"] != "eastus" {
		t.Fatalf("observe reverse-map wrong: %+v", got)
	}
}

// TestObserveBackupVaultDisabledReportsNone: a vault with immutability Disabled reports
// retention.lockMode "none" — a MEASURED off-value (S3 D1041), so a `compliance`
// candidate over an unprotected vault reads VIOLATED, not merely unwitnessed. Before
// this the Disabled state emitted nothing (a one-state emit, false-secure by omission).
func TestObserveBackupVaultDisabledReportsNone(t *testing.T) {
	srv := backupVaultServer(t, "eastus", "Disabled", 30, false,
		map[string]string{"groundhold-capability": "archive", "groundhold-environment": "prod"})
	defer srv.Close()
	d := backupVaultDriver(t, srv)
	pid := backupVaultProviderID(testSub, "rg1", BackupVaultName("prod", "archive", 1))
	obs, _, err := d.observeBackupVault("archive", pid)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]any{}
	for _, o := range obs {
		got[o.Path] = o.Value
	}
	if got["retention.lockMode"] != "none" {
		t.Fatalf("a Disabled vault must report retention.lockMode=none (measured off-value), got %+v", got)
	}
	// retention.minimum still comes from soft-delete when present — never fabricated when absent.
	if got["retention.minimum"] != "720h" {
		t.Fatalf("retention.minimum must reflect soft-delete, got %+v", got)
	}
}

func TestBackupVaultForeignDeleteRefused(t *testing.T) {
	srv := backupVaultServer(t, "eastus", "Disabled", 0, false,
		map[string]string{"groundhold-capability": "someone-else", "groundhold-environment": "prod"})
	defer srv.Close()
	d := backupVaultDriver(t, srv)
	pid := backupVaultProviderID(testSub, "rg1", BackupVaultName("prod", "archive", 1))
	res := d.deleteBackupVault("archive", "prod", pid)
	if res.Status != "failed" || !strings.Contains(res.Reason, "not ours") {
		t.Fatalf("a foreign-tagged vault must be refused, got %+v", res)
	}
}

// D47: a compliance-Locked vault refuses deletion (recovery points are data).
func TestBackupVaultLockedDeleteRefused(t *testing.T) {
	srv := backupVaultServer(t, "eastus", "Locked", 30, false, nil)
	defer srv.Close()
	d := backupVaultDriver(t, srv)
	pid := backupVaultProviderID(testSub, "rg1", BackupVaultName("prod", "archive", 1))
	res := d.deleteBackupVault("archive", "prod", pid)
	if res.Status != "failed" || !strings.Contains(res.Reason, "immutability-Locked") {
		t.Fatalf("a Locked vault must refuse deletion, got %+v", res)
	}
}

// Metamorphic: what create WRITES, observe reads back — across both lockModes, so
// governance is proven to survive the round trip (Azure honors it).
func TestMetamorphicBackupVaultRoundTrip(t *testing.T) {
	for _, tc := range []struct{ mode, wantState, wantVerdict string }{
		{"governance", "Unlocked", "governance"},
		{"compliance", "Locked", "compliance"},
	} {
		var immState string
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.Method {
			case "PUT":
				var body map[string]any
				b, _ := io.ReadAll(r.Body)
				_ = json.Unmarshal(b, &body)
				props, _ := body["properties"].(map[string]any)
				sec, _ := props["securitySettings"].(map[string]any)
				imm, _ := sec["immutabilitySettings"].(map[string]any)
				immState, _ = imm["state"].(string)
				w.WriteHeader(201)
				_, _ = w.Write([]byte(`{"properties":{"provisioningState":"Succeeded"}}`))
			case "GET":
				doc := map[string]any{"location": "eastus",
					"tags": map[string]string{"groundhold-capability": "archive", "groundhold-environment": "prod"},
					"properties": map[string]any{"provisioningState": "Succeeded",
						"securitySettings": map[string]any{"immutabilitySettings": map[string]any{"state": immState}}}}
				bb, _ := json.Marshal(doc)
				_, _ = w.Write(bb)
			}
		}))
		d := backupVaultDriver(t, srv)
		a := bvAttrs()
		a["retention.lockMode"] = tc.mode
		res := d.createBackupVault("prod", "archive", a, bvImpl(), 1)
		if res.Status != "succeeded" {
			t.Fatalf("%s: create failed: %+v", tc.mode, res)
		}
		if immState != tc.wantState {
			t.Fatalf("%s: written immutability state = %q, want %q", tc.mode, immState, tc.wantState)
		}
		obs, _, _ := d.observeBackupVault("archive", res.ProviderID)
		var lm any
		for _, o := range obs {
			if o.Path == "retention.lockMode" {
				lm = o.Value
			}
		}
		if lm != tc.wantVerdict {
			t.Errorf("%s: observed lockMode = %v, want %q", tc.mode, lm, tc.wantVerdict)
		}
		srv.Close()
	}
}

func backupVaultHarnessFake() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case "PUT":
			w.WriteHeader(201)
			_, _ = w.Write([]byte(`{"properties":{"provisioningState":"Succeeded"}}`))
		case "GET":
			_, _ = w.Write([]byte(`{"location":"eastus","tags":{"groundhold-capability":"archive","groundhold-environment":"prod"},` +
				`"properties":{"provisioningState":"Succeeded","securitySettings":{"immutabilitySettings":{"state":"Disabled"}}}}`))
		case "DELETE":
			w.WriteHeader(200)
		default:
			w.WriteHeader(404)
		}
	}))
}

func TestHonestyHarnessAzureBackupVault(t *testing.T) {
	pid := backupVaultProviderID(testSub, "rg1", BackupVaultName("prod", "archive", 1))
	p := &certifynet.Probe{
		Name:            "azure/backupvault",
		AssertTransient: true, // D237
		Classify:        armRole,
		OwnerTagValue:   "archive",
		DeterministicID: true,
		// F-LC3 (D522): migrated to the absence property.
		ObserveAbsent: func(pr provider.Provider) ([]provider.Observation, []string, error) {
			return pr.Observe("backupvault", "archive", pid)
		},
		GoneCode: "ResourceNotFound", // this service's own not-found code (D522)
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
				Happy: func() *httptest.Server { return backupVaultHarnessFake() },
				Run: func(pr provider.Provider) provider.CreateResult {
					return pr.Create("backupvault", "archive", "prod", bvAttrs(), bvImpl(), "k", 1)
				},
			},
			{
				Name:  "delete",
				Happy: func() *httptest.Server { return backupVaultHarnessFake() },
				Run: func(pr provider.Provider) provider.CreateResult {
					return pr.Delete("backupvault", "archive", "prod", pid, "k")
				},
			},
		},
	}
	certifynet.CertifyDriverNet(t, p)
}

// D741: a failed vault delete used to be rewritten to "vault still holds backup
// instances" whatever the cause. A missing permission, a throttle and a policy denial
// all told the operator to wait for recovery points to age out — a cause never
// established, and an action wrong for every case but one.
func TestVaultDeleteRefusalNamesAMeasuredCause(t *testing.T) {
	cases := []struct {
		name      string
		instances string
		instSt    int
		want      string
	}{
		{"the vault really does hold data",
			`{"value":[{"name":"bi-1"},{"name":"bi-2"}]}`, 200, "holds 2 backup instance(s)"},
		{"empty vault — the refusal is something else",
			`{"value":[]}`, 200, "NOT about stored data"},
		{"instances unreadable — say so, never assume empty",
			`{"error":{"code":"AuthorizationFailed"}}`, 403, "cause was not established"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch {
				case strings.Contains(r.URL.Path, "/backupInstances"):
					if c.instSt != 200 {
						w.WriteHeader(c.instSt)
					}
					_, _ = w.Write([]byte(c.instances))
				case r.Method == "DELETE":
					w.WriteHeader(409)
					_, _ = w.Write([]byte(`{"error":{"code":"VaultNotEmpty","message":"provider said this"}}`))
				default:
					_, _ = w.Write([]byte(`{"tags":{"groundhold-capability":"archive",` +
						`"groundhold-environment":"prod"},"properties":{}}`))
				}
			}))
			defer srv.Close()
			d := backupVaultDriver(t, srv)

			res := d.Delete("backupvault", "archive", "prod",
				"backupvault:"+testSub+":rg1:v1", "k")
			if res.Status != "failed" {
				t.Fatalf("a refused delete must fail, got %+v", res)
			}
			if !strings.Contains(res.Reason, c.want) {
				t.Fatalf("reason does not say %q; it said: %s", c.want, res.Reason)
			}
			// The provider's own words must survive in every branch — the tool's
			// reading is added to them, never substituted for them.
			if !strings.Contains(res.Reason, "provider said this") {
				t.Fatalf("the provider's own reason was discarded: %s", res.Reason)
			}
		})
	}
}
