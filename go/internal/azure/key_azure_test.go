package azure

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func azKeyAttrs() map[string]any {
	return map[string]any{
		"location.region":  "eastus",
		"rotation.period":  "90d",
		"protection.level": "hsm",
		"service.managed":  true,
	}
}

func azKeyImpl() map[string]any {
	return map[string]any{"resource_group": "rg1", "tenant_id": testTenant}
}

func TestBuildAzureKeyHonors(t *testing.T) {
	p, err := BuildAzureKey("prod", "datakey", azKeyAttrs(), azKeyImpl(), 1)
	if err != nil {
		t.Fatal(err)
	}
	// hsm -> RSA-HSM key + a PREMIUM vault
	if p.Kty != "RSA-HSM" || p.VaultSku != "premium" || p.RotationDays != 90 {
		t.Fatalf("plan = %+v", p)
	}
	vbody := p.vaultCreateBody(map[string]any{})
	if vbody["properties"].(map[string]any)["sku"].(map[string]any)["name"] != "premium" {
		t.Fatalf("hsm must use a premium vault: %+v", vbody)
	}
	kbody := p.keyCreateBody()["properties"].(map[string]any)
	if kbody["kty"] != "RSA-HSM" || kbody["rotationPolicy"] == nil {
		t.Fatalf("key body = %+v", kbody)
	}
	// software -> RSA + standard vault
	sa := azKeyAttrs()
	sa["protection.level"] = "software"
	sp, _ := BuildAzureKey("prod", "datakey", sa, azKeyImpl(), 1)
	if sp.Kty != "RSA" || sp.VaultSku != "standard" {
		t.Fatalf("software must use RSA + standard vault: %+v", sp)
	}
}

func TestBuildAzureKeyRefusals(t *testing.T) {
	base := func() map[string]any {
		return map[string]any{"location.region": "eastus", "protection.level": "hsm", "service.managed": true}
	}
	cases := map[string]struct {
		extra map[string]any
		impl  map[string]any
	}{
		"unmanaged":      {map[string]any{"service.managed": false}, azKeyImpl()},
		"bad-protection": {map[string]any{"protection.level": "quantum"}, azKeyImpl()},
		"rotation-short": {map[string]any{"rotation.period": "1d"}, azKeyImpl()},
		"unknown-attr":   {map[string]any{"key.material": "AAAA"}, azKeyImpl()},
		"missing-tenant": {nil, map[string]any{"resource_group": "rg1"}},
	}
	for name, c := range cases {
		a := base()
		for k, v := range c.extra {
			a[k] = v
		}
		if _, err := BuildAzureKey("prod", "datakey", a, c.impl, 1); err == nil {
			t.Errorf("%s: expected refusal, got none", name)
		}
	}
	if _, err := BuildAzureKey("prod", "datakey",
		map[string]any{"protection.level": "hsm", "service.managed": true}, azKeyImpl(), 1); err == nil {
		t.Error("missing location.region must refuse")
	}
}

func azKeyServer(t *testing.T, tagCap, kty, rotationISO string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			switch {
			case r.Method == "PUT":
				w.WriteHeader(200)
				_, _ = w.Write([]byte(`{"properties":{"provisioningState":"Succeeded"}}`))
			case r.Method == "GET" && strings.Contains(r.URL.Path, "/keys/"):
				rp := ""
				if rotationISO != "" {
					rp = `,"rotationPolicy":{"lifetimeActions":[{"trigger":{"timeAfterCreate":"` + rotationISO + `"}}]}`
				}
				_, _ = w.Write([]byte(`{"properties":{"kty":"` + kty + `"` + rp + `}}`))
			case r.Method == "GET": // the vault
				_, _ = w.Write([]byte(`{"location":"eastus",` +
					`"tags":{"groundhold-capability":"` + tagCap + `","groundhold-environment":"prod"},` +
					`"properties":{"provisioningState":"Succeeded"}}`))
			case r.Method == "DELETE":
				w.WriteHeader(200)
			default:
				w.WriteHeader(404)
			}
		}))
}

func azKeyDriver(t *testing.T, srv *httptest.Server) *Driver {
	t.Helper()
	d := NewDriver(testSub)
	d.BaseURL = srv.URL
	d.token = "test-token"
	d.Now = time.Now
	d.PollInterval = time.Millisecond
	d.PollTimeout = 2 * time.Second
	return d
}

func TestCreateObserveDeleteAzureKey(t *testing.T) {
	srv := azKeyServer(t, "datakey", "RSA-HSM", "P90D")
	defer srv.Close()
	d := azKeyDriver(t, srv)
	res := d.createAzureKey("prod", "datakey", azKeyAttrs(), azKeyImpl(), 1)
	if res.Status != "succeeded" || !strings.HasPrefix(res.ProviderID, "akvkey:"+testSub+":rg1:eastus:") {
		t.Fatalf("create: %+v", res)
	}
	obs, _, err := d.observeAzureKey("datakey", res.ProviderID)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]any{}
	for _, o := range obs {
		got[o.Path] = o.Value
	}
	if got["location.region"] != "eastus" || got["protection.level"] != "hsm" ||
		got["rotation.period"] != "90d" {
		t.Fatalf("observe: %+v", got)
	}
	if del := d.deleteAzureKey("datakey", "prod", res.ProviderID); del.Status != "succeeded" ||
		!strings.Contains(del.Reason, "soft-delete") {
		t.Fatalf("delete must succeed + note soft-delete: %+v", del)
	}
}

func TestDeleteAzureKeyForeignRefused(t *testing.T) {
	srv := azKeyServer(t, "someone-else", "RSA", "")
	defer srv.Close()
	d := azKeyDriver(t, srv)
	pid := azureKeyProviderID(testSub, "rg1", "eastus", keyVaultName("prod", "datakey", 1), azResourceName("pv-key", "prod", "datakey", 1))
	res := d.deleteAzureKey("datakey", "prod", pid)
	if res.Status != "failed" || !strings.Contains(res.Reason, "not ours") {
		t.Fatalf("foreign key must refuse delete, got %+v", res)
	}
}
