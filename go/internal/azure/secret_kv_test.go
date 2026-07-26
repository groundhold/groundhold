package azure

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

const testTenant = "00000000-0000-0000-0000-0000000000aa"

func kvAttrs() map[string]any {
	return map[string]any{
		"location.region":        "eastus",
		"network.publicExposure": false,
		"encryption.atRest":      true,
		"service.managed":        true,
	}
}

func kvImpl() map[string]any {
	return map[string]any{"resource_group": "rg1", "tenant_id": testTenant}
}

func TestBuildKeyVaultHonors(t *testing.T) {
	p, err := BuildKeyVault("prod", "dbcreds", kvAttrs(), kvImpl(), 1)
	if err != nil {
		t.Fatal(err)
	}
	if p.Region != "eastus" || p.TenantID != testTenant || p.Public {
		t.Fatalf("plan = %+v", p)
	}
	if !vaultNameOK.MatchString(p.Vault) {
		t.Fatalf("vault name invalid: %q", p.Vault)
	}
	body := p.createBody(map[string]any{})
	props := body["properties"].(map[string]any)
	if props["publicNetworkAccess"] != "Disabled" {
		t.Fatalf("private vault must disable public network access: %+v", props)
	}
}

func TestBuildKeyVaultRefusals(t *testing.T) {
	base := func() map[string]any {
		return map[string]any{"location.region": "eastus", "encryption.atRest": true, "service.managed": true}
	}
	cases := map[string]struct {
		attrExtra map[string]any
		impl      map[string]any
	}{
		"atRest-false":   {map[string]any{"encryption.atRest": false}, kvImpl()},
		"unmanaged":      {map[string]any{"service.managed": false}, kvImpl()},
		"cmk-refused":    {map[string]any{"encryption.customerManagedKeys": true}, kvImpl()},
		"rotation":       {map[string]any{"rotation.enabled": true}, kvImpl()},
		"value":          {map[string]any{"value": "hunter2"}, kvImpl()},
		"missing-tenant": {nil, map[string]any{"resource_group": "rg1"}},
	}
	for name, c := range cases {
		a := base()
		for k, v := range c.attrExtra {
			a[k] = v
		}
		if _, err := BuildKeyVault("prod", "dbcreds", a, c.impl, 1); err == nil {
			t.Errorf("%s: expected refusal, got none", name)
		}
	}
	// missing region
	if _, err := BuildKeyVault("prod", "dbcreds",
		map[string]any{"encryption.atRest": true, "service.managed": true}, kvImpl(), 1); err == nil {
		t.Error("missing region must refuse")
	}
}

func kvServer(t *testing.T, tagCap, publicAccess string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			switch r.Method {
			case "PUT":
				w.WriteHeader(200)
				_, _ = w.Write([]byte(`{"properties":{"provisioningState":"Succeeded"}}`))
			case "GET":
				_, _ = w.Write([]byte(`{"location":"eastus",` +
					`"tags":{"groundhold-capability":"` + tagCap + `","groundhold-environment":"prod"},` +
					`"properties":{"provisioningState":"Succeeded","publicNetworkAccess":"` + publicAccess + `"}}`))
			case "DELETE":
				w.WriteHeader(200)
			default:
				w.WriteHeader(404)
			}
		}))
}

func kvDriver(t *testing.T, srv *httptest.Server) *Driver {
	t.Helper()
	d := NewDriver(testSub)
	d.BaseURL = srv.URL
	d.token = "test-token"
	d.Now = time.Now
	d.PollInterval = time.Millisecond
	d.PollTimeout = 2 * time.Second
	return d
}

func TestCreateObserveDeleteKeyVault(t *testing.T) {
	srv := kvServer(t, "dbcreds", "Disabled")
	defer srv.Close()
	d := kvDriver(t, srv)
	res := d.createKeyVault("prod", "dbcreds", kvAttrs(), kvImpl(), 1)
	if res.Status != "succeeded" || !strings.HasPrefix(res.ProviderID, "akv:"+testSub+":rg1:") {
		t.Fatalf("create: %+v", res)
	}
	if !strings.Contains(res.Reason, "out of band") {
		t.Fatalf("create result must state the value is supplied out of band: %q", res.Reason)
	}
	obs, _, err := d.observeKeyVault("dbcreds", res.ProviderID)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]any{}
	for _, o := range obs {
		got[o.Path] = o.Value
	}
	if got["location.region"] != "eastus" || got["encryption.atRest"] != true ||
		got["network.publicExposure"] != false {
		t.Fatalf("observe: %+v", got)
	}
	// the value is never observed
	if _, ok := got["value"]; ok {
		t.Fatalf("observe must never report a secret value: %+v", got)
	}
	if del := d.deleteKeyVault("dbcreds", "prod", res.ProviderID); del.Status != "succeeded" {
		t.Fatalf("delete: %+v", del)
	}
}

func TestDeleteKeyVaultForeignRefused(t *testing.T) {
	srv := kvServer(t, "someone-else", "Disabled")
	defer srv.Close()
	d := kvDriver(t, srv)
	pid := keyVaultProviderID(testSub, "rg1", keyVaultName("prod", "dbcreds", 1))
	res := d.deleteKeyVault("dbcreds", "prod", pid)
	if res.Status != "failed" || !strings.Contains(res.Reason, "not ours") {
		t.Fatalf("foreign vault must refuse delete, got %+v", res)
	}
}
