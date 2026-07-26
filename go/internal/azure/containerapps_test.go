package azure

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func acaAttrs() map[string]any {
	return map[string]any{
		"location.region":        "eastus",
		"network.publicExposure": true,
		"tls.enforced":           true,
		"replicas.minimum":       2,
		"autoscaling.enabled":    true,
		"availability.class":     "zonal",
		"service.managed":        true,
	}
}

func acaImpl() map[string]any {
	return map[string]any{"image": "mcr.microsoft.com/hello:latest", "resource_group": "rg1"}
}

func TestBuildContainerAppHonors(t *testing.T) {
	p, err := BuildContainerApp("prod", "api", acaAttrs(), acaImpl(), 1)
	if err != nil {
		t.Fatal(err)
	}
	if !p.Public || p.AllowInsecure || p.MinReplicas != 2 || p.ZoneRedundant {
		t.Fatalf("plan = %+v", p)
	}
	if p.Env != p.App+"-env" || p.Image == "" {
		t.Fatalf("env/image = %+v", p)
	}
}

func TestBuildContainerAppRefusals(t *testing.T) {
	base := func() map[string]any {
		return map[string]any{"location.region": "eastus", "service.managed": true}
	}
	// image missing (impl nil)
	if _, err := BuildContainerApp("prod", "api", base(), nil, 1); err == nil {
		t.Error("missing image must refuse")
	}
	cases := map[string]map[string]any{
		"autoscaling-false":  {"autoscaling.enabled": false},
		"multi-regional":     {"availability.class": "multi-regional"},
		"regional-no-subnet": {"availability.class": "regional"},
		"signed-provenance":  {"image.signedProvenance": true},
		"unmanaged":          {"service.managed": false},
		"unknown":            {"engine.protocol": "x"},
	}
	for name, extra := range cases {
		a := base()
		for k, v := range extra {
			a[k] = v
		}
		if _, err := BuildContainerApp("prod", "api", a, acaImpl(), 1); err == nil {
			t.Errorf("%s: expected refusal, got none", name)
		}
	}
	// availability regional WITH subnet is honored
	a := base()
	a["availability.class"] = "regional"
	impl := acaImpl()
	impl["infrastructure_subnet_id"] = "/subscriptions/x/resourceGroups/rg/providers/Microsoft.Network/virtualNetworks/v/subnets/s"
	if p, err := BuildContainerApp("prod", "api", a, impl, 1); err != nil || !p.ZoneRedundant {
		t.Errorf("regional+subnet must honor zoneRedundant: %v %+v", err, p)
	}
}

func acaArmFake(t *testing.T, tagCap string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			switch r.Method {
			case "PUT":
				w.WriteHeader(201)
				_, _ = w.Write([]byte(`{"properties":{"provisioningState":"Succeeded"}}`))
			case "GET":
				_, _ = w.Write([]byte(`{"location":"eastus",` +
					`"tags":{"groundhold-capability":"` + tagCap + `","groundhold-environment":"prod"},` +
					`"properties":{"provisioningState":"Succeeded",` +
					`"configuration":{"ingress":{"external":true,"allowInsecure":false}},` +
					`"template":{"scale":{"minReplicas":2}}}}`))
			case "DELETE":
				w.WriteHeader(200)
			default:
				w.WriteHeader(404)
			}
		}))
}

func TestCreateObserveDeleteContainerApp(t *testing.T) {
	srv := acaArmFake(t, "api")
	defer srv.Close()
	d := vnetTestDriver(t, srv)

	res := d.createContainerApp("prod", "api", acaAttrs(), acaImpl(), 1)
	if res.Status != "succeeded" || res.ProviderID == "" {
		t.Fatalf("create: %+v", res)
	}
	obs, _, err := d.observeContainerApp("api", res.ProviderID)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]any{}
	for _, o := range obs {
		got[o.Path] = o.Value
	}
	if got["network.publicExposure"] != true || got["tls.enforced"] != true || got["replicas.minimum"] != float64(2) {
		t.Fatalf("observe: %+v", got)
	}
	if del := d.deleteContainerApp("api", "prod", res.ProviderID); del.Status != "succeeded" {
		t.Fatalf("delete: %+v", del)
	}
}

func TestDeleteContainerAppForeignRefused(t *testing.T) {
	srv := acaArmFake(t, "someone-else")
	defer srv.Close()
	d := vnetTestDriver(t, srv)
	pid := acaProviderID(testSub, "rg1", containerAppName("prod", "api", 1))
	res := d.deleteContainerApp("api", "prod", pid)
	if res.Status != "failed" || !strings.Contains(res.Reason, "not ours") {
		t.Fatalf("foreign app must refuse delete, got %+v", res)
	}
}
