package azure

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func acrAttrs() map[string]any {
	return map[string]any{
		"location.region":                "eastus",
		"network.publicExposure":         false,
		"encryption.customerManagedKeys": true,
		"immutable.tags":                 false,
		"service.managed":                true,
	}
}

func acrImpl() map[string]any {
	return map[string]any{
		"resource_group": "rg1",
		"key_vault_key":  "https://kv1.vault.azure.net/keys/k/v",
	}
}

func TestBuildACRHonors(t *testing.T) {
	p, err := BuildACR("prod", "images", acrAttrs(), acrImpl(), 1)
	if err != nil {
		t.Fatal(err)
	}
	if !p.CMEK || p.Sku != "Premium" || p.KeyVaultKey == "" || p.Public || !acrNameOK.MatchString(p.Name) {
		t.Fatalf("plan = %+v", p)
	}
	body := p.createBody(map[string]any{})
	if body["properties"].(map[string]any)["publicNetworkAccess"] != "Disabled" {
		t.Fatalf("body = %+v", body)
	}
}

func TestBuildACRRefusals(t *testing.T) {
	cases := map[string]struct {
		extra map[string]any
		impl  map[string]any
	}{
		"immutable-refused": {map[string]any{"immutable.tags": true}, acrImpl()}, // ACR has no registry flag
		"cmek-no-key":       {map[string]any{"encryption.customerManagedKeys": true}, map[string]any{"resource_group": "rg1"}},
		"unmanaged":         {map[string]any{"service.managed": false}, acrImpl()},
		"unknown-attr":      {map[string]any{"registry.tier": "x"}, acrImpl()},
	}
	for name, c := range cases {
		a := acrAttrs()
		for k, v := range c.extra {
			a[k] = v
		}
		if _, err := BuildACR("prod", "images", a, c.impl, 1); err == nil {
			t.Errorf("%s: expected refusal, got none", name)
		}
	}
	a := acrAttrs()
	delete(a, "location.region")
	if _, err := BuildACR("prod", "images", a, acrImpl(), 1); err == nil {
		t.Error("missing location.region must refuse")
	}
}

func acrServer(t *testing.T, tagCap string) *httptest.Server {
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
					`"sku":{"name":"Premium"},` +
					`"properties":{"publicNetworkAccess":"Disabled","encryption":{"status":"enabled"},"provisioningState":"Succeeded"}}`))
			case "DELETE":
				w.WriteHeader(200)
			default:
				w.WriteHeader(404)
			}
		}))
}

func acrDriver(t *testing.T, srv *httptest.Server) *Driver {
	t.Helper()
	d := NewDriver(testSub)
	d.BaseURL = srv.URL
	d.token = "test-token"
	d.Now = time.Now
	d.PollInterval = time.Millisecond
	d.PollTimeout = 2 * time.Second
	return d
}

func TestCreateObserveDeleteACR(t *testing.T) {
	srv := acrServer(t, "images")
	defer srv.Close()
	d := acrDriver(t, srv)
	res := d.createACR("prod", "images", acrAttrs(), acrImpl(), 1)
	if res.Status != "succeeded" || !strings.HasPrefix(res.ProviderID, "acr:"+testSub+":rg1:") {
		t.Fatalf("create: %+v", res)
	}
	obs, _, err := d.observeACR("images", res.ProviderID)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]any{}
	for _, o := range obs {
		got[o.Path] = o.Value
	}
	if got["location.region"] != "eastus" || got["network.publicExposure"] != false ||
		got["encryption.customerManagedKeys"] != true {
		t.Fatalf("observe: %+v", got)
	}
	if del := d.deleteACR("images", "prod", res.ProviderID); del.Status != "succeeded" {
		t.Fatalf("delete: %+v", del)
	}
}

func TestDeleteACRForeignRefused(t *testing.T) {
	srv := acrServer(t, "someone-else")
	defer srv.Close()
	d := acrDriver(t, srv)
	res := d.deleteACR("images", "prod", "acr:"+testSub+":rg1:"+acrName("prod", "images", 1))
	if res.Status != "failed" || !strings.Contains(res.Reason, "not ours") {
		t.Fatalf("foreign registry must refuse delete, got %+v", res)
	}
}

// scanOnPush=true is HONEST-REFUSED at build: Azure has no per-registry scanning field —
// it is Microsoft Defender for Containers (a subscription posture), governed by the
// defender driver. The refusal must direct the author there, never fake a registry field.
func TestBuildACRScanOnPushTrueRefused(t *testing.T) {
	a := acrAttrs()
	a["security.scanOnPush"] = true
	_, err := BuildACR("prod", "images", a, acrImpl(), 1)
	if err == nil {
		t.Fatal("scanOnPush=true must be refused (not a per-registry field)")
	}
	if !strings.Contains(err.Error(), "Defender for Containers") ||
		!strings.Contains(err.Error(), "capability.security.threatdetection") {
		t.Fatalf("refusal must direct to Defender/threatdetection: %v", err)
	}
}

// scanOnPush=false (or absent) is a known, accepted attribute — nothing to provision on
// the registry, and NOT the "unknown attribute" refusal (fala-2 parity: the vocab attribute
// is recognized by the ACR driver).
func TestBuildACRScanOnPushFalseAccepted(t *testing.T) {
	a := acrAttrs()
	a["security.scanOnPush"] = false
	if _, err := BuildACR("prod", "images", a, acrImpl(), 1); err != nil {
		t.Fatalf("scanOnPush=false must be accepted, got %v", err)
	}
}

// acrScanServer serves the registry GET on its /registries/ path and the Defender
// Containers pricing on the Microsoft.Security/pricings/Containers path, so observe can
// measure scanOnPush from the subscription posture (not the registry).
func acrScanServer(t *testing.T, tagCap string, containersStandard bool) *httptest.Server {
	t.Helper()
	tier := "Free"
	if containersStandard {
		tier = "Standard"
	}
	return httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			switch {
			case strings.Contains(r.URL.Path, "/Microsoft.Security/pricings/"):
				_, _ = w.Write([]byte(`{"properties":{"pricingTier":"` + tier + `"}}`))
			case r.Method == "PUT":
				w.WriteHeader(200)
				_, _ = w.Write([]byte(`{"properties":{"provisioningState":"Succeeded"}}`))
			case r.Method == "GET":
				_, _ = w.Write([]byte(`{"location":"eastus",` +
					`"tags":{"groundhold-capability":"` + tagCap + `","groundhold-environment":"prod"},` +
					`"sku":{"name":"Premium"},` +
					`"properties":{"publicNetworkAccess":"Disabled","encryption":{"status":"enabled"},"provisioningState":"Succeeded"}}`))
			case r.Method == "DELETE":
				w.WriteHeader(200)
			default:
				w.WriteHeader(404)
			}
		}))
}

// observe MEASURES scanOnPush from the Defender for Containers pricing: Standard => true,
// with a diagnostic that names it a subscription posture. This is the honest divergence
// from ECR (per-repo field) — the value comes from Microsoft.Security/pricings, not the
// registry.
func TestObserveACRScanOnPushFromDefender(t *testing.T) {
	srv := acrScanServer(t, "images", true)
	defer srv.Close()
	d := acrDriver(t, srv)
	pid := "acr:" + testSub + ":rg1:" + acrName("prod", "images", 1)
	obs, diags, err := d.observeACR("images", pid)
	if err != nil {
		t.Fatal(err)
	}
	var got any
	var seen bool
	for _, o := range obs {
		if o.Path == "security.scanOnPush" {
			got, seen = o.Value, true
		}
	}
	if !seen || got != true {
		t.Fatalf("observe must measure scanOnPush=true from Defender Containers Standard, got %v (seen=%v)", got, seen)
	}
	joined := strings.Join(diags, " | ")
	if !strings.Contains(joined, "Microsoft Defender for Containers") ||
		!strings.Contains(joined, "capability.security.threatdetection") {
		t.Fatalf("observe must diagnose scanOnPush as a subscription Defender posture: %q", joined)
	}
}

// when Defender for Containers is Free (or absent), observe reports scanOnPush=false.
func TestObserveACRScanOnPushDefenderFree(t *testing.T) {
	srv := acrScanServer(t, "images", false)
	defer srv.Close()
	d := acrDriver(t, srv)
	pid := "acr:" + testSub + ":rg1:" + acrName("prod", "images", 1)
	obs, _, err := d.observeACR("images", pid)
	if err != nil {
		t.Fatal(err)
	}
	var seen bool
	for _, o := range obs {
		if o.Path == "security.scanOnPush" {
			seen = true
			if o.Value != false {
				t.Fatalf("Free Defender Containers must observe scanOnPush=false, got %v", o.Value)
			}
		}
	}
	if !seen {
		t.Fatal("scanOnPush must be observed when the Defender pricing is readable")
	}
}

// scanOnPush is deliberately classified unsupported for in-place change (a subscription
// posture owned by the defender driver, not a per-registry toggle) — honest, and NOT
// mutable-without-updater.
func TestClassifyACRChangeScanOnPushUnsupported(t *testing.T) {
	cls, reason := classifyACRChange("security.scanOnPush")
	if cls != "unsupported" {
		t.Fatalf("scanOnPush must classify unsupported (subscription posture), got %q", cls)
	}
	if !strings.Contains(reason, "Defender for Containers") ||
		!strings.Contains(reason, "capability.security.threatdetection") {
		t.Fatalf("reason must explain the Defender/threatdetection nature: %q", reason)
	}
	if c, _ := classifyACRChange("location.region"); c != "immutable" {
		t.Fatalf("region change must be immutable (replacement), got %q", c)
	}
}

// TestObserveACRAbsentPublicNetworkAccessNotFabricated pins the honesty fix: ARM
// omits publicNetworkAccess for Basic/Standard registries (it is a Premium-only
// control) — those registries are ALWAYS public. The driver must NOT collapse the
// absent field to network.publicExposure=false measured (a false PASS on a
// no-public-exposure constraint); absent → no observation + a diagnostic.
func TestObserveACRAbsentPublicNetworkAccessNotFabricated(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			switch r.Method {
			case "PUT":
				w.WriteHeader(200)
				_, _ = w.Write([]byte(`{"properties":{"provisioningState":"Succeeded"}}`))
			case "GET":
				// a Basic registry: NO publicNetworkAccess field
				_, _ = w.Write([]byte(`{"location":"eastus",` +
					`"tags":{"groundhold-capability":"images","groundhold-environment":"prod"},` +
					`"sku":{"name":"Basic"},` +
					`"properties":{"encryption":{"status":"disabled"},"provisioningState":"Succeeded"}}`))
			default:
				w.WriteHeader(404)
			}
		}))
	defer srv.Close()
	d := acrDriver(t, srv)
	res := d.createACR("prod", "images", acrAttrs(), acrImpl(), 1)
	if res.Status != "succeeded" {
		t.Fatalf("create: %+v", res)
	}
	obs, diags, err := d.observeACR("images", res.ProviderID)
	if err != nil {
		t.Fatal(err)
	}
	for _, o := range obs {
		if o.Path == "network.publicExposure" {
			t.Fatalf("absent publicNetworkAccess must NOT be observed — got a fabricated %v", o.Value)
		}
	}
	found := false
	for _, dg := range diags {
		if strings.Contains(dg, "publicNetworkAccess absent") {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected a diagnostic for the absent publicNetworkAccess, got %v", diags)
	}
}
