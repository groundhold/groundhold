package azure

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func redisAzAttrs() map[string]any {
	return map[string]any{
		"engine.protocol":        "redis/6",
		"location.region":        "eastus",
		"network.publicExposure": false,
		"encryption.atRest":      true,
		"encryption.inTransit":   true,
		"availability.class":     "zonal", // zonal path (Basic); regional maps to Standard but observe honestly reads it as zonal (D946)
		"service.managed":        true,
	}
}

func redisAzImpl() map[string]any {
	return map[string]any{"resource_group": "rg1"}
}

func TestBuildRedisAzureHonors(t *testing.T) {
	p, err := BuildRedisAzure("prod", "sessions", redisAzAttrs(), redisAzImpl(), 1)
	if err != nil {
		t.Fatal(err)
	}
	if p.RedisVersion != "6" || p.SkuName != "Basic" || !p.InTransit || p.Public {
		t.Fatalf("plan = %+v", p)
	}
	body := p.createBody(map[string]any{})
	props := body["properties"].(map[string]any)
	if props["publicNetworkAccess"] != "Disabled" || props["enableNonSslPort"] != false {
		t.Fatalf("props = %+v", props)
	}
}

// Azure Redis CAN be public — publicExposure=true is a real toggle, not a refusal.
func TestBuildRedisAzurePublicIsAToggle(t *testing.T) {
	a := redisAzAttrs()
	a["network.publicExposure"] = true
	p, err := BuildRedisAzure("prod", "sessions", a, redisAzImpl(), 1)
	if err != nil {
		t.Fatalf("public exposure must be honored on Azure, got: %v", err)
	}
	props := p.createBody(map[string]any{})["properties"].(map[string]any)
	if props["publicNetworkAccess"] != "Enabled" {
		t.Fatalf("public cache must set publicNetworkAccess=Enabled: %+v", props)
	}
}

func TestBuildRedisAzureRefusals(t *testing.T) {
	base := func() map[string]any {
		return map[string]any{"engine.protocol": "redis/6", "location.region": "eastus",
			"encryption.atRest": true, "service.managed": true}
	}
	cases := map[string]map[string]any{
		"atRest-false":      {"encryption.atRest": false},
		"unmanaged":         {"service.managed": false},
		"multi-regional":    {"availability.class": "multi-regional"},
		"memcached":         {"engine.protocol": "memcached/1.6"},
		"redis7-enterprise": {"engine.protocol": "redis/7"},
		"cmk-refused":       {"encryption.customerManagedKeys": true},
		"unknown-attr":      {"eviction.policy": "lru"},
	}
	for name, extra := range cases {
		a := base()
		for k, v := range extra {
			a[k] = v
		}
		if _, err := BuildRedisAzure("prod", "sessions", a, redisAzImpl(), 1); err == nil {
			t.Errorf("%s: expected refusal, got none", name)
		}
	}
	if _, err := BuildRedisAzure("prod", "sessions",
		map[string]any{"location.region": "eastus", "encryption.atRest": true, "service.managed": true}, redisAzImpl(), 1); err == nil {
		t.Error("missing engine.protocol must refuse")
	}
}

func redisAzServer(t *testing.T, tagCap, sku, redisVer, pubAccess string, nonSsl bool) *httptest.Server {
	t.Helper()
	nonSslStr := "false"
	if nonSsl {
		nonSslStr = "true"
	}
	return httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			switch r.Method {
			case "PUT":
				w.WriteHeader(200)
				_, _ = w.Write([]byte(`{"properties":{"provisioningState":"Succeeded"}}`))
			case "GET":
				_, _ = w.Write([]byte(`{"location":"eastus",` +
					`"tags":{"groundhold-capability":"` + tagCap + `","groundhold-environment":"prod"},` +
					`"properties":{"provisioningState":"Succeeded","redisVersion":"` + redisVer + `",` +
					`"publicNetworkAccess":"` + pubAccess + `","enableNonSslPort":` + nonSslStr + `,` +
					`"sku":{"name":"` + sku + `"}}}`))
			case "DELETE":
				w.WriteHeader(200)
			default:
				w.WriteHeader(404)
			}
		}))
}

func redisAzDriver(t *testing.T, srv *httptest.Server) *Driver {
	t.Helper()
	d := NewDriver(testSub)
	d.BaseURL = srv.URL
	d.token = "test-token"
	d.Now = time.Now
	d.PollInterval = time.Millisecond
	d.PollTimeout = 2 * time.Second
	return d
}

func TestCreateObserveDeleteRedisAzure(t *testing.T) {
	srv := redisAzServer(t, "sessions", "Standard", "6.0", "Disabled", false)
	defer srv.Close()
	d := redisAzDriver(t, srv)
	res := d.createRedisAzure("prod", "sessions", redisAzAttrs(), redisAzImpl(), 1)
	if res.Status != "succeeded" || !strings.HasPrefix(res.ProviderID, "aredis:"+testSub+":rg1:") {
		t.Fatalf("create: %+v", res)
	}
	obs, _, err := d.observeRedisAzure("sessions", res.ProviderID)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]any{}
	for _, o := range obs {
		got[o.Path] = o.Value
	}
	if got["engine.protocol"] != "redis/6" || got["availability.class"] != "zonal" ||
		got["encryption.inTransit"] != true || got["network.publicExposure"] != false ||
		got["location.region"] != "eastus" {
		t.Fatalf("observe: %+v", got)
	}
	if del := d.deleteRedisAzure("sessions", "prod", res.ProviderID); del.Status != "succeeded" {
		t.Fatalf("delete: %+v", del)
	}
}

func TestDeleteRedisAzureForeignRefused(t *testing.T) {
	srv := redisAzServer(t, "someone-else", "Basic", "6.0", "Disabled", false)
	defer srv.Close()
	d := redisAzDriver(t, srv)
	pid := redisAzureProviderID(testSub, "rg1", azResourceName("pv-cache", "prod", "sessions", 1))
	res := d.deleteRedisAzure("sessions", "prod", pid)
	if res.Status != "failed" || !strings.Contains(res.Reason, "not ours") {
		t.Fatalf("foreign cache must refuse delete, got %+v", res)
	}
}

// D946: availability.class must be derived from the ACTUAL zone-redundancy (the top-level
// `zones` array), not the SKU tier. A Standard cache with no zones reads `zonal`
// (covered by TestCreateObserveDeleteRedisAzure); a cache WITH zones reads `regional`.
func TestObserveRedisAzureDerivesRegionalFromZonesNotTier(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" {
			// a Standard cache — the OLD code would call this "regional" off the tier —
			// but it carries a populated zones array, so it genuinely IS zone-redundant.
			_, _ = w.Write([]byte(`{"location":"eastus","zones":["1","2","3"],` +
				`"tags":{"groundhold-capability":"sessions","groundhold-environment":"prod"},` +
				`"properties":{"provisioningState":"Succeeded","redisVersion":"6.0",` +
				`"publicNetworkAccess":"Disabled","enableNonSslPort":false,"sku":{"name":"Premium"}}}`))
			return
		}
		w.WriteHeader(200)
	}))
	defer srv.Close()
	d := redisAzDriver(t, srv)
	pid := redisAzureProviderID(testSub, "rg1", azResourceName("pv-cache", "prod", "sessions", 1))
	obs, _, err := d.observeRedisAzure("sessions", pid)
	if err != nil {
		t.Fatal(err)
	}
	var got any
	for _, o := range obs {
		if o.Path == "availability.class" {
			got = o.Value
		}
	}
	if got != "regional" {
		t.Errorf("a cache with a populated zones array must read availability.class=regional, got %v", got)
	}
}

// D948: regional maps to Premium + a top-level zones array (genuine zone redundancy),
// and the create refuses a region that cannot span at least two availability zones.
func TestBuildRedisAzureRegionalIsPremiumZoneRedundant(t *testing.T) {
	a := redisAzAttrs()
	a["availability.class"] = "regional"
	p, err := BuildRedisAzure("prod", "sessions", a, redisAzImpl(), 1)
	if err != nil {
		t.Fatal(err)
	}
	if p.SkuName != "Premium" || !p.ZoneRedundant {
		t.Fatalf("regional must map to Premium + ZoneRedundant, got %+v", p)
	}
	p.Zones = []string{"1", "2", "3"}
	body := p.createBody(nil)
	if body["zones"] == nil {
		t.Error("a zone-redundant create body must carry a top-level zones array")
	}
	if body["properties"].(map[string]any)["sku"].(map[string]any)["family"] != "P" {
		t.Errorf("the Premium tier must use sku family P, got %+v", body["properties"])
	}
}

func TestCreateRedisAzureRefusesRegionWithoutAvailabilityZones(t *testing.T) {
	for _, c := range []struct {
		name       string
		azm        string
		wantRefuse bool
	}{
		{"single-AZ region refuses regional", `{"logicalZone":"1"}`, true},
		{"multi-AZ region proceeds", `{"logicalZone":"1"},{"logicalZone":"2"},{"logicalZone":"3"}`, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if strings.Contains(r.URL.Path, "/locations") {
					_, _ = w.Write([]byte(`{"value":[{"name":"eastus","availabilityZoneMappings":[` + c.azm + `]}]}`))
					return
				}
				if r.Method == "PUT" {
					w.WriteHeader(202)
					_, _ = w.Write([]byte(`{"properties":{"provisioningState":"Succeeded"}}`))
					return
				}
				w.WriteHeader(404)
			}))
			defer srv.Close()
			d := redisAzDriver(t, srv)
			a := redisAzAttrs()
			a["availability.class"] = "regional"
			res := d.createRedisAzure("prod", "sessions", a, redisAzImpl(), 1)
			refusedForAZ := res.Status == "failed" && strings.Contains(res.Reason, "at least two")
			if c.wantRefuse && !refusedForAZ {
				t.Errorf("a single-AZ region must refuse regional up front, got %+v", res)
			}
			if !c.wantRefuse && refusedForAZ {
				t.Errorf("a multi-AZ region must NOT be preflight-refused: %+v", res)
			}
		})
	}
}
