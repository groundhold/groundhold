package gcp

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func redisAttrs() map[string]any {
	return map[string]any{
		"engine.protocol":                "redis/7",
		"location.region":                "europe-west1",
		"network.publicExposure":         false,
		"encryption.atRest":              true,
		"encryption.inTransit":           true,
		"encryption.customerManagedKeys": true,
		"availability.class":             "regional",
		"service.managed":                true,
	}
}

func redisImpl() map[string]any {
	return map[string]any{
		"kms_key_name":   "projects/p/locations/europe-west1/keyRings/r/cryptoKeys/k",
		"memory_size_gb": 4,
	}
}

func TestBuildMemorystoreHonors(t *testing.T) {
	p, err := BuildMemorystoreCreate("acme-prod", "prod", "sessions", redisAttrs(), redisImpl(), 1)
	if err != nil {
		t.Fatal(err)
	}
	if p.RedisVersion != "REDIS_7_0" || p.Tier != "STANDARD_HA" || !p.TransitEncryption ||
		p.KmsKey == "" || p.MemorySizeGb != 4 || p.Region != "europe-west1" {
		t.Fatalf("plan = %+v", p)
	}
	body := p.createBody("sessions", "prod")
	if body["transitEncryptionMode"] != "SERVER_AUTHENTICATION" || body["tier"] != "STANDARD_HA" {
		t.Fatalf("body = %+v", body)
	}
}

func TestBuildMemorystoreRefusals(t *testing.T) {
	base := func() map[string]any {
		return map[string]any{"engine.protocol": "redis/7", "location.region": "europe-west1",
			"encryption.atRest": true, "service.managed": true}
	}
	cases := map[string]map[string]any{
		"public-refused": {"network.publicExposure": true}, // Memorystore is always private
		"atRest-false":   {"encryption.atRest": false},
		"unmanaged":      {"service.managed": false},
		"multi-regional": {"availability.class": "multi-regional"},
		"memcached":      {"engine.protocol": "memcached/1.6"},
		"bad-version":    {"engine.protocol": "redis/99"},
		"unknown-attr":   {"eviction.policy": "lru"},
	}
	for name, extra := range cases {
		a := base()
		for k, v := range extra {
			a[k] = v
		}
		if _, err := BuildMemorystoreCreate("acme-prod", "prod", "sessions", a, nil, 1); err == nil {
			t.Errorf("%s: expected refusal, got none", name)
		}
	}
	// CMK without key
	cmk := base()
	cmk["encryption.customerManagedKeys"] = true
	if _, err := BuildMemorystoreCreate("acme-prod", "prod", "sessions", cmk, nil, 1); err == nil {
		t.Error("CMK without kms_key_name must refuse")
	}
	// missing engine / region
	if _, err := BuildMemorystoreCreate("acme-prod", "prod", "sessions",
		map[string]any{"location.region": "europe-west1", "encryption.atRest": true, "service.managed": true}, nil, 1); err == nil {
		t.Error("missing engine.protocol must refuse")
	}
	if _, err := BuildMemorystoreCreate("acme-prod", "prod", "sessions",
		map[string]any{"engine.protocol": "redis/7", "encryption.atRest": true, "service.managed": true}, nil, 1); err == nil {
		t.Error("missing location.region must refuse")
	}
}

// redisServer is a fake Memorystore endpoint: create/delete return an LRO that the
// poll immediately finds done; GET returns an owned instance doc.
func redisServer(t *testing.T, tagCap, tier, transit, cmk string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			switch {
			case r.Method == "POST" && strings.Contains(r.URL.RawQuery, "instanceId="):
				_, _ = w.Write([]byte(`{"name":"projects/acme-prod/locations/europe-west1/operations/op1"}`))
			case r.Method == "DELETE":
				_, _ = w.Write([]byte(`{"name":"projects/acme-prod/locations/europe-west1/operations/op2"}`))
			case r.Method == "GET" && strings.Contains(r.URL.Path, "/operations/"):
				_, _ = w.Write([]byte(`{"done":true}`))
			case r.Method == "GET": // instance
				doc := `{"name":"projects/acme-prod/locations/europe-west1/instances/x",` +
					`"labels":{"groundhold-capability":"` + tagCap + `","groundhold-environment":"prod"},` +
					`"redisVersion":"REDIS_7_0","tier":"` + tier + `","transitEncryptionMode":"` + transit + `"`
				if cmk != "" {
					doc += `,"customerManagedKey":"` + cmk + `"`
				}
				doc += `}`
				_, _ = w.Write([]byte(doc))
			default:
				w.WriteHeader(404)
			}
		}))
}

func redisDriver(t *testing.T, srv *httptest.Server) *Driver {
	t.Helper()
	t.Setenv("GROUNDHOLD_GCP_ACCESS_TOKEN", "test-token")
	d := NewDriver("acme-prod")
	d.MemorystoreBaseURL = srv.URL
	d.Now = time.Now
	d.PollInterval = time.Millisecond
	d.PollTimeout = 2 * time.Second
	return d
}

func TestCreateObserveDeleteMemorystore(t *testing.T) {
	srv := redisServer(t, "sessions", "STANDARD_HA", "SERVER_AUTHENTICATION",
		"projects/p/locations/europe-west1/keyRings/r/cryptoKeys/k")
	defer srv.Close()
	d := redisDriver(t, srv)
	res := d.createMemorystore("prod", "sessions", redisAttrs(), redisImpl(), 1)
	if res.Status != "succeeded" || !strings.HasPrefix(res.ProviderID, "gredis:acme-prod:europe-west1:") {
		t.Fatalf("create: %+v", res)
	}
	obs, _, err := d.observeMemorystore("sessions", res.ProviderID)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]any{}
	for _, o := range obs {
		got[o.Path] = o.Value
	}
	if got["engine.protocol"] != "redis/7" || got["availability.class"] != "regional" ||
		got["encryption.inTransit"] != true || got["encryption.customerManagedKeys"] != true ||
		got["network.publicExposure"] != false || got["location.region"] != "europe-west1" {
		t.Fatalf("observe: %+v", got)
	}
	if del := d.deleteMemorystore("sessions", "prod", res.ProviderID); del.Status != "succeeded" {
		t.Fatalf("delete: %+v", del)
	}
}

func TestDeleteMemorystoreForeignRefused(t *testing.T) {
	srv := redisServer(t, "someone-else", "BASIC", "DISABLED", "")
	defer srv.Close()
	d := redisDriver(t, srv)
	res := d.deleteMemorystore("sessions", "prod", "gredis:acme-prod:europe-west1:x")
	if res.Status != "failed" || !strings.Contains(res.Reason, "not ours") {
		t.Fatalf("foreign instance must refuse delete, got %+v", res)
	}
}

// D1235. A redisVersion the mapping does not know — a new major, or Valkey — used to
// drop `engine.protocol` with no word, which reads as "this cache reports no engine"
// rather than "we could not place the engine it reports". Same shape as the budget
// period (D1234) and the CloudFront viewer protocol, in the family sweep that found
// six of these.
func TestUnmappedRedisVersionIsDiagnosedNotDropped(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			w.WriteHeader(404)
			return
		}
		_, _ = w.Write([]byte(`{"name":"projects/acme-prod/locations/europe-west1/instances/gh",` +
			`"redisVersion":"VALKEY_8_0","locationId":"europe-west1","tier":"BASIC",` +
			`"memorySizeGb":1,"authEnabled":true,"transitEncryptionMode":"SERVER_AUTHENTICATION"}`))
	}))
	defer srv.Close()
	d := redisDriver(t, srv)
	obs, diags, err := d.observeMemorystore("sessions",
		"gredis:acme-prod:europe-west1:gh")
	if err != nil {
		t.Fatal(err)
	}
	for _, o := range obs {
		if o.Path == "engine.protocol" {
			t.Fatalf("an unmapped redisVersion must not be coerced into the engine set, got %v", o.Value)
		}
	}
	var named bool
	for _, dg := range diags {
		if strings.Contains(dg, "engine.protocol not observed") && strings.Contains(dg, "VALKEY_8_0") {
			named = true
		}
	}
	if !named {
		t.Fatalf("the diagnostic must name the version it could not map, got %v", diags)
	}
}
