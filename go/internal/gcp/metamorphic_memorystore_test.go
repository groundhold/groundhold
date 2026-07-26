package gcp

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Weapon 2 (D87), the metamorphic write/read round-trip for capability.cache.keyvalue
// on GCP Memorystore. A STATEFUL fake records what createMemorystore writes (tier,
// transit encryption, CMEK) and reflects it on the observe read; the test varies
// (availability, inTransit, cmek) and asserts observe reverse-maps what create was
// given. A driver that read the tier from the wrong field or inverted transit
// encryption fails here with no fault injected.
func metamorphicRedisServer(t *testing.T) *httptest.Server {
	t.Helper()
	var tier, transit, kms, version string
	return httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			switch {
			case r.Method == "POST" && strings.Contains(r.URL.RawQuery, "instanceId="):
				body, _ := io.ReadAll(r.Body)
				var doc struct {
					Tier                  string `json:"tier"`
					TransitEncryptionMode string `json:"transitEncryptionMode"`
					CustomerManagedKey    string `json:"customerManagedKey"`
					RedisVersion          string `json:"redisVersion"`
				}
				_ = json.Unmarshal(body, &doc)
				tier, transit, kms, version = doc.Tier, doc.TransitEncryptionMode, doc.CustomerManagedKey, doc.RedisVersion
				_, _ = w.Write([]byte(`{"name":"projects/acme-prod/locations/europe-west1/operations/op1"}`))
			case r.Method == "GET" && strings.Contains(r.URL.Path, "/operations/"):
				_, _ = w.Write([]byte(`{"done":true}`))
			case r.Method == "GET":
				out := map[string]any{
					"name":                  "projects/acme-prod/locations/europe-west1/instances/x",
					"labels":                map[string]any{"groundhold-capability": "sessions", "groundhold-environment": "prod"},
					"redisVersion":          version,
					"tier":                  tier,
					"transitEncryptionMode": transit,
				}
				if kms != "" {
					out["customerManagedKey"] = kms
				}
				b, _ := json.Marshal(out)
				_, _ = w.Write(b)
			default:
				w.WriteHeader(404)
			}
		}))
}

func TestMetamorphicMemorystoreRoundTrip(t *testing.T) {
	cases := []struct {
		name      string
		avail     string
		tls       bool
		cmek      bool
		wantClass string
	}{
		{"zonal-notls-nocmek", "zonal", false, false, "zonal"},
		{"regional-tls-cmek", "regional", true, true, "regional"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			srv := metamorphicRedisServer(t)
			defer srv.Close()
			d := redisDriver(t, srv)
			attrs := map[string]any{
				"engine.protocol":                "redis/7",
				"location.region":                "europe-west1",
				"network.publicExposure":         false,
				"encryption.atRest":              true,
				"encryption.inTransit":           c.tls,
				"encryption.customerManagedKeys": c.cmek,
				"availability.class":             c.avail,
				"service.managed":                true,
			}
			var impl map[string]any
			if c.cmek {
				impl = redisImpl()
			}
			res := d.createMemorystore("prod", "sessions", attrs, impl, 1)
			if res.Status != "succeeded" {
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
			if got["availability.class"] != c.wantClass {
				t.Errorf("availability.class %q not reflected: %+v", c.wantClass, got)
			}
			if got["encryption.inTransit"] != c.tls {
				t.Errorf("inTransit %v not reflected: %+v", c.tls, got)
			}
			if got["engine.protocol"] != "redis/7" {
				t.Errorf("engine.protocol not reflected: %+v", got)
			}
			if c.cmek && got["encryption.customerManagedKeys"] != true {
				t.Errorf("CMEK true not reflected: %+v", got)
			}
			if !c.cmek {
				if _, claimed := got["encryption.customerManagedKeys"]; claimed {
					t.Errorf("CMEK false must not be claimed: %+v", got)
				}
			}
		})
	}
}
