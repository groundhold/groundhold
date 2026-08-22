package azure

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// Weapon 2 (D87), the metamorphic write/read round-trip for the Azure drivers.
// Stateful ARM fakes record the properties create PUTs and reflect them on the
// GET reads; the tests vary the semantic attributes and assert observe reverse-
// maps what create was given. A driver that inverted publicNetworkAccess, read HA
// from the wrong field, or dropped a property fails here with no fault injected.
// (KeyVault has its own metamorphic file; this covers the remaining services.)

func metamorphicDriver(t *testing.T, url string) *Driver {
	t.Helper()
	d := NewDriver(testSub)
	d.BaseURL = url
	d.token = "test-token"
	d.Now = time.Now
	d.PollInterval = time.Millisecond
	d.PollTimeout = 2 * time.Second
	return d
}

func flatObserve(t *testing.T, d *Driver, service, capability, pid string) map[string]any {
	t.Helper()
	obs, _, err := d.Observe(service, capability, pid)
	if err != nil {
		t.Fatalf("observe: %v", err)
	}
	m := map[string]any{}
	for _, o := range obs {
		m[o.Path] = o.Value
	}
	return m
}

// ---- Flexible Server (database.relational) ----
func metamorphicFlexServer(t *testing.T) *httptest.Server {
	t.Helper()
	var version, pubAccess, haMode string
	var backupDays float64
	created := false // D256: the server is absent until its create PUT lands
	return httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			switch r.Method {
			case "PUT":
				created = true
				body, _ := io.ReadAll(r.Body)
				var doc struct {
					Properties struct {
						Version string `json:"version"`
						Network struct {
							PublicNetworkAccess string `json:"publicNetworkAccess"`
						} `json:"network"`
						Backup struct {
							BackupRetentionDays float64 `json:"backupRetentionDays"`
						} `json:"backup"`
						HighAvailability struct {
							Mode string `json:"mode"`
						} `json:"highAvailability"`
					} `json:"properties"`
				}
				_ = json.Unmarshal(body, &doc)
				version = doc.Properties.Version
				pubAccess = doc.Properties.Network.PublicNetworkAccess
				backupDays = doc.Properties.Backup.BackupRetentionDays
				haMode = doc.Properties.HighAvailability.Mode
				w.WriteHeader(200)
				_, _ = w.Write([]byte(`{"properties":{"state":"Ready"}}`))
			case "GET":
				if !created {
					w.WriteHeader(404) // D256: pre-create adopt read sees absence
					return
				}
				out := map[string]any{
					"location": "eastus",
					"tags":     map[string]any{"groundhold-capability": "db", "groundhold-environment": "prod"},
					"properties": map[string]any{
						"state":            "Ready",
						"version":          version,
						"network":          map[string]any{"publicNetworkAccess": pubAccess},
						"backup":           map[string]any{"backupRetentionDays": backupDays},
						"highAvailability": map[string]any{"mode": haMode},
					},
				}
				b, _ := json.Marshal(out)
				_, _ = w.Write(b)
			default:
				w.WriteHeader(404)
			}
		}))
}

func TestMetamorphicFlexRoundTrip(t *testing.T) {
	cases := []struct {
		name      string
		public    bool
		avail     string
		wantClass string
	}{
		{"private-regional", false, "regional", "regional"},
		{"public-zonal", true, "zonal", "zonal"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			srv := metamorphicFlexServer(t)
			defer srv.Close()
			d := metamorphicDriver(t, srv.URL)
			attrs := map[string]any{
				"engine.protocol":        "postgresql/16",
				"location.region":        "eastus",
				"network.publicExposure": c.public,
				"encryption.atRest":      true,
				"encryption.inTransit":   true,
				"availability.class":     c.avail,
				"service.managed":        true,
			}
			res := d.createFlexServer("prod", "db", attrs, flexImpl(), 1)
			if res.Status != "succeeded" {
				t.Fatalf("create: %+v", res)
			}
			got := flatObserve(t, d, "flexpostgres", "db", res.ProviderID)
			if got["network.publicExposure"] != c.public {
				t.Errorf("public %v not reflected: %+v", c.public, got)
			}
			if got["availability.class"] != c.wantClass {
				t.Errorf("availability.class %q not reflected: %+v", c.wantClass, got)
			}
			if got["engine.protocol"] != "postgresql/16" {
				t.Errorf("engine.protocol not reflected: %+v", got)
			}
			// D796: recovery.rpo is deliberately NOT part of this round trip. It used
			// to be, and the round trip PASSED — writing "7d" and reading "7d" back
			// proved the loop was closed, not that either end meant a data-loss window.
			// A metamorphic test can only ever prove the loop; the meaning has to be
			// checked against the world.
			if _, ok := got["recovery.rpo"]; ok {
				t.Errorf("recovery.rpo observed from configuration: %+v", got)
			}
		})
	}
}

// ---- Container Apps (workload.container) ----
func metamorphicACAServer(t *testing.T) *httptest.Server {
	t.Helper()
	var external, allowInsecure bool
	var minReplicas float64
	haveIngress := false
	return httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			switch r.Method {
			case "PUT":
				body, _ := io.ReadAll(r.Body)
				var doc struct {
					Properties struct {
						Configuration *struct {
							Ingress *struct {
								External      bool `json:"external"`
								AllowInsecure bool `json:"allowInsecure"`
							} `json:"ingress"`
						} `json:"configuration"`
						Template *struct {
							Scale *struct {
								MinReplicas *float64 `json:"minReplicas"`
							} `json:"scale"`
						} `json:"template"`
					} `json:"properties"`
				}
				_ = json.Unmarshal(body, &doc)
				// only the app PUT carries ingress; the env PUT does not.
				if doc.Properties.Configuration != nil && doc.Properties.Configuration.Ingress != nil {
					external = doc.Properties.Configuration.Ingress.External
					allowInsecure = doc.Properties.Configuration.Ingress.AllowInsecure
					haveIngress = true
				}
				if doc.Properties.Template != nil && doc.Properties.Template.Scale != nil &&
					doc.Properties.Template.Scale.MinReplicas != nil {
					minReplicas = *doc.Properties.Template.Scale.MinReplicas
				}
				w.WriteHeader(200)
				_, _ = w.Write([]byte(`{"properties":{"provisioningState":"Succeeded"}}`))
			case "GET":
				props := map[string]any{
					"provisioningState": "Succeeded",
					"template":          map[string]any{"scale": map[string]any{"minReplicas": minReplicas}},
				}
				if haveIngress {
					props["configuration"] = map[string]any{
						"ingress": map[string]any{"external": external, "allowInsecure": allowInsecure}}
				}
				b, _ := json.Marshal(map[string]any{
					"location":   "eastus",
					"tags":       map[string]any{"groundhold-capability": "api", "groundhold-environment": "prod"},
					"properties": props,
				})
				_, _ = w.Write(b)
			default:
				w.WriteHeader(404)
			}
		}))
}

func TestMetamorphicACARoundTrip(t *testing.T) {
	cases := []struct {
		name     string
		public   bool
		tls      bool
		replicas int
	}{
		{"public-tls-2", true, true, 2},
		{"private-notls-1", false, false, 1},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			srv := metamorphicACAServer(t)
			defer srv.Close()
			d := metamorphicDriver(t, srv.URL)
			attrs := map[string]any{
				"location.region":        "eastus",
				"network.publicExposure": c.public,
				"tls.enforced":           c.tls,
				"replicas.minimum":       c.replicas,
				"autoscaling.enabled":    true,
				"availability.class":     "zonal",
				"service.managed":        true,
			}
			res := d.createContainerApp("prod", "api", attrs, acaImpl(), 1)
			if res.Status != "succeeded" {
				t.Fatalf("create: %+v", res)
			}
			got := flatObserve(t, d, "containerapps", "api", res.ProviderID)
			if got["network.publicExposure"] != c.public {
				t.Errorf("public %v not reflected: %+v", c.public, got)
			}
			// tls.enforced is only observed when the app is publicly exposed
			// (ingress present); a private app reports no ingress-derived tls.
			if c.public && got["tls.enforced"] != c.tls {
				t.Errorf("tls %v not reflected: %+v", c.tls, got)
			}
			if got["replicas.minimum"] != float64(c.replicas) {
				t.Errorf("replicas %d not reflected: %+v", c.replicas, got)
			}
		})
	}
}

// ---- Service Bus (messaging.queue + messaging.topic) ----
func metamorphicSBServer(t *testing.T) *httptest.Server {
	t.Helper()
	var pna string
	var dedup, session bool
	nsCreated := false // D254: the namespace is absent until its create PUT lands
	return httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			isEntity := strings.Contains(r.URL.Path, "/queues/") || strings.Contains(r.URL.Path, "/topics/")
			switch r.Method {
			case "PUT":
				body, _ := io.ReadAll(r.Body)
				if !isEntity {
					nsCreated = true
				}
				if isEntity {
					var doc struct {
						Properties struct {
							RequiresDuplicateDetection bool `json:"requiresDuplicateDetection"`
							RequiresSession            bool `json:"requiresSession"`
						} `json:"properties"`
					}
					_ = json.Unmarshal(body, &doc)
					dedup = doc.Properties.RequiresDuplicateDetection
					session = doc.Properties.RequiresSession
				} else {
					var doc struct {
						Properties struct {
							PublicNetworkAccess string `json:"publicNetworkAccess"`
						} `json:"properties"`
					}
					_ = json.Unmarshal(body, &doc)
					pna = doc.Properties.PublicNetworkAccess
				}
				w.WriteHeader(200)
				_, _ = w.Write([]byte(`{"properties":{"provisioningState":"Succeeded"}}`))
			case "GET":
				if isEntity {
					b, _ := json.Marshal(map[string]any{"properties": map[string]any{
						"requiresDuplicateDetection": dedup, "requiresSession": session}})
					_, _ = w.Write(b)
					return
				}
				if !nsCreated {
					w.WriteHeader(404) // D254: pre-create ownership read sees absence
					return
				}
				b, _ := json.Marshal(map[string]any{
					"location":   "eastus",
					"tags":       map[string]any{"groundhold-capability": "orders", "groundhold-environment": "prod"},
					"properties": map[string]any{"provisioningState": "Succeeded", "publicNetworkAccess": pna},
				})
				_, _ = w.Write(b)
			default:
				w.WriteHeader(404)
			}
		}))
}

func TestMetamorphicServiceBusQueueRoundTrip(t *testing.T) {
	cases := []struct {
		name     string
		public   bool
		guar     string
		ordering bool
	}{
		{"private-exactly-once-ordered", false, "exactly-once", true},
		{"public-at-least-once", true, "at-least-once", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			srv := metamorphicSBServer(t)
			defer srv.Close()
			d := metamorphicDriver(t, srv.URL)
			attrs := map[string]any{
				"location.region":        "eastus",
				"delivery.guarantee":     c.guar,
				"ordering.enabled":       c.ordering,
				"retention.minimum":      "7d",
				"network.publicExposure": c.public,
				"encryption.atRest":      true,
				"service.managed":        true,
			}
			res := d.createServiceBusQueue("prod", "orders", attrs, map[string]any{"resource_group": "rg1"}, 1)
			if res.Status != "succeeded" {
				t.Fatalf("create: %+v", res)
			}
			got := flatObserve(t, d, "servicebusqueue", "orders", res.ProviderID)
			if got["network.publicExposure"] != c.public {
				t.Errorf("public %v not reflected: %+v", c.public, got)
			}
			if got["delivery.guarantee"] != c.guar {
				t.Errorf("guarantee %q not reflected: %+v", c.guar, got)
			}
			if got["ordering.enabled"] != c.ordering {
				t.Errorf("ordering %v not reflected: %+v", c.ordering, got)
			}
		})
	}
}

func TestMetamorphicServiceBusTopicRoundTrip(t *testing.T) {
	for _, public := range []bool{false, true} {
		name := "private"
		if public {
			name = "public"
		}
		t.Run(name, func(t *testing.T) {
			srv := metamorphicSBServer(t)
			defer srv.Close()
			d := metamorphicDriver(t, srv.URL)
			attrs := map[string]any{
				"location.region":        "eastus",
				"network.publicExposure": public,
				"encryption.atRest":      true,
				"service.managed":        true,
			}
			res := d.createServiceBusTopic("prod", "events", attrs, map[string]any{"resource_group": "rg1"}, 1)
			if res.Status != "succeeded" {
				t.Fatalf("create: %+v", res)
			}
			got := flatObserve(t, d, "servicebustopic", "events", res.ProviderID)
			if got["network.publicExposure"] != public {
				t.Errorf("public %v not reflected: %+v", public, got)
			}
		})
	}
}

// ---- VNet (network.private) ----
func metamorphicVNetServer(t *testing.T) *httptest.Server {
	t.Helper()
	hasNSG := false
	return httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			isVNet := strings.Contains(r.URL.Path, "/virtualNetworks/")
			switch r.Method {
			case "PUT":
				body, _ := io.ReadAll(r.Body)
				if isVNet {
					var doc struct {
						Properties struct {
							Subnets []struct {
								Properties struct {
									NetworkSecurityGroup *struct {
										ID string `json:"id"`
									} `json:"networkSecurityGroup"`
								} `json:"properties"`
							} `json:"subnets"`
						} `json:"properties"`
					}
					_ = json.Unmarshal(body, &doc)
					hasNSG = len(doc.Properties.Subnets) == 1 &&
						doc.Properties.Subnets[0].Properties.NetworkSecurityGroup != nil &&
						doc.Properties.Subnets[0].Properties.NetworkSecurityGroup.ID != ""
				}
				w.WriteHeader(200)
				_, _ = w.Write([]byte(`{"properties":{"provisioningState":"Succeeded"}}`))
			case "GET":
				subnetProps := map[string]any{}
				if hasNSG {
					subnetProps["networkSecurityGroup"] = map[string]any{
						"id": "/subscriptions/x/resourceGroups/rg1/providers/Microsoft.Network/networkSecurityGroups/n"}
				}
				b, _ := json.Marshal(map[string]any{
					"location": "eastus",
					"tags":     map[string]any{"groundhold-capability": "backbone", "groundhold-environment": "prod"},
					"properties": map[string]any{
						"provisioningState": "Succeeded",
						"subnets":           []any{map[string]any{"properties": subnetProps}},
					},
				})
				_, _ = w.Write(b)
			default:
				w.WriteHeader(404)
			}
		}))
}

func TestMetamorphicVNetRoundTrip(t *testing.T) {
	for _, restricted := range []bool{false, true} {
		name := "open-egress"
		if restricted {
			name = "restricted-egress"
		}
		t.Run(name, func(t *testing.T) {
			srv := metamorphicVNetServer(t)
			defer srv.Close()
			d := metamorphicDriver(t, srv.URL)
			attrs := map[string]any{
				"location.region":   "eastus",
				"egress.restricted": restricted,
				"service.managed":   true,
			}
			res := d.createVNet("prod", "backbone", attrs, map[string]any{"resource_group": "rg1"}, 1)
			if res.Status != "succeeded" {
				t.Fatalf("create: %+v", res)
			}
			got := flatObserve(t, d, "vnet", "backbone", res.ProviderID)
			if got["egress.restricted"] != restricted {
				t.Errorf("egress.restricted %v not reflected: %+v", restricted, got)
			}
		})
	}
}

// ---- Blob (storage.object) ----
func metamorphicBlobServer(t *testing.T) *httptest.Server {
	t.Helper()
	var sku string
	var allowPublic bool             // account allowBlobPublicAccess (D1198)
	var containerPublicAccess string // container publicAccess (None/Blob/Container)
	return httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			path := strings.SplitN(r.URL.Path, "?", 2)[0]
			isImmutability := strings.Contains(path, "/immutabilityPolicies/")
			isContainer := strings.Contains(path, "/containers/") && !isImmutability
			isAccount := !strings.Contains(path, "/blobServices/")
			switch r.Method {
			case "PUT":
				body, _ := io.ReadAll(r.Body)
				if isAccount { // the storage account PUT
					var doc struct {
						Sku        struct{ Name string } `json:"sku"`
						Properties struct {
							AllowBlobPublicAccess *bool `json:"allowBlobPublicAccess"`
						} `json:"properties"`
					}
					_ = json.Unmarshal(body, &doc)
					sku = doc.Sku.Name
					if doc.Properties.AllowBlobPublicAccess != nil {
						allowPublic = *doc.Properties.AllowBlobPublicAccess
					}
				} else if isContainer { // the container PUT carries publicAccess
					var doc struct {
						Properties struct {
							PublicAccess string `json:"publicAccess"`
						} `json:"properties"`
					}
					_ = json.Unmarshal(body, &doc)
					containerPublicAccess = doc.Properties.PublicAccess
				}
				w.WriteHeader(200)
				_, _ = w.Write([]byte(`{"properties":{"provisioningState":"Succeeded"}}`))
			case "GET":
				switch {
				case isImmutability:
					w.WriteHeader(404) // no WORM policy
				case isContainer:
					b, _ := json.Marshal(map[string]any{
						"properties": map[string]any{"publicAccess": containerPublicAccess}})
					_, _ = w.Write(b)
				default: // storage account (anonymous access gated by allowBlobPublicAccess)
					b, _ := json.Marshal(map[string]any{
						"location": "eastus",
						"tags":     map[string]any{"groundhold-capability": "assets", "groundhold-environment": "prod"},
						"sku":      map[string]any{"name": sku},
						"properties": map[string]any{
							"provisioningState":     "Succeeded",
							"allowBlobPublicAccess": allowPublic,
						},
					})
					_, _ = w.Write(b)
				}
			default:
				w.WriteHeader(404)
			}
		}))
}

func TestMetamorphicBlobRoundTrip(t *testing.T) {
	cases := []struct {
		name      string
		durab     string
		public    bool
		wantClass string
	}{
		{"regional-private", "regional", false, "regional"},
		{"single-zone-public", "single-zone", true, "single-zone"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			srv := metamorphicBlobServer(t)
			defer srv.Close()
			d := metamorphicDriver(t, srv.URL)
			attrs := map[string]any{
				"location.region":        "eastus",
				"durability.class":       c.durab,
				"network.publicExposure": c.public,
				"encryption.atRest":      true,
				"service.managed":        true,
			}
			res := d.createBlob("prod", "assets", attrs, map[string]any{"resource_group": "rg1"}, 1)
			if res.Status != "succeeded" {
				t.Fatalf("create: %+v", res)
			}
			got := flatObserve(t, d, "blob", "assets", res.ProviderID)
			if got["durability.class"] != c.wantClass {
				t.Errorf("durability.class %q not reflected: %+v", c.wantClass, got)
			}
			if got["network.publicExposure"] != c.public {
				t.Errorf("public %v not reflected: %+v", c.public, got)
			}
		})
	}
}

// ---- Azure Cache for Redis (cache.keyvalue) ----
func metamorphicRedisAzServer(t *testing.T) *httptest.Server {
	t.Helper()
	var sku, pubAccess, redisVer string
	var nonSsl bool
	return httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			switch r.Method {
			case "PUT":
				body, _ := io.ReadAll(r.Body)
				var doc struct {
					Properties struct {
						RedisVersion        string `json:"redisVersion"`
						PublicNetworkAccess string `json:"publicNetworkAccess"`
						EnableNonSslPort    bool   `json:"enableNonSslPort"`
						Sku                 struct {
							Name string `json:"name"`
						} `json:"sku"`
					} `json:"properties"`
				}
				_ = json.Unmarshal(body, &doc)
				sku, pubAccess, redisVer, nonSsl = doc.Properties.Sku.Name,
					doc.Properties.PublicNetworkAccess, doc.Properties.RedisVersion, doc.Properties.EnableNonSslPort
				w.WriteHeader(200)
				_, _ = w.Write([]byte(`{"properties":{"provisioningState":"Succeeded"}}`))
			case "GET":
				b, _ := json.Marshal(map[string]any{
					"location": "eastus",
					"tags":     map[string]any{"groundhold-capability": "sessions", "groundhold-environment": "prod"},
					"properties": map[string]any{
						"provisioningState":   "Succeeded",
						"redisVersion":        redisVer,
						"publicNetworkAccess": pubAccess,
						"enableNonSslPort":    nonSsl,
						"sku":                 map[string]any{"name": sku},
					},
				})
				_, _ = w.Write(b)
			default:
				w.WriteHeader(404)
			}
		}))
}

func TestMetamorphicRedisAzureRoundTrip(t *testing.T) {
	cases := []struct {
		name      string
		avail     string
		public    bool
		tls       bool
		wantClass string
	}{
		{"zonal-private-tls", "zonal", false, true, "zonal"},
		// D946: regional (zone-redundant) is refused for Azure Redis, so the round-trip
		// varies public/tls under the valid zonal class instead.
		{"zonal-public-notls", "zonal", true, false, "zonal"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			srv := metamorphicRedisAzServer(t)
			defer srv.Close()
			d := metamorphicDriver(t, srv.URL)
			attrs := map[string]any{
				"engine.protocol":        "redis/6",
				"location.region":        "eastus",
				"network.publicExposure": c.public,
				"encryption.atRest":      true,
				"encryption.inTransit":   c.tls,
				"availability.class":     c.avail,
				"service.managed":        true,
			}
			res := d.createRedisAzure("prod", "sessions", attrs, map[string]any{"resource_group": "rg1"}, 1)
			if res.Status != "succeeded" {
				t.Fatalf("create: %+v", res)
			}
			got := flatObserve(t, d, "rediscache", "sessions", res.ProviderID)
			if got["availability.class"] != c.wantClass {
				t.Errorf("availability.class %q not reflected: %+v", c.wantClass, got)
			}
			if got["network.publicExposure"] != c.public {
				t.Errorf("public %v not reflected: %+v", c.public, got)
			}
			if got["encryption.inTransit"] != c.tls {
				t.Errorf("inTransit %v not reflected: %+v", c.tls, got)
			}
		})
	}
}

// ---- Azure DNS (dns.zone) — the resource-type split ----
func metamorphicAzureDNSServer(t *testing.T) *httptest.Server {
	t.Helper()
	var putType string // "pub" | "priv", recorded from the create PUT path
	typeOf := func(path string) string {
		if strings.Contains(path, "/privateDnsZones/") {
			return "priv"
		}
		if strings.Contains(path, "/dnsZones/") {
			return "pub"
		}
		return ""
	}
	return httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			switch r.Method {
			case "PUT":
				putType = typeOf(r.URL.Path)
				w.WriteHeader(200)
				_, _ = w.Write([]byte(`{"properties":{"provisioningState":"Succeeded"}}`))
			case "GET":
				// only the SAME resource type create PUT answers — a driver that
				// reads the wrong type (mis-mapped the pid kind) gets a 404.
				if typeOf(r.URL.Path) != putType {
					w.WriteHeader(404)
					return
				}
				_, _ = w.Write([]byte(`{"location":"global",` +
					`"tags":{"groundhold-capability":"apex","groundhold-environment":"prod"},` +
					`"properties":{"provisioningState":"Succeeded"}}`))
			default:
				w.WriteHeader(200)
			}
		}))
}

func TestMetamorphicAzureDNSRoundTrip(t *testing.T) {
	for _, public := range []bool{true, false} {
		name := "public"
		if !public {
			name = "private"
		}
		t.Run(name, func(t *testing.T) {
			srv := metamorphicAzureDNSServer(t)
			defer srv.Close()
			d := metamorphicDriver(t, srv.URL)
			attrs := map[string]any{
				"zone.domain":            "example.com",
				"network.publicExposure": public,
				"service.managed":        true,
			}
			res := d.createAzureDNS("prod", "apex", attrs, map[string]any{"resource_group": "rg1"}, 1)
			if res.Status != "succeeded" {
				t.Fatalf("create: %+v", res)
			}
			got := flatObserve(t, d, "dnszone", "apex", res.ProviderID)
			if got["zone.domain"] != "example.com" {
				t.Errorf("domain not reflected (wrong resource type read?): %+v", got)
			}
			if got["network.publicExposure"] != public {
				t.Errorf("public %v not reflected: %+v", public, got)
			}
		})
	}
}

// ---- Azure Key Vault key (key.encryption) — the vault+key composite ----
func metamorphicAzureKeyServer(t *testing.T) *httptest.Server {
	t.Helper()
	var kty, rotationISO string
	return httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			isKey := strings.Contains(r.URL.Path, "/keys/")
			switch r.Method {
			case "PUT":
				if isKey {
					body, _ := io.ReadAll(r.Body)
					var doc struct {
						Properties struct {
							Kty            string `json:"kty"`
							RotationPolicy struct {
								LifetimeActions []struct {
									Trigger struct {
										TimeAfterCreate string `json:"timeAfterCreate"`
									} `json:"trigger"`
								} `json:"lifetimeActions"`
							} `json:"rotationPolicy"`
						} `json:"properties"`
					}
					_ = json.Unmarshal(body, &doc)
					kty = doc.Properties.Kty
					if la := doc.Properties.RotationPolicy.LifetimeActions; len(la) > 0 {
						rotationISO = la[0].Trigger.TimeAfterCreate
					}
				}
				w.WriteHeader(200)
				_, _ = w.Write([]byte(`{"properties":{"provisioningState":"Succeeded"}}`))
			case "GET":
				if isKey {
					rp := ""
					if rotationISO != "" {
						rp = `,"rotationPolicy":{"lifetimeActions":[{"trigger":{"timeAfterCreate":"` + rotationISO + `"}}]}`
					}
					_, _ = w.Write([]byte(`{"properties":{"kty":"` + kty + `"` + rp + `}}`))
					return
				}
				_, _ = w.Write([]byte(`{"location":"eastus","tags":{"groundhold-capability":"datakey","groundhold-environment":"prod"},"properties":{"provisioningState":"Succeeded"}}`))
			default:
				w.WriteHeader(200)
			}
		}))
}

func TestMetamorphicAzureKeyRoundTrip(t *testing.T) {
	cases := []struct {
		name     string
		prot     string
		wantProt string
		rotation string
		wantRot  string
	}{
		{"hsm-rotating", "hsm", "hsm", "90d", "90d"},
		{"software-manual", "software", "software", "", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			srv := metamorphicAzureKeyServer(t)
			defer srv.Close()
			d := metamorphicDriver(t, srv.URL)
			attrs := map[string]any{
				"location.region":  "eastus",
				"protection.level": c.prot,
				"service.managed":  true,
			}
			if c.rotation != "" {
				attrs["rotation.period"] = c.rotation
			}
			res := d.createAzureKey("prod", "datakey", attrs, map[string]any{"resource_group": "rg1", "tenant_id": testTenant}, 1)
			if res.Status != "succeeded" {
				t.Fatalf("create: %+v", res)
			}
			got := flatObserve(t, d, "keyvaultkey", "datakey", res.ProviderID)
			if got["protection.level"] != c.wantProt {
				t.Errorf("protection %q not reflected: %+v", c.wantProt, got)
			}
			if c.wantRot == "" {
				if _, has := got["rotation.period"]; has {
					t.Errorf("manual key must not report rotation: %+v", got)
				}
			} else if got["rotation.period"] != c.wantRot {
				t.Errorf("rotation %q not reflected: %+v", c.wantRot, got)
			}
		})
	}
}
