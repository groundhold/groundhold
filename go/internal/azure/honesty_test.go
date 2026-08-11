package azure

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"groundhold/internal/certifynet"
	"groundhold/internal/provider"
)

// armRole classifies ARM requests for the honesty harness: GET is a read, every
// other method (PUT/PATCH/DELETE) is an opaque mutation (ARM success is status +
// provisioningState, not a parsed id).
func armRole(req *http.Request, _ []byte) certifynet.Role {
	if req.Method == http.MethodGet {
		return certifynet.RoleRead
	}
	return certifynet.RoleMutateOpaque
}

// armHarnessFake: a fresh happy ARM double for each fault replay.
func armHarnessFake() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			switch r.Method {
			case "PUT":
				w.WriteHeader(201)
				_, _ = w.Write([]byte(`{"properties":{"provisioningState":"Succeeded"}}`))
			case "GET":
				_, _ = w.Write([]byte(`{"location":"eastus",` +
					`"tags":{"groundhold-capability":"backbone","groundhold-environment":"prod"},` +
					`"properties":{"provisioningState":"Succeeded","subnets":[{"properties":{` +
					`"networkSecurityGroup":{"id":"/subscriptions/x/resourceGroups/rg/providers/Microsoft.Network/networkSecurityGroups/n"}}}]}}`))
			case "DELETE":
				w.WriteHeader(200)
			default:
				w.WriteHeader(404)
			}
		}))
}

func TestHonestyHarnessAzureBlob(t *testing.T) {
	pid := blobProviderID(testSub, "rg1", azStorageName("prod", "assets", 1), blobContainerName("prod", "assets", 1))
	p := &certifynet.Probe{
		Name:            "azure/blob",
		AssertTransient: true, // D237
		Classify:        armRole,
		OwnerTagValue:   "assets",
		DeterministicID: true, // account + container names are chosen
		// F-LC3 (D518): migrated to the absence property.
		ObserveAbsent: func(pr provider.Provider) ([]provider.Observation, []string, error) {
			return pr.Observe("blob", "assets", pid)
		},
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
				Happy: func() *httptest.Server { return blobHarnessFake() },
				Run: func(pr provider.Provider) provider.CreateResult {
					return pr.Create("blob", "assets", "prod", blobAttrs(),
						map[string]any{"resource_group": "rg1"}, "k", 1)
				},
			},
			{
				Name:  "delete",
				Happy: func() *httptest.Server { return blobHarnessFake() },
				Run: func(pr provider.Provider) provider.CreateResult {
					return pr.Delete("blob", "assets", "prod", pid, "k")
				},
			},
		},
	}
	certifynet.CertifyDriverNet(t, p)
}

func blobHarnessFake() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			switch r.Method {
			case "PUT", "POST":
				w.WriteHeader(200)
				_, _ = w.Write([]byte(`{"etag":"W/\"x\"","properties":{"provisioningState":"Succeeded"}}`))
			case "GET":
				_, _ = w.Write([]byte(`{"location":"eastus","sku":{"name":"Standard_ZRS"},` +
					`"tags":{"groundhold-capability":"assets","groundhold-environment":"prod"},` +
					`"properties":{"provisioningState":"Succeeded","allowBlobPublicAccess":false}}`))
			case "DELETE":
				w.WriteHeader(200)
			default:
				w.WriteHeader(404)
			}
		}))
}

func TestHonestyHarnessAzureContainerApp(t *testing.T) {
	pid := acaProviderID(testSub, "rg1", containerAppName("prod", "api", 1))
	p := &certifynet.Probe{
		Name:            "azure/containerapps",
		AssertTransient: true, // D237
		Classify:        armRole,
		OwnerTagValue:   "api",
		DeterministicID: true,
		// F-LC3 (D518): migrated to the absence property.
		ObserveAbsent: func(pr provider.Provider) ([]provider.Observation, []string, error) {
			return pr.Observe("containerapps", "api", pid)
		},
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
				Happy: func() *httptest.Server { return acaHarnessFake() },
				Run: func(pr provider.Provider) provider.CreateResult {
					return pr.Create("containerapps", "api", "prod", acaAttrs(), acaImpl(), "k", 1)
				},
			},
			{
				Name:  "delete",
				Happy: func() *httptest.Server { return acaHarnessFake() },
				Run: func(pr provider.Provider) provider.CreateResult {
					return pr.Delete("containerapps", "api", "prod", pid, "k")
				},
			},
		},
	}
	certifynet.CertifyDriverNet(t, p)
}

func acaHarnessFake() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			switch r.Method {
			case "PUT":
				w.WriteHeader(201)
				_, _ = w.Write([]byte(`{"properties":{"provisioningState":"Succeeded"}}`))
			case "GET":
				_, _ = w.Write([]byte(`{"location":"eastus","tags":{"groundhold-capability":"api","groundhold-environment":"prod"},` +
					`"properties":{"provisioningState":"Succeeded","configuration":{"ingress":{"external":true,"allowInsecure":false}},"template":{"scale":{"minReplicas":2}}}}`))
			case "DELETE":
				w.WriteHeader(200)
			default:
				w.WriteHeader(404)
			}
		}))
}

func TestHonestyHarnessAzureFlex(t *testing.T) {
	pid := flexProviderID(testSub, "rg1", flexServerName("prod", "db", 1))
	p := &certifynet.Probe{
		Name:            "azure/flexpostgres",
		AssertTransient: true, // D237
		Classify:        armRole,
		OwnerTagValue:   "db",
		DeterministicID: true,
		// F-LC3 (D518): migrated to the absence property.
		ObserveAbsent: func(pr provider.Provider) ([]provider.Observation, []string, error) {
			return pr.Observe("flexpostgres", "db", pid)
		},
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
				Happy: func() *httptest.Server { return flexHarnessFake() },
				Run: func(pr provider.Provider) provider.CreateResult {
					return pr.Create("flexpostgres", "db", "prod", flexAttrs(), flexImpl(), "k", 1)
				},
			},
			{
				Name:  "delete",
				Happy: func() *httptest.Server { return flexHarnessFake() },
				Run: func(pr provider.Provider) provider.CreateResult {
					return pr.Delete("flexpostgres", "db", "prod", pid, "k")
				},
			},
		},
	}
	certifynet.CertifyDriverNet(t, p)
}

func flexHarnessFake() *httptest.Server {
	deleted := false
	return httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			// once deleted, the server is GONE — the ARM delete's 202 poll-to-absence
			// (D971) must be able to confirm a 404.
			if deleted && r.Method == "GET" {
				w.WriteHeader(404)
				return
			}
			switch r.Method {
			case "PUT":
				w.WriteHeader(202)
				_, _ = w.Write([]byte(`{"properties":{"state":"Creating"}}`))
			case "GET":
				_, _ = w.Write([]byte(`{"location":"eastus","tags":{"groundhold-capability":"db","groundhold-environment":"prod"},` +
					`"properties":{"state":"Ready","version":"16","network":{"publicNetworkAccess":"Disabled"},"highAvailability":{"mode":"ZoneRedundant"}}}`))
			case "DELETE":
				deleted = true
				w.WriteHeader(202)
			default:
				w.WriteHeader(404)
			}
		}))
}

func sbHarnessFake() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			isEntity := strings.Contains(r.URL.Path, "/queues/") || strings.Contains(r.URL.Path, "/topics/")
			switch {
			case r.Method == "PUT" && !isEntity:
				w.WriteHeader(201)
				_, _ = w.Write([]byte(`{"properties":{"provisioningState":"Succeeded"}}`))
			case r.Method == "PUT":
				w.WriteHeader(200)
				_, _ = w.Write([]byte(`{"properties":{}}`))
			case r.Method == "GET":
				_, _ = w.Write([]byte(`{"location":"eastus","tags":{"groundhold-capability":"orders","groundhold-environment":"prod"},` +
					`"properties":{"provisioningState":"Succeeded","publicNetworkAccess":"Disabled"}}`))
			case r.Method == "DELETE":
				w.WriteHeader(200)
			default:
				w.WriteHeader(404)
			}
		}))
}

func TestHonestyHarnessAzureServiceBus(t *testing.T) {
	pid := sbProviderID("sbq", testSub, "rg1", serviceBusNamespace("prod", "orders", 1), azResourceName("q", "prod", "orders", 1))
	p := &certifynet.Probe{
		Name:            "azure/servicebusqueue",
		AssertTransient: true, // D237
		Classify:        armRole,
		OwnerTagValue:   "orders",
		DeterministicID: true,
		// F-LC3 (D523): hand-wired — the providerId comes from the delete op.
		ObserveAbsent: func(pr provider.Provider) ([]provider.Observation, []string, error) {
			return pr.Observe("servicebusqueue", "orders", pid)
		},
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
				Happy: func() *httptest.Server { return sbHarnessFake() },
				Run: func(pr provider.Provider) provider.CreateResult {
					return pr.Create("servicebusqueue", "orders", "prod", sbQueueAttrs(), map[string]any{"resource_group": "rg1"}, "k", 1)
				},
			},
			{
				Name:  "delete",
				Happy: func() *httptest.Server { return sbHarnessFake() },
				Run: func(pr provider.Provider) provider.CreateResult {
					return pr.Delete("servicebusqueue", "orders", "prod", pid, "k")
				},
			},
		},
	}
	certifynet.CertifyDriverNet(t, p)
}

func TestHonestyHarnessAzureRedis(t *testing.T) {
	pid := redisAzureProviderID(testSub, "rg1", azResourceName("pv-cache", "prod", "sessions", 1))
	p := &certifynet.Probe{
		Name:            "azure/rediscache",
		AssertTransient: true, // D237 sweep
		Classify:        armRole,
		OwnerTagValue:   "sessions",
		DeterministicID: true, // the cache name is chosen
		// F-LC3 (D518): migrated to the absence property.
		ObserveAbsent: func(pr provider.Provider) ([]provider.Observation, []string, error) {
			return pr.Observe("rediscache", "sessions", pid)
		},
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
				Happy: func() *httptest.Server { return redisAzServer(t, "sessions", "Standard", "6.0", "Disabled", false) },
				Run: func(pr provider.Provider) provider.CreateResult {
					return pr.Create("rediscache", "sessions", "prod", redisAzAttrs(), redisAzImpl(), "k", 1)
				},
			},
			{
				Name:  "delete",
				Happy: func() *httptest.Server { return redisAzServer(t, "sessions", "Standard", "6.0", "Disabled", false) },
				Run: func(pr provider.Provider) provider.CreateResult {
					return pr.Delete("rediscache", "sessions", "prod", pid, "k")
				},
			},
		},
	}
	certifynet.CertifyDriverNet(t, p)
}

func TestHonestyHarnessAzureKeyVault(t *testing.T) {
	pid := keyVaultProviderID(testSub, "rg1", keyVaultName("prod", "dbcreds", 1))
	p := &certifynet.Probe{
		Name:            "azure/keyvault",
		AssertTransient: true, // D237 sweep
		Classify:        armRole,
		OwnerTagValue:   "dbcreds",
		DeterministicID: true, // the vault name is chosen
		// F-LC3 (D518): migrated to the absence property.
		ObserveAbsent: func(pr provider.Provider) ([]provider.Observation, []string, error) {
			return pr.Observe("keyvault", "dbcreds", pid)
		},
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
				Happy: func() *httptest.Server { return kvServer(t, "dbcreds", "Disabled") },
				Run: func(pr provider.Provider) provider.CreateResult {
					return pr.Create("keyvault", "dbcreds", "prod", kvAttrs(), kvImpl(), "k", 1)
				},
			},
			{
				Name:  "delete",
				Happy: func() *httptest.Server { return kvServer(t, "dbcreds", "Disabled") },
				Run: func(pr provider.Provider) provider.CreateResult {
					return pr.Delete("keyvault", "dbcreds", "prod", pid, "k")
				},
			},
		},
	}
	certifynet.CertifyDriverNet(t, p)
}

func TestHonestyHarnessAzureVNet(t *testing.T) {
	pid := vnetProviderID(testSub, "rg1", "pv-net-backbone-prod-abcd1234")
	p := &certifynet.Probe{
		Name:            "azure/vnet",
		AssertTransient: true, // D237
		Classify:        armRole,
		OwnerTagValue:   "backbone",
		DeterministicID: true, // the vnet name is chosen, pid known before create
		// F-LC3 (D517): first Azure service migrated to the absence property.
		ObserveAbsent: func(pr provider.Provider) ([]provider.Observation, []string, error) {
			return pr.Observe("vnet", "backbone", pid)
		},
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
				Happy: func() *httptest.Server { return armHarnessFake() },
				Run: func(pr provider.Provider) provider.CreateResult {
					return pr.Create("vnet", "backbone", "prod", vnetAttrs(),
						map[string]any{"resource_group": "rg1"}, "k", 1)
				},
			},
			{
				Name:  "delete",
				Happy: func() *httptest.Server { return armHarnessFake() },
				Run: func(pr provider.Provider) provider.CreateResult {
					return pr.Delete("vnet", "backbone", "prod", pid, "k")
				},
			},
		},
	}
	certifynet.CertifyDriverNet(t, p)
}

func TestHonestyHarnessAzureDNS(t *testing.T) {
	pid := "adns:" + testSub + ":rg1:pub:example.com"
	p := &certifynet.Probe{
		Name:            "azure/dnszone",
		AssertTransient: true, // D237 sweep
		Classify:        armRole,
		OwnerTagValue:   "apex",
		DeterministicID: true, // the zone name is the domain (chosen)
		// F-LC3 (D518): migrated to the absence property.
		ObserveAbsent: func(pr provider.Provider) ([]provider.Observation, []string, error) {
			return pr.Observe("dnszone", "apex", pid)
		},
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
				Happy: func() *httptest.Server { return azDNSServer(t, "apex", nil) },
				Run: func(pr provider.Provider) provider.CreateResult {
					return pr.Create("dnszone", "apex", "prod", azDNSAttrs(), map[string]any{"resource_group": "rg1"}, "k", 1)
				},
			},
			{
				Name:  "delete",
				Happy: func() *httptest.Server { return azDNSServer(t, "apex", nil) },
				Run: func(pr provider.Provider) provider.CreateResult {
					return pr.Delete("dnszone", "apex", "prod", pid, "k")
				},
			},
		},
	}
	certifynet.CertifyDriverNet(t, p)
}

func TestHonestyHarnessAzureRole(t *testing.T) {
	pid := azureRoleProviderID(testSub, azAssignmentGUID("/subscriptions/"+testSub, testPrincipal, readerGUID))
	p := &certifynet.Probe{
		Name:            "azure/roleassignment",
		AssertTransient: true, // D237 sweep
		Classify:        armRole,
		OwnerTagValue:   "reader", // content-addressed: no tag to poison (foreign-tag n/a)
		DeterministicID: true,     // the assignment name is a deterministic GUID
		// F-LC3 (D518): migrated to the absence property.
		ObserveAbsent: func(pr provider.Provider) ([]provider.Observation, []string, error) {
			return pr.Observe("roleassignment", "reader", pid)
		},
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
				Happy: func() *httptest.Server { return azRoleServer(t, readerGUID) },
				Run: func(pr provider.Provider) provider.CreateResult {
					return pr.Create("roleassignment", "reader", "prod", azRoleAttrs(), nil, "k", 1)
				},
			},
			{
				Name:  "delete",
				Happy: func() *httptest.Server { return azRoleServer(t, readerGUID) },
				Run: func(pr provider.Provider) provider.CreateResult {
					return pr.Delete("roleassignment", "reader", "prod", pid, "k")
				},
			},
		},
	}
	certifynet.CertifyDriverNet(t, p)
}

func TestHonestyHarnessAzureCustomRole(t *testing.T) {
	pid := azureCustomRoleProviderID(testSub, azRoleDefGUID("/subscriptions/"+testSub, "groundhold viewer (prod)"))
	p := &certifynet.Probe{
		Name:            "azure/customroledef",
		AssertTransient: true, // D237 sweep
		Classify:        armRole,
		OwnerTagValue:   "viewer", // content-addressed by deterministic GUID (foreign-tag n/a)
		DeterministicID: true,
		// F-LC3 (D518): migrated to the absence property.
		ObserveAbsent: func(pr provider.Provider) ([]provider.Observation, []string, error) {
			return pr.Observe("customroledef", "viewer", pid)
		},
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
				Happy: func() *httptest.Server { return azCustomRoleServer(t) },
				Run: func(pr provider.Provider) provider.CreateResult {
					return pr.Create("customroledef", "viewer", "prod", azRoleDefAttrs(), nil, "k", 1)
				},
			},
			{
				Name:  "delete",
				Happy: func() *httptest.Server { return azCustomRoleServer(t) },
				Run: func(pr provider.Provider) provider.CreateResult {
					return pr.Delete("customroledef", "viewer", "prod", pid, "k")
				},
			},
		},
	}
	certifynet.CertifyDriverNet(t, p)
}

func TestHonestyHarnessAzureAlert(t *testing.T) {
	pid := azureAlertProviderID(testSub, "rg1", azResourceName("pv-alert", "prod", "cpu", 1))
	p := &certifynet.Probe{
		Name:            "azure/metricalert",
		AssertTransient: true, // D237 sweep
		Classify:        armRole,
		OwnerTagValue:   "cpu",
		DeterministicID: true, // the metricAlert name is a chosen slug+hash
		// F-LC3 (D518): migrated to the absence property.
		ObserveAbsent: func(pr provider.Provider) ([]provider.Observation, []string, error) {
			return pr.Observe("metricalert", "cpu", pid)
		},
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
				Happy: func() *httptest.Server { return azAlertOwnedServer(t) },
				Run: func(pr provider.Provider) provider.CreateResult {
					return pr.Create("metricalert", "cpu", "prod", azAlertAttrs(), azAlertImpl(), "k", 1)
				},
			},
			{
				Name:  "delete",
				Happy: func() *httptest.Server { return azAlertOwnedServer(t) },
				Run: func(pr provider.Provider) provider.CreateResult {
					return pr.Delete("metricalert", "cpu", "prod", pid, "k")
				},
			},
		},
	}
	certifynet.CertifyDriverNet(t, p)
}

func TestHonestyHarnessAzureDashboard(t *testing.T) {
	pid := azureDashProviderID(testSub, "rg1", azResourceName("pv-dash", "prod", "golden", 1))
	p := &certifynet.Probe{
		Name:            "azure/portaldash",
		AssertTransient: true, // D237 sweep
		Classify:        armRole,
		OwnerTagValue:   "golden",
		DeterministicID: true, // the dashboard name is a chosen slug+hash
		// F-LC3 (D518): migrated to the absence property.
		ObserveAbsent: func(pr provider.Provider) ([]provider.Observation, []string, error) {
			return pr.Observe("portaldash", "golden", pid)
		},
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
				Happy: func() *httptest.Server { return azDashOwnedServer(t) },
				Run: func(pr provider.Provider) provider.CreateResult {
					return pr.Create("portaldash", "golden", "prod", azDashAttrs(), azDashImpl(), "k", 1)
				},
			},
			{
				Name:  "delete",
				Happy: func() *httptest.Server { return azDashOwnedServer(t) },
				Run: func(pr provider.Provider) provider.CreateResult {
					return pr.Delete("portaldash", "golden", "prod", pid, "k")
				},
			},
		},
	}
	certifynet.CertifyDriverNet(t, p)
}

func TestHonestyHarnessAzureWebtest(t *testing.T) {
	pid := azureWebtestProviderID(testSub, "rg1", azResourceName("pv-webtest", "prod", "api", 1))
	p := &certifynet.Probe{
		Name:            "azure/webtest",
		AssertTransient: true, // D237 sweep
		Classify:        armRole,
		OwnerTagValue:   "api",
		DeterministicID: true, // the webtest name is a chosen slug+hash
		// F-LC3 (D518): migrated to the absence property.
		ObserveAbsent: func(pr provider.Provider) ([]provider.Observation, []string, error) {
			return pr.Observe("webtest", "api", pid)
		},
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
				Happy: func() *httptest.Server { return azWebtestOwnedServer(t) },
				Run: func(pr provider.Provider) provider.CreateResult {
					return pr.Create("webtest", "api", "prod", azWebtestAttrs(), azWebtestImpl(), "k", 1)
				},
			},
			{
				Name:  "delete",
				Happy: func() *httptest.Server { return azWebtestOwnedServer(t) },
				Run: func(pr provider.Provider) provider.CreateResult {
					return pr.Delete("webtest", "api", "prod", pid, "k")
				},
			},
		},
	}
	certifynet.CertifyDriverNet(t, p)
}

func TestHonestyHarnessAzureScheduledQuery(t *testing.T) {
	pid := azureSQProviderID(testSub, "rg1", azResourceName("pv-lm", "prod", "errors", 1))
	p := &certifynet.Probe{
		Name:            "azure/scheduledquery",
		AssertTransient: true, // D237 sweep
		Classify:        armRole,
		OwnerTagValue:   "errors",
		DeterministicID: true, // the rule name is a chosen slug+hash
		// F-LC3 (D518): migrated to the absence property.
		ObserveAbsent: func(pr provider.Provider) ([]provider.Observation, []string, error) {
			return pr.Observe("scheduledquery", "errors", pid)
		},
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
				Happy: func() *httptest.Server { return azSQOwnedServer(t) },
				Run: func(pr provider.Provider) provider.CreateResult {
					return pr.Create("scheduledquery", "errors", "prod", azSQAttrs(), azSQImpl(), "k", 1)
				},
			},
			{
				Name:  "delete",
				Happy: func() *httptest.Server { return azSQOwnedServer(t) },
				Run: func(pr provider.Provider) provider.CreateResult {
					return pr.Delete("scheduledquery", "errors", "prod", pid, "k")
				},
			},
		},
	}
	certifynet.CertifyDriverNet(t, p)
}

func TestHonestyHarnessACR(t *testing.T) {
	pid := azureACRProviderID(testSub, "rg1", acrName("prod", "images", 1))
	p := &certifynet.Probe{
		Name:            "azure/acr",
		AssertTransient: true, // D237 sweep
		Classify:        armRole,
		OwnerTagValue:   "images",
		DeterministicID: true, // the registry name is a deterministic hash
		// F-LC3 (D518): migrated to the absence property.
		ObserveAbsent: func(pr provider.Provider) ([]provider.Observation, []string, error) {
			return pr.Observe("acr", "images", pid)
		},
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
				Happy: func() *httptest.Server { return acrServer(t, "images") },
				Run: func(pr provider.Provider) provider.CreateResult {
					return pr.Create("acr", "images", "prod", acrAttrs(), acrImpl(), "k", 1)
				},
			},
			{
				Name:  "delete",
				Happy: func() *httptest.Server { return acrServer(t, "images") },
				Run: func(pr provider.Provider) provider.CreateResult {
					return pr.Delete("acr", "images", "prod", pid, "k")
				},
			},
		},
	}
	certifynet.CertifyDriverNet(t, p)
}

// uamiHarnessFake: a happy user-assigned managed identity ARM double. PUT is
// synchronous (200 with clientId/principalId); GET reflects OUR ownership tags.
func uamiHarnessFake() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			switch r.Method {
			case "PUT":
				w.WriteHeader(200)
				_, _ = w.Write([]byte(`{"location":"eastus","properties":{"clientId":"c","principalId":"p"}}`))
			case "GET":
				_, _ = w.Write([]byte(`{"location":"eastus",` +
					`"tags":{"groundhold-capability":"runner","groundhold-environment":"prod","groundhold-display":"batch runner"},` +
					`"properties":{"clientId":"c","principalId":"p"}}`))
			case "DELETE":
				w.WriteHeader(200)
			default:
				w.WriteHeader(404)
			}
		}))
}

func TestHonestyHarnessAzureManagedIdentity(t *testing.T) {
	pid := uamiProviderID(testSub, "rg1", azResourceName("id", "prod", "runner", 1))
	impl := map[string]any{"resource_group": "rg1", "location": "eastus"}
	p := &certifynet.Probe{
		Name:            "azure/managedidentity",
		AssertTransient: true,    // D237 sweep
		Classify:        armRole, // PUT synchronous opaque; GET read
		OwnerTagValue:   "runner",
		DeterministicID: true, // the identity name is chosen, pid known before create
		// F-LC3 (D518): migrated to the absence property.
		ObserveAbsent: func(pr provider.Provider) ([]provider.Observation, []string, error) {
			return pr.Observe("managedidentity", "runner", pid)
		},
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
				Happy: func() *httptest.Server { return uamiHarnessFake() },
				Run: func(pr provider.Provider) provider.CreateResult {
					return pr.Create("managedidentity", "runner", "prod", uamiAttrs(), impl, "k", 1)
				},
			},
			{
				Name:  "delete",
				Happy: func() *httptest.Server { return uamiHarnessFake() },
				Run: func(pr provider.Provider) provider.CreateResult {
					return pr.Delete("managedidentity", "runner", "prod", pid, "k")
				},
			},
		},
	}
	certifynet.CertifyDriverNet(t, p)
}

func TestHonestyHarnessAzureKey(t *testing.T) {
	pid := azureKeyProviderID(testSub, "rg1", "eastus",
		keyVaultName("prod", "datakey", 1), azResourceName("pv-key", "prod", "datakey", 1))
	p := &certifynet.Probe{
		Name:            "azure/keyvaultkey",
		AssertTransient: true, // D237 sweep
		Classify:        armRole,
		OwnerTagValue:   "datakey",
		DeterministicID: true, // vault + key names are chosen
		// F-LC3 (D518): migrated to the absence property.
		ObserveAbsent: func(pr provider.Provider) ([]provider.Observation, []string, error) {
			return pr.Observe("keyvaultkey", "datakey", pid)
		},
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
				Happy: func() *httptest.Server { return azKeyServer(t, "datakey", "RSA-HSM", "P90D") },
				Run: func(pr provider.Provider) provider.CreateResult {
					return pr.Create("keyvaultkey", "datakey", "prod", azKeyAttrs(), azKeyImpl(), "k", 1)
				},
			},
			{
				Name:  "delete",
				Happy: func() *httptest.Server { return azKeyServer(t, "datakey", "RSA-HSM", "P90D") },
				Run: func(pr provider.Provider) provider.CreateResult {
					return pr.Delete("keyvaultkey", "datakey", "prod", pid, "k")
				},
			},
		},
	}
	certifynet.CertifyDriverNet(t, p)
}

// azDiskHarnessFake answers the happy path for the managed-disk probe: a PUT that
// succeeds, a GET that returns a readable disk carrying our tags, a DELETE that
// works. certifynet then injects transport faults, 5xx, garbled and empty bodies
// into each mutating call and checks the driver never converts an unknown outcome
// into a definite one.
func azDiskHarnessFake() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodDelete {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{}`))
			return
		}
		_, _ = w.Write([]byte(`{"location":"swedencentral","sku":{"name":"Premium_LRS"},
"tags":{"groundhold-capability":"orders-data","groundhold-environment":"prod"},
"properties":{"provisioningState":"Succeeded"}}`))
	}))
}

// The adversarial honesty pass for the Azure half of capability.storage.block
// (D369). ARM's PUT is an UPSERT, which is why the foreign-upsert refusal (D254)
// carries more weight here than on a stateless resource: a name collision that
// wrote anyway would not misconfigure somebody else's disk, it would overwrite
// their data.
func TestHonestyHarnessAzureDisk(t *testing.T) {
	pid := azureDiskProviderID(testSub, "rg1", "pv-disk-orders-data-prod-abcd1234")
	p := &certifynet.Probe{
		Name:            "azure/azdisk",
		AssertTransient: true, // D237 sweep
		Classify:        armRole,
		OwnerTagValue:   "orders-data",
		DeterministicID: true, // the disk name is a deterministic hash
		// F-LC3 (D518): migrated to the absence property.
		ObserveAbsent: func(pr provider.Provider) ([]provider.Observation, []string, error) {
			return pr.Observe("azdisk", "orders-data", pid)
		},
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
				Happy: azDiskHarnessFake,
				Run: func(pr provider.Provider) provider.CreateResult {
					return pr.Create("azdisk", "orders-data", "prod", azDiskAttrs(),
						map[string]any{"resource_group": "rg1", "disk_sku": "Premium_LRS", "size_gb": 100},
						"k", 1)
				},
			},
			{
				Name:  "delete",
				Happy: azDiskHarnessFake,
				Run: func(pr provider.Provider) provider.CreateResult {
					return pr.Delete("azdisk", "orders-data", "prod", pid, "k")
				},
			},
		},
	}
	certifynet.CertifyDriverNet(t, p)
}

// vmssHarnessFake answers the happy path for the fleet probe: the scale-set PUT,
// the read-back that gives its resource id, the autoscale-setting PUT and the
// deletes.
func vmssHarnessFake() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodPut, http.MethodDelete:
			_, _ = w.Write([]byte(`{"properties":{"provisioningState":"Succeeded"}}`))
		default:
			if strings.Contains(r.URL.Path, "autoscalesettings") {
				// the setting carries the ownership tags the driver writes, so the
				// foreign-upsert check (D254) sees its own resource rather than a stranger's
				_, _ = w.Write([]byte(`{"tags":{"groundhold-capability":"web-fleet","groundhold-environment":"prod"},` +
					`"properties":{"enabled":true,"profiles":[{"capacity":{"minimum":"2","maximum":"10"}}]}}`))
				return
			}
			// the probe creates in environment "prod", and the foreign-upsert
			// refusal (D254) compares tags — a fake carrying another environment
			// would fail the baseline for the right reason at the wrong moment
			_, _ = w.Write([]byte(strings.Replace(vmssDoc("web-fleet", 2, false),
				`"groundhold-environment":"production"`, `"groundhold-environment":"prod"`, 1)))
		}
	}))
}

// The adversarial honesty pass for the Azure third of a fleet (D372). ARM's PUT
// is an UPSERT, so the foreign-upsert refusal (D254) is what stands between a
// name collision and overwriting somebody else's fleet — and the stake on this
// type is a bill that grows on its own.
func TestHonestyHarnessAzureVMSS(t *testing.T) {
	pid := azureVMSSProviderID(testSub, "rg1", "pv-vmss-web-fleet-prod-abcd1234")
	p := &certifynet.Probe{
		Name:            "azure/azvmss",
		AssertTransient: true, // D237 sweep
		Classify:        armRole,
		OwnerTagValue:   "web-fleet",
		DeterministicID: true, // the scale-set name is a deterministic hash
		// F-LC3 (D518): migrated to the absence property.
		ObserveAbsent: func(pr provider.Provider) ([]provider.Observation, []string, error) {
			return pr.Observe("azvmss", "web-fleet", pid)
		},
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
				Happy: vmssHarnessFake,
				Run: func(pr provider.Provider) provider.CreateResult {
					return pr.Create("azvmss", "web-fleet", "prod", vmssAttrs(), vmssImpl(), "k", 1)
				},
			},
			{
				Name:  "delete",
				Happy: vmssHarnessFake,
				Run: func(pr provider.Provider) provider.CreateResult {
					return pr.Delete("azvmss", "web-fleet", "prod", pid, "k")
				},
			},
		},
	}
	certifynet.CertifyDriverNet(t, p)
}
