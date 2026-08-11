package azure

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"groundhold/internal/certifynet"
	"groundhold/internal/provider"
)

// D431: Azure needs no conflict wrapper, and the reason IS the finding.
//
// On AWS and GCP an "already exists" estate had to be constructed — a 409, a tag scan
// that finds something, a stateful fake seeded by a previous run. On Azure the estate is
// the ordinary fixture: an ARM PUT is idempotent by path, so a driver's happy fake, whose
// GET already describes a resource carrying our tags, IS a standing resource of ours. The
// create runs against it unchanged.
//
// That makes the property being asserted different in an important way. Everywhere else
// the gate asked "did it avoid duplicating". Here it asks "did the ownership PRE-READ
// happen and did it bind" — because the PUT will overwrite whatever is at that path
// whether it is ours or not (D254). The mutation allowance is therefore not a duplicate
// budget: the PUT is the converge, and it is meant to happen.

func azReadRole(req *http.Request, _ []byte) certifynet.Role {
	if req.Method == http.MethodGet {
		return certifynet.RoleRead
	}
	return certifynet.RoleMutateOpaque
}

type azAdoptCase struct {
	idFromContent bool // D525: identity derived by hashing the request
	svc, cap      string
	server        func(t *testing.T) *httptest.Server
	attrs         func() map[string]any
	impl          map[string]any
	mutations     int
}

func runAzAdoptCase(t *testing.T, c azAdoptCase) {
	t.Helper()
	p := &certifynet.ExistingProbe{
		Name: "azure/" + c.svc,
		// D525: the id is a hash of the request, so the write cannot land elsewhere.
		IdentityFromContent: c.idFromContent,
		Classify:            azReadRole,
		ExistingServer:      func() *httptest.Server { return c.server(t) },
		New: func(happyURL string, rt http.RoundTripper) provider.Provider {
			d := NewDriver(testSub)
			d.HTTP = &http.Client{Transport: rt}
			d.BaseURL = happyURL
			d.token = "test-token"
			d.Now = time.Now
			d.PollInterval = time.Millisecond
			d.PollTimeout = 2 * time.Second
			return d
		},
		Create: func(pr provider.Provider) provider.CreateResult {
			return pr.Create(c.svc, c.cap, "prod", c.attrs(), c.impl, "k", 1)
		},
		AllowedMutations: c.mutations,
	}
	certifynet.CertifyCreateAdoptsExisting(t, p)
}

func TestAdoptsExistingVNet(t *testing.T) {
	runAzAdoptCase(t, azAdoptCase{svc: "vnet", cap: "backbone",
		server: func(t *testing.T) *httptest.Server { return armFake(t, "backbone") },
		attrs:  vnetAttrs, impl: map[string]any{"resource_group": "rg1"}, mutations: 2})
}

func TestAdoptsExistingCosmos(t *testing.T) {
	runAzAdoptCase(t, azAdoptCase{svc: "cosmos", cap: "sessions",
		server: func(t *testing.T) *httptest.Server {
			return cosmosServer(t, "sessions", "Continuous", "")
		},
		attrs: cosmosAttrs, impl: cosmosImpl(), mutations: 3})
}

func TestAdoptsExistingBlob(t *testing.T) {
	runAzAdoptCase(t, azAdoptCase{svc: "blob", cap: "assets",
		server: func(t *testing.T) *httptest.Server { return blobArmFake(t, "assets") },
		attrs:  blobAttrs, impl: map[string]any{"resource_group": "rg1"}, mutations: 4})
}

// ---- D432: eight more, each against its own driver's happy fixture. No wrapper: on
// Azure the happy fixture already IS a standing resource of ours (D431).

func TestAdoptsExistingACR(t *testing.T) {
	runAzAdoptCase(t, azAdoptCase{svc: "acr", cap: "images",
		server: func(t *testing.T) *httptest.Server { return acrServer(t, "images") },
		attrs:  acrAttrs, impl: acrImpl(), mutations: 3})
}

func TestAdoptsExistingEventHubs(t *testing.T) {
	runAzAdoptCase(t, azAdoptCase{svc: "eventhubs", cap: "events",
		server: func(t *testing.T) *httptest.Server { return ehServer(t, "events", true, false, 7) },
		attrs:  ehAttrs, impl: ehImpl(), mutations: 3})
}

func TestAdoptsExistingLogAnalytics(t *testing.T) {
	runAzAdoptCase(t, azAdoptCase{svc: "loganalytics", cap: "app-logs",
		server: func(t *testing.T) *httptest.Server { return laServer(t, "app-logs", 30) },
		attrs:  laAttrs, impl: laImpl(), mutations: 2})
}

func TestAdoptsExistingAzFiles(t *testing.T) {
	runAzAdoptCase(t, azAdoptCase{svc: "azurefiles", cap: "shared",
		server: func(t *testing.T) *httptest.Server {
			return azfilesServer(t, "shared", "FileStorage", "Premium_LRS", "Microsoft.Storage")
		},
		attrs: azfilesAttrs, impl: azfilesImpl(), mutations: 3})
}

func TestAdoptsExistingAzKafka(t *testing.T) {
	runAzAdoptCase(t, azAdoptCase{svc: "azkafka", cap: "bus",
		server: func(t *testing.T) *httptest.Server { return azKafkaServer(t, "bus", true, false) },
		attrs:  azKafkaAttrs, impl: azKafkaImpl(), mutations: 3})
}

func TestAdoptsExistingRedisAzure(t *testing.T) {
	runAzAdoptCase(t, azAdoptCase{svc: "rediscache", cap: "sessions",
		server: func(t *testing.T) *httptest.Server {
			return redisAzServer(t, "sessions", "Premium", "6.0", "Disabled", false)
		},
		attrs: redisAzAttrs, impl: redisAzImpl(), mutations: 3})
}

func TestAdoptsExistingServiceBusQueue(t *testing.T) {
	runAzAdoptCase(t, azAdoptCase{svc: "servicebusqueue", cap: "orders",
		server: func(t *testing.T) *httptest.Server { return sbArmFake(t, "orders") },
		attrs:  sbQueueAttrs, impl: map[string]any{"resource_group": "rg1"}, mutations: 3})
}

func TestAdoptsExistingFlexPostgres(t *testing.T) {
	runAzAdoptCase(t, azAdoptCase{svc: "flexpostgres", cap: "db",
		server: func(t *testing.T) *httptest.Server { return flexArmFake(t, "db") },
		attrs:  flexAttrs, impl: flexImpl(), mutations: 4})
}

// ---- D433: twelve more, same one-line shape.

func TestAdoptsExistingAPIM(t *testing.T) {
	runAzAdoptCase(t, azAdoptCase{svc: "apim", cap: "front",
		server: func(t *testing.T) *httptest.Server { return apimServer(t, "front") },
		attrs:  apimAttrs, impl: apimImpl(), mutations: 3})
}

func TestAdoptsExistingAISearch(t *testing.T) {
	runAzAdoptCase(t, azAdoptCase{svc: "aisearch", cap: "catalog",
		server: func(t *testing.T) *httptest.Server {
			return aiSearchServer(t, "catalog", "standard", 3, "disabled", "Enabled")
		},
		attrs: aiSearchAttrs, impl: aiSearchImpl(), mutations: 3})
}

func TestAdoptsExistingAzureCDN(t *testing.T) {
	runAzAdoptCase(t, azAdoptCase{svc: "azurecdn", cap: "edge",
		server: func(t *testing.T) *httptest.Server {
			return azCDNServer(t, "edge", "origin.example.com", "https-only")
		},
		attrs:     azCDNAttrs,
		impl:      map[string]any{"resource_group": "rg1", "origin_hostname": "origin.example.com"},
		mutations: 5})
}

func TestAdoptsExistingContainerApp(t *testing.T) {
	runAzAdoptCase(t, azAdoptCase{svc: "containerapps", cap: "api",
		server: func(t *testing.T) *httptest.Server { return acaArmFake(t, "api") },
		attrs:  acaAttrs, impl: acaImpl(), mutations: 4})
}

func TestAdoptsExistingContainerAppsJob(t *testing.T) {
	runAzAdoptCase(t, azAdoptCase{svc: "containerappsjob", cap: "worker",
		server: func(t *testing.T) *httptest.Server {
			return cajServer(t, "worker", "Manual", "myregistry.azurecr.io/worker:1.2")
		},
		attrs: cajAttrs, impl: cajImpl(), mutations: 4})
}

func TestAdoptsExistingCustomRoleDef(t *testing.T) {
	runAzAdoptCase(t, azAdoptCase{svc: "customroledef", idFromContent: true, cap: "viewer",
		server: func(t *testing.T) *httptest.Server { return azCustomRoleServer(t) },
		attrs:  azRoleDefAttrs, mutations: 2})
}

func TestAdoptsExistingFrontDoorWAF(t *testing.T) {
	runAzAdoptCase(t, azAdoptCase{svc: "frontdoorwaf", cap: "edge",
		server: func(t *testing.T) *httptest.Server {
			return fdWafServer(t, "edge", "Prevention", true, true)
		},
		attrs: fdWafAttrs, impl: fdWafImpl(), mutations: 3})
}

func TestAdoptsExistingKeyVaultKey(t *testing.T) {
	runAzAdoptCase(t, azAdoptCase{svc: "keyvaultkey", cap: "datakey",
		server: func(t *testing.T) *httptest.Server { return azKeyServer(t, "datakey", "RSA-HSM", "P90D") },
		attrs:  azKeyAttrs, impl: azKeyImpl(), mutations: 3})
}

func TestAdoptsExistingKeyVault(t *testing.T) {
	runAzAdoptCase(t, azAdoptCase{svc: "keyvault", cap: "dbcreds",
		server: func(t *testing.T) *httptest.Server { return kvServer(t, "dbcreds", "Disabled") },
		attrs:  kvAttrs, impl: kvImpl(), mutations: 3})
}

func TestAdoptsExistingMetricAlert(t *testing.T) {
	runAzAdoptCase(t, azAdoptCase{svc: "metricalert", cap: "cpu",
		server: func(t *testing.T) *httptest.Server { return azAlertServer(t) },
		attrs:  azAlertAttrs, impl: azAlertImpl(), mutations: 2})
}

func TestAdoptsExistingPortalDash(t *testing.T) {
	runAzAdoptCase(t, azAdoptCase{svc: "portaldash", cap: "golden",
		server: func(t *testing.T) *httptest.Server { return azDashServer(t) },
		attrs:  azDashAttrs, impl: azDashImpl(), mutations: 2})
}

func TestAdoptsExistingScheduledQuery(t *testing.T) {
	runAzAdoptCase(t, azAdoptCase{svc: "scheduledquery", cap: "errors",
		server: func(t *testing.T) *httptest.Server { return azSQServer(t) },
		attrs:  azSQAttrs, impl: azSQImpl(), mutations: 2})
}

func TestAdoptsExistingWebtest(t *testing.T) {
	runAzAdoptCase(t, azAdoptCase{svc: "webtest", cap: "api",
		server: func(t *testing.T) *httptest.Server { return azWebtestServer(t) },
		attrs:  azWebtestAttrs, impl: azWebtestImpl(), mutations: 2})
}

// ---- D434: thirteen more.

func TestAdoptsExistingActivityLog(t *testing.T) {
	runAzAdoptCase(t, azAdoptCase{svc: "activitylog", cap: "audit",
		server: func(t *testing.T) *httptest.Server {
			return activityLogArmFake(t, "workspaceId", testWorkspaceDest, true)
		},
		attrs: activityLogAttrs, impl: activityLogImpl(), mutations: 2})
}

func TestAdoptsExistingAKSAddon(t *testing.T) {
	runAzAdoptCase(t, azAdoptCase{svc: "aks-addon", cap: "csi",
		server: func(t *testing.T) *httptest.Server { return aksAddonServer(t, true, true, nil) },
		attrs:  aksAddonAttrs, impl: aksAddonImpl(), mutations: 2})
}

func TestAdoptsExistingBackupPolicy(t *testing.T) {
	runAzAdoptCase(t, azAdoptCase{svc: "backuppolicy", cap: "dr-plan",
		server: func(t *testing.T) *httptest.Server {
			return backupPolicyServer(t, BackupPolicyName("prod", "dr-plan", 1), "westeurope")
		},
		attrs: backupPolicyAttrs, impl: backupPolicyImpl(), mutations: 2})
}

// TestAdoptsExistingAzBackupVault: the third backup vault in the sweep after AWS (D400)
// and GCP (D430), and the same damage model on all three — a duplicate splits the estate,
// the new one is empty and looks healthy, and you find out at restore.
func TestAdoptsExistingAzBackupVault(t *testing.T) {
	runAzAdoptCase(t, azAdoptCase{svc: "backupvault", cap: "archive",
		server: func(t *testing.T) *httptest.Server {
			return backupVaultServer(t, "eastus", "Locked", 30, false, nil)
		},
		attrs: bvAttrs, impl: bvImpl(), mutations: 2})
}

func TestAdoptsExistingConsumptionBudget(t *testing.T) {
	runAzAdoptCase(t, azAdoptCase{svc: "consumptionbudget", cap: "spend-guard",
		server: func(t *testing.T) *httptest.Server {
			return consBudgetServer(t, ConsumptionBudgetName("prod", "spend-guard", 1))
		},
		attrs: consBudgetAttrs, impl: consBudgetImpl(), mutations: 2})
}

func TestAdoptsExistingAzureDNSZone(t *testing.T) {
	runAzAdoptCase(t, azAdoptCase{svc: "dnszone", cap: "apex",
		server: func(t *testing.T) *httptest.Server {
			var path string
			return azDNSServer(t, "apex", &path)
		},
		attrs: azDNSAttrs, impl: map[string]any{"resource_group": "rg1"}, mutations: 2})
}

func TestAdoptsExistingAzureDNSRecord(t *testing.T) {
	runAzAdoptCase(t, azAdoptCase{svc: "dnsrecord", cap: azDNSRecordCap,
		server: func(t *testing.T) *httptest.Server {
			var path string
			return azDNSRecordServer(t, sanitizeAzTag(azDNSRecordCap), &path)
		},
		attrs: azDNSRecordAttrs, impl: azDNSRecordImpl(), mutations: 2})
}

func TestAdoptsExistingManagedIdentity(t *testing.T) {
	runAzAdoptCase(t, azAdoptCase{svc: "managedidentity", cap: "runner",
		server: func(t *testing.T) *httptest.Server { return uamiServer(t, "runner", "batch runner") },
		attrs:  uamiAttrs, impl: uamiImpl(), mutations: 2})
}

func TestAdoptsExistingRoleAssignment(t *testing.T) {
	runAzAdoptCase(t, azAdoptCase{svc: "roleassignment", idFromContent: true, cap: "reader",
		server: func(t *testing.T) *httptest.Server { return azRoleServer(t, readerGUID) },
		attrs:  azRoleAttrs, mutations: 2})
}

func TestAdoptsExistingServiceBusTopic(t *testing.T) {
	runAzAdoptCase(t, azAdoptCase{svc: "servicebustopic", cap: "events",
		server: func(t *testing.T) *httptest.Server { return sbArmFake(t, "events") },
		attrs: func() map[string]any {
			return map[string]any{"location.region": "eastus",
				"network.publicExposure": false, "encryption.atRest": true, "service.managed": true}
		},
		impl: map[string]any{"resource_group": "rg1"}, mutations: 3})
}

func TestAdoptsExistingACSEmail(t *testing.T) {
	runAzAdoptCase(t, azAdoptCase{svc: "acsemail", cap: "email",
		server: func(t *testing.T) *httptest.Server {
			f := &acsEmailArmFake{t: t, wantData: "Europe", wantDom: "mail.example.com"}
			srv := httptest.NewServer(f.handler())
			t.Cleanup(srv.Close)
			return srv
		},
		attrs: acsEmailAttrs, impl: acsEmailImpl(), mutations: 3})
}

// ---- D435: aks and the compute family.

// TestAdoptsExistingAKS: the Azure member of the cluster trio (EKS D395, GKE D430). All
// three now assert the same property against the estate their own sagas were about — a
// cluster of ours already standing.
func TestAdoptsExistingAKS(t *testing.T) {
	name := aksPlanName(t)
	attrs, impl := aksCandidate()
	p := &certifynet.ExistingProbe{
		Name:     "azure/aks",
		Classify: azReadRole,
		ExistingServer: func() *httptest.Server {
			f := newFakeAKS(testSub, "rg1", name)
			f.exists = true
			srv := httptest.NewServer(f.handler())
			t.Cleanup(srv.Close)
			return srv
		},
		New: func(happyURL string, rt http.RoundTripper) provider.Provider {
			d := NewDriver(testSub)
			d.HTTP = &http.Client{Transport: rt}
			d.BaseURL = happyURL
			d.token = "test-token"
			d.Now = time.Now
			d.PollInterval = time.Millisecond
			d.PollTimeout = 2 * time.Second
			d.AKSLROTimeout = 2 * time.Second
			return d
		},
		Create: func(pr provider.Provider) provider.CreateResult {
			return pr.Create("aks", aksCap, "prod", attrs, impl, "k", 1)
		},
		PID:              aksProviderID(testSub, "rg1", name),
		AllowedMutations: 2,
	}
	certifynet.CertifyCreateAdoptsExisting(t, p)
}

func TestAdoptsExistingAKSWorkloadIdentity(t *testing.T) {
	runAzAdoptCase(t, azAdoptCase{svc: "aks-workloadidentity", cap: "runner",
		server: func(t *testing.T) *httptest.Server {
			// the FIC subject the plan derives: system:serviceaccount:<ns>:<sa>
			return ficServer(t, "system:serviceaccount:payments:worker")
		},
		attrs: aksWIAttrs, impl: aksWIImpl(), mutations: 2})
}

func TestAdoptsExistingChangeFeedAz(t *testing.T) {
	runAzAdoptCase(t, azAdoptCase{svc: "changefeed", cap: "feed",
		server: func(t *testing.T) *httptest.Server {
			return changeFeedArmFake(t,
				"/subscriptions/00000000-0000-0000-0000-000000000001/resourceGroups/rg1"+
					"/providers/Microsoft.Storage/storageAccounts/pvstore01", "changes")
		},
		attrs: changeFeedAttrs, mutations: 3})
}

// ---- D436: the compute family, whose fakes are struct-configured rather than helper
// functions — so each needs its own probe rather than the one-line adoptCase.

func TestAdoptsExistingAzureDisk(t *testing.T) {
	p := &certifynet.ExistingProbe{
		Name:     "azure/azdisk",
		Classify: azReadRole,
		ExistingServer: func() *httptest.Server {
			s := &azDiskServer{
				getStatus: 200, getBody: azDiskDoc(t, "orders-data", "Premium_LRS", true),
				putStatus: 200, putBody: `{}`,
			}
			srv := httptest.NewServer(s.handler())
			t.Cleanup(srv.Close)
			return srv
		},
		New: func(happyURL string, rt http.RoundTripper) provider.Provider {
			d := NewDriver(testSub)
			d.HTTP = &http.Client{Transport: rt}
			d.BaseURL = happyURL
			d.token = "test-token"
			d.Now = time.Now
			d.PollInterval = time.Millisecond
			d.PollTimeout = 2 * time.Second
			return d
		},
		Create: func(pr provider.Provider) provider.CreateResult {
			return pr.Create("azdisk", "orders-data", "production", azDiskAttrs(), azDiskImpl(), "k", 0)
		},
		AllowedMutations: 2,
	}
	certifynet.CertifyCreateAdoptsExisting(t, p)
}

func TestAdoptsExistingAzureVMSS(t *testing.T) {
	p := &certifynet.ExistingProbe{
		Name:     "azure/azvmss",
		Classify: azReadRole,
		// A VMSS is a COMPOSITE: the scale set AND its autoscale setting. The stock
		// fixture's autoscale doc carries no tags, so the D254 ownership pre-read
		// correctly refused to overwrite it — "an Azure ARM PUT is an unconditional
		// upsert" is the driver's own phrasing, and it is refusing on the SECOND
		// resource, which is exactly the case a composite makes easy to miss.
		ExistingServer: func() *httptest.Server {
			s := vmssHappyServer()
			s.autoBody = `{"tags":{"groundhold-capability":"web-fleet",` +
				`"groundhold-environment":"production"},` +
				`"properties":{"enabled":true,"profiles":[{"capacity":` +
				`{"minimum":"2","maximum":"10"}}]}}`
			srv := httptest.NewServer(s.handler())
			t.Cleanup(srv.Close)
			return srv
		},
		New: func(happyURL string, rt http.RoundTripper) provider.Provider {
			d := NewDriver(testSub)
			d.HTTP = &http.Client{Transport: rt}
			d.BaseURL = happyURL
			d.token = "test-token"
			d.Now = time.Now
			d.PollInterval = time.Millisecond
			d.PollTimeout = 2 * time.Second
			return d
		},
		Create: func(pr provider.Provider) provider.CreateResult {
			return pr.Create("azvmss", "web-fleet", "production", vmssAttrs(), vmssImpl(), "k", 0)
		},
		AllowedMutations: 3,
	}
	certifynet.CertifyCreateAdoptsExisting(t, p)
}

// ---- D437: azureopenai, defender, loadbalancer.

func TestAdoptsExistingAzureOpenAI(t *testing.T) {
	p := &certifynet.ExistingProbe{
		Name:     "azure/azureopenai",
		Classify: azReadRole,
		ExistingServer: func() *httptest.Server {
			srv := httptest.NewServer((&fakeAOI{
				location: "swedencentral", tags: aoiTags(aoiCap)}).handler(t))
			t.Cleanup(srv.Close)
			return srv
		},
		New: func(happyURL string, rt http.RoundTripper) provider.Provider {
			d := NewDriver(testSub)
			d.HTTP = &http.Client{Transport: rt}
			d.BaseURL = happyURL
			d.token = "test-token"
			d.Now = time.Now
			d.PollInterval = time.Millisecond
			d.PollTimeout = 2 * time.Second
			return d
		},
		Create: func(pr provider.Provider) provider.CreateResult {
			return pr.Create("azureopenai", aoiCap, "prod", aoiAttrs(),
				map[string]any{"resource_group": "rg1", "deployment_model": "gpt-4o",
					"deployment_sku": "Standard"}, "k", 1)
		},
		AllowedMutations: 3,
	}
	certifynet.CertifyCreateAdoptsExisting(t, p)
}

// TestAdoptsExistingDefender: subscription-scoped PRICING plans, so "already exists" is
// the plans already carrying the tier the contract asks for — the Azure sibling of GCP's
// scc (D423), where there is no resource to create and the converge is a settings write.
func TestAdoptsExistingDefender(t *testing.T) {
	p := &certifynet.ExistingProbe{
		Name:     "azure/defender",
		Classify: azReadRole,
		ExistingServer: func() *httptest.Server {
			return newFakeDefender("Standard", "Standard", "Free").handler(t)
		},
		New: func(happyURL string, rt http.RoundTripper) provider.Provider {
			d := NewDriver(testSub)
			d.HTTP = &http.Client{Transport: rt}
			d.BaseURL = happyURL
			d.token = "test-token"
			d.Now = time.Now
			d.PollInterval = time.Millisecond
			d.PollTimeout = 2 * time.Second
			return d
		},
		Create: func(pr provider.Provider) provider.CreateResult {
			return pr.Create("defender", defenderCap, "prod",
				defenderAttrs(true, true, false), nil, "k", 1)
		},
		AllowedMutations: 3,
	}
	certifynet.CertifyCreateAdoptsExisting(t, p)
}

// TestAdoptsExistingAppGateway: the same seed-by-previous-converge shape D429 arrived at
// on GCP's load balancer. This fake builds its GET document FROM the PUT body, so running
// the create once makes it describe exactly the gateway our driver would have made —
// which is the most faithful "already exists" a stateful fixture can offer.
func TestAdoptsExistingAppGateway(t *testing.T) {
	attrs := map[string]any{
		"location.region":        "eastus",
		"network.publicExposure": true,
		"encryption.inTransit":   false,
		"service.managed":        true,
	}
	impl := map[string]any{
		"resource_group": "rg1",
		"subnetId":       "/subscriptions/x/resourceGroups/rg1/providers/Microsoft.Network/virtualNetworks/vn/subnets/agw",
		"publicIpId":     "/subscriptions/x/resourceGroups/rg1/providers/Microsoft.Network/publicIPAddresses/pip",
		"backendFqdns":   []any{"app.example.com"},
	}
	f := &agwProvisionFake{}
	srv := f.server(t)
	t.Cleanup(srv.Close)

	seed := NewDriver(testSub)
	seed.BaseURL = srv.URL
	seed.token = "test-token"
	seed.Now = time.Now
	seed.PollInterval = time.Millisecond
	seed.PollTimeout = 5 * time.Second
	if res := seed.Create("loadbalancer", "edge", "prod", attrs, impl, "k", 1); res.Status != "succeeded" {
		t.Fatalf("seeding the standing gateway failed: %+v", res)
	}

	p := &certifynet.ExistingProbe{
		Name:           "azure/loadbalancer",
		Classify:       azReadRole,
		ExistingServer: func() *httptest.Server { return srv },
		New: func(happyURL string, rt http.RoundTripper) provider.Provider {
			d := NewDriver(testSub)
			d.HTTP = &http.Client{Transport: rt}
			d.BaseURL = happyURL
			d.token = "test-token"
			d.Now = time.Now
			d.PollInterval = time.Millisecond
			d.PollTimeout = 5 * time.Second
			return d
		},
		Create: func(pr provider.Provider) provider.CreateResult {
			return pr.Create("loadbalancer", "edge", "prod", attrs, impl, "k", 1)
		},
		AllowedMutations: 2,
	}
	certifynet.CertifyCreateAdoptsExisting(t, p)
}

// ---- D438: azvm, the last enrolment.
func TestAdoptsExistingAzureVM(t *testing.T) {
	p := &certifynet.ExistingProbe{
		Name:     "azure/azvm",
		Classify: azReadRole,
		ExistingServer: func() *httptest.Server {
			s := &azVMServer{
				vmStatus: 200, vmBody: azVMDoc(t, "web", true),
				nicStatus: 200, nicBody: `{"properties":{"ipConfigurations":[{"properties":{}}]}}`,
			}
			srv := httptest.NewServer(s.handler())
			t.Cleanup(srv.Close)
			return srv
		},
		New: func(happyURL string, rt http.RoundTripper) provider.Provider {
			d := NewDriver(testSub)
			d.HTTP = &http.Client{Transport: rt}
			d.BaseURL = happyURL
			d.token = "test-token"
			d.Now = time.Now
			d.PollInterval = time.Millisecond
			d.PollTimeout = 50 * time.Millisecond
			return d
		},
		Create: func(pr provider.Provider) provider.CreateResult {
			return pr.Create("azvm", "web", "production", azVMAttrs(), azVMImpl(), "k", 0)
		},
		AllowedMutations: 3,
	}
	certifynet.CertifyCreateAdoptsExisting(t, p)
}
