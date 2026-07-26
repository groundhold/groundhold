package azure

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"groundhold/internal/provider"
)

func discoverAzDriver(t *testing.T, srv *httptest.Server) *Driver {
	t.Helper()
	d := NewDriver(testSub)
	d.BaseURL = srv.URL
	d.token = "test-token"
	d.Now = time.Now
	return d
}

// azDiscoverServer answers the subscription-scoped storageAccounts.list
// (one account in-region, one elsewhere), the container list for the
// in-region account, and the per-account GET that observe reads.
func azDiscoverServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			p := r.URL.Path
			switch {
			// subscription-scoped list: no resourceGroups segment
			case strings.HasSuffix(p, "/providers/Microsoft.Storage/storageAccounts") &&
				!strings.Contains(p, "/resourceGroups/"):
				_, _ = w.Write([]byte(`{"value":[
					{"id":"/subscriptions/` + testSub + `/resourceGroups/rg1/providers/Microsoft.Storage/storageAccounts/hereacct","name":"hereacct","location":"West Europe"},
					{"id":"/subscriptions/` + testSub + `/resourceGroups/rg2/providers/Microsoft.Storage/storageAccounts/faracct","name":"faracct","location":"eastus"}
				]}`))
			case strings.Contains(p, "/storageAccounts/hereacct/blobServices/default/containers"):
				_, _ = w.Write([]byte(`{"value":[{"name":"data"}]}`))
			case strings.HasSuffix(p, "/storageAccounts/hereacct"):
				_, _ = w.Write([]byte(`{"location":"westeurope","sku":{"name":"Standard_LRS"},` +
					`"properties":{"allowBlobPublicAccess":false,"encryption":{"keySource":"Microsoft.Storage"}}}`))
			// PostgreSQL flexible servers: subscription-scoped list, then get
			case strings.HasSuffix(p, "/providers/Microsoft.DBforPostgreSQL/flexibleServers") &&
				!strings.Contains(p, "/resourceGroups/"):
				_, _ = w.Write([]byte(`{"value":[
					{"id":"/subscriptions/` + testSub + `/resourceGroups/rg1/providers/Microsoft.DBforPostgreSQL/flexibleServers/pgserver","name":"pgserver","location":"West Europe"},
					{"id":"/subscriptions/` + testSub + `/resourceGroups/rg2/providers/Microsoft.DBforPostgreSQL/flexibleServers/farpg","name":"farpg","location":"eastus"}
				]}`))
			case strings.HasSuffix(p, "/flexibleServers/pgserver"):
				_, _ = w.Write([]byte(`{"location":"westeurope","properties":{"version":"16",` +
					`"network":{"publicNetworkAccess":"Disabled"}}}`))
			// Cosmos DB: subscription-scoped list, then get
			case strings.HasSuffix(p, "/providers/Microsoft.DocumentDB/databaseAccounts") &&
				!strings.Contains(p, "/resourceGroups/"):
				_, _ = w.Write([]byte(`{"value":[
					{"id":"/subscriptions/` + testSub + `/resourceGroups/rg1/providers/Microsoft.DocumentDB/databaseAccounts/cosmosacct","name":"cosmosacct","location":"West Europe"}
				]}`))
			case strings.HasSuffix(p, "/databaseAccounts/cosmosacct"):
				_, _ = w.Write([]byte(`{"location":"westeurope","properties":{"publicNetworkAccess":"Disabled"}}`))
			// Azure Cache for Redis: subscription-scoped list, then get
			case strings.HasSuffix(p, "/providers/Microsoft.Cache/redis") &&
				!strings.Contains(p, "/resourceGroups/"):
				_, _ = w.Write([]byte(`{"value":[
					{"id":"/subscriptions/` + testSub + `/resourceGroups/rg1/providers/Microsoft.Cache/Redis/rediscache","name":"rediscache","location":"West Europe"}
				]}`))
			case strings.HasSuffix(p, "/Microsoft.Cache/Redis/rediscache"):
				_, _ = w.Write([]byte(`{"location":"westeurope","properties":{"sku":{"name":"Standard"}}}`))
			// Service Bus: namespaces list, entities per namespace, entity/namespace get
			case strings.HasSuffix(p, "/providers/Microsoft.ServiceBus/namespaces") &&
				!strings.Contains(p, "/resourceGroups/"):
				_, _ = w.Write([]byte(`{"value":[
					{"id":"/subscriptions/` + testSub + `/resourceGroups/rg1/providers/Microsoft.ServiceBus/namespaces/sbns","name":"sbns","location":"West Europe"}
				]}`))
			case strings.HasSuffix(p, "/namespaces/sbns/queues/jobs"):
				_, _ = w.Write([]byte(`{"properties":{"requiresDuplicateDetection":false}}`))
			case strings.HasSuffix(p, "/namespaces/sbns/queues"):
				_, _ = w.Write([]byte(`{"value":[{"name":"jobs"}]}`))
			case strings.HasSuffix(p, "/namespaces/sbns/topics"):
				_, _ = w.Write([]byte(`{"value":[{"name":"events"}]}`))
			case strings.HasSuffix(p, "/namespaces/sbns"):
				_, _ = w.Write([]byte(`{"location":"westeurope","properties":{"publicNetworkAccess":"Disabled"}}`))
			// Container Apps: subscription-scoped list (one in-region, one elsewhere), then get
			case strings.HasSuffix(p, "/providers/Microsoft.App/containerApps") &&
				!strings.Contains(p, "/resourceGroups/"):
				_, _ = w.Write([]byte(`{"value":[
					{"id":"/subscriptions/` + testSub + `/resourceGroups/rg1/providers/Microsoft.App/containerApps/hereapp","name":"hereapp","location":"West Europe"},
					{"id":"/subscriptions/` + testSub + `/resourceGroups/rg2/providers/Microsoft.App/containerApps/farapp","name":"farapp","location":"eastus"}
				]}`))
			case strings.HasSuffix(p, "/containerApps/hereapp"):
				_, _ = w.Write([]byte(`{"location":"westeurope","properties":{` +
					`"configuration":{"ingress":{"external":false,"allowInsecure":false}},` +
					`"template":{"scale":{"minReplicas":1}}}}`))
			// Container Apps Jobs: subscription-scoped list, then get
			case strings.HasSuffix(p, "/providers/Microsoft.App/jobs") &&
				!strings.Contains(p, "/resourceGroups/"):
				_, _ = w.Write([]byte(`{"value":[
					{"id":"/subscriptions/` + testSub + `/resourceGroups/rg1/providers/Microsoft.App/jobs/herejob","name":"herejob","location":"West Europe"}
				]}`))
			case strings.HasSuffix(p, "/jobs/herejob"):
				_, _ = w.Write([]byte(`{"location":"westeurope","properties":{` +
					`"configuration":{"triggerType":"Manual"},"template":{"containers":[{"image":"nginx:latest"}]}}}`))
			// Virtual networks: subscription-scoped list, then get
			case strings.HasSuffix(p, "/providers/Microsoft.Network/virtualNetworks") &&
				!strings.Contains(p, "/resourceGroups/"):
				_, _ = w.Write([]byte(`{"value":[
					{"id":"/subscriptions/` + testSub + `/resourceGroups/rg1/providers/Microsoft.Network/virtualNetworks/herevnet","name":"herevnet","location":"West Europe"}
				]}`))
			case strings.HasSuffix(p, "/virtualNetworks/herevnet"):
				_, _ = w.Write([]byte(`{"location":"westeurope","properties":{"subnets":[{"properties":{}}]}}`))
			// Key Vaults: subscription-scoped list, then get (D53: metadata only, no value)
			case strings.HasSuffix(p, "/providers/Microsoft.KeyVault/vaults") &&
				!strings.Contains(p, "/resourceGroups/"):
				_, _ = w.Write([]byte(`{"value":[
					{"id":"/subscriptions/` + testSub + `/resourceGroups/rg1/providers/Microsoft.KeyVault/vaults/herevault","name":"herevault","location":"West Europe"}
				]}`))
			case strings.HasSuffix(p, "/vaults/herevault"):
				_, _ = w.Write([]byte(`{"location":"westeurope","properties":{"publicNetworkAccess":"Disabled"}}`))
			// User-assigned managed identities: subscription-scoped list, then get
			case strings.HasSuffix(p, "/providers/Microsoft.ManagedIdentity/userAssignedIdentities") &&
				!strings.Contains(p, "/resourceGroups/"):
				_, _ = w.Write([]byte(`{"value":[
					{"id":"/subscriptions/` + testSub + `/resourceGroups/rg1/providers/Microsoft.ManagedIdentity/userAssignedIdentities/hereid","name":"hereid","location":"West Europe"}
				]}`))
			case strings.HasSuffix(p, "/userAssignedIdentities/hereid"):
				_, _ = w.Write([]byte(`{"location":"westeurope","tags":{"groundhold-display":"my-id"},` +
					`"properties":{"clientId":"c","principalId":"p"}}`))
			// Custom role definitions: subscription-global list (one CustomRole, one BuiltIn), then get
			case strings.HasSuffix(p, "/providers/Microsoft.Authorization/roleDefinitions"):
				_, _ = w.Write([]byte(`{"value":[
					{"name":"11111111-1111-1111-1111-111111111111","properties":{"type":"CustomRole"}},
					{"name":"acdd72a7-3385-48ef-bd42-f606fba81ae7","properties":{"type":"BuiltInRole"}}
				]}`))
			case strings.Contains(p, "/roleDefinitions/"):
				_, _ = w.Write([]byte(`{"properties":{"permissions":[{"actions":["Microsoft.Storage/storageAccounts/read"]}]}}`))
			// Role assignments: subscription-global list, then get
			case strings.HasSuffix(p, "/providers/Microsoft.Authorization/roleAssignments"):
				_, _ = w.Write([]byte(`{"value":[
					{"name":"22222222-2222-2222-2222-222222222222"}
				]}`))
			case strings.Contains(p, "/roleAssignments/"):
				_, _ = w.Write([]byte(`{"properties":{` +
					`"roleDefinitionId":"/subscriptions/` + testSub + `/providers/Microsoft.Authorization/roleDefinitions/acdd72a7-3385-48ef-bd42-f606fba81ae7",` +
					`"principalId":"33333333-3333-3333-3333-333333333333"}}`))
			default:
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`{"value":[]}`))
			}
		}))
}

func TestAzureListDiscoversAcrossServices(t *testing.T) {
	srv := azDiscoverServer(t)
	defer srv.Close()
	d := discoverAzDriver(t, srv)

	found, diags, err := d.List("westeurope")
	if err != nil {
		t.Fatal(err)
	}
	byType := map[string]provider.Discovered{}
	for _, f := range found {
		byType[f.ResourceType] = f
	}
	if len(found) != 14 {
		t.Fatalf("want the 6 base sweeps + container apps, jobs, vnet, key vault, managed identity, "+
			"custom role, role assignment and the Defender posture singleton, got %d: %+v (diags %v)", len(found), found, diags)
	}
	wantID := map[string]string{
		"capability.storage.object":           "blob:" + testSub + ":rg1:hereacct:data",
		"capability.database.relational":      "flexpg:" + testSub + ":rg1:pgserver",
		"capability.database.nosql":           "cosmos:" + testSub + ":rg1:cosmosacct",
		"capability.cache.keyvalue":           "aredis:" + testSub + ":rg1:rediscache",
		"capability.messaging.queue":          "sbq:" + testSub + ":rg1:sbns:jobs",
		"capability.messaging.topic":          "sbt:" + testSub + ":rg1:sbns:events",
		"capability.workload.container":       "aca:" + testSub + ":rg1:hereapp",
		"capability.container.job":            "acjob:" + testSub + ":rg1:herejob",
		"capability.network.private":          "vnet:" + testSub + ":rg1:herevnet",
		"capability.secret":                   "akv:" + testSub + ":rg1:herevault",
		"capability.identity.serviceaccount":  "uami:" + testSub + ":rg1:hereid",
		"capability.authorization.role":       "azcrole:" + testSub + ":11111111-1111-1111-1111-111111111111",
		"capability.authorization.grant":      "azauth:" + testSub + ":22222222-2222-2222-2222-222222222222",
		"capability.security.threatdetection": "defender:" + testSub,
	}
	for typ, id := range wantID {
		if got := byType[typ].ProviderID; got != id {
			t.Fatalf("%s providerId = %q, want %q", typ, got, id)
		}
	}
	pg := map[string]any{}
	for _, o := range byType["capability.database.relational"].Observations {
		pg[o.Path] = o.Value
	}
	if pg["location.region"] != "westeurope" || pg["engine.protocol"] != "postgresql/16" {
		t.Fatalf("postgres observations = %+v", pg)
	}
}

func TestAzureListRequiresRegionAndSubscription(t *testing.T) {
	srv := azDiscoverServer(t)
	defer srv.Close()
	d := discoverAzDriver(t, srv)
	if _, _, err := d.List(""); err == nil {
		t.Fatal("discovery without a region must refuse")
	}
	bad := NewDriver("not-a-guid")
	bad.BaseURL = srv.URL
	bad.token = "t"
	if _, _, err := bad.List("westeurope"); err == nil {
		t.Fatal("discovery without a valid subscription must refuse")
	}
}

// TestAzureDiscoverBearerOnExpandedSweeps asserts the expanded List sweep signs
// its subscription-scope requests with the AAD bearer and reverse-maps a Container
// App through the SAME observe map (measured location + tls derivation).
func TestAzureDiscoverBearerOnExpandedSweeps(t *testing.T) {
	var sawContainerAppsList, sawBearer bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := r.URL.Path
		if strings.HasSuffix(p, "/providers/Microsoft.App/containerApps") && !strings.Contains(p, "/resourceGroups/") {
			sawContainerAppsList = true
			if r.Header.Get("Authorization") == "Bearer test-token" {
				sawBearer = true
			}
			_, _ = w.Write([]byte(`{"value":[{"id":"/subscriptions/` + testSub +
				`/resourceGroups/rg1/providers/Microsoft.App/containerApps/hereapp","name":"hereapp","location":"westeurope"}]}`))
			return
		}
		if strings.HasSuffix(p, "/containerApps/hereapp") {
			_, _ = w.Write([]byte(`{"location":"westeurope","properties":{` +
				`"configuration":{"ingress":{"external":true,"allowInsecure":true}},` +
				`"template":{"scale":{"minReplicas":2}}}}`))
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"value":[]}`))
	}))
	defer srv.Close()
	d := discoverAzDriver(t, srv)

	found, _, err := d.discoverContainerApps("westeurope")
	if err != nil {
		t.Fatal(err)
	}
	if !sawContainerAppsList || !sawBearer {
		t.Fatalf("container apps List not seen with bearer: list=%v bearer=%v", sawContainerAppsList, sawBearer)
	}
	if len(found) != 1 || found[0].ProviderID != "aca:"+testSub+":rg1:hereapp" {
		t.Fatalf("container app discovery = %+v", found)
	}
	obs := map[string]any{}
	for _, o := range found[0].Observations {
		obs[o.Path] = o.Value
	}
	if obs["location.region"] != "westeurope" || obs["network.publicExposure"] != true || obs["tls.enforced"] != false {
		t.Fatalf("container app reverse-map = %+v", obs)
	}
}

// TestAzureDiscoverKeyVaultNeverLeaksSecretValue is the D53 guard: Key Vault
// discovery surfaces existence + metadata ONLY. No observation may carry a secret
// value — the sweep does no data-plane read at all.
func TestAzureDiscoverKeyVaultNeverLeaksSecretValue(t *testing.T) {
	srv := azDiscoverServer(t)
	defer srv.Close()
	d := discoverAzDriver(t, srv)

	found, _, err := d.discoverKeyVault("westeurope")
	if err != nil {
		t.Fatal(err)
	}
	if len(found) != 1 || found[0].ResourceType != "capability.secret" {
		t.Fatalf("key vault discovery = %+v", found)
	}
	allowed := map[string]bool{
		"service.managed": true, "encryption.atRest": true,
		"location.region": true, "network.publicExposure": true,
	}
	for _, o := range found[0].Observations {
		if !allowed[o.Path] {
			t.Fatalf("D53: unexpected key-vault observation path %q (value %v) — discovery must be metadata only", o.Path, o.Value)
		}
	}
}

// TestAzureDiscoverGlobalRolesIgnoreRegion asserts custom roles and role
// assignments (subscription-global, no location) surface regardless of the region
// argument, and that built-in roles are filtered out of the custom-role sweep.
func TestAzureDiscoverGlobalRolesIgnoreRegion(t *testing.T) {
	srv := azDiscoverServer(t)
	defer srv.Close()
	d := discoverAzDriver(t, srv)

	roles, _, err := d.discoverCustomRoles("eastus") // a region no regional resource lives in
	if err != nil {
		t.Fatal(err)
	}
	if len(roles) != 1 || roles[0].ProviderID != "azcrole:"+testSub+":11111111-1111-1111-1111-111111111111" {
		t.Fatalf("custom role discovery (built-in must be filtered) = %+v", roles)
	}
	grants, _, err := d.discoverRoleAssignments("eastus")
	if err != nil {
		t.Fatal(err)
	}
	if len(grants) != 1 || grants[0].ProviderID != "azauth:"+testSub+":22222222-2222-2222-2222-222222222222" {
		t.Fatalf("role assignment discovery = %+v", grants)
	}
}
