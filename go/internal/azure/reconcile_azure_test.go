package azure

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"groundhold/internal/provider"
)

// reconFake serves a single ARM resource shape usable by EVERY reconcile path: it
// carries ownership tags, a provisioningState (async services), a properties.state
// (flexpostgres), an enabled addonProfile (aks-addon) and a healthy agentPool (aks).
// status<400 => the JSON is served on GET; status>=400 => that status is returned
// (the readable-absence / unreadable cases).
func reconFake(t *testing.T, capLabel, provState, flexState string, status int) *httptest.Server {
	t.Helper()
	body := fmt.Sprintf(`{"location":"eastus",`+
		`"tags":{"groundhold-capability":"%s","groundhold-environment":"prod"},`+
		`"properties":{"provisioningState":"%s","state":"%s",`+
		`"addonProfiles":{"omsagent":{"enabled":true}},`+
		`"agentPoolProfiles":[{"provisioningState":"Succeeded"}],`+
		`"amount":100,"timeGrain":"Monthly"}}`, capLabel, provState, flexState)
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" && status >= 400 {
			w.WriteHeader(status)
			return
		}
		if r.Method == "GET" {
			_, _ = w.Write([]byte(body))
			return
		}
		w.WriteHeader(200)
	}))
}

func reconDriver(t *testing.T, srv *httptest.Server) *Driver {
	t.Helper()
	d := NewDriver(testSub)
	d.BaseURL = srv.URL
	d.token = "test-token"
	d.Now = time.Now
	d.PollInterval = time.Millisecond
	d.PollTimeout = time.Second
	d.AKSLROTimeout = time.Second // AKS reconcile drives aks/aks-addon Create — keep its LRO budget fast (D264 class)
	return d
}

const reconGUID = "11111111-1111-1111-1111-111111111111"

// reconRows: (service token, a well-formed pinned providerId) for every service in
// the Azure Create dispatch. reconcile must conclude each a SUCCEEDED create when the
// live resource is present, owned and provisioned.
func reconRows() []struct{ svc, pid string } {
	budget := ConsumptionBudgetName("prod", "sessions", 1)
	backup := BackupPolicyName("prod", "sessions", 1)
	alog := activityLogName("prod", "sessions", 1)
	return []struct{ svc, pid string }{
		{"vnet", vnetProviderID(testSub, "rg1", "res1")},
		{"cosmos", cosmosProviderID(testSub, "rg1", "acct1")},
		{"keyvault", keyVaultProviderID(testSub, "rg1", "vault1")},
		{"rediscache", redisAzureProviderID(testSub, "rg1", "res1")},
		{"acr", azureACRProviderID(testSub, "rg1", "reg123")},
		{"aisearch", aiSearchProviderID(testSub, "rg1", "res1")},
		{"frontdoorwaf", frontDoorWAFProviderID(testSub, "rg1", "waf1")},
		{"apim", apimProviderID(testSub, "rg1", "apim1")},
		{"containerappsjob", containerAppsJobProviderID(testSub, "rg1", "res1")},
		{"azureopenai", aoiProviderID(testSub, "rg1", "acct1")},
		{"loganalytics", laProviderID(testSub, "rg1", "res1")},
		{"containerapps", acaProviderID(testSub, "rg1", "res1")},
		{"azkafka", azKafkaProviderID(testSub, "rg1", "res1")},
		{"metricalert", azureAlertProviderID(testSub, "rg1", "res1")},
		{"portaldash", azureDashProviderID(testSub, "rg1", "res1")},
		{"webtest", azureWebtestProviderID(testSub, "rg1", "res1")},
		{"scheduledquery", azureSQProviderID(testSub, "rg1", "res1")},
		{"managedidentity", uamiProviderID(testSub, "rg1", "res1")},
		{"blob", blobProviderID(testSub, "rg1", "acct1", "cont1")},
		{"azurefiles", azFilesProviderID(testSub, "rg1", "acct1", "share1")},
		{"eventhubs", eventHubsProviderID(testSub, "rg1", "nsone", "hub1")},
		{"servicebusqueue", sbProviderID("sbq", testSub, "rg1", "nsone", "queue1")},
		{"servicebustopic", sbProviderID("sbt", testSub, "rg1", "nsone", "topic1")},
		{"dnszone", azureDNSProviderID(testSub, "rg1", "pub", "example.com")},
		{"dnsrecord", azureDNSRecordProviderID(testSub, "rg1", "example.com", "CNAME", "connect")},
		{"loadbalancer", agwProviderID(testSub, "rg1", "res1")},
		{"azurecdn", azureCDNProviderID(testSub, "rg1", "prof1", "ep1")},
		{"keyvaultkey", azureKeyProviderID(testSub, "rg1", "eastus", "vault1", "key1")},
		{"acsemail", acsEmailProviderID(testSub, "rg1", "res1")},
		{"flexpostgres", flexProviderID(testSub, "rg1", "res1")},
		{"aks", aksProviderID(testSub, "rg1", "res1")},
		{"aks-addon", aksAddonProviderID(testSub, "rg1", "res1", "monitoring")},
		{"aks-workloadidentity", aksWIProviderID(testSub, "rg1", "res1", "cred1")},
		{"roleassignment", azureRoleProviderID(testSub, reconGUID)},
		{"customroledef", azureCustomRoleProviderID(testSub, reconGUID)},
		{"changefeed", changeFeedProviderID(testSub, "res1")},
		{"consumptionbudget", consBudgetProviderID(testSub, "rg1", budget)},
		{"activitylog", activityLogProviderID(testSub, alog)},
		{"defender", defenderProviderID(testSub)},
		{"backuppolicy", backupPolicyProviderID(testSub, "rg1", "vault1", backup)},
		{"backupvault", backupVaultProviderID(testSub, "rg1", "vault1")},
	}
}

// TestReconcileEverySucceeds: for every wired service, a live, owned, provisioned
// resource concludes SUCCEEDED with the pinned providerId echoed back. This proves the
// Create dispatch (39 services) is fully covered by the Reconciler — resume no longer
// refuses an Azure run.
func TestReconcileEverySucceeds(t *testing.T) {
	srv := reconFake(t, "sessions", "Succeeded", "Ready", 200)
	defer srv.Close()
	d := reconDriver(t, srv)
	for _, row := range reconRows() {
		receipt := map[string]any{
			"target": "azure." + row.svc + "/sessions", "operation": "create",
			"generation": 1, "targetProviderId": row.pid,
		}
		res := d.Reconcile("sessions", "prod", receipt)
		// defender is a subscription posture configured in place: reconcile CANNOT
		// verify the desired tier landed from a receipt alone, so it honestly returns
		// unknown (never a fabricated "security control is active"). It is covered by
		// the dispatch but not a succeeded case.
		if row.svc == "defender" {
			if res.Status != "unknown" {
				t.Errorf("defender: want unknown (posture not verifiable from a receipt), got %+v", res)
			}
			continue
		}
		if res.Status != "succeeded" {
			t.Errorf("%s: want succeeded, got %+v", row.svc, res)
			continue
		}
		if res.ProviderID != row.pid {
			t.Errorf("%s: providerId = %q, want the pinned %q", row.svc, res.ProviderID, row.pid)
		}
	}
}

// TestReconcileEverySucceeds_coversDispatch asserts the table exercises the full
// Create switch — a service added there without a reconcile row fails this test.
func TestReconcileEverySucceeds_coversDispatch(t *testing.T) {
	covered := map[string]bool{}
	for _, row := range reconRows() {
		covered[row.svc] = true
	}
	// servicebusqueue+topic collapse to one reconcile, both listed; the azureServices
	// set is the source of truth for the dispatch surface.
	for svc := range azureServices {
		if !covered[svc] {
			t.Errorf("service %q is in the Create dispatch but has no reconcile test row", svc)
		}
	}
}

// TestReconcileNoPinnedID: a create receipt with no targetProviderId cannot be
// concluded (the resource group is an impl operand) — unknown, stays pending.
func TestReconcileNoPinnedID(t *testing.T) {
	d := NewDriver(testSub)
	d.token = "test-token"
	receipt := map[string]any{"target": "azure.cosmos/sessions", "operation": "create", "generation": 1}
	res := d.Reconcile("sessions", "prod", receipt)
	if res.Status != "unknown" || !strings.Contains(res.Reason, "no pinned providerId") {
		t.Fatalf("missing pinned id must be unknown, got %+v", res)
	}
}

// TestReconcileForeignNotOurs: a resource that exists but carries someone else's tags
// is NEVER attributed to our create — unknown, never succeeded.
func TestReconcileForeignNotOurs(t *testing.T) {
	srv := reconFake(t, "someone-else", "Succeeded", "Ready", 200)
	defer srv.Close()
	d := reconDriver(t, srv)
	receipt := map[string]any{"target": "azure.cosmos/sessions", "operation": "create",
		"generation": 1, "targetProviderId": cosmosProviderID(testSub, "rg1", "acct1")}
	res := d.Reconcile("sessions", "prod", receipt)
	if res.Status != "unknown" || !strings.Contains(res.Reason, "ownership") {
		t.Fatalf("foreign-owned resource must be unknown, got %+v", res)
	}
}

// TestReconcileAbsentFailed: a readable 404 means the create did not land — failed, so
// the pending intent clears and a re-plan recreates.
func TestReconcileAbsentFailed(t *testing.T) {
	srv := reconFake(t, "sessions", "Succeeded", "Ready", 404)
	defer srv.Close()
	d := reconDriver(t, srv)
	receipt := map[string]any{"target": "azure.cosmos/sessions", "operation": "create",
		"generation": 1, "targetProviderId": cosmosProviderID(testSub, "rg1", "acct1")}
	res := d.Reconcile("sessions", "prod", receipt)
	if res.Status != "failed" || !strings.Contains(res.Reason, "not present") {
		t.Fatalf("absent resource must be failed, got %+v", res)
	}
}

// TestReconcileUnreadableUnknown: a 500 read is unreadable — unknown, stays pending.
func TestReconcileUnreadableUnknown(t *testing.T) {
	srv := reconFake(t, "sessions", "Succeeded", "Ready", 500)
	defer srv.Close()
	d := reconDriver(t, srv)
	receipt := map[string]any{"target": "azure.rediscache/sessions", "operation": "create",
		"generation": 1, "targetProviderId": redisAzureProviderID(testSub, "rg1", "res1")}
	res := d.Reconcile("sessions", "prod", receipt)
	if res.Status != "unknown" {
		t.Fatalf("unreadable read must be unknown, got %+v", res)
	}
}

// TestReconcileUnwiredService: a target naming a service outside the dispatch fails
// closed to unknown, never a fabricated conclusion.
func TestReconcileUnwiredService(t *testing.T) {
	d := NewDriver(testSub)
	d.token = "test-token"
	receipt := map[string]any{"target": "azure.bogus/x", "operation": "create",
		"generation": 1, "targetProviderId": "bogus:x"}
	res := d.Reconcile("x", "prod", receipt)
	if res.Status != "unknown" || !strings.Contains(res.Reason, "not wired") {
		t.Fatalf("unwired service must be unknown/not-wired, got %+v", res)
	}
}

// TestReconcileFlexStillProvisioning: flexpostgres reports readiness on
// properties.state — a server not yet Ready stays unknown (pending).
func TestReconcileFlexStillProvisioning(t *testing.T) {
	srv := reconFake(t, "sessions", "Succeeded", "Creating", 200)
	defer srv.Close()
	d := reconDriver(t, srv)
	receipt := map[string]any{"target": "azure.flexpostgres/sessions", "operation": "create",
		"generation": 1, "targetProviderId": flexProviderID(testSub, "rg1", "res1")}
	res := d.Reconcile("sessions", "prod", receipt)
	if res.Status != "unknown" {
		t.Fatalf("a not-Ready flex server must stay unknown, got %+v", res)
	}
	// a terminal Failed state concludes failed.
	srv2 := reconFake(t, "sessions", "Succeeded", "Failed", 200)
	defer srv2.Close()
	d2 := reconDriver(t, srv2)
	if r := d2.Reconcile("sessions", "prod", receipt); r.Status != "failed" {
		t.Fatalf("a Failed flex server must be failed, got %+v", r)
	}
}

// TestReconcileAKSHalfProvisioned: an AKS cluster standing in Failed is a
// half-provisioned composite — unknown (repair/resume-again), never a bare failed
// that would prompt a double-creating re-plan.
func TestReconcileAKSHalfProvisioned(t *testing.T) {
	srv := reconFake(t, "sessions", "Failed", "Ready", 200)
	defer srv.Close()
	d := reconDriver(t, srv)
	receipt := map[string]any{"target": "azure.aks/sessions", "operation": "create",
		"generation": 1, "targetProviderId": aksProviderID(testSub, "rg1", "res1")}
	res := d.Reconcile("sessions", "prod", receipt)
	if res.Status != "unknown" || !strings.Contains(res.Reason, "half-provisioned") {
		t.Fatalf("a Failed AKS cluster must be unknown/half-provisioned, got %+v", res)
	}
}

// TestReconcileRoleAssignmentAbsent: a role assignment (GUID-owned, no tags) that is
// absent (404) concludes failed.
func TestReconcileRoleAssignmentAbsent(t *testing.T) {
	srv := reconFake(t, "sessions", "Succeeded", "Ready", 404)
	defer srv.Close()
	d := reconDriver(t, srv)
	receipt := map[string]any{"target": "azure.roleassignment/sessions", "operation": "create",
		"generation": 1, "targetProviderId": azureRoleProviderID(testSub, reconGUID)}
	res := d.Reconcile("sessions", "prod", receipt)
	if res.Status != "failed" {
		t.Fatalf("an absent role assignment must be failed, got %+v", res)
	}
}

// TestReconcilerAssertsInterface pins that *Driver satisfies provider.Reconciler, so
// resume dispatches to it instead of refusing the whole run.
func TestReconcilerAssertsInterface(t *testing.T) {
	var p provider.Provider = NewDriver(testSub)
	if _, ok := p.(provider.Reconciler); !ok {
		t.Fatal("*azure.Driver must implement provider.Reconciler")
	}
}
