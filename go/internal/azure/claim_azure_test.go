package azure

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestClaimFlexServerMergesTags: claiming a TF-created Flexible Server ADDS groundhold's
// ownership tags via a read-modify-write PATCH that PRESERVES the operator's existing
// tag (additive, no clobber). Asserts the bearer + api-version on every request.
func TestClaimFlexServerMergesTags(t *testing.T) {
	var patchBody map[string]any
	var sawGET, sawPATCH bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer test-token" {
			t.Errorf("missing/wrong bearer: %q", got)
		}
		if got := r.URL.Query().Get("api-version"); got != pgAPIVersion {
			t.Errorf("missing/wrong api-version: %q", got)
		}
		switch r.Method {
		case "GET":
			sawGET = true
			// a TF-created server: an operator tag, NO groundhold tags.
			_, _ = w.Write([]byte(`{"location":"eastus","tags":{"team":"ops"},` +
				`"properties":{"state":"Ready"}}`))
		case "PATCH":
			sawPATCH = true
			b, _ := io.ReadAll(r.Body)
			_ = json.Unmarshal(b, &patchBody)
			_, _ = w.Write([]byte(`{"properties":{"state":"Ready"}}`))
		default:
			w.WriteHeader(http.StatusBadRequest)
		}
	}))
	defer srv.Close()
	d := vnetTestDriver(t, srv)

	pid := flexProviderID(testSub, "rg1", flexServerName("prod", "orders-db", 1))
	cr := d.Claim("flexpostgres", "orders-db", "prod", pid)
	if cr.Status != "succeeded" {
		t.Fatalf("claim must succeed, got %+v", cr)
	}
	if cr.ProviderID != pid {
		t.Fatalf("claim must carry the providerId, got %q", cr.ProviderID)
	}
	if !sawGET || !sawPATCH {
		t.Fatalf("claim must READ then PATCH (got=%v patch=%v)", sawGET, sawPATCH)
	}
	tags, _ := patchBody["tags"].(map[string]any)
	if tags["groundhold-capability"] != "orders-db" || tags["groundhold-environment"] != "prod" {
		t.Fatalf("claim must stamp groundhold's ownership tags: %v", tags)
	}
	if tags["team"] != "ops" {
		t.Fatalf("claim must PRESERVE the operator's tag (additive, no clobber): %v", tags)
	}
}

// TestClaimFlexServerNotFoundFails: a claim on a resource that is gone fails cleanly
// (never a fabricated success).
func TestClaimFlexServerNotFoundFails(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()
	d := vnetTestDriver(t, srv)
	pid := flexProviderID(testSub, "rg1", flexServerName("prod", "gone", 1))
	cr := d.Claim("flexpostgres", "gone", "prod", pid)
	if cr.Status != "failed" {
		t.Fatalf("a vanished resource must fail the claim, got %+v", cr)
	}
}

// TestClaimNonTagBearingServiceRefusesHonestly: a service that carries NO groundhold tag
// (RBAC role assignment / definition, the change-feed proxy resource, the observe-only
// L4 load balancer) refuses (failed) so the converge stops and the resource stays
// externally owned — a failed claim is safer than a silent one (no orphan).
func TestClaimNonTagBearingServiceRefusesHonestly(t *testing.T) {
	d := NewDriver(testSub)
	for _, tc := range []struct{ service, pid string }{
		{"roleassignment", "azauth:sub:guid"},
		{"customroledef", "azcrole:sub:guid"},
		{"changefeed", "eventgrid:sub:name"},
		// the L4 load balancer layer is observe-only (groundhold never created it).
		{"loadbalancer", lbProviderID(testSub, "rg1", "existing-lb")},
	} {
		cr := d.Claim(tc.service, "cap", "prod", tc.pid)
		if cr.Status != "failed" {
			t.Fatalf("%s: an unclaimable service must refuse (failed), got %+v", tc.service, cr)
		}
		if !strings.Contains(cr.Reason, "externally owned") {
			t.Fatalf("%s: the refusal must say it stays externally owned: %q", tc.service, cr.Reason)
		}
	}
}

// TestClaimTagBearingServicesGolden: EVERY tag-bearing ARM service claims through the
// SAME generic read-modify-write — GET the resource, then PATCH the UNION of the
// operator's tags and groundhold's ownership tags (additive, no clobber). Asserts the
// resource-type path, the bearer + api-version, and a succeeded result carrying the
// providerId — for three representative newly-wired services.
func TestClaimTagBearingServicesGolden(t *testing.T) {
	cases := []struct {
		service    string
		pid        string
		apiVersion string
		wantPath   string
	}{
		{
			service:    "blob",
			pid:        blobProviderID(testSub, "rg1", azStorageName("prod", "assets", 1), blobContainerName("prod", "assets", 1)),
			apiVersion: storageAPIVersion,
			wantPath:   "Microsoft.Storage/storageAccounts/",
		},
		{
			service:    "cosmos",
			pid:        cosmosProviderID(testSub, "rg1", cosmosAccountName("prod", "sessions", 1)),
			apiVersion: cosmosAPIVersion,
			wantPath:   "Microsoft.DocumentDB/databaseAccounts/",
		},
		{
			service:    "keyvault",
			pid:        keyVaultProviderID(testSub, "rg1", keyVaultName("prod", "dbcreds", 1)),
			apiVersion: keyVaultAPIVersion,
			wantPath:   "Microsoft.KeyVault/vaults/",
		},
	}
	for _, tc := range cases {
		t.Run(tc.service, func(t *testing.T) {
			var patchBody map[string]any
			var sawGET, sawPATCH, sawAPIVersion, sawPath bool
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if got := r.Header.Get("Authorization"); got != "Bearer test-token" {
					t.Errorf("missing/wrong bearer: %q", got)
				}
				if r.URL.Query().Get("api-version") == tc.apiVersion {
					sawAPIVersion = true
				}
				if strings.Contains(r.URL.Path, tc.wantPath) {
					sawPath = true
				}
				switch r.Method {
				case "GET":
					sawGET = true
					_, _ = w.Write([]byte(`{"location":"eastus","tags":{"team":"ops"}}`))
				case "PATCH":
					sawPATCH = true
					b, _ := io.ReadAll(r.Body)
					_ = json.Unmarshal(b, &patchBody)
					_, _ = w.Write([]byte(`{"tags":{}}`))
				default:
					w.WriteHeader(http.StatusBadRequest)
				}
			}))
			defer srv.Close()
			d := vnetTestDriver(t, srv)

			cr := d.Claim(tc.service, "assets", "prod", tc.pid)
			if cr.Status != "succeeded" {
				t.Fatalf("%s claim must succeed, got %+v", tc.service, cr)
			}
			if cr.ProviderID != tc.pid {
				t.Fatalf("%s claim must carry the providerId, got %q", tc.service, cr.ProviderID)
			}
			if !sawGET || !sawPATCH {
				t.Fatalf("%s claim must READ then PATCH (got=%v patch=%v)", tc.service, sawGET, sawPATCH)
			}
			if !sawAPIVersion {
				t.Fatalf("%s claim must use api-version %q", tc.service, tc.apiVersion)
			}
			if !sawPath {
				t.Fatalf("%s claim must GET/PATCH the %q resource type", tc.service, tc.wantPath)
			}
			tags, _ := patchBody["tags"].(map[string]any)
			if tags["groundhold-capability"] != "assets" || tags["groundhold-environment"] != "prod" {
				t.Fatalf("%s claim must stamp groundhold's ownership tags: %v", tc.service, tags)
			}
			if tags["team"] != "ops" {
				t.Fatalf("%s claim must PRESERVE the operator's tag (additive, no clobber): %v", tc.service, tags)
			}
		})
	}
}

// TestClaimARMTagsFourValued: the generic helper is four-valued on the wire — a 404 is
// a clean `failed`, a 5xx pre-read is `unknown` WITH the providerId (never a silent
// success). Uses blob as the representative carrier of the shared helper.
func TestClaimARMTagsFourValued(t *testing.T) {
	pid := blobProviderID(testSub, "rg1", azStorageName("prod", "assets", 1), blobContainerName("prod", "assets", 1))

	// 404 → failed (the resource is gone; nothing to claim).
	srv404 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv404.Close()
	d := vnetTestDriver(t, srv404)
	if cr := d.Claim("blob", "assets", "prod", pid); cr.Status != "failed" {
		t.Fatalf("a 404 pre-read must fail the claim, got %+v", cr)
	}

	// 5xx pre-read → unknown WITH the providerId (ambiguous, never a silent success).
	srv500 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv500.Close()
	d = vnetTestDriver(t, srv500)
	cr := d.Claim("blob", "assets", "prod", pid)
	if cr.Status != "unknown" {
		t.Fatalf("a 5xx pre-read must be unknown, got %+v", cr)
	}
	if cr.ProviderID != pid {
		t.Fatalf("an unknown claim must carry the providerId, got %q", cr.ProviderID)
	}
}

// TestClaimUnknownServiceFailsClosed: dispatch is fail-closed (D76).
func TestClaimUnknownServiceFailsClosed(t *testing.T) {
	d := NewDriver(testSub)
	cr := d.Claim("__not_a_service__", "x", "y", "a:b:c:d")
	if cr.Status != "failed" {
		t.Fatalf("an unknown service must fail closed, got %+v", cr)
	}
}

// TestClaimTargetResolvesEveryTagBearingService is the completeness sweep for
// claimTarget's dispatch (a PURE function — no network, so exercised directly):
// for every tag-bearing ARM service it resolves a real providerId into a
// non-empty resource URL carrying that service's ARM type, with no reason and
// no error. This is the sibling of TestClaimTagBearingServicesGolden above,
// which only round-trips THREE representative services end to end through a
// fake server; this one instead pins the URL RESOLUTION for every remaining
// tag-bearing service claimTarget knows how to route, without needing an ARM
// double for each one.
func TestClaimTargetResolvesEveryTagBearingService(t *testing.T) {
	d := NewDriver(testSub)
	cases := []struct {
		service, pid, wantPathContains string
	}{
		{"acsemail", acsEmailProviderID(testSub, "rg1", "pvmailsvc"), "Microsoft.Communication/emailServices/"},
		{"aks", aksProviderID(testSub, "rg1", "pv-aks-c-00000000"), "Microsoft.ContainerService/managedClusters/"},
		{"loganalytics", laProviderID(testSub, "rg1", "pvlaw01"), "Microsoft.OperationalInsights/workspaces/"},
		{"azureopenai", aoiProviderID(testSub, "rg1", "acct1"), "Microsoft.CognitiveServices/accounts/"},
		{"flexpostgres", flexProviderID(testSub, "rg1", "pv-db-1"), "Microsoft.DBforPostgreSQL/flexibleServers/"},
		{"backupvault", backupVaultProviderID(testSub, "rg1", "bv1"), "Microsoft.DataProtection/backupVaults/bv1"},
		{"blob", blobProviderID(testSub, "rg1", "pvacct000000000000000", "container"), "Microsoft.Storage/storageAccounts/"},
		{"azurefiles", azFilesProviderID(testSub, "rg1", "pvacct000000000000000", "share1"), "Microsoft.Storage/storageAccounts/"},
		{"vnet", vnetProviderID(testSub, "rg1", "pv-net-1"), "Microsoft.Network/virtualNetworks/pv-net-1"},
		{"dnszone", azureDNSProviderID(testSub, "rg1", "pub", "example.com"), "dnsZones/example.com"},
		{"frontdoorwaf", frontDoorWAFProviderID(testSub, "rg1", "fdwaf1"), "FrontDoorWebApplicationFirewallPolicies/fdwaf1"},
		{"azurecdn", azureCDNProviderID(testSub, "rg1", "profile1", "endpoint1"), "Microsoft.Cdn/profiles/profile1"},
		{"loadbalancer", agwProviderID(testSub, "rg1", "agw1"), "Microsoft.Network/applicationGateways/agw1"},
		{"containerapps", acaProviderID(testSub, "rg1", "app1"), "Microsoft.App/containerApps/app1"},
		{"containerappsjob", containerAppsJobProviderID(testSub, "rg1", "job1"), "Microsoft.App/jobs/job1"},
		{"acr", azureACRProviderID(testSub, "rg1", "acreg1"), "Microsoft.ContainerRegistry/registries/acreg1"},
		{"servicebusqueue", sbProviderID("sbq", testSub, "rg1", "sbns1", "queue1"), "Microsoft.ServiceBus/namespaces/sbns1"},
		{"servicebustopic", sbProviderID("sbt", testSub, "rg1", "sbns1", "topic1"), "Microsoft.ServiceBus/namespaces/sbns1"},
		{"eventhubs", eventHubsProviderID(testSub, "rg1", "ehns1", "hub1"), "Microsoft.EventHub/namespaces/ehns1"},
		{"azkafka", azKafkaProviderID(testSub, "rg1", "kns1"), "Microsoft.EventHub/namespaces/kns1"},
		{"keyvault", keyVaultProviderID(testSub, "rg1", "kv1"), "Microsoft.KeyVault/vaults/kv1"},
		{"keyvaultkey", azureKeyProviderID(testSub, "rg1", "eastus", "kv1", "key1"), "Microsoft.KeyVault/vaults/kv1"},
		{"rediscache", redisAzureProviderID(testSub, "rg1", "redis1"), "Microsoft.Cache/Redis/redis1"},
		{"cosmos", cosmosProviderID(testSub, "rg1", "cosmosacct1"), "Microsoft.DocumentDB/databaseAccounts/cosmosacct1"},
		{"aisearch", aiSearchProviderID(testSub, "rg1", "search1"), "Microsoft.Search/searchServices/search1"},
		{"apim", apimProviderID(testSub, "rg1", "apim1"), "Microsoft.ApiManagement/service/apim1"},
		{"managedidentity", uamiProviderID(testSub, "rg1", "uami1"), "Microsoft.ManagedIdentity/userAssignedIdentities/uami1"},
		{"metricalert", azureAlertProviderID(testSub, "rg1", "alert1"), "Microsoft.Insights/metricAlerts/alert1"},
		{"portaldash", azureDashProviderID(testSub, "rg1", "dash1"), "Microsoft.Portal/dashboards/dash1"},
		{"webtest", azureWebtestProviderID(testSub, "rg1", "wt1"), "Microsoft.Insights/webtests/wt1"},
		{"scheduledquery", azureSQProviderID(testSub, "rg1", "sq1"), "Microsoft.Insights/scheduledQueryRules/sq1"},
	}
	for _, tc := range cases {
		t.Run(tc.service, func(t *testing.T) {
			url, reason, err := d.claimTarget(tc.service, tc.pid)
			if err != nil {
				t.Fatalf("claimTarget(%q): unexpected error: %v", tc.service, err)
			}
			if reason != "" {
				t.Fatalf("claimTarget(%q): unexpected refusal reason: %q", tc.service, reason)
			}
			if !strings.Contains(url, tc.wantPathContains) {
				t.Fatalf("claimTarget(%q) url = %q, want it to contain %q", tc.service, url, tc.wantPathContains)
			}
		})
	}
}

// TestClaimTargetNotTagBearingServices pins EVERY structural-refusal branch:
// services claimTarget knows carry no groundhold ARM tag (RBAC/proxy/observe-only),
// so a claim always refuses honestly rather than silently no-op'ing (an
// unclaimable resource must stay externally owned, never orphaned nor
// falsely marked ours).
func TestClaimTargetNotTagBearingServices(t *testing.T) {
	d := NewDriver(testSub)
	for _, service := range []string{
		"roleassignment", "customroledef", "changefeed", "defender",
		"consumptionbudget", "activitylog", "aks-addon", "aks-workloadidentity", "backuppolicy",
	} {
		t.Run(service, func(t *testing.T) {
			url, reason, err := d.claimTarget(service, "irrelevant:pid")
			if err != nil {
				t.Fatalf("claimTarget(%q): unexpected error: %v", service, err)
			}
			if url != "" {
				t.Fatalf("claimTarget(%q): expected no url, got %q", service, url)
			}
			if !strings.Contains(reason, "not a") || !strings.Contains(reason, "tag-bearing ARM resource") {
				t.Fatalf("claimTarget(%q) reason = %q, want it to explain the resource is not tag-bearing", service, reason)
			}
		})
	}
}

// TestClaimTargetLoadBalancerL4ObserveOnlyRefuses: within the SAME "loadbalancer"
// service token, the L4 load balancer kind is observe-only (groundhold never creates
// it) while the L7 Application Gateway kind IS claimable — the kind fork inside
// one dispatch case, not just the top-level switch.
func TestClaimTargetLoadBalancerL4ObserveOnlyRefuses(t *testing.T) {
	d := NewDriver(testSub)
	url, reason, err := d.claimTarget("loadbalancer", lbProviderID(testSub, "rg1", "lb1"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if url != "" {
		t.Fatalf("expected no url for an observe-only L4 load balancer, got %q", url)
	}
	if !strings.Contains(reason, "observe-only") {
		t.Fatalf("reason = %q, want it to say observe-only", reason)
	}
}

// TestClaimTargetUnroutedServiceRefusesWithNoDefault pins the default branch: a
// service requireService lets through (known to azureServices) but with no
// claimTarget case would refuse "no claim mapping" rather than guess a resource
// type. There is no such service today (every wired service is routed above or
// listed as not-tag-bearing) — deliberately probe the private switch with a
// token that is NOT in azureServices to pin the "no default" wording itself.
func TestClaimTargetUnroutedServiceRefusesWithNoDefault(t *testing.T) {
	d := NewDriver(testSub)
	url, reason, err := d.claimTarget("__totally_unrouted__", "x:y:z")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if url != "" {
		t.Fatalf("expected no url, got %q", url)
	}
	if !strings.Contains(reason, "no claim mapping") {
		t.Fatalf("reason = %q, want it to say no claim mapping", reason)
	}
}

// TestClaimTargetMalformedProviderIDErrors: a malformed providerId for a
// tag-bearing service surfaces the SPLIT function's parse error rather than a
// panic or a fabricated URL.
func TestClaimTargetMalformedProviderIDErrors(t *testing.T) {
	d := NewDriver(testSub)
	if _, _, err := d.claimTarget("blob", "not-a-blob-pid"); err == nil {
		t.Fatal("a malformed providerId must error")
	}
}

// TestClaimURLForCrossSubscriptionRefused: claimURLFor bounds the providerId's
// subscription against the driver's pinned one (the D73 injection boundary) —
// a cross-subscription providerId is refused rather than addressed.
func TestClaimURLForCrossSubscriptionRefused(t *testing.T) {
	d := NewDriver(testSub)
	other := "11111111-1111-1111-1111-111111111111"
	if _, _, err := d.claimTarget("blob", blobProviderID(other, "rg1", "pvacct000000000000000", "container")); err == nil {
		t.Fatal("a providerId from a different subscription must be refused")
	}
}
