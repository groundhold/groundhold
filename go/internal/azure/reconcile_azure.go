// Azure receipt reconciliation (D57): the OPTIONAL provider.Reconciler capability
// that lets `resume` conclude a PENDING receipt read-only — determine what actually
// happened by reading live state. Without it, resume REFUSES the whole run for an
// Azure provider ("provider azure cannot reconcile receipts"), so every pending
// Azure create/update/delete left by a lost or false-"unknown" response stays
// in-flight forever and converge is permanently STALE. STRICTLY READ-ONLY — a
// reconciler that mutates is a bug.
//
// The Azure advantage AND trap (D99): a resource's identity (its deterministic
// name/GUID) is knowable, but its RESOURCE GROUP — needed to build the ARM URL — is
// an implementation operand (candidate impl.resource_group), NOT a function of
// (capability, environment). So reconcile cannot recompute the URL the way the AWS
// driver recomputes a name. Instead it reads the receipt's PINNED providerId
// (apply persists `targetProviderId` for an unknown create that computed one, which
// every ambiguous Azure create does), splits it into subscription+resourceGroup+leaf,
// and reads live state by identity. A receipt with no pinned providerId cannot be
// concluded — reconcile returns unknown (stays pending) with an honest reason rather
// than guess a resource group.
package azure

import (
	"fmt"
	"net/http"
	"strings"

	"groundhold/internal/provider"
)

var _ provider.Reconciler = (*Driver)(nil)

// serviceFromTarget extracts the service token from a plan action target
// (<provider>.<service>/<id>) — the same shape the AWS/GCP drivers read.
func serviceFromTarget(target string) string {
	dot := strings.IndexByte(target, '.')
	slash := strings.IndexByte(target, '/')
	if dot < 0 || slash < 0 || slash < dot {
		return ""
	}
	return target[dot+1 : slash]
}

// receiptGeneration reads the receipt's generation tolerantly (JSON round-trips a
// whole float; a missing generation is the first generation, never a panic).
func receiptGeneration(receipt map[string]any) int {
	switch g := receipt["generation"].(type) {
	case int:
		if g >= 1 {
			return g
		}
	case float64:
		if g >= 1 {
			return int(g)
		}
	}
	return 1
}

// Reconcile concludes a pending receipt by reading live state. Dispatch is on the
// receipt's target service (D76) and FAILS CLOSED to unknown for a service not yet
// wired — never a fabricated conclusion against the wrong resource. The pinned
// providerId is the required handle (the resource group is unrecoverable otherwise).
func (d *Driver) Reconcile(capability, environment string,
	receipt map[string]any) provider.ReconcileResult {
	_ = receiptGeneration(receipt) // tolerated for symmetry; identity rides the pid
	tgt, _ := receipt["target"].(string)
	service := serviceFromTarget(tgt)
	pid, _ := receipt["targetProviderId"].(string)
	if pid == "" {
		svc := service
		if svc == "" {
			svc = "unknown"
		}
		return provider.ReconcileResult{Status: "unknown",
			Reason: fmt.Sprintf("azure %s reconcile has no pinned providerId in the receipt — "+
				"the resource group is an implementation operand, not recoverable from "+
				"(capability, environment); reconcile manually", svc)}
	}
	switch service {
	// --- single-resource, tag-owned, provisioningState (or synchronous) ---
	case "vnet":
		return d.reconcileVNet(capability, environment, pid)
	case "cosmos":
		return d.reconcileCosmos(capability, environment, pid)
	case "keyvault":
		return d.reconcileKeyVault(capability, environment, pid)
	case "rediscache":
		return d.reconcileRedis(capability, environment, pid)
	case "acr":
		return d.reconcileACR(capability, environment, pid)
	case "aisearch":
		return d.reconcileAISearch(capability, environment, pid)
	case "frontdoorwaf":
		return d.reconcileFrontDoorWAF(capability, environment, pid)
	case "apim":
		return d.reconcileAPIM(capability, environment, pid)
	case "containerappsjob":
		return d.reconcileContainerAppsJob(capability, environment, pid)
	case "azureopenai":
		return d.reconcileAzureOpenAI(capability, environment, pid)
	case "loganalytics":
		return d.reconcileLogAnalytics(capability, environment, pid)
	case "containerapps":
		return d.reconcileContainerApp(capability, environment, pid)
	case "azkafka":
		return d.reconcileAzKafka(capability, environment, pid)
	case "metricalert":
		return d.reconcileMetricAlert(capability, environment, pid)
	case "portaldash":
		return d.reconcilePortalDash(capability, environment, pid)
	case "webtest":
		return d.reconcileWebtest(capability, environment, pid)
	case "scheduledquery":
		return d.reconcileScheduledQuery(capability, environment, pid)
	case "managedidentity":
		return d.reconcileManagedIdentity(capability, environment, pid)
	case "blob":
		return d.reconcileBlob(capability, environment, pid)
	case "azurefiles":
		return d.reconcileAzFiles(capability, environment, pid)
	case "eventhubs":
		return d.reconcileEventHubs(capability, environment, pid)
	case "servicebusqueue", "servicebustopic":
		return d.reconcileServiceBus(capability, environment, pid)
	case "dnszone":
		return d.reconcileAzureDNS(capability, environment, pid)
	case "dnsrecord":
		return d.reconcileAzureDNSRecord(capability, environment, pid)
	case "loadbalancer":
		return d.reconcileLoadBalancer(capability, environment, pid)
	case "azurecdn":
		return d.reconcileAzureCDN(capability, environment, pid)
	case "keyvaultkey":
		return d.reconcileAzureKey(capability, environment, pid)
	case "acsemail":
		return d.reconcileACSEmail(capability, environment, pid)
	// --- state-shaped / composite-cluster ---
	case "flexpostgres":
		return d.reconcileFlex(capability, environment, pid)
	case "aks":
		return d.reconcileAKS(capability, environment, pid)
	case "aks-addon":
		return d.reconcileAKSAddon(capability, environment, pid)
	case "aks-workloadidentity":
		return d.reconcileAKSWorkloadIdentity(capability, environment, pid)
	// --- deterministic-name / GUID owned, no ARM tags ---
	case "roleassignment":
		return d.reconcileAzureRole(pid)
	case "customroledef":
		return d.reconcileAzureCustomRole(pid)
	case "changefeed":
		return d.reconcileChangeFeed(pid)
	case "consumptionbudget":
		return d.reconcileConsumptionBudget(capability, environment, pid)
	case "activitylog":
		return d.reconcileActivityLog(pid)
	case "defender":
		return d.reconcileDefender(pid)
	case "backuppolicy":
		return d.reconcileBackupPolicy(capability, environment, pid)
	case "backupvault":
		return d.reconcileBackupVault(capability, environment, pid)
	default:
		return provider.ReconcileResult{Status: "unknown",
			Reason: fmt.Sprintf("azure reconcile for service %q is not wired yet — reconcile manually", service)}
	}
}

// concludeByStatus maps a live read of a deterministically-identified resource to a
// reconcile verdict, uniform across every Azure service. ready → succeeded WITH the
// pinned pid; a terminal-failed state or a readable ABSENCE (404) → failed (the
// pending intent clears so a re-plan recreates); still-provisioning or any unreadable
// read → unknown (the receipt stays pending, D29). found-but-not-ours refuses to
// conclude (unknown) rather than attribute a foreign resource to our create.
func concludeByStatus(pid, what string, found bool, rerr error, ours, ready, failed bool) provider.ReconcileResult {
	switch {
	case rerr != nil:
		return provider.ReconcileResult{Status: "unknown",
			Reason: what + " read gave no answer — cannot conclude the pending create: " + rerr.Error()}
	case !found:
		return provider.ReconcileResult{Status: "failed",
			Reason: what + " is not present — the create did not land"}
	case !ours:
		return provider.ReconcileResult{Status: "unknown",
			Reason: what + " exists but does not carry our ownership tags — refusing to attribute it to this create"}
	case failed:
		return provider.ReconcileResult{Status: "failed",
			Reason: what + " reached a terminal-failed state — the create did not land cleanly"}
	case ready:
		return provider.ReconcileResult{Status: "succeeded", ProviderID: pid}
	default:
		return provider.ReconcileResult{Status: "unknown",
			Reason: what + " is still provisioning — resume again once it settles"}
	}
}

// azReconcileOwn reports whether ARM tags carry groundhold's ownership marker.
func azReconcileOwn(tags map[string]string, capability, environment string) bool {
	return tags["groundhold-capability"] == sanitizeAzTag(capability) &&
		tags["groundhold-environment"] == sanitizeAzTag(environment)
}

// armReconcileDoc is the shape shared by ~every ARM resource: top-level ownership
// tags + a properties.provisioningState. A synchronous resource (no LRO) has no
// provisioningState field — it reads as "" and is ready once found+owned.
type armReconcileDoc struct {
	Tags       map[string]string `json:"tags"`
	Properties struct {
		ProvisioningState string `json:"provisioningState"`
	} `json:"properties"`
}

// getARMState GETs one ARM resource and returns (tags, provisioningState, found,
// readable). (found, readable): a 404 is found=false + readable=true (authoritatively
// absent); a transport/HTTP/parse failure is readable=false (unknown — never a
// fabricated absence).
func (d *Driver) getARMState(rg, providerPath, apiVersion string) (tags map[string]string, state string, found bool, err error) {
	var doc armReconcileDoc
	found, err = d.armGetInto("reconcile.get", rg, providerPath, apiVersion, &doc)
	if err != nil || !found {
		return nil, "", false, err
	}
	return doc.Tags, doc.Properties.ProvisioningState, true, nil
}

// subMismatch refuses (unknown) a pid that names another subscription than the
// driver's — the read would target the driver's subscription regardless, so a
// mismatch cannot be honestly concluded.
func (d *Driver) subMismatch(pid, sub, what string) *provider.ReconcileResult {
	if sub != "" && d.Subscription != "" && sub != d.Subscription {
		r := provider.ReconcileResult{Status: "unknown",
			Reason: what + " providerId names a different subscription than the driver's — refusing to conclude across subscriptions"}
		return &r
	}
	return nil
}

// reconcileStdARM concludes a create whose ownership + readiness live on a single ARM
// resource carrying top-level tags and properties.provisioningState. The resource
// group + leaf name are recovered from the pinned providerId. A resource with no
// provisioningState (a synchronous PUT: UAMI, metric alert, dashboard, webtest...)
// reads ready once found+owned.
func (d *Driver) reconcileStdARM(pid, sub, rg, providerPath, apiVersion, what,
	capability, environment string) provider.ReconcileResult {
	if r := d.subMismatch(pid, sub, what); r != nil {
		return *r
	}
	tags, state, found, rerr := d.getARMState(rg, providerPath, apiVersion)
	ours := found && azReconcileOwn(tags, capability, environment)
	ready := state == "" || strings.EqualFold(state, "Succeeded")
	failed := strings.EqualFold(state, "Failed") || strings.EqualFold(state, "Canceled")
	return concludeByStatus(pid, what, found, rerr, ours, ready, failed)
}

// badPidReconcile is the honest refusal for a pinned providerId that will not parse
// (a corrupt/foreign receipt) — unknown, never a guess.
func badPidReconcile(service string, err error) provider.ReconcileResult {
	return provider.ReconcileResult{Status: "unknown",
		Reason: fmt.Sprintf("azure %s reconcile: pinned providerId is unusable (%v) — reconcile manually", service, err)}
}

// reconcileExistence concludes a create whose ownership is a DETERMINISTIC name/GUID
// (no ARM tags): a readable 200 is succeeded WITH the pid (the pinned id is ours by
// construction), a readable 404 is failed (the create did not land), anything else is
// unknown (stays pending).
func (d *Driver) reconcileExistence(pid, url, what string) provider.ReconcileResult {
	st, body, err := d.doARM("GET", url, nil)
	switch {
	case err != nil:
		return provider.ReconcileResult{Status: "unknown",
			Reason: what + " read gave no answer — cannot conclude the pending create: " +
				armTransport("existence.get", err).Error()}
	case st == http.StatusOK:
		return provider.ReconcileResult{Status: "succeeded", ProviderID: pid}
	case st == http.StatusNotFound:
		return provider.ReconcileResult{Status: "failed",
			Reason: what + " is not present — the create did not land"}
	default:
		return provider.ReconcileResult{Status: "unknown",
			Reason: what + " read gave no answer — cannot conclude the pending create: " +
				armHTTP("existence.get", st, body).Error()}
	}
}

// ---- single-resource, tag-owned services -------------------------------------

func (d *Driver) reconcileVNet(capability, environment, pid string) provider.ReconcileResult {
	sub, rg, name, err := splitVNetProviderID(pid)
	if err != nil {
		return badPidReconcile("vnet", err)
	}
	return d.reconcileStdARM(pid, sub, rg, "Microsoft.Network/virtualNetworks/"+name,
		networkAPIVersion, "vnet "+name, capability, environment)
}

func (d *Driver) reconcileCosmos(capability, environment, pid string) provider.ReconcileResult {
	sub, rg, account, err := splitCosmosProviderID(pid)
	if err != nil {
		return badPidReconcile("cosmos", err)
	}
	return d.reconcileStdARM(pid, sub, rg, d.cosmosPath(account), cosmosAPIVersion,
		"cosmos account "+account, capability, environment)
}

func (d *Driver) reconcileKeyVault(capability, environment, pid string) provider.ReconcileResult {
	sub, rg, vault, err := splitKeyVaultProviderID(pid)
	if err != nil {
		return badPidReconcile("keyvault", err)
	}
	return d.reconcileStdARM(pid, sub, rg, d.vaultPath(vault), keyVaultAPIVersion,
		"key vault "+vault, capability, environment)
}

func (d *Driver) reconcileRedis(capability, environment, pid string) provider.ReconcileResult {
	sub, rg, name, err := splitRedisAzureProviderID(pid)
	if err != nil {
		return badPidReconcile("rediscache", err)
	}
	return d.reconcileStdARM(pid, sub, rg, d.redisPath(name), redisAPIVersion,
		"redis "+name, capability, environment)
}

func (d *Driver) reconcileACR(capability, environment, pid string) provider.ReconcileResult {
	sub, rg, name, err := splitAzureACRProviderID(pid)
	if err != nil {
		return badPidReconcile("acr", err)
	}
	return d.reconcileStdARM(pid, sub, rg, "Microsoft.ContainerRegistry/registries/"+name,
		acrAPIVersion, "container registry "+name, capability, environment)
}

func (d *Driver) reconcileAISearch(capability, environment, pid string) provider.ReconcileResult {
	sub, rg, name, err := splitAISearchProviderID(pid)
	if err != nil {
		return badPidReconcile("aisearch", err)
	}
	return d.reconcileStdARM(pid, sub, rg, d.aiSearchPath(name), searchAPIVersion,
		"search service "+name, capability, environment)
}

func (d *Driver) reconcileFrontDoorWAF(capability, environment, pid string) provider.ReconcileResult {
	sub, rg, name, err := splitFrontDoorWAFProviderID(pid)
	if err != nil {
		return badPidReconcile("frontdoorwaf", err)
	}
	return d.reconcileStdARM(pid, sub, rg, d.frontDoorWAFPath(name), frontDoorWAFAPIVersion,
		"front door WAF policy "+name, capability, environment)
}

func (d *Driver) reconcileAPIM(capability, environment, pid string) provider.ReconcileResult {
	sub, rg, name, err := splitAPIMProviderID(pid)
	if err != nil {
		return badPidReconcile("apim", err)
	}
	return d.reconcileStdARM(pid, sub, rg, d.apimPath(name), apimAPIVersion,
		"api management service "+name, capability, environment)
}

func (d *Driver) reconcileContainerAppsJob(capability, environment, pid string) provider.ReconcileResult {
	sub, rg, name, err := splitContainerAppsJobProviderID(pid)
	if err != nil {
		return badPidReconcile("containerappsjob", err)
	}
	return d.reconcileStdARM(pid, sub, rg, d.containerAppsJobPath(name), containerAppsJobsAPIVersion,
		"container apps job "+name, capability, environment)
}

func (d *Driver) reconcileAzureOpenAI(capability, environment, pid string) provider.ReconcileResult {
	sub, rg, account, err := splitAzureOpenAIProviderID(pid)
	if err != nil {
		return badPidReconcile("azureopenai", err)
	}
	return d.reconcileStdARM(pid, sub, rg, d.aoiAccountPath(account), cognitiveAPIVersion,
		"cognitive services account "+account, capability, environment)
}

func (d *Driver) reconcileLogAnalytics(capability, environment, pid string) provider.ReconcileResult {
	sub, rg, name, err := splitLAProviderID(pid)
	if err != nil {
		return badPidReconcile("loganalytics", err)
	}
	return d.reconcileStdARM(pid, sub, rg, d.laPath(name), laAPIVersion,
		"log analytics workspace "+name, capability, environment)
}

func (d *Driver) reconcileContainerApp(capability, environment, pid string) provider.ReconcileResult {
	sub, rg, app, err := splitACAProviderID(pid)
	if err != nil {
		return badPidReconcile("containerapps", err)
	}
	return d.reconcileStdARM(pid, sub, rg, "Microsoft.App/containerApps/"+app, appAPIVersion,
		"container app "+app, capability, environment)
}

func (d *Driver) reconcileAzKafka(capability, environment, pid string) provider.ReconcileResult {
	sub, rg, ns, err := splitAzKafkaProviderID(pid)
	if err != nil {
		return badPidReconcile("azkafka", err)
	}
	return d.reconcileStdARM(pid, sub, rg, d.azKafkaPath(ns), azKafkaAPIVersion,
		"event hubs (kafka) namespace "+ns, capability, environment)
}

func (d *Driver) reconcileMetricAlert(capability, environment, pid string) provider.ReconcileResult {
	sub, rg, name, err := splitAzureAlertProviderID(pid)
	if err != nil {
		return badPidReconcile("metricalert", err)
	}
	return d.reconcileStdARM(pid, sub, rg, "Microsoft.Insights/metricAlerts/"+name,
		metricAlertAPIVersion, "metric alert "+name, capability, environment)
}

func (d *Driver) reconcilePortalDash(capability, environment, pid string) provider.ReconcileResult {
	sub, rg, name, err := splitAzureDashProviderID(pid)
	if err != nil {
		return badPidReconcile("portaldash", err)
	}
	return d.reconcileStdARM(pid, sub, rg, "Microsoft.Portal/dashboards/"+name,
		portalDashAPIVersion, "portal dashboard "+name, capability, environment)
}

func (d *Driver) reconcileWebtest(capability, environment, pid string) provider.ReconcileResult {
	sub, rg, name, err := splitAzureWebtestProviderID(pid)
	if err != nil {
		return badPidReconcile("webtest", err)
	}
	return d.reconcileStdARM(pid, sub, rg, "Microsoft.Insights/webtests/"+name,
		webtestAPIVersion, "web test "+name, capability, environment)
}

func (d *Driver) reconcileScheduledQuery(capability, environment, pid string) provider.ReconcileResult {
	sub, rg, name, err := splitAzureSQProviderID(pid)
	if err != nil {
		return badPidReconcile("scheduledquery", err)
	}
	return d.reconcileStdARM(pid, sub, rg, "Microsoft.Insights/scheduledQueryRules/"+name,
		scheduledQueryAPIVersion, "scheduled query rule "+name, capability, environment)
}

func (d *Driver) reconcileManagedIdentity(capability, environment, pid string) provider.ReconcileResult {
	sub, rg, name, err := splitUAMIProviderID(pid)
	if err != nil {
		return badPidReconcile("managedidentity", err)
	}
	// UAMI is a synchronous PUT (no provisioningState) — reconcileStdARM reads "" as
	// ready, so found+owned concludes succeeded.
	return d.reconcileStdARM(pid, sub, rg, "Microsoft.ManagedIdentity/userAssignedIdentities/"+name,
		managedIdentityAPIVersion, "user-assigned identity "+name, capability, environment)
}

// blob / azurefiles: the constitutive composite's ownership + readiness live on the
// storage ACCOUNT (the substrate). Reconcile reads the account.
func (d *Driver) reconcileBlob(capability, environment, pid string) provider.ReconcileResult {
	sub, rg, account, _, err := splitBlobProviderID(pid)
	if err != nil {
		return badPidReconcile("blob", err)
	}
	return d.reconcileStdARM(pid, sub, rg, d.acctPath(account), storageAPIVersion,
		"storage account "+account, capability, environment)
}

func (d *Driver) reconcileAzFiles(capability, environment, pid string) provider.ReconcileResult {
	sub, rg, account, _, err := splitAzFilesProviderID(pid)
	if err != nil {
		return badPidReconcile("azurefiles", err)
	}
	return d.reconcileStdARM(pid, sub, rg, d.acctPath(account), storageAPIVersion,
		"storage account "+account, capability, environment)
}

// eventhubs / servicebus: the namespace is the tagged, provisioningState-bearing
// substrate; the entity (hub/queue/topic) rides inside it.
func (d *Driver) reconcileEventHubs(capability, environment, pid string) provider.ReconcileResult {
	sub, rg, ns, _, err := splitEventHubsProviderID(pid)
	if err != nil {
		return badPidReconcile("eventhubs", err)
	}
	return d.reconcileStdARM(pid, sub, rg, d.ehNamespacePath(ns), eventHubsAPIVersion,
		"event hubs namespace "+ns, capability, environment)
}

func (d *Driver) reconcileServiceBus(capability, environment, pid string) provider.ReconcileResult {
	_, sub, rg, ns, _, err := splitSBProviderID(pid)
	if err != nil {
		return badPidReconcile("servicebus", err)
	}
	return d.reconcileStdARM(pid, sub, rg, d.sbNamespacePath(ns), serviceBusAPIVersion,
		"service bus namespace "+ns, capability, environment)
}

func (d *Driver) reconcileAzureDNS(capability, environment, pid string) provider.ReconcileResult {
	sub, rg, kind, domain, err := splitAzureDNSProviderID(pid)
	if err != nil {
		return badPidReconcile("dnszone", err)
	}
	path, apiVersion := dnsTypePath(kind, domain)
	return d.reconcileStdARM(pid, sub, rg, path, apiVersion, "dns zone "+domain, capability, environment)
}

// dnsrecord: ownership is the PARENT ZONE's tags; the record set is a synchronous
// sub-resource, so its mere existence (found) is readiness once the zone is ours
// (mirrors keyvaultkey — a key inside a vault).
func (d *Driver) reconcileAzureDNSRecord(capability, environment, pid string) provider.ReconcileResult {
	sub, rg, zone, recordType, name, err := splitAzureDNSRecordProviderID(pid)
	if err != nil {
		return badPidReconcile("dnsrecord", err)
	}
	what := "dns record " + zone + "/" + recordType + "/" + name
	if r := d.subMismatch(pid, sub, what); r != nil {
		return *r
	}
	zTags, _, zFound, zErr := d.getARMState(rg, "Microsoft.Network/dnsZones/"+zone, publicDNSAPIVersion)
	if zErr != nil {
		return provider.ReconcileResult{Status: "unknown",
			Reason: "dns zone " + zone + " read gave no answer — cannot conclude the pending record create: " + zErr.Error()}
	}
	ours := zFound && azReconcileOwn(zTags, capability, environment)
	childPath := "Microsoft.Network/dnsZones/" + zone + "/" + azDNSRecordTypeOK[recordType] + "/" + name
	_, _, rFound, rErr := d.getARMState(rg, childPath, publicDNSAPIVersion)
	return concludeByStatus(pid, what, rFound, rErr, ours, rFound, false)
}

func (d *Driver) reconcileLoadBalancer(capability, environment, pid string) provider.ReconcileResult {
	kind, sub, rg, name, err := splitLBProviderID(pid)
	if err != nil {
		return badPidReconcile("loadbalancer", err)
	}
	// createLoadBalancer provisions the L7 Application Gateway; an L4 loadBalancers pid
	// (read-only slice) is handled for completeness by its own path.
	path := "Microsoft.Network/applicationGateways/" + name
	if kind == "loadbalancer" {
		path = "Microsoft.Network/loadBalancers/" + name
	}
	return d.reconcileStdARM(pid, sub, rg, path, networkAPIVersion, kind+" "+name, capability, environment)
}

// azurecdn: ownership is the PROFILE's tags; readiness is the ENDPOINT's
// provisioningState (the leaf the create finishes on). Two reads, honestly combined.
func (d *Driver) reconcileAzureCDN(capability, environment, pid string) provider.ReconcileResult {
	sub, rg, profile, endpoint, err := splitAzureCDNProviderID(pid)
	if err != nil {
		return badPidReconcile("azurecdn", err)
	}
	what := "cdn endpoint " + endpoint
	if r := d.subMismatch(pid, sub, what); r != nil {
		return *r
	}
	pTags, _, pFound, pErr := d.getARMState(rg, d.cdnProfilePath(profile), azureCDNAPIVersion)
	if pErr != nil {
		return provider.ReconcileResult{Status: "unknown",
			Reason: "cdn profile " + profile + " read gave no answer — cannot conclude the pending create: " + pErr.Error()}
	}
	ours := pFound && azReconcileOwn(pTags, capability, environment)
	_, state, eFound, eErr := d.getARMState(rg, d.cdnProfilePath(profile)+"/endpoints/"+endpoint, azureCDNAPIVersion)
	ready := strings.EqualFold(state, "Succeeded")
	failed := strings.EqualFold(state, "Failed") || strings.EqualFold(state, "Canceled")
	return concludeByStatus(pid, what, eFound, eErr, ours, ready, failed)
}

// keyvaultkey: ownership is the VAULT's tags; the key is a synchronous sub-resource,
// so its mere existence (found) is readiness once the vault is ours.
func (d *Driver) reconcileAzureKey(capability, environment, pid string) provider.ReconcileResult {
	sub, rg, _, vault, key, err := splitAzureKeyProviderID(pid)
	if err != nil {
		return badPidReconcile("keyvaultkey", err)
	}
	what := "key vault key " + vault + "/" + key
	if r := d.subMismatch(pid, sub, what); r != nil {
		return *r
	}
	vTags, _, vFound, vErr := d.getARMState(rg, d.vaultPath(vault), keyVaultAPIVersion)
	if vErr != nil {
		return provider.ReconcileResult{Status: "unknown",
			Reason: "key vault " + vault + " read gave no answer — cannot conclude the pending key create: " + vErr.Error()}
	}
	ours := vFound && azReconcileOwn(vTags, capability, environment)
	_, _, kFound, kErr := d.getARMState(rg, d.keyPath(vault, key), keyVaultAPIVersion)
	return concludeByStatus(pid, what, kFound, kErr, ours, kFound, false)
}

// acsemail: ownership + readiness on the emailService (the composite's anchor); the
// service PUT is an LRO polled to provisioningState=Succeeded.
func (d *Driver) reconcileACSEmail(capability, environment, pid string) provider.ReconcileResult {
	sub, rg, name, err := splitACSEmailProviderID(pid)
	if err != nil {
		return badPidReconcile("acsemail", err)
	}
	what := "email service " + name
	if r := d.subMismatch(pid, sub, what); r != nil {
		return *r
	}
	doc, found, rerr := d.getEmailService(rg, name)
	ours := found && d.acsOwned(doc.Tags, capability, environment)
	ready := strings.EqualFold(doc.Properties.ProvisioningState, "Succeeded")
	failed := strings.EqualFold(doc.Properties.ProvisioningState, "Failed") ||
		strings.EqualFold(doc.Properties.ProvisioningState, "Canceled")
	return concludeByStatus(pid, what, found, rerr, ours, ready, failed)
}

// ---- state-shaped / composite-cluster services -------------------------------

// reconcileFlex: PostgreSQL Flexible Server reports readiness on properties.state,
// not provisioningState — Ready is up, Failed/Dropping/Disabled are terminal-failed.
func (d *Driver) reconcileFlex(capability, environment, pid string) provider.ReconcileResult {
	sub, rg, name, err := splitFlexProviderID(pid)
	if err != nil {
		return badPidReconcile("flexpostgres", err)
	}
	if r := d.subMismatch(pid, sub, "flexible server "+name); r != nil {
		return *r
	}
	doc, found, rerr := d.getFlex(rg, name)
	ours := found && azReconcileOwn(doc.Tags, capability, environment)
	state := doc.Properties.State
	ready := state == "Ready"
	failed := state == "Failed" || state == "Dropping" || state == "Disabled"
	return concludeByStatus(pid, "flexible server "+name, found, rerr, ours, ready, failed)
}

// reconcileAKS mirrors the create's partial-composite honesty (the EKS precedent): a
// cluster that STANDS in Failed/Canceled, or a Succeeded control plane with an
// unhealthy agent pool, is a HALF-PROVISIONED cluster — unknown (repair/resume-again;
// a re-plan must not double-create it), never a bare "failed".
func (d *Driver) reconcileAKS(capability, environment, pid string) provider.ReconcileResult {
	sub, rg, name, err := splitAKSProviderID(pid)
	if err != nil {
		return badPidReconcile("aks", err)
	}
	if r := d.subMismatch(pid, sub, "aks cluster "+name); r != nil {
		return *r
	}
	doc, _, found, rerr := d.getAKS(rg, name)
	if rerr != nil {
		return provider.ReconcileResult{Status: "unknown",
			Reason: "aks cluster " + name + " read gave no answer — cannot conclude the pending create: " + rerr.Error()}
	}
	if !found {
		return provider.ReconcileResult{Status: "failed",
			Reason: "aks cluster " + name + " is not present — the create did not land"}
	}
	if !aksOwned(doc, capability, environment) {
		return provider.ReconcileResult{Status: "unknown",
			Reason: "aks cluster " + name + " exists but does not carry our ownership tags — refusing to attribute it to this create"}
	}
	switch doc.Properties.ProvisioningState {
	case "Failed", "Canceled":
		return provider.ReconcileResult{Status: "unknown",
			Reason: "aks cluster " + name + " stands in provisioningState " + doc.Properties.ProvisioningState +
				" — a half-provisioned cluster; repair it (a re-plan must not double-create the cluster)"}
	case "Succeeded":
		if !aksHealthy(doc) {
			return provider.ReconcileResult{Status: "unknown",
				Reason: "aks cluster " + name + " control plane is Succeeded but an agent pool is not — " +
					"a half-provisioned cluster; repair it"}
		}
		return provider.ReconcileResult{Status: "succeeded", ProviderID: pid}
	default:
		return provider.ReconcileResult{Status: "unknown",
			Reason: "aks cluster " + name + " is still provisioning — resume again once it settles"}
	}
}

// reconcileAKSAddon concludes an addon-enable on an operand cluster. Ownership is
// STRUCTURAL (the addon is enabled in the cluster's addonProfiles). A vanished
// cluster is failed (the operand is gone); a Succeeded cluster with the addon enabled
// is succeeded, with it absent is failed (the enable did not land); a Failed/Canceled
// cluster is failed; an updating cluster stays unknown.
func (d *Driver) reconcileAKSAddon(capability, environment, pid string) provider.ReconcileResult {
	sub, rg, cluster, addon, err := splitAKSAddonProviderID(pid)
	if err != nil {
		return badPidReconcile("aks-addon", err)
	}
	if r := d.subMismatch(pid, sub, "aks addon "+addon); r != nil {
		return *r
	}
	profileKey := aksAddonRegistry[addon]
	doc, found, rerr := d.getAKSAddonCluster(rg, cluster)
	if rerr != nil {
		return provider.ReconcileResult{Status: "unknown",
			Reason: "aks cluster " + cluster + " read gave no answer — cannot conclude the pending addon enable: " + rerr.Error()}
	}
	if !found {
		return provider.ReconcileResult{Status: "failed",
			Reason: "aks cluster " + cluster + " (the addon's operand) is not present — the enable did not land"}
	}
	props, _ := doc["properties"].(map[string]any)
	state, _ := props["provisioningState"].(string)
	switch state {
	case "Failed", "Canceled":
		return provider.ReconcileResult{Status: "failed",
			Reason: "aks cluster " + cluster + " stands in provisioningState " + state + " — the addon enable did not land cleanly"}
	case "Succeeded":
		if enabled, _ := aksAddonReadEnabled(doc, profileKey); enabled {
			return provider.ReconcileResult{Status: "succeeded", ProviderID: pid}
		}
		return provider.ReconcileResult{Status: "failed",
			Reason: "addon " + addon + " is not enabled on cluster " + cluster + " — the enable did not land"}
	default:
		return provider.ReconcileResult{Status: "unknown",
			Reason: "aks cluster " + cluster + " is still updating — resume again once it settles"}
	}
}

// reconcileAKSWorkloadIdentity: the federated credential is a synchronous PUT on the
// UAMI, named deterministically (the name IS the ownership handle). Existence
// concludes succeeded; a readable absence is failed.
func (d *Driver) reconcileAKSWorkloadIdentity(capability, environment, pid string) provider.ReconcileResult {
	sub, rg, uami, name, err := splitAKSWIProviderID(pid)
	if err != nil {
		return badPidReconcile("aks-workloadidentity", err)
	}
	if r := d.subMismatch(pid, sub, "federated credential "+name); r != nil {
		return *r
	}
	_, found, rerr := d.getFIC(rg, uami, name)
	return concludeByStatus(pid, "federated credential "+uami+"/"+name, found, rerr, found, found, false)
}

// ---- deterministic-name / GUID owned services (no ARM tags) -------------------

func (d *Driver) reconcileAzureRole(pid string) provider.ReconcileResult {
	sub, guid, err := splitAzureRoleProviderID(pid)
	if err != nil {
		return badPidReconcile("roleassignment", err)
	}
	if r := d.subMismatch(pid, sub, "role assignment "+guid); r != nil {
		return *r
	}
	return d.reconcileExistence(pid, d.roleAssignmentURL(sub, guid), "role assignment "+guid)
}

func (d *Driver) reconcileAzureCustomRole(pid string) provider.ReconcileResult {
	sub, guid, err := splitAzureCustomRoleProviderID(pid)
	if err != nil {
		return badPidReconcile("customroledef", err)
	}
	if r := d.subMismatch(pid, sub, "role definition "+guid); r != nil {
		return *r
	}
	return d.reconcileExistence(pid, d.customRoleURL(sub, guid), "role definition "+guid)
}

// reconcileChangeFeed: an Event Grid system topic subscription (LRO); ownership is the
// deterministic name (no tags), readiness is provisioningState.
func (d *Driver) reconcileChangeFeed(pid string) provider.ReconcileResult {
	sub, name, err := splitChangeFeedProviderID(pid)
	if err != nil {
		return badPidReconcile("changefeed", err)
	}
	if r := d.subMismatch(pid, sub, "change feed "+name); r != nil {
		return *r
	}
	doc, found, rerr := d.getChangeFeed(sub, name)
	state := doc.Properties.ProvisioningState
	ready := strings.EqualFold(state, "Succeeded")
	failed := strings.EqualFold(state, "Failed") || strings.EqualFold(state, "Canceled")
	// deterministic name => ours by construction (the pinned pid got us here).
	return concludeByStatus(pid, "change feed "+name, found, rerr, found, ready, failed)
}

func (d *Driver) reconcileConsumptionBudget(capability, environment, pid string) provider.ReconcileResult {
	sub, rg, name, err := splitConsBudgetProviderID(pid)
	if err != nil {
		return badPidReconcile("consumptionbudget", err)
	}
	if r := d.subMismatch(pid, sub, "consumption budget "+name); r != nil {
		return *r
	}
	// ownership: the deterministic NAME carries our (env, cap) marker.
	ours := consBudgetOurs(name, environment, capability)
	url, uerr := d.consBudgetURL(rg, name)
	if uerr != nil {
		return badPidReconcile("consumptionbudget", uerr)
	}
	_, found, rerr := d.consBudgetGet(url)
	// synchronous create-or-update: existence is readiness.
	return concludeByStatus(pid, "consumption budget "+name, found, rerr, ours && found, found, false)
}

// reconcileActivityLog: a diagnostic setting (synchronous PUT), owned by its
// deterministic content-addressed name. Existence concludes succeeded.
func (d *Driver) reconcileActivityLog(pid string) provider.ReconcileResult {
	sub, name, err := splitActivityLogProviderID(pid)
	if err != nil {
		return badPidReconcile("activitylog", err)
	}
	if r := d.subMismatch(pid, sub, "activity-log setting "+name); r != nil {
		return *r
	}
	_, found, rerr := d.getActivityLog(sub, name)
	return concludeByStatus(pid, "activity-log setting "+name, found, rerr, found, found, false)
}

// reconcileDefender: Defender for Cloud is a subscription-singleton POSTURE (pricing
// tiers) configured in place — the resource always exists, so "is it present" answers
// nothing. A pending receipt means the configure PUT's outcome was LOST; whether the
// DESIRED tier landed can only be judged against the candidate posture, which a receipt
// does not carry. So reconcile CANNOT honestly conclude succeeded here: a lost PUT of
// Standard reads a clean Free and would record an INACTIVE security control as active.
// It returns unknown — the receipt stays pending (which safely blocks converge until an
// operator re-asserts the posture, idempotent, or repairs it), never fabricated. This
// is the honest four-valued answer when the desired value is not in scope.
func (d *Driver) reconcileDefender(pid string) provider.ReconcileResult {
	sub, err := splitDefenderProviderID(pid)
	if err != nil {
		return badPidReconcile("defender", err)
	}
	if r := d.subMismatch(pid, sub, "defender posture"); r != nil {
		return *r
	}
	if _, _, rerr := d.getDefenderPricing(sub, defenderPlanServers); rerr != nil {
		return provider.ReconcileResult{Status: "unknown",
			Reason: "defender pricing read gave no answer — cannot conclude the pending configure: " + rerr.Error()}
	}
	return provider.ReconcileResult{Status: "unknown",
		Reason: "defender is a subscription posture configured in place; whether the desired tier " +
			"landed cannot be verified from a receipt alone — re-assert via converge (idempotent) " +
			"or repair, never concluded succeeded here"}
}

// reconcileBackupPolicy: a backup policy in an OPERAND (foreign-owned) vault, created
// synchronously. The policy is owned by its deterministic name (pv-...-<ownerToken>),
// so — like consumptionbudget — reconcile must gate on that name marker, not on bare
// existence: a foreign policy colliding at the pid's name must NOT be attributed to our
// create. found-but-not-ours → unknown (never a claimed success).
func (d *Driver) reconcileBackupPolicy(capability, environment, pid string) provider.ReconcileResult {
	sub, rg, vault, policy, err := splitBackupPolicyProviderID(pid)
	if err != nil {
		return badPidReconcile("backuppolicy", err)
	}
	if r := d.subMismatch(pid, sub, "backup policy "+policy); r != nil {
		return *r
	}
	_, found, rerr := d.getBackupPolicy(rg, vault, policy)
	ours := found && backupPolicyOurs(policy, environment, capability)
	return concludeByStatus(pid, "backup policy "+vault+"/"+policy, found, rerr, ours, ours, false)
}
