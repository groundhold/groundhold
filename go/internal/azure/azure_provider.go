// The Azure driver's provider.Provider implementation (D99): dispatch on the
// SERVICE token, fail-closed on unknown — the same discipline as the AWS (D86) and
// GCP (D76) drivers. Services land one slice at a time (vnet -> blob ->
// containerapps -> database); an unbuilt service returns an honest "not wired".
package azure

import (
	"fmt"
	"strings"

	"groundhold/internal/provider"
)

// azureServices is the set of recognized ARM service tokens. A token is added here
// only when its driver is wired; an unknown/empty token fails closed (no default).
var azureServices = map[string]bool{
	"vnet":             true, // capability.network.private (Microsoft.Network/virtualNetworks)
	"blob":             true, // capability.storage.object (Microsoft.Storage constitutive composite)
	"containerapps":    true, // capability.workload.container (Microsoft.App env+app)
	"flexpostgres":     true, // capability.database.relational (PostgreSQL Flexible Server)
	"servicebusqueue":  true, // capability.messaging.queue (Service Bus namespace+queue)
	"servicebustopic":  true, // capability.messaging.topic (Service Bus namespace+topic)
	"keyvault":         true, // capability.secret (Microsoft.KeyVault/vaults; value out of band)
	"rediscache":       true, // capability.cache.keyvalue (Microsoft.Cache/Redis)
	"dnszone":          true, // capability.dns.zone (Microsoft.Network/dnsZones | privateDnsZones)
	"dnsrecord":        true, // capability.dns.record (Microsoft.Network/dnsZones/{TYPE} child; public only)
	"roleassignment":   true, // capability.authorization.grant (Microsoft.Authorization/roleAssignments)
	"customroledef":    true, // capability.authorization.role (Microsoft.Authorization/roleDefinitions)
	"metricalert":      true, // capability.monitoring.alert (Microsoft.Insights/metricAlerts)
	"portaldash":       true, // capability.monitoring.dashboard (Microsoft.Portal/dashboards)
	"webtest":          true, // capability.monitoring.uptime (Microsoft.Insights/webtests)
	"scheduledquery":   true, // capability.monitoring.logmetric (Microsoft.Insights/scheduledQueryRules)
	"acr":              true, // capability.registry.image (Microsoft.ContainerRegistry/registries)
	"azurefiles":       true, // capability.storage.filesystem (Microsoft.Storage account+fileShare)
	"cosmos":           true, // capability.database.nosql (Microsoft.DocumentDB/databaseAccounts)
	"azvm":             true, // capability.compute.instance (Microsoft.Compute/virtualMachines)
	"azdisk":           true, // capability.storage.block (Microsoft.Compute/disks)
	"azimage":          true, // capability.compute.image (Microsoft.Compute/images) — WITNESS
	"azvmss":           true, // capability.compute.autoscaling (Microsoft.Compute/virtualMachineScaleSets)
	"aisearch":         true, // capability.search.index (Microsoft.Search/searchServices)
	"eventhubs":        true, // capability.streaming.pipe (Microsoft.EventHub namespace+hub)
	"azkafka":          true, // capability.messaging.kafka (Event Hubs namespace, kafkaEnabled)
	"frontdoorwaf":     true, // capability.security.waf (FrontDoorWebApplicationFirewallPolicies)
	"azurecdn":         true, // capability.cdn.distribution (Microsoft.Cdn profile+endpoint)
	"apim":             true, // capability.apigateway.http (Microsoft.ApiManagement/service)
	"containerappsjob": true, // capability.container.job (Microsoft.App/jobs)
	"managedidentity":  true, // capability.identity.serviceaccount (Microsoft.ManagedIdentity/userAssignedIdentities)
	"keyvaultkey":      true, // capability.key.encryption (Microsoft.KeyVault/vaults/keys)
	"changefeed":       true, // capability.observability.changefeed (Microsoft.EventGrid/eventSubscriptions)
	"loadbalancer":     true, // capability.network.loadbalancer (Microsoft.Network/loadBalancers | applicationGateways) — READ-ONLY slice
	// posture parity (D76): budget / log retention / audit / threat-detection / AI
	"consumptionbudget": true, // capability.cost.budget (Microsoft.Consumption/budgets)
	"loganalytics":      true, // capability.monitoring.logs (Microsoft.OperationalInsights/workspaces)
	"activitylog":       true, // capability.audit.trail (Microsoft.Insights/diagnosticSettings, subscription Activity Log export)
	"defender":          true, // capability.security.threatdetection (Microsoft.Security/pricings)
	"azureopenai":       true, // capability.ai.inference (Microsoft.CognitiveServices/accounts kind=OpenAI)
	// cluster family (D76 parity)
	"aks":                  true, // capability.cluster.kubernetes (Microsoft.ContainerService/managedClusters)
	"aks-addon":            true, // capability.cluster.addon (managedCluster addonProfiles)
	"aks-workloadidentity": true, // capability.identity.podidentity (UAMI federatedIdentityCredentials)
	// backup + email (D76 parity, fala 4)
	"backuppolicy": true, // capability.backup.plan (Microsoft.DataProtection/backupVaults/backupPolicies)
	"backupvault":  true, // capability.backup.vault (Microsoft.DataProtection/backupVaults)
	"acsemail":     true, // capability.email.sending (Microsoft.Communication/emailServices + domains)
}

func (d *Driver) requireService(service string) error {
	if !azureServices[service] {
		return fmt.Errorf("azure driver: unknown service %q — refusing (no default)", service)
	}
	if d.Subscription != "" && !subOK.MatchString(d.Subscription) {
		return fmt.Errorf("azure driver: pinned subscription %q is not a valid GUID", d.Subscription)
	}
	return nil
}

func (d *Driver) Validate(service, capability, environment string,
	attrs, impl map[string]any, generation int) error {
	if err := d.requireService(service); err != nil {
		return err
	}
	switch service {
	case "vnet":
		_, err := BuildVNet(environment, capability, attrs, impl, generation)
		return err
	case "blob":
		_, err := BuildBlob(environment, capability, attrs, impl, generation)
		return err
	case "containerapps":
		_, err := BuildContainerApp(environment, capability, attrs, impl, generation)
		return err
	case "flexpostgres":
		_, err := BuildFlexServer(environment, capability, attrs, impl, generation)
		return err
	case "servicebusqueue":
		_, err := BuildServiceBusQueue(environment, capability, attrs, impl, generation)
		return err
	case "servicebustopic":
		_, err := BuildServiceBusTopic(environment, capability, attrs, impl, generation)
		return err
	case "keyvault":
		_, err := BuildKeyVault(environment, capability, attrs, impl, generation)
		return err
	case "rediscache":
		_, err := BuildRedisAzure(environment, capability, attrs, impl, generation)
		return err
	case "dnszone":
		_, err := BuildAzureDNS(environment, capability, attrs, impl, generation)
		return err
	case "dnsrecord":
		_, err := BuildAzureDNSRecord(environment, capability, attrs, impl, generation)
		return err
	case "roleassignment":
		_, err := BuildAzureRole(environment, capability, attrs, impl, generation)
		return err
	case "customroledef":
		_, err := BuildAzureCustomRole(environment, capability, attrs, impl, generation)
		return err
	case "metricalert":
		_, err := BuildAzureAlert(environment, capability, attrs, impl, generation)
		return err
	case "portaldash":
		_, err := BuildAzureDashboard(environment, capability, attrs, impl, generation)
		return err
	case "webtest":
		_, err := BuildAzureWebtest(environment, capability, attrs, impl, generation)
		return err
	case "scheduledquery":
		_, err := BuildAzureScheduledQuery(environment, capability, attrs, impl, generation)
		return err
	case "acr":
		_, err := BuildACR(environment, capability, attrs, impl, generation)
		return err
	case "azurefiles":
		_, err := BuildAzFiles(environment, capability, attrs, impl, generation)
		return err
	case "cosmos":
		_, err := BuildCosmos(environment, capability, attrs, impl, generation)
		return err
	case "azvm":
		_, err := BuildAzureVM(environment, capability, attrs, impl, generation)
		return err
	case "azdisk":
		_, err := BuildAzureDisk(environment, capability, attrs, impl, generation)
		return err
	case "azimage":
		return errWitnessOnlyAzure("azimage")
	case "azvmss":
		_, err := BuildVMSS(environment, capability, attrs, impl, generation)
		return err
	case "aisearch":
		_, err := BuildAISearch(environment, capability, attrs, impl, generation)
		return err
	case "eventhubs":
		_, err := BuildEventHubs(environment, capability, attrs, impl, generation)
		return err
	case "azkafka":
		_, err := BuildAzKafka(environment, capability, attrs, impl, generation)
		return err
	case "frontdoorwaf":
		_, err := BuildFrontDoorWAF(environment, capability, attrs, impl, generation)
		return err
	case "azurecdn":
		_, err := BuildAzureCDN(environment, capability, attrs, impl, generation)
		return err
	case "apim":
		_, err := BuildAPIM(environment, capability, attrs, impl, generation)
		return err
	case "containerappsjob":
		_, err := BuildContainerAppsJob(environment, capability, attrs, impl, generation)
		return err
	case "managedidentity":
		_, err := BuildManagedIdentity(environment, capability, attrs, impl, generation)
		return err

	case "keyvaultkey":
		_, err := BuildAzureKey(environment, capability, attrs, impl, generation)
		return err
	case "changefeed":
		_, err := BuildChangeFeed(environment, capability, attrs, impl, generation)
		return err
	case "loadbalancer":
		// Provisions the L7 Application Gateway (the honest composite). Validate is
		// the pure builder: a missing required operand (subnetId; publicIpId iff
		// public; the cert REFERENCE iff inTransit) is a refusal surfaced here.
		_, err := BuildAppGateway(environment, capability, attrs, impl, generation)
		return err
	case "consumptionbudget":
		_, err := BuildConsumptionBudget(environment, capability, attrs, impl, generation)
		return err
	case "loganalytics":
		_, err := BuildLogAnalytics(environment, capability, attrs, impl, generation)
		return err
	case "activitylog":
		_, err := BuildActivityLog(d.Subscription, environment, capability, attrs, impl, generation)
		return err
	case "defender":
		_, err := BuildDefender(environment, capability, attrs, impl, generation)
		return err
	case "azureopenai":
		_, err := BuildAzureOpenAI(environment, capability, attrs, impl, generation)
		return err
	case "aks":
		_, err := BuildAKS(environment, capability, attrs, impl, generation)
		return err
	case "aks-addon":
		_, err := BuildAKSAddon(environment, capability, attrs, impl, generation)
		return err
	case "aks-workloadidentity":
		_, err := BuildAKSWorkloadIdentity(d.Subscription, environment, capability, attrs, impl, generation)
		return err
	case "backuppolicy":
		_, err := BuildBackupPolicy(environment, capability, attrs, impl, generation)
		return err
	case "backupvault":
		_, err := BuildBackupVault(environment, capability, attrs, impl, generation)
		return err
	case "acsemail":
		_, err := BuildACSEmail(environment, capability, attrs, impl, generation)
		return err

	default:
		return fmt.Errorf("azure service %q is not wired yet", service)
	}
}

// Create dispatches the per-service create and, for services declaring typed
// outputs (D284), attaches them to a succeeded result — derived from the
// provider id (plus one identity read for managedidentity's server-assigned
// principalId/clientId), so every succeeded path receipts the same set.
func (d *Driver) Create(service, capability, environment string,
	attrs, impl map[string]any, key string, generation int) provider.CreateResult {
	// D309: the credentials this action carries are remembered for the duration of
	// the mutation and scrubbed out of its Reason on the way back — the Reason is
	// persisted in the ledger and signed into capsules.
	defer d.forgetSecrets()
	d.rememberSecrets(impl)
	cr := d.createService(service, capability, environment, attrs, impl, key, generation)
	d.attachOutputs(service, &cr)
	cr.Reason = d.scrub(cr.Reason)
	return cr
}

// ---- credential redaction (D309) -------------------------------------------
// See internal/provider/redact.go for why this is exact rather than pattern-matching.

func (d *Driver) rememberSecrets(impl map[string]any) { d.secrets.Remember(impl) }

func (d *Driver) forgetSecrets() { d.secrets.Forget() }

func (d *Driver) scrub(s string) string { return d.secrets.Scrub(s) }

func (d *Driver) createService(service, capability, environment string,
	attrs, impl map[string]any, key string, generation int) provider.CreateResult {
	if err := d.requireService(service); err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	if !d.hasToken() {
		return provider.CreateResult{Status: "failed",
			Reason: "no Azure access token — refusing before any mutation"}
	}
	switch service {
	case "vnet":
		return d.createVNet(environment, capability, attrs, impl, generation)
	case "blob":
		return d.createBlob(environment, capability, attrs, impl, generation)
	case "containerapps":
		return d.createContainerApp(environment, capability, attrs, impl, generation)
	case "flexpostgres":
		return d.createFlexServer(environment, capability, attrs, impl, generation)
	case "servicebusqueue":
		return d.createServiceBusQueue(environment, capability, attrs, impl, generation)
	case "servicebustopic":
		return d.createServiceBusTopic(environment, capability, attrs, impl, generation)
	case "keyvault":
		return d.createKeyVault(environment, capability, attrs, impl, generation)
	case "rediscache":
		return d.createRedisAzure(environment, capability, attrs, impl, generation)
	case "dnszone":
		return d.createAzureDNS(environment, capability, attrs, impl, generation)
	case "dnsrecord":
		return d.createAzureDNSRecord(environment, capability, attrs, impl, generation)
	case "roleassignment":
		return d.createAzureRole(environment, capability, attrs, impl, generation)
	case "customroledef":
		return d.createAzureCustomRole(environment, capability, attrs, impl, generation)
	case "metricalert":
		return d.createAzureAlert(environment, capability, attrs, impl, generation)
	case "portaldash":
		return d.createAzureDashboard(environment, capability, attrs, impl, generation)
	case "webtest":
		return d.createAzureWebtest(environment, capability, attrs, impl, generation)
	case "scheduledquery":
		return d.createAzureScheduledQuery(environment, capability, attrs, impl, generation)
	case "acr":
		return d.createACR(environment, capability, attrs, impl, generation)
	case "azurefiles":
		return d.createAzFiles(environment, capability, attrs, impl, generation)
	case "cosmos":
		return d.createCosmos(environment, capability, attrs, impl, generation)
	case "azvm":
		return d.createAzureVM(environment, capability, attrs, impl, generation)
	case "azdisk":
		return d.createAzureDisk(environment, capability, attrs, impl, generation)
	case "azimage":
		return provider.CreateResult{Status: "failed", Reason: errWitnessOnlyAzure("azimage").Error()}
	case "azvmss":
		return d.createAzureVMSS(environment, capability, attrs, impl, generation)
	case "aisearch":
		return d.createAISearch(environment, capability, attrs, impl, generation)
	case "eventhubs":
		return d.createEventHubs(environment, capability, attrs, impl, generation)
	case "azkafka":
		return d.createAzKafka(environment, capability, attrs, impl, generation)
	case "frontdoorwaf":
		return d.createFrontDoorWAF(environment, capability, attrs, impl, generation)
	case "azurecdn":
		return d.createAzureCDN(environment, capability, attrs, impl, generation)
	case "apim":
		return d.createAPIM(environment, capability, attrs, impl, generation)
	case "containerappsjob":
		return d.createContainerAppsJob(environment, capability, attrs, impl, generation)
	case "managedidentity":
		return d.createManagedIdentity(environment, capability, attrs, impl, generation)

	case "keyvaultkey":
		return d.createAzureKey(environment, capability, attrs, impl, generation)
	case "changefeed":
		return d.createChangeFeed(environment, capability, attrs, impl, generation)
	case "loadbalancer":
		return d.createLoadBalancer(environment, capability, attrs, impl, generation)
	case "consumptionbudget":
		return d.createConsumptionBudget(environment, capability, attrs, impl, generation)
	case "loganalytics":
		return d.createLogAnalytics(environment, capability, attrs, impl, generation)
	case "activitylog":
		return d.createActivityLog(environment, capability, attrs, impl, generation)
	case "defender":
		return d.createDefender(environment, capability, attrs, impl, generation)
	case "azureopenai":
		return d.createAzureOpenAI(environment, capability, attrs, impl, generation)
	case "aks":
		return d.createAKS(environment, capability, attrs, impl, generation)
	case "aks-addon":
		return d.createAKSAddon(environment, capability, attrs, impl, generation)
	case "aks-workloadidentity":
		return d.createAKSWorkloadIdentity(environment, capability, attrs, impl, generation)
	case "backuppolicy":
		return d.createBackupPolicy(environment, capability, attrs, impl, generation)
	case "backupvault":
		return d.createBackupVault(environment, capability, attrs, impl, generation)
	case "acsemail":
		return d.createACSEmail(environment, capability, attrs, impl, generation)

	default:
		return provider.CreateResult{Status: "failed",
			Reason: fmt.Sprintf("azure service %q create is not wired yet", service)}
	}
}

// Observe reads a bound resource. D294: the SUBSCRIPTION comes from the
// providerId when the driver carries no pin. Every Azure providerId is
// "<kind>:<subscription>:<resourceGroup>:...", so the identity already says
// WHERE the resource lives — and `observe` deliberately builds the driver
// without a subscription (the ledger may span several). Until now the read
// path built its URL from d.Subscription regardless, so an unpinned driver
// failed armURL's guard and EVERY Azure observation came back "unreadable" —
// the whole family, never once working outside a test that set the field by
// hand. The scoping happens here, once, rather than in 138 armURL call sites:
// a per-call VALUE COPY (the Driver holds no locks; the HTTP client is shared
// deliberately) so nothing mutates shared state.
func (d *Driver) Observe(service, capability, providerID string) ([]provider.Observation, []string, error) {
	if err := d.requireService(service); err != nil {
		return nil, nil, err
	}
	if d.Subscription == "" {
		if sub, ok := subFromProviderID(providerID); ok {
			scoped := *d
			scoped.Subscription = sub
			return scoped.observeDispatch(service, capability, providerID)
		}
	}
	return d.observeDispatch(service, capability, providerID)
}

// subFromProviderID lifts the subscription out of an Azure providerId. Every
// one of them is "<kind>:<subscription>:<resourceGroup>:...", so the second
// component is the scope; anything that does not parse as a subscription is
// refused rather than guessed (the caller then keeps the driver's own pin and
// the per-service split reports the malformed id).
func subFromProviderID(providerID string) (string, bool) {
	parts := strings.Split(providerID, ":")
	if len(parts) < 3 || !subOK.MatchString(parts[1]) {
		return "", false
	}
	return parts[1], true
}

func (d *Driver) observeDispatch(service, capability, providerID string) ([]provider.Observation, []string, error) {
	switch service {
	case "vnet":
		return d.observeVNet(capability, providerID)
	case "blob":
		return d.observeBlob(capability, providerID)
	case "containerapps":
		return d.observeContainerApp(capability, providerID)
	case "flexpostgres":
		return d.observeFlexServer(capability, providerID)
	case "servicebusqueue", "servicebustopic":
		return d.sbObserve(capability, providerID)
	case "keyvault":
		return d.observeKeyVault(capability, providerID)
	case "rediscache":
		return d.observeRedisAzure(capability, providerID)
	case "dnszone":
		return d.observeAzureDNS(capability, providerID)
	case "dnsrecord":
		return d.observeAzureDNSRecord(capability, providerID)
	case "roleassignment":
		return d.observeAzureRole(capability, providerID)
	case "customroledef":
		return d.observeAzureCustomRole(capability, providerID)
	case "metricalert":
		return d.observeAzureAlert(capability, providerID)
	case "portaldash":
		return d.observeAzureDashboard(capability, providerID)
	case "webtest":
		return d.observeAzureWebtest(capability, providerID)
	case "scheduledquery":
		return d.observeAzureScheduledQuery(capability, providerID)
	case "acr":
		return d.observeACR(capability, providerID)
	case "azurefiles":
		return d.observeAzFiles(capability, providerID)
	case "cosmos":
		return d.observeCosmos(capability, providerID)
	case "azvm":
		return d.observeAzureVM(capability, providerID)
	case "azdisk":
		return d.observeAzureDisk(capability, providerID)
	case "azimage":
		return d.observeAzureImage(capability, providerID)
	case "azvmss":
		return d.observeAzureVMSS(capability, providerID)
	case "aisearch":
		return d.observeAISearch(capability, providerID)
	case "eventhubs":
		return d.observeEventHubs(capability, providerID)
	case "azkafka":
		return d.observeAzKafka(capability, providerID)
	case "frontdoorwaf":
		return d.observeFrontDoorWAF(capability, providerID)
	case "azurecdn":
		return d.observeAzureCDN(capability, providerID)
	case "apim":
		return d.observeAPIM(capability, providerID)
	case "containerappsjob":
		return d.observeContainerAppsJob(capability, providerID)
	case "managedidentity":
		return d.observeManagedIdentity(capability, providerID)

	case "keyvaultkey":
		return d.observeAzureKey(capability, providerID)
	case "changefeed":
		return d.observeChangeFeed(capability, providerID)
	case "loadbalancer":
		return d.observeLoadBalancer(capability, providerID)
	case "consumptionbudget":
		return d.observeConsumptionBudget(capability, providerID)
	case "loganalytics":
		return d.observeLogAnalytics(capability, providerID)
	case "activitylog":
		return d.observeActivityLog(capability, providerID)
	case "defender":
		return d.observeDefender(capability, providerID)
	case "azureopenai":
		return d.observeAzureOpenAI(capability, providerID)
	case "aks":
		return d.observeAKS(capability, providerID)
	case "aks-addon":
		return d.observeAKSAddon(capability, providerID)
	case "aks-workloadidentity":
		return d.observeAKSWorkloadIdentity(capability, providerID)
	case "backuppolicy":
		return d.observeBackupPolicy(capability, providerID)
	case "backupvault":
		return d.observeBackupVault(capability, providerID)
	case "acsemail":
		return d.observeACSEmail(capability, providerID)

	default:
		return nil, nil, fmt.Errorf("azure service %q observe is not wired yet", service)
	}
}

func (d *Driver) Delete(service, capability, environment, providerID, key string) provider.CreateResult {
	if err := d.requireService(service); err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	if !d.hasToken() {
		return provider.CreateResult{Status: "failed",
			Reason: "no Azure access token — refusing before any mutation"}
	}
	switch service {
	case "vnet":
		return d.deleteVNet(capability, environment, providerID)
	case "blob":
		return d.deleteBlob(capability, environment, providerID)
	case "containerapps":
		return d.deleteContainerApp(capability, environment, providerID)
	case "flexpostgres":
		return d.deleteFlexServer(capability, environment, providerID)
	case "servicebusqueue", "servicebustopic":
		return d.sbDelete(capability, environment, providerID)
	case "keyvault":
		return d.deleteKeyVault(capability, environment, providerID)
	case "rediscache":
		return d.deleteRedisAzure(capability, environment, providerID)
	case "dnszone":
		return d.deleteAzureDNS(capability, environment, providerID)
	case "dnsrecord":
		return d.deleteAzureDNSRecord(capability, environment, providerID)
	case "roleassignment":
		return d.deleteAzureRole(capability, environment, providerID)
	case "customroledef":
		return d.deleteAzureCustomRole(capability, environment, providerID)
	case "metricalert":
		return d.deleteAzureAlert(capability, environment, providerID)
	case "portaldash":
		return d.deleteAzureDashboard(capability, environment, providerID)
	case "webtest":
		return d.deleteAzureWebtest(capability, environment, providerID)
	case "scheduledquery":
		return d.deleteAzureScheduledQuery(capability, environment, providerID)
	case "acr":
		return d.deleteACR(capability, environment, providerID)
	case "azurefiles":
		return d.deleteAzFiles(capability, environment, providerID)
	case "cosmos":
		return d.deleteCosmos(capability, environment, providerID)
	case "azvm":
		return d.deleteAzureVM(capability, environment, providerID)
	case "azdisk":
		return d.deleteAzureDisk(capability, environment, providerID)
	case "azimage":
		// Deleting an image groundhold never created would destroy something a
		// pipeline owns, on the strength of a record we only ever read.
		return provider.CreateResult{Status: "failed", Reason: errWitnessOnlyAzure("azimage").Error()}
	case "azvmss":
		return d.deleteAzureVMSS(capability, environment, providerID)
	case "aisearch":
		return d.deleteAISearch(capability, environment, providerID)
	case "eventhubs":
		return d.deleteEventHubs(capability, environment, providerID)
	case "azkafka":
		return d.deleteAzKafka(capability, environment, providerID)
	case "frontdoorwaf":
		return d.deleteFrontDoorWAF(capability, environment, providerID)
	case "azurecdn":
		return d.deleteAzureCDN(capability, environment, providerID)
	case "apim":
		return d.deleteAPIM(capability, environment, providerID)
	case "containerappsjob":
		return d.deleteContainerAppsJob(capability, environment, providerID)
	case "managedidentity":
		return d.deleteManagedIdentity(capability, environment, providerID)

	case "keyvaultkey":
		return d.deleteAzureKey(capability, environment, providerID)
	case "changefeed":
		return d.deleteChangeFeed(capability, environment, providerID)
	case "loadbalancer":
		return d.deleteLoadBalancer(capability, environment, providerID)
	case "consumptionbudget":
		return d.deleteConsumptionBudget(capability, environment, providerID)
	case "loganalytics":
		return d.deleteLogAnalytics(capability, environment, providerID)
	case "activitylog":
		return d.deleteActivityLog(capability, environment, providerID)
	case "defender":
		return d.deleteDefender(capability, environment, providerID)
	case "azureopenai":
		return d.deleteAzureOpenAI(capability, environment, providerID)
	case "aks":
		return d.deleteAKS(capability, environment, providerID)
	case "aks-addon":
		return d.deleteAKSAddon(capability, environment, providerID)
	case "aks-workloadidentity":
		return d.deleteAKSWorkloadIdentity(capability, environment, providerID)
	case "backuppolicy":
		return d.deleteBackupPolicy(capability, environment, providerID)
	case "backupvault":
		return d.deleteBackupVault(capability, environment, providerID)
	case "acsemail":
		return d.deleteACSEmail(capability, environment, providerID)

	default:
		return provider.CreateResult{Status: "failed",
			Reason: fmt.Sprintf("azure service %q delete is not wired yet", service)}
	}
}

// ClassifyChange / Update: in-place update is not wired for any Azure service in
// v0 — an honest "unsupported"/"not wired", never a silent claim.
func (d *Driver) ClassifyChange(service, path string, current, desired any,
	impl map[string]any) (string, string) {
	switch service {
	case "azvm":
		return classifyAzureVMChange(path)
	case "azdisk":
		return classifyAzureDiskChange(path)
	case "azimage":
		return classifyAzureImageChange(path)
	case "azvmss":
		return classifyVMSSChange(path)
	case "acr":
		return classifyACRChange(path)
	case "blob":
		return classifyBlobChange(path)
	case "flexpostgres":
		return classifyFlexServerChange(path)
	case "rediscache":
		return classifyRedisAzureChange(path)
	case "aisearch":
		return classifyAISearchChange(path)
	case "eventhubs":
		return classifyEventHubsChange(path)
	case "cosmos":
		return classifyCosmosChange(path)
	case "servicebusqueue":
		return classifyServiceBusQueueChange(path)
	case "loadbalancer":
		return classifyLoadBalancerChange(path)
	case "consumptionbudget":
		return classifyConsumptionBudgetChange(path)
	case "loganalytics":
		return classifyLogAnalyticsChange(path)
	case "activitylog":
		return classifyActivityLogChange(path)
	case "defender":
		return classifyDefenderChange(path)
	case "azureopenai":
		return classifyAzureOpenAIChange(path)
	case "aks":
		return classifyAKSChange(path)
	case "aks-addon":
		return classifyAKSAddonChange(path)
	case "aks-workloadidentity":
		return classifyAKSWorkloadIdentityChange(path)
	case "backuppolicy":
		return classifyBackupPolicyChange(path)
	case "acsemail":
		return classifyACSEmailChange(path)
	case "dnsrecord":
		return classifyAzureDNSRecordChange(path)
	default:
		// D215: no explicit ClassifyChange => no in-place update path, so a drift is
		// honestly a REPLACEMENT (consent-gated when stateful), never a freeze.
		return "immutable", fmt.Sprintf(
			"azure service %q has no in-place update path — reconciling a drift is a replacement", service)
	}
}

func (d *Driver) Update(service, capability, environment, providerID string,
	attrs, impl map[string]any, changes []string, key string) provider.CreateResult {
	defer d.forgetSecrets()
	d.rememberSecrets(impl)
	cr := d.update(service, capability, environment, providerID, attrs, impl, changes, key)
	cr.Reason = d.scrub(cr.Reason)
	return cr
}

func (d *Driver) update(service, capability, environment, providerID string,
	attrs, impl map[string]any, changes []string, key string) provider.CreateResult {
	if err := d.requireService(service); err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	if !d.hasToken() {
		return provider.CreateResult{Status: "failed",
			Reason: "no Azure access token — refusing before any mutation"}
	}
	switch service {
	case "consumptionbudget":
		return d.updateConsumptionBudget(capability, environment, providerID, attrs, impl, changes)
	case "loganalytics":
		return d.updateLogAnalytics(capability, environment, providerID, attrs, impl, changes)
	case "activitylog":
		return d.updateActivityLog(capability, environment, providerID, attrs, impl, changes)
	case "defender":
		return d.updateDefender(capability, environment, providerID, attrs, impl, changes)
	case "servicebusqueue":
		return d.updateServiceBus(capability, environment, providerID, attrs, impl, changes)
	case "blob":
		return d.updateBlob(capability, environment, providerID, attrs, changes)
	case "flexpostgres":
		return d.updateFlexServer(capability, environment, providerID, attrs, changes)
	case "rediscache":
		return d.updateRedisAzure(capability, environment, providerID, attrs, changes)
	case "aisearch":
		return d.updateAISearch(capability, environment, providerID, attrs, changes)
	case "eventhubs":
		return d.updateEventHubs(capability, environment, providerID, attrs, changes)
	case "cosmos":
		return d.updateCosmos(capability, environment, providerID, attrs, changes)
	case "aks":
		return d.updateAKS(capability, environment, providerID, attrs, impl, changes)
	case "aks-addon":
		return d.updateAKSAddon(capability, environment, providerID, attrs, impl, changes)
	case "backuppolicy":
		return d.updateBackupPolicy(capability, environment, providerID, attrs, impl, changes)
	case "acsemail":
		return d.updateACSEmail(capability, environment, providerID, attrs, impl, changes)
	case "dnsrecord":
		return d.updateAzureDNSRecord(capability, environment, providerID, attrs, impl, changes)
	default:
		return provider.CreateResult{Status: "failed",
			Reason: fmt.Sprintf("azure service %q in-place update is not wired yet", service)}
	}
}
