// Cross-cloud parity map (D76): for every SERVICE token this driver certifies,
// the single capability TYPE it fulfils. This is the Azure column of the
// machine-verifiable parity matrix. Every value is the exact capability.<...>
// string the service's Observe/discover stamps as ResourceType — ground truth,
// read token-by-token out of the discover sweeps, not a guess. Azure sets
// ResourceType non-uniformly: some sweeps carry a literal, others thread it
// through the shared discoverRegional/discoverGapBGlobal helper as the
// `resourceType` argument — each such argument was traced to its literal at the
// call site. The two non-listable tokens (changefeed, keyvaultkey) have no
// top-level discover ResourceType; their TYPE is taken from the driver's Build
// dispatch table (azure_provider.go) and noted inline.
package azure

// ServiceCapabilities reports, for every SERVICE token this driver certifies,
// the capability TYPE it fulfils (D76). Key set MUST equal azureCertifyServices.
// Value = the capability.<...> the service's Observe/discover stamps as
// ResourceType — verified against that ground truth, never guessed.
func (d *Driver) ServiceCapabilities() map[string]string {
	return map[string]string{
		// --- literal discover ResourceType (discover_azure.go) ---
		"blob":            "capability.storage.object",      // discoverBlob (literal)
		"flexpostgres":    "capability.database.relational", // discoverPostgres (literal)
		"rediscache":      "capability.cache.keyvalue",      // discoverRedis (literal)
		"servicebusqueue": "capability.messaging.queue",     // discoverServiceBus -> sbEntities("queues", literal)
		"servicebustopic": "capability.messaging.topic",     // discoverServiceBus -> sbEntities("topics", literal)
		"cosmos":          "capability.database.nosql",      // discoverCosmos (literal)

		// --- resourceType arg into discoverRegional (discover_azure_expand.go) ---
		"containerapps":    "capability.workload.container",      // discoverContainerApps
		"containerappsjob": "capability.container.job",           // discoverContainerAppsJobs
		"vnet":             "capability.network.private",         // discoverVNet
		"keyvault":         "capability.secret",                  // discoverKeyVault
		"managedidentity":  "capability.identity.serviceaccount", // discoverManagedIdentity
		// customroledef / roleassignment: subscription-GLOBAL literals in discover_azure_expand.go
		"customroledef":  "capability.authorization.role",  // discoverCustomRoles (literal)
		"roleassignment": "capability.authorization.grant", // discoverRoleAssignments (literal)

		// --- gap batch A (discover_gap_azure_a.go) ---
		"acr":        "capability.registry.image",     // discoverACR (discoverRegional arg)
		"azdisk":     "capability.storage.block",      // discoverAzureDisks
		"azimage":    "capability.compute.image",      // discoverAzureImages (witness, D370)
		"azvm":       "capability.compute.instance",   // discoverAzureVMs
		"aisearch":   "capability.search.index",       // discoverAISearch (discoverRegional arg)
		"apim":       "capability.apigateway.http",    // discoverAPIM (discoverRegional arg)
		"azkafka":    "capability.messaging.kafka",    // discoverAzKafka (discoverRegional arg)
		"azurefiles": "capability.storage.filesystem", // discoverAzureFiles -> azFilesShareLeaves (literal)
		"azurecdn":   "capability.cdn.distribution",   // discoverAzureCDN -> azcdnEndpointLeaves (literal)
		"dnszone":    "capability.dns.zone",           // discoverDNSZone -> dnszoneZonesOfKind (literal, both pub+priv)

		// --- gap batch B (discover_gap_azure_b.go) ---
		"metricalert":    "capability.monitoring.alert",     // discoverMetricAlert (discoverGapBGlobal arg)
		"frontdoorwaf":   "capability.security.waf",         // discoverFrontDoorWAF (discoverGapBGlobal arg)
		"portaldash":     "capability.monitoring.dashboard", // discoverPortalDash (discoverRegional arg)
		"webtest":        "capability.monitoring.uptime",    // discoverWebTest (discoverRegional arg)
		"scheduledquery": "capability.monitoring.logmetric", // discoverScheduledQuery (discoverRegional arg)
		"eventhubs":      "capability.streaming.pipe",       // discoverEventHubs -> ehDiscoverHubs (literal)

		// --- per-driver *_net.go discover literals ---
		"loadbalancer":         "capability.network.loadbalancer",     // discoverLoadBalancers (discoverRegional arg, L4+L7)
		"consumptionbudget":    "capability.cost.budget",              // discoverConsumptionBudget (literal)
		"loganalytics":         "capability.monitoring.logs",          // discoverLogAnalytics (literal)
		"activitylog":          "capability.audit.trail",              // discoverActivityLog (literal)
		"defender":             "capability.security.threatdetection", // discoverDefender (literal)
		"azureopenai":          "capability.ai.inference",             // discoverAzureOpenAI (literal)
		"aks":                  "capability.cluster.kubernetes",       // discoverAKS (literal)
		"aks-addon":            "capability.cluster.addon",            // discoverAKSAddon (literal)
		"aks-workloadidentity": "capability.identity.podidentity",     // discoverAKSWorkloadIdentity (literal)
		"backuppolicy":         "capability.backup.plan",              // discoverBackupPolicy (literal)
		"backupvault":          "capability.backup.vault",             // discoverBackupVault (literal)
		"acsemail":             "capability.email.sending",            // discoverACSEmail (literal)

		// --- non-listable (NonListableServices); TYPE from Build dispatch, azure_provider.go ---
		"changefeed":  "capability.observability.changefeed", // provisioned-feed; BuildChangeFeed / observeChangeFeed
		"keyvaultkey": "capability.key.encryption",           // sub-resource; BuildAzureKey / observeAzureKey
		"dnsrecord":   "capability.dns.record",               // sub-resource; BuildAzureDNSRecord / observeAzureDNSRecord
	}
}
