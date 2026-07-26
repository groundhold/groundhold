// Cross-cloud parity map (D76): for every SERVICE token this driver certifies,
// the single capability TYPE it fulfils. This is the GCP column of the
// machine-verifiable parity matrix. Every value is the exact capability.<...>
// string the service's Observe/discover stamps as ResourceType — ground truth,
// not a guess. The one non-listable token (assetfeed) has no top-level discover
// ResourceType; its TYPE is taken from the driver's Build dispatch + header
// docstring and noted inline.
package gcp

// ServiceCapabilities reports, for every SERVICE token this driver certifies,
// the capability TYPE it fulfils (D76: one TYPE, many services). The key set MUST
// equal gcpCertifyServices exactly. The value is the capability.<...> string the
// service's Observe/discover stamps as ResourceType — verified against that
// ground truth, never guessed.
func (d *Driver) ServiceCapabilities() map[string]string {
	return map[string]string{
		// --- verified against a literal discover ResourceType ---
		"loadbalancer":         "capability.network.loadbalancer",     // discoverLoadBalancers (loadbalancer_net.go:310)
		"cloudsql":             "capability.database.relational",      // discoverCloudSQL (driver.go:802)
		"cloudrun":             "capability.workload.container",       // discoverCloudRun (discover_gcp.go:399)
		"gcs":                  "capability.storage.object",           // discoverGCS (discover_gcp.go:128)
		"vpc":                  "capability.network.private",          // discoverVPC (discover_gcp.go:457)
		"cloudfunctions":       "capability.workload.container",       // discoverCloudFunctions (discover_gap_gcp_a.go:218) — many-to-one with cloudrun
		"cloudfunctions-fn":    "capability.function.serverless",      // discoverCloudFunctionFn (cloudfunctionsfn_net.go) — 2nd token on Cloud Functions (Pub/Sub precedent)
		"pubsub-topic":         "capability.messaging.topic",          // discoverPubSubTopics (discover_gcp.go:180)
		"pubsub-queue":         "capability.messaging.queue",          // discoverPubSubQueues (discover_gcp.go:224)
		"secretmanager":        "capability.secret",                   // discoverSecrets (discover_gcp.go:637)
		"memorystore":          "capability.cache.keyvalue",           // discoverMemorystore (discover_gcp.go:271)
		"clouddns":             "capability.dns.zone",                 // discoverCloudDNS (discover_gap_gcp_a.go:154)
		"clouddnsrecord":       "capability.dns.record",               // sub-resource of a managed zone (NonListable); BuildCloudDNSRecord + clouddnsrecord.go header fulfil capability.dns.record
		"iambinding":           "capability.authorization.grant",      // discoverIAMBindings (discover_gcp.go:588)
		"customrole":           "capability.authorization.role",       // discoverCustomRoles (discover_gcp.go:556)
		"monitoring":           "capability.monitoring.alert",         // discoverAlertPolicies (discover_gcp.go:682)
		"dashboard":            "capability.monitoring.dashboard",     // discoverDashboards (discover_gap_gcp_b.go:224)
		"uptime":               "capability.monitoring.uptime",        // discoverUptimeChecks (discover_gcp.go:727)
		"logmetric":            "capability.monitoring.logmetric",     // discoverLogMetrics (discover_gap_gcp_b.go:270)
		"gce":                  "capability.compute.instance",         // discoverGCEInstances
		"artifactregistry":     "capability.registry.image",           // discoverArtifactRegistries (discover_gcp.go:817)
		"filestore":            "capability.storage.filesystem",       // discoverFilestore (discover_gap_gcp_b.go:131)
		"firestore":            "capability.database.nosql",           // discoverFirestore (discover_gcp.go:335)
		"managedkafka":         "capability.messaging.kafka",          // discoverManagedKafka (discover_gap_gcp_b.go:179)
		"cloudarmor":           "capability.security.waf",             // discoverCloudArmor (discover_gap_gcp_a.go:110)
		"certmanager":          "capability.certificate.tls",          // discoverCertManager (discover_gap_gcp_a.go:288)
		"cloudrunjobs":         "capability.container.job",            // discoverCloudRunJobs (discover_gap_gcp_b.go:83)
		"serviceaccount":       "capability.identity.serviceaccount",  // discoverServiceAccounts (discover_gcp.go:510)
		"bigquery":             "capability.warehouse.analytics",      // discoverBigQuery (discover_gap_gcp_a.go:66)
		"cloudscheduler":       "capability.scheduler.cron",           // discoverCloudScheduler (discover_gap_gcp_b.go:361)
		"cloudkms":             "capability.key.encryption",           // discoverCloudKMS (discover_gap_gcp_a.go:421)
		"vpngateway":           "capability.vpn.gateway",              // discoverVPNGateways (discover_gap_gcp_b.go:419)
		"backupvault":          "capability.backup.vault",             // discoverBackupVault (discover_gap_gcp_a.go:358)
		"billingbudget":        "capability.cost.budget",              // discoverBillingBudget (billingbudget_net.go:404)
		"logbucket":            "capability.monitoring.logs",          // discoverLogBuckets (logbucket_net.go:349)
		"auditlogs":            "capability.audit.trail",              // discoverAuditLogs (auditlogs_net.go:322)
		"scc":                  "capability.security.threatdetection", // discoverSCC (scc_net.go:333)
		"vertexai":             "capability.ai.inference",             // discoverVertexAI (vertexai_net.go:384)
		"gke":                  "capability.cluster.kubernetes",       // discoverGKE (gke_net.go:545)
		"gke-addon":            "capability.cluster.addon",            // discoverGKEAddon (gke_addon_net.go:344)
		"gke-workloadidentity": "capability.identity.podidentity",     // discoverGKEWorkloadIdentity (gke_workloadidentity_net.go:229)
		"backupplan":           "capability.backup.plan",              // discoverBackupPlansGCP (gcpbackupplan_net.go:353)

		// --- non-listable token: TYPE from Build dispatch + driver header docstring ---
		// assetfeed has no discover ResourceType (NonListableServices: "provisioned-feed");
		// assetfeed.go header + BuildAssetFeed (driver.go:253) fulfil capability.observability.changefeed.
		"assetfeed": "capability.observability.changefeed",
	}
}
