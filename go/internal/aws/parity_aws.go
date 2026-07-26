// Cross-cloud parity map (D76): for every SERVICE token this driver certifies,
// the single capability TYPE it fulfils. This is the AWS column of the
// machine-verifiable parity matrix. Every value is the exact capability.<...>
// string the service's Observe/discover stamps as ResourceType — ground truth,
// not a guess. The three non-listable tokens (changefeed, rolepolicy,
// cwlogfilter) have no top-level discover ResourceType; their TYPE is taken
// from the driver's Build dispatch + header docstring and noted inline.
package aws

// ServiceCapabilities reports, for every SERVICE token this driver certifies,
// the capability TYPE it fulfils (D76: one TYPE, many services). The key set MUST
// equal awsCertifyServices exactly. The value is the capability.<...> string the
// service's Observe/discover stamps as ResourceType — verified against that
// ground truth, never guessed.
func (d *Driver) ServiceCapabilities() map[string]string {
	return map[string]string{
		// --- verified against a literal discover ResourceType ---
		"s3":                     "capability.storage.object",           // discoverS3
		"rds":                    "capability.database.relational",      // discoverRDS (many-to-one with aurora)
		"aurora":                 "capability.database.relational",      // discoverAurora (aurora_net.go)
		"dynamodb":               "capability.database.nosql",           // discoverDynamoDB
		"elasticache":            "capability.cache.keyvalue",           // discoverElastiCache (provisioned replication group)
		"elasticache-serverless": "capability.cache.keyvalue",           // discoverElastiCacheServerless (second backend, pay-per-use)
		"sns":                    "capability.messaging.topic",          // discoverSNS
		"sqs":                    "capability.messaging.queue",          // discoverSQS
		"ecs":                    "capability.workload.container",       // discoverECS
		"apprunner":              "capability.workload.container",       // discoverAppRunner (second AWS backend, Cloud Run twin)
		"vpc":                    "capability.network.private",          // discoverVPC
		"loadbalancer":           "capability.network.loadbalancer",     // discoverLoadBalancers
		"iam":                    "capability.identity.serviceaccount",  // discoverIAM
		"secretsmanager":         "capability.secret",                   // discoverSecrets
		"cloudwatch":             "capability.monitoring.alert",         // discoverCloudWatch
		"ecr":                    "capability.registry.image",           // discoverECR
		"eks":                    "capability.cluster.kubernetes",       // discoverEKS (eks_net.go)
		"eks-addon":              "capability.cluster.addon",            // discoverEKSAddon (eks_addon.go)
		"eks-podidentity":        "capability.identity.podidentity",     // discoverEKSPodIdentity (eks_podidentity.go)
		"ses-sending":            "capability.email.sending",            // discoverSESSending (ses_sending_net.go)
		"ses-inbound":            "capability.email.inbound",            // discoverSESInbound (ses_inbound_net.go)
		"bedrock":                "capability.ai.inference",             // discoverBedrock (bedrock_net.go)
		"budgets":                "capability.cost.budget",              // discoverBudgets (budgets_net.go)
		"cloudtrail":             "capability.audit.trail",              // discoverCloudTrail (cloudtrail_net.go)
		"backupplan":             "capability.backup.plan",              // discoverBackupPlans (backupplan_net.go)
		"backupvault":            "capability.backup.vault",             // discoverBackupVaults
		"guardduty":              "capability.security.threatdetection", // discoverGuardDuty (guardduty_net.go)
		"cwlogs":                 "capability.monitoring.logs",          // discoverCWLogs (cwlogs_net.go)
		"acm":                    "capability.certificate.tls",          // discoverACM
		"apigateway":             "capability.apigateway.http",          // discoverAPIGateway
		"cloudfront":             "capability.cdn.distribution",         // discoverCloudFront
		"cloudwatchdash":         "capability.monitoring.dashboard",     // discoverCloudWatchDashboards
		"custompolicy":           "capability.authorization.role",       // discoverCustomPolicies
		"ami":                    "capability.compute.image",            // discoverAMIs (witness, D370)
		"ebs":                    "capability.storage.block",            // discoverEBSVolumes
		"ec2":                    "capability.compute.instance",         // discoverEC2Instances
		"efs":                    "capability.storage.filesystem",       // discoverEFS
		"eventbridgescheduler":   "capability.scheduler.cron",           // discoverEventBridgeSchedulers
		"kinesis":                "capability.streaming.pipe",           // discoverKinesis
		"kms":                    "capability.key.encryption",           // discoverKMS
		"msk":                    "capability.messaging.kafka",          // discoverMSK
		"opensearch":             "capability.search.index",             // discoverOpenSearch
		"opensearch-serverless":  "capability.search.index",             // discoverOpenSearchServerless (second backend, pay-per-use)
		"redshiftserverless":     "capability.warehouse.analytics",      // discoverRedshiftServerless
		"route53":                "capability.dns.zone",                 // discoverRoute53
		"route53record":          "capability.dns.record",               // sub-resource of a hosted zone (NonListable)
		"route53health":          "capability.monitoring.uptime",        // discoverRoute53Health
		"vpngateway":             "capability.vpn.gateway",              // discoverVpnGateway
		"waf":                    "capability.security.waf",             // discoverWAF
		"rolepolicy":             "capability.authorization.grant",      // discoverRoleGrants literal (sub-resource, enumerated under its role)
		"lambda":                 "capability.function.serverless",      // discoverLambda (lambda_net.go)

		// --- non-listable tokens: TYPE from Build dispatch + driver header docstring ---
		// changefeed has no discover ResourceType (NonListableServices: "provisioned-feed");
		// changefeed.go header + BuildChangeFeed fulfil capability.observability.changefeed.
		"changefeed": "capability.observability.changefeed",
		// cwlogfilter has no discover ResourceType (NonListableServices: "sub-resource");
		// awslogfilter.go header + BuildCWLogFilter fulfil capability.monitoring.logmetric.
		"cwlogfilter": "capability.monitoring.logmetric",
	}
}
