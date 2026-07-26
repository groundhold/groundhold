// AWS receipt reconciliation (D57, F19): the OPTIONAL Reconciler capability that
// lets `resume` conclude a PENDING receipt read-only — determine what actually
// happened by reading live state. Without it, a pending create left by a lost or
// false-"unknown" response (F18's bedrock case) permanently blocked every apply
// ("in-flight must be reconciled first", D29) because `resume` could not conclude
// it. STRICTLY READ-ONLY — a reconciler that mutates is a bug.
package aws

import (
	"fmt"
	"strings"

	"groundhold/internal/provider"
)

// serviceFromTarget extracts the service token from a plan action target
// (<provider>.<service>/<id>) — the same shape the GCP driver reads.
func serviceFromTarget(target string) string {
	dot := strings.IndexByte(target, '.')
	slash := strings.IndexByte(target, '/')
	if dot < 0 || slash < 0 || slash < dot {
		return ""
	}
	return target[dot+1 : slash]
}

// Reconcile concludes a pending receipt by reading live state. Dispatch is on the
// receipt's target service (D76) and FAILS CLOSED to unknown for a service not yet
// wired — never a fabricated conclusion against the wrong resource.
//
// Most AWS resources have a DETERMINISTIC name (a pure function of environment +
// capability + generation), so reconcile RECOMPUTES the name from the receipt and
// reads live state directly — this works even for a receipt written before we
// persisted any id (the pending-create case that leaves no providerID). bedrock is
// the exception: its id is server-assigned, so it stays a tag-scan.
func (d *Driver) Reconcile(capability, environment string,
	receipt map[string]any) provider.ReconcileResult {
	tgt, _ := receipt["target"].(string)
	gen := receiptGeneration(receipt)
	switch serviceFromTarget(tgt) {
	case "bedrock":
		return d.reconcileBedrock(capability, environment)
	case "eks":
		return d.reconcileEKS(capability, environment, gen)
	case "elasticache":
		return d.reconcileElastiCache(capability, environment, gen)
	// ---- batch 1 (deterministic-name, tag/name owned) ----
	case "sns":
		return d.reconcileSNS(capability, environment, rc1Generation(receipt))
	case "sqs":
		return d.reconcileSQS(capability, environment, rc1Generation(receipt))
	case "ecr":
		return d.reconcileECR(capability, environment, rc1Generation(receipt))
	case "dynamodb":
		return d.reconcileDynamoDB(capability, environment, rc1Generation(receipt))
	case "kinesis":
		return d.reconcileKinesis(capability, environment, rc1Generation(receipt))
	// ---- batch 2 (regional log/trail/secret/vault) ----
	case "secretsmanager":
		return d.reconcileSecretsManager(capability, environment, gen)
	case "cwlogs":
		return d.reconcileCWLogs(capability, environment, gen)
	case "cwlogfilter":
		return d.reconcileCWLogFilter(capability, environment, gen)
	case "cloudtrail":
		return d.reconcileCloudTrail(capability, environment, gen)
	case "backupvault":
		return d.reconcileBackupVault(capability, environment, gen)
	// ---- batch 3 (IAM/global) ----
	case "iam":
		return d.reconcileIAM(capability, environment, gen)
	case "custompolicy":
		return d.reconcileCustomPolicy(capability, environment, gen)
	case "waf":
		return d.reconcileWAF(capability, environment, gen)
	case "budgets":
		return d.reconcileBudget(capability, environment, gen)
	case "rolepolicy":
		// the attachment identity is attribute-derived; the only handle is the
		// pinned targetProviderId (absent on a bare create receipt -> unknown).
		pid, _ := receipt["targetProviderId"].(string)
		return d.reconcileRolePolicy(capability, environment, pid)
	// ---- batch 4 (async db/search) ----
	case "rds":
		return d.reconcileRDS(capability, environment, gen)
	case "aurora":
		return d.reconcileAurora(capability, environment, gen)
	case "opensearch":
		return d.reconcileOpenSearch(capability, environment, gen)
	case "msk":
		return d.reconcileMSK(capability, environment, gen)
	case "redshiftserverless":
		return d.reconcileRedshiftServerless(capability, environment, gen)
	// ---- batch 5 (compute/net/monitoring) ----
	case "lambda":
		return d.reconcileLambda(capability, environment, gen)
	case "ecs":
		return d.reconcileECS(capability, environment, gen)
	case "loadbalancer":
		return d.reconcileLoadBalancer(capability, environment, gen)
	case "eks-addon":
		return d.reconcileEKSAddon(capability, environment, gen)
	case "cloudwatch":
		return d.reconcileCloudWatchAlarm(capability, environment, gen)
	case "cloudwatchdash":
		return d.reconcileCWDashboard(capability, environment, gen)
	// ---- batch 6 (s3 + operand-identity services) ----
	case "s3":
		return d.reconcileS3(capability, environment, gen)
	case "eventbridgescheduler":
		return d.reconcileEventBridgeScheduler(capability, environment, gen)
	case "changefeed":
		// the rule region is derived from the feed.target ARN (not recomputable) —
		// conclude by the providerId the create persisted on its unknown response.
		pid, _ := receipt["targetProviderId"].(string)
		return d.reconcileChangeFeed(capability, environment, pid)
	case "ses-sending":
		// the sending domain is an operand — conclude by the recorded providerId.
		pid, _ := receipt["targetProviderId"].(string)
		return d.reconcileSESSending(capability, environment, pid)
	case "ses-inbound":
		// the rule name derives from the recipient operand — conclude by the recorded pid.
		pid, _ := receipt["targetProviderId"].(string)
		return d.reconcileSESInbound(capability, environment, pid)
	// ---- batch 7 (server-assigned id WITH a list wrapper: tier-1 pid fast path, tag-scan fallback) ----
	case "route53":
		pid, _ := receipt["targetProviderId"].(string)
		return d.reconcileRoute53(capability, environment, gen, pid)
	case "acm":
		pid, _ := receipt["targetProviderId"].(string)
		return d.reconcileACM(capability, environment, gen, pid)
	case "efs":
		pid, _ := receipt["targetProviderId"].(string)
		return d.reconcileEFS(capability, environment, gen, pid)
	case "eks-podidentity":
		pid, _ := receipt["targetProviderId"].(string)
		return d.reconcileEKSPodIdentity(capability, environment, gen, pid)
	case "backupplan":
		pid, _ := receipt["targetProviderId"].(string)
		return d.reconcileBackupPlan(capability, environment, gen, pid)
	case "guardduty":
		pid, _ := receipt["targetProviderId"].(string)
		return d.reconcileGuardDuty(capability, environment, gen, pid)
	// ---- batch 8 (server-assigned id, NO list wrapper: tier-1 pid only) ----
	case "vpc":
		pid, _ := receipt["targetProviderId"].(string)
		return d.reconcileVPC(capability, environment, pid)
	case "kms":
		pid, _ := receipt["targetProviderId"].(string)
		return d.reconcileKMS(capability, environment, pid)
	case "cloudfront":
		pid, _ := receipt["targetProviderId"].(string)
		return d.reconcileCloudFront(capability, environment, pid)
	case "apigateway":
		pid, _ := receipt["targetProviderId"].(string)
		return d.reconcileApiGW(capability, environment, pid)
	case "route53health":
		pid, _ := receipt["targetProviderId"].(string)
		return d.reconcileRoute53Health(capability, environment, pid)
	case "vpngateway":
		pid, _ := receipt["targetProviderId"].(string)
		return d.reconcileVpnGateway(capability, environment, pid)
	default:
		return provider.ReconcileResult{Status: "unknown",
			Reason: fmt.Sprintf("aws reconcile for service %q is not wired yet — reconcile manually",
				serviceFromTarget(tgt))}
	}
}

// receiptGeneration reads the receipt's generation tolerantly. Ledger events round-
// trip through JSON; the replay normalizer turns whole floats back into int, but a
// float64 can still reach us on an unnormalized path — treat a missing generation as
// 1 (the first generation), never a panic.
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

// concludeByStatus maps a live read of a deterministically-named resource to a
// reconcile verdict, uniform across every async AWS service. ready → succeeded WITH
// the recomputed pid; a terminal-failed state or a readable ABSENCE → failed (the
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

// regionlessReconcile is the honest refusal shared by every region-scoped reconcile
// when the driver has no region (the CLI was invoked without --region /
// GROUNDHOLD_REGION). A region-scoped read with an empty region builds a malformed
// endpoint; refuse by NAMING the missing region rather than reporting "unreadable".
func regionlessReconcile(service string) provider.ReconcileResult {
	return provider.ReconcileResult{Status: "unknown",
		Reason: service + " reconcile needs a region — re-run with --region <region> " +
			"or set GROUNDHOLD_REGION (a pending create is region-scoped)"}
}

// reconcileEKS concludes a pending EKS create. The cluster name is deterministic, so
// we recompute it and read live state. The create's contract is cluster ACTIVE AND
// the managed node group ACTIVE, so reconcile mirrors it: an ACTIVE, owned cluster
// whose node group is also ACTIVE → succeeded; a half-provisioned cluster (node group
// failed/creating/absent) stays unknown (the cluster exists — a re-plan must not
// double-create it; repair or resume-again is the path), exactly as the create's own
// poll reports it.
func (d *Driver) reconcileEKS(capability, environment string, generation int) provider.ReconcileResult {
	region := d.Region
	if region == "" {
		return regionlessReconcile("eks")
	}
	name := eksCompositeName(environment, capability, generation)
	pid := eksProviderID(region, name)
	c, found, rerr := d.describeEKSCluster(region, name)
	ours := found && groundholdTagsMatch(c.Tags, capability, environment)
	clusterFailed := found && (c.Status == "FAILED" || c.Status == "DELETING")
	if rerr != nil || !found || !ours || clusterFailed || c.Status != "ACTIVE" {
		return concludeByStatus(pid, "eks cluster "+name, found, rerr, ours,
			found && c.Status == "ACTIVE", clusterFailed)
	}
	// cluster is ACTIVE and ours; the managed node group must be ACTIVE too.
	ng, ngFound, ngReadable := d.describeNodegroup(region, name, name+"-ng")
	if ngReadable == nil && ngFound && (ng.Status == "CREATE_FAILED" || ng.Status == "DEGRADED") {
		return provider.ReconcileResult{Status: "unknown",
			Reason: "eks cluster " + name + " is ACTIVE but its node group is " + ng.Status +
				" — a half-provisioned cluster; repair it (a re-plan must not double-create the cluster)"}
	}
	return concludeByStatus(pid, "eks node group "+name+"-ng", ngFound, ngReadable, true,
		ng.Status == "ACTIVE", false)
}

// reconcileElastiCache concludes a pending Redis replication-group create. The id is a
// deterministic function of account + environment + capability + generation, so it is
// its own ownership handle (a per-account namespace) — reconcile recomputes it and
// reads DescribeReplicationGroups. available → succeeded; create-failed → failed;
// still creating or unreadable → unknown.
func (d *Driver) reconcileElastiCache(capability, environment string, generation int) provider.ReconcileResult {
	region := d.Region
	if region == "" {
		return regionlessReconcile("elasticache")
	}
	account, err := d.resolveAccount()
	if err != nil {
		return provider.ReconcileResult{Status: "unknown",
			Reason: "elasticache reconcile could not resolve the AWS account: " + err.Error()}
	}
	id := ecacheID(account, environment, capability, generation)
	pid := ecacheProviderID(region, account, id)
	rg, found, rerr := d.describeRG(region, id)
	// Ownership: the replication group IS taggable and the whole family gates on the
	// groundhold tags — create REFUSES (failed) a name collision whose tags don't match,
	// delete refuses to touch a foreign group. Reconcile MUST match, or it would bind
	// someone else's live database (a hand-made group, another install at the same
	// deterministic id) to this create. Read the tags only when the group is present;
	// an unreadable tag read is unknown (it could be ours), never a claimed success.
	ours := false
	if rerr == nil && found {
		tags, terr := d.ecacheTags(region, account, id)
		if terr != nil {
			return provider.ReconcileResult{Status: "unknown",
				Reason: "elasticache replication group " + id + " tag read gave no answer — cannot conclude the pending create: " + terr.Error()}
		}
		ours = groundholdTagsMatch(tags, capability, environment)
	}
	return concludeByStatus(pid, "elasticache replication group "+id, found, rerr, ours,
		rg.Status == "available", rg.Status == "create-failed")
}

// reconcileBedrock concludes a pending inference-profile create by OWNERSHIP TAGS.
// The application profile carries groundhold-capability/environment tags, so a live
// list + tag match tells us the create landed (succeeded WITH the id), never landed
// (a readable, COMPLETE list with no match => failed, so the pending intent clears
// and a re-plan recreates), or is unreadable (unknown — never a fabricated verdict).
// This is exactly the "identity survives a lost response" contract of D57: the id is
// server-assigned, but the ownership tag is a deterministic handle we set at create.
func (d *Driver) reconcileBedrock(capability, environment string) provider.ReconcileResult {
	region := d.Region
	// A region-scoped read with no region builds a malformed endpoint and fails
	// as an opaque "unreadable" — refuse HONESTLY instead. The AWS driver takes
	// the operator's region at construction (symmetric with GCP's project); a
	// reconcile has no providerID/attrs to fall back on, so an empty region here
	// means the CLI was invoked without --region / GROUNDHOLD_REGION.
	if region == "" {
		return provider.ReconcileResult{Status: "unknown",
			Reason: "AWS reconcile needs a region — re-run with --region <region> " +
				"or set GROUNDHOLD_REGION (a pending create is region-scoped)"}
	}
	ids, lerr := d.listInferenceProfiles(region, "APPLICATION")
	if lerr != nil {
		return provider.ReconcileResult{Status: "unknown",
			Reason: "cannot conclude the pending create: " + lerr.Error()}
	}
	for _, id := range ids {
		p, found, rerr := d.getInferenceProfile(region, id)
		if rerr != nil {
			// an unreadable profile could be ours — refuse to conclude either way.
			return provider.ReconcileResult{Status: "unknown",
				Reason: "a bedrock profile read was gave no answer — cannot conclude the pending create: " + rerr.Error()}
		}
		if found && groundholdTagsMatch(p.tagMap(), capability, environment) {
			return provider.ReconcileResult{Status: "succeeded", ProviderID: bedrockProviderID(region, id)}
		}
	}
	return provider.ReconcileResult{Status: "failed",
		Reason: "no bedrock inference profile carries our ownership tags — the create did not land"}
}
