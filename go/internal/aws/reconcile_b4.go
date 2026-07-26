// AWS receipt reconciliation, BATCH 4 (F19, D57): the async DB/search family —
// rds, aurora, opensearch, msk, redshiftserverless. These services provision
// ASYNCHRONOUSLY (a create returns "unknown" while the resource is still coming
// up), so a lost/false-"unknown" response leaves a pending create that only
// `resume` -> Reconcile can conclude. All five are IDENTITY TIER 2: the create
// derives a DETERMINISTIC name from (account,env,capability,generation) or
// (env,capability,generation), so reconcile RECOMPUTES that same name with the
// SAME func the create used, builds the providerId, and reads live state.
// STRICTLY READ-ONLY — a single describe, never a mutation. Verdict mapping is the
// shared concludeByStatus (reconcile_aws.go); the region guard is regionlessReconcile.
package aws

import (
	"groundhold/internal/provider"
)

// reconcileRDS concludes a pending DB-instance create. The id is deterministic
// (DBIdentifier, exactly as createRDS derives it); ownership is the instance's
// tags; ready is DBInstanceStatus=="available" and terminal-failed mirrors the
// create poll's failed states.
func (d *Driver) reconcileRDS(capability, environment string, generation int) provider.ReconcileResult {
	region := d.Region
	if region == "" {
		return regionlessReconcile("rds")
	}
	account, err := d.resolveAccount()
	if err != nil {
		return provider.ReconcileResult{Status: "unknown",
			Reason: "rds reconcile could not resolve the AWS account: " + err.Error()}
	}
	id := DBIdentifier(account, environment, capability, generation)
	pid := rdsProviderID(region, id)
	inst, found, rerr := d.describeDB(region, id)
	ready := inst.Status == "available"
	failed := inst.Status == "failed" ||
		inst.Status == "incompatible-parameters" ||
		inst.Status == "incompatible-restore"
	ours := groundholdTagsMatch(inst.tags(), capability, environment)
	return concludeByStatus(pid, "rds instance "+id, found, rerr, ours, ready, failed)
}

// reconcileAurora concludes a pending cluster create. The cluster id is
// deterministic (DBIdentifier, exactly as createAurora derives it); ownership is
// the cluster's tags; ready is Status=="available". The create poll defines no
// terminal-failed cluster state (any non-available is still-provisioning ->
// unknown), so reconcile mirrors that — never a fabricated "failed" that would
// hide a standing, still-coming-up cluster.
func (d *Driver) reconcileAurora(capability, environment string, generation int) provider.ReconcileResult {
	region := d.Region
	if region == "" {
		return regionlessReconcile("aurora")
	}
	account, err := d.resolveAccount()
	if err != nil {
		return provider.ReconcileResult{Status: "unknown",
			Reason: "aurora reconcile could not resolve the AWS account: " + err.Error()}
	}
	id := DBIdentifier(account, environment, capability, generation)
	pid := auroraProviderID(region, id)
	cl, found, rerr := d.describeCluster(region, id)
	ready := cl.Status == "available"
	ours := groundholdTagsMatch(cl.tags(), capability, environment)
	return concludeByStatus(pid, "aurora cluster "+id, found, rerr, ours, ready, false)
}

// reconcileOpenSearch concludes a pending domain create. The domain name is
// deterministic (OpenSearchDomainName); ready is Processing==false (the create
// poll's readiness signal); ownership is the domain's tags (ListTags). An
// unreadable tag read on a found domain is unknown (never treated as "not ours").
func (d *Driver) reconcileOpenSearch(capability, environment string, generation int) provider.ReconcileResult {
	region := d.Region
	if region == "" {
		return regionlessReconcile("opensearch")
	}
	account, err := d.resolveAccount()
	if err != nil {
		return provider.ReconcileResult{Status: "unknown",
			Reason: "opensearch reconcile could not resolve the AWS account: " + err.Error()}
	}
	domain := OpenSearchDomainName(environment, capability, generation)
	pid := openSearchProviderID(region, account, domain)
	dom, found, rerr := d.describeDomain(region, domain)
	ready := found && !dom.Processing
	ours := false
	if found {
		tags, terr := d.openSearchTags(region, account, domain)
		if terr != nil {
			return provider.ReconcileResult{Status: "unknown",
				Reason: "opensearch domain " + domain + " tags gave no answer — cannot conclude the pending create: " + terr.Error()}
		}
		ours = groundholdTagsMatch(tags, capability, environment)
	}
	return concludeByStatus(pid, "opensearch domain "+domain, found, rerr, ours, ready, false)
}

// reconcileMSK concludes a pending cluster create. The cluster name is
// deterministic (MSKClusterName); the cluster ARN is server-assigned but the
// name is the handle (ListClustersV2 name filter); ready is State=="ACTIVE" and
// terminal-failed is State=="FAILED" (exactly the create poll's states);
// ownership is the cluster's inline Tags.
func (d *Driver) reconcileMSK(capability, environment string, generation int) provider.ReconcileResult {
	region := d.Region
	if region == "" {
		return regionlessReconcile("msk")
	}
	account, err := d.resolveAccount()
	if err != nil {
		return provider.ReconcileResult{Status: "unknown",
			Reason: "msk reconcile could not resolve the AWS account: " + err.Error()}
	}
	cluster := MSKClusterName(environment, capability, generation)
	pid := mskProviderID(region, account, cluster)
	c, found, rerr := d.getMSKByName(region, cluster)
	ready := c.State == "ACTIVE"
	failed := c.State == "FAILED"
	ours := groundholdTagsMatch(c.Tags, capability, environment)
	return concludeByStatus(pid, "msk cluster "+cluster, found, rerr, ours, ready, failed)
}

// reconcileRedshiftServerless concludes a pending workgroup create. The name is
// deterministic (RSSName); ready is the workgroup Status=="AVAILABLE" and
// terminal-failed is "FAILED" (the create poll's states); ownership is the
// workgroup's tags (ListTagsForResource against the live ARN). An unreadable tag
// read on a found workgroup is unknown (never "not ours"). No account is needed
// (the pid is rss:region:name).
func (d *Driver) reconcileRedshiftServerless(capability, environment string, generation int) provider.ReconcileResult {
	region := d.Region
	if region == "" {
		return regionlessReconcile("redshiftserverless")
	}
	name := RSSName(environment, capability, generation)
	pid := rssProviderID(region, name)
	wg, found, rerr := d.getWorkgroup(region, name)
	ready := wg.Status == "AVAILABLE"
	failed := wg.Status == "FAILED"
	ours := false
	if found {
		tags, terr := d.rssTagsFor(region, wg.WorkgroupArn)
		if terr != nil {
			return provider.ReconcileResult{Status: "unknown",
				Reason: "redshift serverless workgroup " + name + " tags gave no answer — cannot conclude the pending create: " + terr.Error()}
		}
		ours = groundholdTagsMatch(tags, capability, environment)
	}
	return concludeByStatus(pid, "redshift serverless workgroup "+name, found, rerr, ours, ready, failed)
}
