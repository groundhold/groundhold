// Reconcile batch 9 (D374): the seven AWS services that could create a resource
// but could not conclude a lost create.
//
// `resume` exists to get out of `unknown`. A create whose outcome the executor
// never learned is concluded by re-deriving the resource's identity and asking
// the provider whether it landed. These seven fell to the dispatch default —
// honest (`unknown`, reconcile manually) but outside the machinery entirely.
//
// IDENTITY IS THE WHOLE PROBLEM, and the seven split three ways:
//
//   - A DETERMINISTIC NAME can be rebuilt from (environment, capability,
//     generation), so a create with no persisted id is still concludable: asg,
//     apprunner, the two serverless services.
//   - A SERVER-ASSIGNED id cannot be rebuilt — but EC2 accepts a `client-token`
//     FILTER, and the token this driver derives is deterministic AND generation-
//     salted. So an instance is findable by the very handle that made its create
//     idempotent. That is the token doing the second half of the job it exists
//     for.
//   - Neither: a volume's id is server-assigned and DescribeVolumes has no
//     client-token filter, and a DNS record's identity is attribute-derived. Both
//     conclude ONLY from a pinned providerId. A tag search would be the tempting
//     shortcut and is wrong: ownership tags carry no generation, so it would
//     match a PREVIOUS generation's resource and report a create landed that
//     never ran. On a stateful capability that error creates a second disk beside
//     the data.
package aws

import (
	"groundhold/internal/provider"
)

// reconcileEC2Instance concludes a lost machine create. The deterministic
// ClientToken is the handle: EC2 filters DescribeInstances by it, so the
// instance the create would have made is findable without its server-assigned id.
func (d *Driver) reconcileEC2Instance(capability, environment string, generation int) provider.ReconcileResult {
	region := d.Region
	if region == "" {
		return rc1Regionless("ec2")
	}
	account, err := d.resolveAccount()
	if err != nil {
		return provider.ReconcileResult{Status: "unknown", Reason: err.Error()}
	}
	token := "groundhold-" + letterHash(environment+"|"+capability+genSuffix(generation), 24)
	inst, found, rerr := d.describeEC2Instances(region, map[string]string{
		"Filter.1.Name": "client-token", "Filter.1.Value.1": token,
	})
	if rerr != nil || !found {
		return rc1ConcludeByStatus("", "instance", found, rerr, false, false, false)
	}
	pid := ec2InstanceProviderID(region, account, inst.InstanceID)
	failed := inst.State == "shutting-down" || inst.State == "terminated" ||
		inst.State == "stopping" || inst.State == "stopped"
	return rc1ConcludeByStatus(pid, "instance", true, nil,
		groundholdTagsMatch(inst.Tags, capability, environment),
		inst.State == "running", failed)
}

// reconcileEBSVolume concludes a lost volume create, and ONLY from a pinned
// providerId. DescribeVolumes offers no client-token filter, and a tag search
// would match a previous generation — which on a stateful capability means
// reporting that a create landed when the data actually sits on the older disk.
func (d *Driver) reconcileEBSVolume(capability, environment, targetProviderID string) provider.ReconcileResult {
	if targetProviderID == "" {
		return provider.ReconcileResult{Status: "unknown",
			Reason: "an EBS volume id is assigned by the API and DescribeVolumes cannot be " +
				"filtered by the idempotency token, so a create receipt that pins no " +
				"targetProviderId cannot be concluded — reconcile manually rather than risk " +
				"binding a previous generation's volume"}
	}
	region, _, id, err := splitEBSVolProviderID(targetProviderID)
	if err != nil {
		return provider.ReconcileResult{Status: "unknown", Reason: "ebs reconcile: " + err.Error()}
	}
	vol, found, rerr := d.describeEC2Volume(region, id)
	if rerr != nil || !found {
		return rc1ConcludeByStatus(targetProviderID, "volume", found, rerr, false, false, false)
	}
	return rc1ConcludeByStatus(targetProviderID, "volume", true, nil,
		groundholdTagsMatch(vol.Tags, capability, environment),
		vol.State == "available" || vol.State == "in-use",
		vol.State == "error")
}

// reconcileASG concludes a lost fleet create. The group NAME is deterministic, so
// the fleet is findable without a persisted id.
//
// It concludes the GROUP only. A group whose scaling policy was lost is a real
// fleet holding its floor — which is what the create already reported — and
// whether it scales is a question for `observe`, not for "did the create land".
func (d *Driver) reconcileASG(capability, environment string, generation int) provider.ReconcileResult {
	region := d.Region
	if region == "" {
		return rc1Regionless("asg")
	}
	account, err := d.resolveAccount()
	if err != nil {
		return provider.ReconcileResult{Status: "unknown", Reason: err.Error()}
	}
	name := "groundhold-" + sanitizeTag(capability) + "-" + sanitizeTag(environment) +
		genSuffix(generation)
	pid := asgProviderID(region, account, name)
	g, found, rerr := d.describeASG(region, name)
	if rerr != nil || !found {
		return rc1ConcludeByStatus(pid, "auto scaling group", found, rerr, false, false, false)
	}
	return rc1ConcludeByStatus(pid, "auto scaling group", true, nil,
		groundholdTagsMatch(g.Tags, capability, environment), true, false)
}

// reconcileAppRunner concludes a lost service create. The service NAME is
// deterministic (it hashes account+environment+capability+generation), so the
// service is findable without a persisted id.
func (d *Driver) reconcileAppRunner(capability, environment string, generation int) provider.ReconcileResult {
	region := d.Region
	if region == "" {
		return rc1Regionless("apprunner")
	}
	account, err := d.resolveAccount()
	if err != nil {
		return provider.ReconcileResult{Status: "unknown", Reason: err.Error()}
	}
	name := AppRunnerName(account, environment, capability, generation)
	pid := apprunnerProviderID(region, name)
	arn, found, rerr := d.resolveServiceArn(region, name)
	if rerr != nil || !found {
		return rc1ConcludeByStatus(pid, "app runner service", found, rerr, false, false, false)
	}
	svc, sfound, serr := d.describeAppRunnerService(region, arn)
	if serr != nil || !sfound {
		return rc1ConcludeByStatus(pid, "app runner service", sfound, serr, false, false, false)
	}
	ours, terr := d.appRunnerTagsMatch(region, arn, capability, environment)
	if terr != nil {
		return rc1ConcludeByStatus(pid, "app runner service", true, terr, false, false, false)
	}
	return rc1ConcludeByStatus(pid, "app runner service", true, nil, ours,
		svc.Status == "RUNNING",
		svc.Status == "CREATE_FAILED" || svc.Status == "DELETED")
}

// reconcileElastiCacheServerless concludes a lost cache create. The cache NAME is
// deterministic.
func (d *Driver) reconcileElastiCacheServerless(capability, environment string, generation int) provider.ReconcileResult {
	region := d.Region
	if region == "" {
		return rc1Regionless("elasticache-serverless")
	}
	account, err := d.resolveAccount()
	if err != nil {
		return provider.ReconcileResult{Status: "unknown", Reason: err.Error()}
	}
	name := ecacheID(account, environment, capability, generation)
	pid := ecacheServerlessProviderID(region, account, name)
	c, found, rerr := d.describeServerlessCache(region, name)
	if rerr != nil || !found {
		return rc1ConcludeByStatus(pid, "serverless cache", found, rerr, false, false, false)
	}
	tags, terr := d.serverlessCacheTags(region, c.ARN)
	if terr != nil {
		return rc1ConcludeByStatus(pid, "serverless cache", true, terr, false, false, false)
	}
	return rc1ConcludeByStatus(pid, "serverless cache", true, nil,
		groundholdTagsMatch(tags, capability, environment),
		c.Status == "available", c.Status == "create-failed")
}

// reconcileOpenSearchServerless concludes a lost collection create. The
// collection NAME is deterministic.
func (d *Driver) reconcileOpenSearchServerless(capability, environment string, generation int) provider.ReconcileResult {
	region := d.Region
	if region == "" {
		return rc1Regionless("opensearch-serverless")
	}
	account, err := d.resolveAccount()
	if err != nil {
		return provider.ReconcileResult{Status: "unknown", Reason: err.Error()}
	}
	name := OpenSearchDomainName(environment, capability, generation)
	pid := openSearchServerlessProviderID(region, account, name)
	c, found, rerr := d.batchGetCollection(region, name)
	if rerr != nil || !found {
		return rc1ConcludeByStatus(pid, "serverless collection", found, rerr, false, false, false)
	}
	tags, terr := d.openSearchServerlessTags(region, c.ARN)
	if terr != nil {
		return rc1ConcludeByStatus(pid, "serverless collection", true, terr, false, false, false)
	}
	return rc1ConcludeByStatus(pid, "serverless collection", true, nil,
		groundholdTagsMatch(tags, capability, environment),
		c.Status == "ACTIVE", c.Status == "FAILED")
}

// reconcileRoute53Record concludes a lost record create, and ONLY from a pinned
// providerId: a record's identity is attribute-derived (zone + name + type), none
// of which the reconcile path is given.
//
// A record carries no tags of its own, so ownership is its parent hosted zone's —
// the same handle the create and delete paths use.
func (d *Driver) reconcileRoute53Record(capability, environment, targetProviderID string) provider.ReconcileResult {
	if targetProviderID == "" {
		return provider.ReconcileResult{Status: "unknown",
			Reason: "a Route 53 record's identity is attribute-derived (zone, name and type) " +
				"and the create receipt pins no targetProviderId — cannot conclude the pending " +
				"create, reconcile manually"}
	}
	zoneID, recordType, name, err := splitR53RecordProviderID(targetProviderID)
	if err != nil {
		return provider.ReconcileResult{Status: "unknown",
			Reason: "route53record reconcile: " + err.Error()}
	}
	owned, oerr := d.zoneOwnedByUs(zoneID, capability, environment)
	if oerr != nil {
		return rc1ConcludeByStatus(targetProviderID, "dns record", false, oerr, false, false, false)
	}
	_, found, rerr := d.listRecordSet(zoneID, name, recordType)
	return rc1ConcludeByStatus(targetProviderID, "dns record", found, rerr, owned, found, false)
}
