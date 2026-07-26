// AWS receipt reconciliation, batch 6 (D57, F19): the READ-ONLY conclusions for
// s3, changefeed, eventbridgescheduler, ses-sending and ses-inbound. Each concludes
// a PENDING create by reading live state — never a mutation, never a guess.
//
// Two identity tiers appear here:
//   - DETERMINISTIC NAME (s3 bucket, eventbridge schedule): the name is a pure
//     function of (account?/environment/capability/generation), so reconcile RECOMPUTES
//     it and reads live state directly — this works even on a receipt that never
//     carried a providerID.
//   - OPERAND-DERIVED IDENTITY (changefeed rule region from the feed.target ARN;
//     ses-sending domain; ses-inbound rule name from the recipient): the identity is
//     NOT recomputable from the capability alone, so reconcile reads the providerID the
//     create PERSISTED on its unknown response (D57's "identity survives a lost
//     response"). With no recorded providerID it refuses HONESTLY to unknown rather
//     than reconcile the wrong resource.
package aws

import "groundhold/internal/provider"

// reconcileS3 concludes a pending bucket create. The bucket name is a deterministic
// function of account+environment+capability+generation and the tags are the ownership
// handle, so reconcile recomputes the name and reads GetBucketTagging: our tags →
// succeeded WITH the recomputed pid; a readable answer WITHOUT our tags (an absent
// bucket, or an untagged/foreign same-name bucket) → failed (the create did not land as
// ours, so a re-plan recreates — and a squatter re-surfaces as the create's own
// BucketAlreadyOwnedByYou unknown); an unreadable read → unknown (stays pending, D29).
func (d *Driver) reconcileS3(capability, environment string, generation int) provider.ReconcileResult {
	region := d.Region
	if region == "" {
		return regionlessReconcile("s3")
	}
	account, err := d.resolveAccount()
	if err != nil {
		return provider.ReconcileResult{Status: "unknown",
			Reason: "s3 reconcile could not resolve the AWS account: " + err.Error()}
	}
	bucket := BucketName(account, environment, capability, generation)
	pid := s3ProviderID(region, bucket)
	tags, rerr := d.s3Tags(region, bucket)
	ours := rerr == nil && groundholdTagsMatch(tags, capability, environment)
	// found is encoded as "ours" (the deterministic name has no other ownership proof):
	// a readable read with no owned tags is a definitive "the create did not land as ours".
	return concludeByStatus(pid, "s3 bucket "+bucket, ours, rerr, true, ours, false)
}

// reconcileEventBridgeScheduler concludes a pending schedule create. The name is
// deterministic and the Description marker is the ownership handle, so reconcile
// recomputes the name and reads GetSchedule. A schedule is SYNCHRONOUS (ENABLED/DISABLED
// at once, no async poll) and a DISABLED schedule is still a successful create — so an
// owned, present schedule IS the landed create (succeeded WITH the recomputed pid); a
// readable absence → failed; an unreadable read or a foreign schedule → unknown.
func (d *Driver) reconcileEventBridgeScheduler(capability, environment string, generation int) provider.ReconcileResult {
	region := d.Region
	if region == "" {
		return regionlessReconcile("eventbridgescheduler")
	}
	name := EBSName(environment, capability, generation)
	pid := ebsProviderID(region, name)
	doc, found, rerr := d.getSchedule(region, name)
	ours := found && awsMarkerOurs(doc.Description, capability, environment)
	return concludeByStatus(pid, "eventbridge schedule "+name, found, rerr, ours, found, false)
}

// reconcileChangeFeed concludes a pending change-feed create. The EventBridge rule's
// REGION is derived from the feed.target ARN at create time (NOT a location.region
// attribute), so it cannot be recomputed from the capability — reconcile reads the
// providerID the create PERSISTED on its unknown response. With no recorded providerID
// it refuses honestly (unknown) rather than read the wrong region. The create's contract
// is a rule AND its target, so reconcile mirrors it: an owned rule WITH a target →
// succeeded; an owned rule with no target is a half-built feed → unknown (resume again).
func (d *Driver) reconcileChangeFeed(capability, environment, providerID string) provider.ReconcileResult {
	if providerID == "" {
		return provider.ReconcileResult{Status: "unknown",
			Reason: "changefeed create left no recorded providerId — the EventBridge rule's region is " +
				"derived from the feed.target ARN and was not persisted; reconcile manually"}
	}
	region, rule, err := splitChangefeedProviderID(providerID)
	if err != nil {
		return provider.ReconcileResult{Status: "unknown",
			Reason: "changefeed recorded providerId is malformed (" + err.Error() + ") — cannot conclude the pending create"}
	}
	doc, found, rerr := d.describeRule(region, rule)
	ours := found && awsMarkerOurs(doc.Description, capability, environment)
	if rerr != nil || !found || !ours {
		return concludeByStatus(providerID, "changefeed rule "+rule, found, rerr, ours, false, false)
	}
	// the rule is ours; verify the feed.target attached (the create returns unknown WITH
	// the pid when it does not, so a rule with no target is a half-built feed to resume).
	targets, hasTargets, terr := d.listRuleTargets(region, rule)
	if terr != nil {
		return provider.ReconcileResult{Status: "unknown",
			Reason: "changefeed rule " + rule + " is ours but its targets gave no answer — cannot conclude the pending create: " + terr.Error()}
	}
	if !hasTargets || len(targets) == 0 {
		return provider.ReconcileResult{Status: "unknown",
			Reason: "changefeed rule " + rule + " exists but has no feed target attached — a half-built feed; resume again once the target lands"}
	}
	return provider.ReconcileResult{Status: "succeeded", ProviderID: providerID}
}

// reconcileSESSending concludes a pending sending-identity create. The sending DOMAIN is
// an operator operand (not recomputable from the capability), so reconcile reads the
// providerID the create PERSISTED; with none it refuses honestly (unknown). The identity
// carries ownership TAGS. DKIM verification is ASYNC (the create does not block on it),
// so a found, owned identity IS the landed create: succeeded WITH the pid; a readable
// absence → failed; an unreadable read or a foreign identity → unknown.
func (d *Driver) reconcileSESSending(capability, environment, providerID string) provider.ReconcileResult {
	if providerID == "" {
		return provider.ReconcileResult{Status: "unknown",
			Reason: "ses-sending create left no recorded providerId — the sending domain is an operator " +
				"operand (not recomputable from the capability); reconcile manually"}
	}
	region, domain, err := splitSESSendingProviderID(providerID)
	if err != nil {
		return provider.ReconcileResult{Status: "unknown",
			Reason: "ses-sending recorded providerId is malformed (" + err.Error() + ") — cannot conclude the pending create"}
	}
	id, found, rerr := d.getEmailIdentity(region, domain)
	ours := found && groundholdTagsMatch(id.tagMap(), capability, environment)
	return concludeByStatus(providerID, "ses-sending identity "+domain, found, rerr, ours, found, false)
}

// reconcileSESInbound concludes a pending receiving-pipeline create. The receipt rule
// name derives from the recipient operand (not recomputable from the capability), so
// reconcile reads the providerID the create PERSISTED; with none it refuses honestly
// (unknown). Ownership is the DETERMINISTIC NAME — there are no tags — so a rule present
// at the pid's exact rule-set+rule is ours. The create's contract also ACTIVATES the
// rule set (an inactive set receives nothing), so reconcile mirrors it: an owned rule in
// the ACTIVE set → succeeded; an owned rule whose set is not active is a half-built
// pipeline → unknown; a readable absence → failed; an unreadable read → unknown.
func (d *Driver) reconcileSESInbound(capability, environment, providerID string) provider.ReconcileResult {
	if providerID == "" {
		return provider.ReconcileResult{Status: "unknown",
			Reason: "ses-inbound create left no recorded providerId — the receipt rule name derives from " +
				"the recipient operand (not recomputable from the capability); reconcile manually"}
	}
	region, ruleSet, rule, err := splitSESInboundProviderID(providerID)
	if err != nil {
		return provider.ReconcileResult{Status: "unknown",
			Reason: "ses-inbound recorded providerId is malformed (" + err.Error() + ") — cannot conclude the pending create"}
	}
	// the NAME is the ownership marker: a rule present at the pid's names is ours.
	_, found, rerr := d.describeReceiptRule(region, ruleSet, rule)
	if rerr != nil || !found {
		return concludeByStatus(providerID, "ses-inbound rule "+ruleSet+"/"+rule, found, rerr, found, false, false)
	}
	// the rule is present (ours by name); verify OUR rule set is the ACTIVE one — an
	// inactive rule receives nothing (the create returns unknown WITH the pid).
	active, activeErr := d.activeReceiptRuleSetName(region)
	if activeErr != nil {
		return provider.ReconcileResult{Status: "unknown",
			Reason: "ses-inbound rule " + rule + " exists but the active rule set gave no answer — cannot conclude the pending create: " + activeErr.Error()}
	}
	if active != ruleSet {
		return provider.ReconcileResult{Status: "unknown",
			Reason: "ses-inbound rule " + rule + " exists but its rule set is not active — the pipeline receives nothing; resume again once the set is activated"}
	}
	return provider.ReconcileResult{Status: "succeeded", ProviderID: providerID}
}
