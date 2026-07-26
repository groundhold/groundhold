// AWS receipt reconciliation, BATCH 3 (F19, D57/D217): the read-only Reconciler
// conclusions for the IAM/global family — rolepolicy, custompolicy, iam, waf,
// budgets. resume calls Reconcile to conclude a PENDING create receipt by reading
// live state; without a wired service the receipt is in-flight forever. STRICTLY
// READ-ONLY — every call here is a describe/get, never a mutation. Shared helpers
// (receiptGeneration, concludeByStatus) live in reconcile_aws.go and are REUSED.
//
// Identity tier: TIER 2 (deterministic name recompute). iam/custompolicy/waf/
// budgets are account-scoped or global, so the create receipt carries enough
// (env+capability+generation) to recompute the SAME deterministic name the create
// chose, rebuild the providerId, and describe live. These are SYNCHRONOUS — ready
// the moment they are found+owned (no async status), so ready is passed as found.
// rolepolicy is the exception: an IAM policy ATTACHMENT is content-addressed by
// (roleName, policyArn), a pair that comes from the grant's ATTRIBUTES — not from
// env+cap+gen — so it cannot be recomputed from a bare create receipt. Its only
// handle is the pinned targetProviderId; absent that, the verdict is unknown.
//
// Ownership per service: iam and waf carry groundhold-* TAGS (groundholdTagsMatch).
// custompolicy and budgets carry NO tags — ownership is the deterministic NAME
// (env+cap+gen salted), the same marker each create relies on. rolepolicy has no
// tags of its own — ownership is the pinned (roleName, policyArn) pair.
package aws

import (
	"net/http"
	"strings"

	"groundhold/internal/provider"
)

// reconcileIAM concludes a pending IAM role create. The role name is deterministic
// (D29) and ownership is TAGS returned inline by GetRole; the create is synchronous
// (ready == found+owned), so a live GetRole answers the whole question.
func (d *Driver) reconcileIAM(capability, environment string, generation int) provider.ReconcileResult {
	account, err := d.resolveAccount()
	if err != nil {
		return provider.ReconcileResult{Status: "unknown",
			Reason: "iam reconcile could not resolve the AWS account: " + err.Error()}
	}
	name := IAMRoleName(environment, capability, generation)
	pid := iamRoleProviderID(account, name)
	role, found, rerr := d.getRole(name)
	ours := found && groundholdTagsMatch(role.tags(), capability, environment)
	return concludeByStatus(pid, "iam role "+name, found, rerr, ours, found, false)
}

// reconcileCustomPolicy concludes a pending customer managed-policy create. The
// policy name is deterministic (env+cap+gen salted); IAM policies carry NO tags, so
// ownership is that deterministic name — a policy at our name is ours (the same
// standard the create's idempotent path relies on). Synchronous.
func (d *Driver) reconcileCustomPolicy(capability, environment string, generation int) provider.ReconcileResult {
	account, err := d.resolveAccount()
	if err != nil {
		return provider.ReconcileResult{Status: "unknown",
			Reason: "custompolicy reconcile could not resolve the AWS account: " + err.Error()}
	}
	name := awsPolicyName(environment, capability, generation)
	arn := customPolicyArn(account, name)
	pid := customPolicyProviderID(arn)
	found, rerr := d.rc3getCustomPolicy(arn)
	return concludeByStatus(pid, "custom policy "+name, found, rerr, found, found, false)
}

// rc3getCustomPolicy is the read-only existence check reconcile needs but the create
// path lacked: GetPolicy that DISTINGUISHES NoSuchEntity (found=false, no error
// — an authoritative absence) from a transport/HTTP failure (readable=false).
// getCustomPolicyActions collapses both to unreadable, which would strand an absent
// create as unknown forever instead of concluding it failed.
func (d *Driver) rc3getCustomPolicy(arn string) (found bool, err error) {
	const op = "GetPolicy"
	st, resp, cerr := d.iamPost(encodeForm(map[string]string{
		"Action": "GetPolicy", "Version": iamVersion, "PolicyArn": arn}))
	if cerr != nil {
		return false, readTransport(op, cerr)
	}
	if strings.Contains(rdsErrCode(resp), "NoSuchEntity") {
		return false, nil
	}
	if st != http.StatusOK {
		return false, readHTTP(op, st, rdsErrCode(resp))
	}
	return true, nil
}

// reconcileWAF concludes a pending WAFv2 (CLOUDFRONT-scope, global) WebACL create.
// The name is deterministic; ownership is TAGS (ListTagsForResource). Synchronous.
func (d *Driver) reconcileWAF(capability, environment string, generation int) provider.ReconcileResult {
	account, err := d.resolveAccount()
	if err != nil {
		return provider.ReconcileResult{Status: "unknown",
			Reason: "waf reconcile could not resolve the AWS account: " + err.Error()}
	}
	name := WAFACLName(environment, capability, generation)
	pid := wafProviderID(account, name)
	s, found, rerr := d.wafListByName(name)
	if rerr != nil || !found {
		// unreadable → unknown, rerr == nil-absent → failed (ours is moot here).
		return concludeByStatus(pid, "waf web ACL "+name, found, rerr, false, false, false)
	}
	tags, terr := d.wafTags(s.ARN)
	if terr != nil {
		return provider.ReconcileResult{Status: "unknown",
			Reason: "waf web ACL " + name + " tag read was gave no answer — cannot conclude the pending create: " + terr.Error()}
	}
	ours := groundholdTagsMatch(tags, capability, environment)
	return concludeByStatus(pid, "waf web ACL "+name, true, nil, ours, true, false)
}

// reconcileBudget concludes a pending AWS Budgets create. Budgets carry NO tags, so
// ownership is the deterministic name (env+cap+gen salted) — the SAME marker create
// uses on a DuplicateRecordException. Account-scoped; synchronous.
func (d *Driver) reconcileBudget(capability, environment string, generation int) provider.ReconcileResult {
	account, err := d.resolveAccount()
	if err != nil {
		return provider.ReconcileResult{Status: "unknown",
			Reason: "budgets reconcile could not resolve the AWS account: " + err.Error()}
	}
	name := BudgetName(environment, capability, generation)
	pid := budgetProviderID(account, name)
	_, found, rerr := d.describeBudget(account, name)
	// F25-b: a budget create is complete only WITH its alert notification (the two
	// halves createBudget writes). If the budget object exists but the notification
	// is missing, the create only PARTIALLY landed — the alert never fired into
	// being. reconcile cannot recreate the notification (it lacks the candidate's
	// declared threshold + SNS topic), so it must NOT conclude "succeeded" and bind
	// a budget without its alert (that would strand it — a later converge sees the
	// threshold as merely un-observable and never rebuilds it). Conclude FAILED so a
	// re-apply re-runs createBudget, whose DuplicateRecordException path idempotently
	// (re)creates the notification and heals the budget. A notification we cannot
	// READ (e.g. missing permission) is left to the budget-based verdict — the fix
	// targets the KNOWN-missing case, never a read error.
	if rerr == nil && found {
		if _, notifFound, notifErr := d.budgetThreshold(account, name); notifErr == nil && !notifFound {
			return provider.ReconcileResult{Status: "failed",
				Reason: "budget " + name + " exists but its alert notification is missing " +
					"(a partial create) — re-apply to recreate the alert; reconcile cannot " +
					"(it lacks the declared threshold and topic)"}
		}
	}
	return concludeByStatus(pid, "budget "+name, found, rerr, found, found, false)
}

// reconcileRolePolicy concludes a pending IAM role-policy ATTACHMENT create. Unlike
// its siblings the (roleName, policyArn) identity is attribute-derived, not
// recomputable from env+cap+gen — so the only handle is the pinned targetProviderId.
// Absent it, the create receipt cannot be tied to a live attachment and the honest
// verdict is unknown (reconcile manually), never a guess. The pinned pair IS ours
// (it is what the write-ahead receipt recorded), so ownership is the pair itself; a
// live ListAttachedRolePolicies answers presence. Synchronous (attach is a no-op
// success once present).
func (d *Driver) reconcileRolePolicy(capability, environment, targetProviderID string) provider.ReconcileResult {
	if targetProviderID == "" {
		return provider.ReconcileResult{Status: "unknown",
			Reason: "rolepolicy attachment identity is attribute-derived and the create receipt pins no " +
				"targetProviderId — cannot conclude the pending attach, reconcile manually"}
	}
	roleName, policyArn, err := splitRolePolicyProviderID(targetProviderID)
	if err != nil {
		return provider.ReconcileResult{Status: "unknown",
			Reason: "rolepolicy reconcile: " + err.Error()}
	}
	attached, rerr := d.iamAttachedPolicy(roleName, policyArn)
	return concludeByStatus(targetProviderID, "role-policy attachment", attached, rerr, true, attached, false)
}
