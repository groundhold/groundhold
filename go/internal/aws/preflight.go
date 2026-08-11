// Permission preflight (D75), the AWS half. The deterministic permission TABLE
// lives in provider.PermissionsFor ("aws" case); this is only the LIVE check, via
// IAM iam:SimulatePrincipalPolicy — AWS's policy simulator, which (unlike GCP's
// testIamPermissions) actually EVALUATES the acting principal's identity policies
// and permission boundary.
//
// A pass is EVIDENCE, not proof: the simulator cannot see resource-based policy
// conditions we do not feed it, session policies, tag/context conditions evaluated
// at mutation time, or propagation lag. Mid-apply denial stays possible; the
// write-ahead receipts remain the recovery story.
//
// Honesty (D78 applied to AWS). An EXPLICIT deny is always authoritative (denied).
// An IMPLICIT deny is authoritative ONLY when the simulation ran in the RESOURCE's
// context — CheckResourcePermissions builds the resource ARN, so a missing grant
// there is a real denial. Against "*" (the account-level CheckPermissions, and any
// create whose resource does not yet exist) an implicit deny may merely reflect a
// grant scoped to a specific ARN, so it is UNATTESTED — never a denial. groundhold
// must not refuse an authorized user.
package aws

import (
	"encoding/xml"
	"fmt"
	"net/http"
	"sort"
	"strings"

	"groundhold/internal/provider"
)

// compile-time proof the AWS driver satisfies both preflight interfaces.
var (
	_ provider.Preflighter         = (*Driver)(nil)
	_ provider.ResourcePreflighter = (*Driver)(nil)
)

type simEvalResult struct {
	EvalActionName string `xml:"EvalActionName"`
	EvalDecision   string `xml:"EvalDecision"` // allowed | explicitDeny | implicitDeny
	// MissingContextValues (D720) is AWS telling us which condition keys the
	// policies it evaluated NEEDED and this simulation did not supply. A decision
	// that rests on a key we did not send is not an answer about the caller's
	// permissions; it is an answer about our incomplete question.
	MissingContextValues []string `xml:"MissingContextValues>member"`
}

// simDecision is a simulator verdict WITH the reason it might not mean what it says.
type simDecision struct {
	decision string
	missing  []string

	// contextless records that WE left the region key out of this simulation. A deny
	// reached that way describes our question, not the caller (D750).
	contextless bool
}

// trustworthy reports whether this decision can be acted on as a denial. A decision
// reached without every condition key the policies asked for cannot.
// trustworthy answers whether this verdict is about the CALLER rather than about the
// question we asked. Two ways it is not, and D720 knew only the first:
//
//   - AWS named condition keys it wanted and we did not supply (MissingContextValues);
//   - we KNOWINGLY simulated without the region key. D720 called that omission "safe",
//     reasoning that AWS would report the key as missing and the verdict would become
//     unattested. That reasoning holds only for a policy that NEEDS the key to decide.
//     A guardrail written as `Deny` with `StringNotEquals: {aws:RequestedRegion: eu-…}`
//     needs nothing: an ABSENT key does not equal the allowed region, so the condition
//     is SATISFIED, the deny fires, and MissingContextValues comes back EMPTY. The
//     safety net had nothing to catch, and the field was told it lacked s3:CreateBucket
//     while the same role created a bucket by hand seconds later (D750).
func (s simDecision) trustworthy() bool { return len(s.missing) == 0 && !s.contextless }

// answered reports whether the simulator said anything about this action at all. A
// map lookup that misses returns the zero value, and the zero value used to read as
// "not allowed" — so an action the response omitted (a truncated page, an action name
// AWS did not echo) became an authoritative denial on the resource path. Absent and
// denied are two answers (D720).
func (s simDecision) answered() bool { return s.decision != "" }

// simulate runs iam:SimulatePrincipalPolicy for the acting principal over actions,
// in the context of resourceArns (pass {"*"} for the account-level check). Returns
// the decision per action. A non-nil error means the simulation itself could not
// run (no simulatable principal, the simulate permission denied, transport/HTTP) —
// the executor maps that to preflight-inconclusive, never to a denial.
func (d *Driver) simulate(actions, resourceArns []string, ctx map[string]string) (map[string]simDecision, error) {
	_, arn, err := d.CallerIdentity()
	if err != nil {
		return nil, fmt.Errorf("caller identity: %w", err)
	}
	src, ok := simulatablePrincipal(arn)
	if !ok {
		return nil, fmt.Errorf("acting identity %q is not a simulatable IAM principal "+
			"(SimulatePrincipalPolicy needs a user or role ARN)", arn)
	}
	form := map[string]string{
		"Action": "SimulatePrincipalPolicy", "Version": iamVersion,
		"PolicySourceArn": src,
	}
	for i, a := range actions {
		form[fmt.Sprintf("ActionNames.member.%d", i+1)] = a
	}
	for i, r := range resourceArns {
		form[fmt.Sprintf("ResourceArns.member.%d", i+1)] = r
	}
	// D720: the request context. A real call carries condition keys the simulator
	// only knows if we send them, and an account whose guardrail is written in those
	// keys (a region allow-list, an org id) then simulates as denied for actions the
	// caller can perform. Keys are sent in a deterministic order — a simulation whose
	// request depends on map iteration is not a check, it is a coin.
	for i, k := range sortedStringKeys(ctx) {
		n := i + 1
		form[fmt.Sprintf("ContextEntries.member.%d.ContextKeyName", n)] = k
		form[fmt.Sprintf("ContextEntries.member.%d.ContextKeyType", n)] = "string"
		form[fmt.Sprintf("ContextEntries.member.%d.ContextKeyValues.member.1", n)] = ctx[k]
	}
	// D720: the simulator PAGINATES, and this driver paginates everywhere else. An
	// unfollowed marker leaves later actions unanswered, and on the resource path an
	// unanswered action was read as denied — a truncated page became a refusal.
	dec := map[string]simDecision{}
	for page := 0; ; page++ {
		if page >= 50 {
			return nil, fmt.Errorf("SimulatePrincipalPolicy: more than 50 pages — refusing " +
				"to loop rather than report a partial answer as complete")
		}
		st, resp, cerr := d.iamPost(encodeForm(form))
		if cerr != nil {
			return nil, fmt.Errorf("SimulatePrincipalPolicy: %w", cerr)
		}
		if st != http.StatusOK {
			// D1002: a throttle is NOT a missing permission. The IAM query API answers
			// SimulatePrincipalPolicy's rate limit with HTTP 400 <Code>Throttling</Code>
			// "Rate exceeded" — and the old message said "the acting identity needs
			// iam:SimulatePrincipalPolicy", sending the operator to grant a permission they
			// already hold (or to broaden IAM). Distinguish: a retryable class asks for a
			// RETRY, a real denial asks for the GRANT.
			if provider.Classify(st, awsErrCodeOf(resp), nil).Retryable() {
				return nil, fmt.Errorf("SimulatePrincipalPolicy HTTP %d — the provider is "+
					"rate-limiting the permission check; retry (the permission is present, not missing): %s",
					st, mutDetail(resp))
			}
			return nil, fmt.Errorf("SimulatePrincipalPolicy HTTP %d "+
				"(the acting identity needs iam:SimulatePrincipalPolicy): %s", st, mutDetail(resp))
		}
		var out struct {
			Results     []simEvalResult `xml:"SimulatePrincipalPolicyResult>EvaluationResults>member"`
			IsTruncated bool            `xml:"SimulatePrincipalPolicyResult>IsTruncated"`
			Marker      string          `xml:"SimulatePrincipalPolicyResult>Marker"`
		}
		if err := xml.Unmarshal(resp, &out); err != nil {
			return nil, fmt.Errorf("SimulatePrincipalPolicy: bad response: %w", err)
		}
		for _, r := range out.Results {
			dec[r.EvalActionName] = simDecision{decision: r.EvalDecision, missing: r.MissingContextValues,
				contextless: len(ctx) == 0}
		}
		if !out.IsTruncated || out.Marker == "" {
			break
		}
		form["Marker"] = out.Marker
	}
	return dec, nil
}

// globalOrAmbiguousPermissionPrefix — services whose call does NOT run in the
// driver's region, derived from what the drivers themselves sign (D720):
//
//	route53, cloudfront, iam, budgets  -> always us-east-1, no regional endpoint
//	wafv2                             -> us-east-1 for the CLOUDFRONT scope this
//	                                     project hard-codes
//	cloudwatch                        -> AMBIGUOUS: alarms are regional, the
//	                                     dashboards driver signs us-east-1
//	sts                               -> a global-ish endpoint; the region a call
//	                                     lands in is not the driver's by default
//
// s3 was in this set and should not have been (D750): every S3 call this project
// makes is signed against `<bucket>.s3.<REGION>.amazonaws.com`, so the driver's region
// IS the one the request carries. Listing it here meant a create was simulated with no
// region against an account whose guardrail denies every region but one — and the
// answer came back explicitDeny, which is what the field measured.
//
// The asymmetry that decides the direction here: OMITTING the key is safe, because
// AWS then reports it in MissingContextValues and the verdict becomes unattested;
// ASSERTING a wrong one is not, because the key is present, the deny is trustworthy,
// and the apply is refused with no way around it. So anything not plainly regional
// is omitted. An audit of this fix caught it re-creating the very defect it was
// written for, by asserting eu-central-1 over `iam:*` and `route53:*`.
var globalOrAmbiguousPermissionPrefix = map[string]bool{
	"route53": true, "cloudfront": true, "iam": true, "budgets": true,
	"wafv2": true, "waf": true, "cloudwatch": true, "sts": true,
	"organizations": true, "ce": true, "support": true,
}

// permissionService reads the service prefix out of "service:Action".
func permissionService(p string) string {
	if i := strings.IndexByte(p, ':'); i > 0 {
		return p[:i]
	}
	return ""
}

// splitByRegionKnowledge partitions permissions into those whose call runs in the
// given region (so the context key can be asserted) and those where it cannot be
// claimed. Deterministic order.
func splitByRegionKnowledge(permissions []string) (regional, unclaimable []string) {
	for _, p := range permissions {
		if globalOrAmbiguousPermissionPrefix[permissionService(p)] {
			unclaimable = append(unclaimable, p)
		} else {
			regional = append(regional, p)
		}
	}
	sort.Strings(regional)
	sort.Strings(unclaimable)
	return regional, unclaimable
}

// requestContext is what this driver KNOWS about the request the caller is about to
// make. Today that is the region, which is both the key most guardrails are written
// in and the one we can always name. An empty region yields no entry rather than a
// guess — and then AWS's own MissingContextValues keeps the resulting deny from
// being read as a denial.
func (d *Driver) requestContext(region string) map[string]string {
	if region == "" {
		region = d.Region
	}
	if region == "" {
		return nil
	}
	return map[string]string{"aws:RequestedRegion": region}
}

// regionOfARN reads the region field out of an ARN (arn:partition:service:REGION:...).
// Empty for a global service, which is correct: there is nothing to claim.
func regionOfARN(arn string) string {
	parts := strings.SplitN(arn, ":", 5)
	if len(parts) < 5 {
		return ""
	}
	return parts[3]
}

// simulatablePrincipal normalizes the caller ARN to a form SimulatePrincipalPolicy
// accepts. An assumed-role SESSION arn is not accepted; its underlying role arn is.
// An IAM user/role arn is used as-is. Root, federated and SSO principals (and any
// role that carries an IAM path the session arn cannot reveal) are not simulatable
// here → ok=false, i.e. inconclusive, never a false denial.
func simulatablePrincipal(arn string) (string, bool) {
	if strings.Contains(arn, ":iam::") &&
		(strings.Contains(arn, ":user/") || strings.Contains(arn, ":role/")) {
		return arn, true
	}
	// arn:aws:sts::<acct>:assumed-role/<RoleName>/<session> → arn:aws:iam::<acct>:role/<RoleName>
	if strings.Contains(arn, ":sts::") && strings.Contains(arn, ":assumed-role/") {
		parts := strings.SplitN(arn, ":", 6)
		if len(parts) < 6 {
			return "", false
		}
		acct := parts[4]
		seg := strings.SplitN(parts[5], "/", 3)
		if len(seg) < 2 || seg[0] != "assumed-role" {
			return "", false
		}
		return "arn:aws:iam::" + acct + ":role/" + seg[1], true
	}
	return "", false
}

// CheckPermissions implements provider.Preflighter — the account-level check, run
// against resource "*". allowed → granted; explicitDeny → denied (authoritative);
// implicitDeny (or an action the simulator did not return) → unattested, since a
// "*" implicit deny cannot distinguish "no grant" from "grant scoped to a specific
// ARN we did not simulate".
func (d *Driver) CheckPermissions(account string, permissions []string) (denied, unattested []string, err error) {
	if len(permissions) == 0 {
		return nil, nil, nil
	}
	// D720: two batches. The region can only be asserted for actions whose call
	// actually runs in it; for the rest the key is omitted and the answer degrades to
	// unattested, which is the safe direction.
	regional, unclaimable := splitByRegionKnowledge(permissions)
	dec := map[string]simDecision{}
	for _, batch := range []struct {
		perms []string
		ctx   map[string]string
	}{{regional, d.requestContext("")}, {unclaimable, nil}} {
		if len(batch.perms) == 0 {
			continue
		}
		part, err := d.simulate(batch.perms, []string{"*"}, batch.ctx)
		if err != nil {
			return nil, nil, err
		}
		for k, v := range part {
			dec[k] = v
		}
	}
	for _, p := range permissions {
		v := dec[p]
		switch {
		case v.decision == "allowed":
			// granted
		case !v.answered() || !v.trustworthy():
			// D720: the policies that produced this verdict asked for condition keys
			// we did not supply, so the verdict is about our question, not about the
			// caller. Unattested — never a denial.
			unattested = append(unattested, p)
		case v.decision == "explicitDeny":
			denied = append(denied, p)
		default: // implicitDeny or omitted — not authoritative against "*"
			unattested = append(unattested, p)
		}
	}
	sort.Strings(denied)
	sort.Strings(unattested)
	return denied, unattested, nil
}

// CheckResourcePermissions implements provider.ResourcePreflighter — the
// AUTHORITATIVE check for an EXISTING resource. We build the resource ARN from the
// providerID and simulate in that context, so an implicit deny IS a real denial
// (the grant, if any, would have matched the ARN). Services whose ARN cannot be
// reconstructed exactly from the providerID return ErrNoResourceSurface so the
// executor falls back to the account "*" check (where their implicit denies are
// unattested — safe). Any simulation error is inconclusive, never a denial.
func (d *Driver) CheckResourcePermissions(service, providerID string, permissions []string) (denied, unattested []string, err error) {
	if len(permissions) == 0 {
		return nil, nil, nil
	}
	account, err := d.resolveAccount()
	if err != nil {
		return nil, nil, err
	}
	arn, ok := awsResourceARN(service, providerID, account)
	if !ok {
		return nil, nil, provider.ErrNoResourceSurface
	}
	// D886 (generalizes D885): an implicitDeny against this ARN is authoritative ONLY for
	// an action that could be ARN-scoped to the ARN's OWN resource TYPE. An action of the
	// same service but a DIFFERENT type — rds:DeleteDBInstance (type db) or
	// DeleteDBSubnetGroup (type subgrp) against an rds CLUSTER arn — has no grant that
	// could match this ARN, so it reads implicitDeny for a permission the caller in fact
	// holds, and the in-context rule below would refuse a legitimate apply. (Confirmed in
	// the field: an Aurora retire refused rds:DeleteDBInstance/SubnetGroup/ParameterGroup,
	// and before that D885's cross-SERVICE case sts:GetCallerIdentity — an action AWS
	// always allows.) So an action is judged authoritatively here only when its service is
	// the ARN's service AND the ARN's resource type is in the action's Service-Reference
	// resource-type set; everything else falls to the account "*" check, where an
	// implicitDeny is unattested, never a denial. A cross-service action fails the service
	// half, so D885 is subsumed. The data can only harm by a FALSE match (a type the action
	// lacks, kept authoritative) — the gate forbids exactly that; an unknown or omitted
	// action yields no match and routes to the SAFE account check.
	arnSvc, arnType := serviceOfARN(arn), awsARNResourceType(service)
	var authoritative, fallback []string
	for _, p := range permissions {
		if actionService(p) == arnSvc && actionScopableToType(p, arnType) {
			authoritative = append(authoritative, p)
		} else {
			fallback = append(fallback, p)
		}
	}
	// The ARN's own region is ground truth for a resource-scoped call, not a default —
	// but a global service's ARN carries no region, and then there is nothing to claim.
	ctx := d.requestContext(regionOfARN(arn))
	if regionOfARN(arn) == "" {
		ctx = nil
	}
	if len(authoritative) > 0 {
		dec, serr := d.simulate(authoritative, []string{arn}, ctx)
		if serr != nil {
			return nil, nil, serr
		}
		for _, p := range authoritative {
			v := dec[p]
			switch {
			case v.decision == "allowed":
				// granted
			case !v.answered() || !v.trustworthy():
				// D720, same rule as the account check and it matters MORE here, because
				// an in-context deny is otherwise authoritative and blocks the apply. An
				// action the simulator never answered lands here too: absent is not denied.
				unattested = append(unattested, p)
			default: // in-context: explicit AND implicit deny are authoritative
				denied = append(denied, p)
			}
		}
	}
	if len(fallback) > 0 {
		cd, cu, cerr := d.CheckPermissions(account, fallback)
		if cerr != nil {
			return nil, nil, cerr
		}
		denied = append(denied, cd...)
		unattested = append(unattested, cu...)
	}
	sort.Strings(denied)
	sort.Strings(unattested)
	return denied, unattested, nil
}

// serviceOfARN returns the service segment of an ARN (arn:partition:SERVICE:...).
func serviceOfARN(arn string) string {
	parts := strings.SplitN(arn, ":", 4)
	if len(parts) < 3 {
		return ""
	}
	return parts[2]
}

// actionService returns the service prefix of an IAM action (SERVICE:Verb).
func actionService(action string) string {
	if i := strings.IndexByte(action, ':'); i >= 0 {
		return action[:i]
	}
	return action
}

// awsARNResourceType returns the AWS Service-Reference resource-type NAME of the ARN
// awsResourceARN builds for this service. A pure function of the service (each
// awsResourceARN case builds exactly one ARN shape), rather than parsing the ARN —
// sqs/sns ARNs carry no type segment at all. "" for a service with no ARN surface.
func awsARNResourceType(service string) string {
	switch service {
	case "rds":
		return "db"
	case "aurora":
		return "cluster"
	case "dynamodb":
		return "table"
	case "sqs":
		return "queue"
	case "sns":
		return "topic"
	case "kms":
		return "key"
	}
	return ""
}

// awsActionResourceTypes maps each IAM action the ARN-surfaced services declare to the
// resource-type tokens it can be ARN-scoped to (AWS Service Reference Actions[].Resources
// []).Name). It is the runtime half of the D886 check; scripts/refresh-aws-action-
// resourcetypes.sh + testdata/aws_action_resourcetypes.verified are AWS's own authority,
// and TestEveryAWSActionResourceTypeIsOnePublished forbids a token this map asserts that
// the Service Reference does not list — the only way this map can HARM (a false match
// keeps a cross-type action authoritative). An absent action is safe: no match → the
// account "*" check → unattested.
var awsActionResourceTypes = map[string][]string{
	"dynamodb:CreateTable":               {"table"},
	"dynamodb:DeleteTable":               {"table"},
	"dynamodb:DescribeContinuousBackups": {"table"},
	"dynamodb:DescribeTable":             {"table"},
	"dynamodb:ListTagsOfResource":        {"stream", "table"},
	"dynamodb:TagResource":               {"stream", "table"},
	"dynamodb:UpdateContinuousBackups":   {"table"},
	"dynamodb:UpdateTable":               {"table"},
	"kms:DescribeKey":                    {"key"},
	"kms:DisableKeyRotation":             {"key"},
	"kms:EnableKeyRotation":              {"key"},
	"kms:GetKeyRotationStatus":           {"key"},
	"kms:ListResourceTags":               {"key"},
	"kms:ScheduleKeyDeletion":            {"key"},
	"kms:TagResource":                    {"key"},
	"rds:AddTagsToResource":              {"auto-backup", "cev", "cluster", "cluster-auto-backup", "cluster-endpoint", "cluster-pg", "cluster-snapshot", "db", "deployment", "es", "global-cluster", "integration", "og", "pg", "proxy", "proxy-endpoint", "ri", "secgrp", "shardgrp", "snapshot", "snapshot-tenant-database", "subgrp", "target-group", "tenant-database"},
	"rds:CreateDBCluster":                {"cluster", "cluster-pg", "db", "global-cluster", "og", "subgrp"},
	"rds:CreateDBClusterParameterGroup":  {"cluster-pg"},
	"rds:CreateDBInstance":               {"cluster", "db", "og", "pg", "secgrp", "subgrp"},
	"rds:CreateDBSubnetGroup":            {"subgrp"},
	"rds:DeleteDBCluster":                {"cluster", "cluster-snapshot"},
	"rds:DeleteDBClusterParameterGroup":  {"cluster-pg"},
	"rds:DeleteDBInstance":               {"db"},
	"rds:DeleteDBSubnetGroup":            {"subgrp"},
	"rds:DescribeDBClusters":             {"cluster"},
	"rds:DescribeDBInstances":            {"db"},
	"rds:DescribeDBSubnetGroups":         {"subgrp"},
	"rds:ModifyDBCluster":                {"cluster", "cluster-pg", "og", "pg"},
	"rds:ModifyDBClusterParameterGroup":  {"cluster-pg"},
	"rds:ModifyDBInstance":               {"db", "og", "pg", "secgrp", "subgrp"},
	"sns:CreateTopic":                    {"topic"},
	"sns:DeleteTopic":                    {"topic"},
	"sns:GetTopicAttributes":             {"topic"},
	"sns:ListTagsForResource":            {"topic"},
	"sns:SetTopicAttributes":             {"topic"},
	"sns:TagResource":                    {"topic"},
	"sqs:CreateQueue":                    {"queue"},
	"sqs:DeleteQueue":                    {"queue"},
	"sqs:GetQueueAttributes":             {"queue"},
	"sqs:ListQueueTags":                  {"queue"},
	"sqs:SetQueueAttributes":             {"queue"},
	"sqs:TagQueue":                       {"queue"},
}

// actionScopableToType reports whether the action can be ARN-scoped to arnType — the
// condition for judging its implicitDeny authoritatively against that ARN. Unknown action
// or empty arnType → false (the safe account-check fallback), by construction.
func actionScopableToType(action, arnType string) bool {
	if arnType == "" {
		return false
	}
	for _, t := range awsActionResourceTypes[action] {
		if t == arnType {
			return true
		}
	}
	return false
}

// awsResourceARN reconstructs a resource ARN from a providerID for services whose
// ARN is a pure function of the providerID (no server-assigned random suffix).
// Conservative on purpose: a WRONG ARN would make an implicit deny falsely
// authoritative, so a service is mapped only when its ARN is exactly derivable;
// everything else returns ok=false → the account-level "*" fallback (unattested,
// never a false denial). More services can join as their ARN shape is confirmed.
func awsResourceARN(service, providerID, account string) (string, bool) {
	switch service {
	case "rds":
		region, id, err := splitRDSProviderID(providerID)
		if err != nil {
			return "", false
		}
		return "arn:aws:rds:" + region + ":" + account + ":db:" + id, true
	case "aurora":
		region, id, err := splitAuroraProviderID(providerID)
		if err != nil {
			return "", false
		}
		return "arn:aws:rds:" + region + ":" + account + ":cluster:" + id, true
	case "dynamodb":
		region, acct, table, err := splitDynamoProviderID(providerID)
		if err != nil {
			return "", false
		}
		return "arn:aws:dynamodb:" + region + ":" + acct + ":table/" + table, true
	case "sqs":
		region, acct, name, err := splitSQSProviderID(providerID)
		if err != nil {
			return "", false
		}
		return "arn:aws:sqs:" + region + ":" + acct + ":" + name, true
	case "sns":
		region, acct, name, err := splitSNSProviderID(providerID)
		if err != nil {
			return "", false
		}
		return "arn:aws:sns:" + region + ":" + acct + ":" + name, true
	case "kms":
		region, keyID, err := splitAWSKMSProviderID(providerID)
		if err != nil {
			return "", false
		}
		return "arn:aws:kms:" + region + ":" + account + ":key/" + keyID, true
	}
	return "", false
}
