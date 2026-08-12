package provider_test

import (
	"sort"
	"strings"
	"testing"

	"groundhold/internal/provider"
)

// D1016. iam:PassRole is the permission-sufficiency blind spot the AWS gate (D846-D853)
// cannot cover: that gate joins a route to the action AWS says AUTHORIZES the operation,
// and PassRole never authorizes an operation — it authorizes the acting identity to HAND a
// role to a service. So a driver whose create/update passes a role ARN needs iam:PassRole
// declared, and nothing derived from the operation table can tell.
//
// The set of role-passers is small and stable, so it is curated here (each entry traced to
// the field that carries the ARN) rather than statically detected — a new one is added the
// same way the discovery-only register is. The gate asserts every role-passer declares
// iam:PassRole, and that the three that do NOT (a fail-loud gap the freeze does not admit
// fixing — the pass 403s and apply reports failed) sit in the register with their reason.
func TestRolePassingMutationsDeclarePassRole(t *testing.T) {
	// capabilities whose create/update hands an IAM role to a service.
	rolePassers := map[string]string{
		"ecs":                  "executionRoleArn on the task definition",
		"apprunner":            "AccessRoleArn, the private-ECR access role",
		"lambda":               "Role, the function execution role",
		"eks":                  "roleArn + nodeRole (control-plane and node roles)",
		"eks-addon":            "the addon's service role (e.g. ebs-csi)",
		"eks-podidentity":      "roleArn passed to the pod-identity association",
		"eventbridgescheduler": "RoleArn, the schedule's target role",
		"vpc":                  "the flow-logs delivery role (flowLogs.enabled)",
	}
	// role-passing but iam:PassRole declared NOWHERE — a fail-loud gap banked for unfreeze
	// (the pass 403s mid-apply and apply reports failed, so not the silent class D716 admits).
	register := map[string]string{
		"backupplan": "D1016: IamRoleArn on CreateBackupSelection is undeclared — the plan lands, the selection 403s, a backup plan that backs up nothing",
		"s3":         "D1016: replication_role_arn -> <Role> is undeclared (conditional on replication)",
		"cloudtrail": "D1016: cloudWatchLogsRoleArn is undeclared (conditional on a CloudWatch Logs group)",
	}

	// rich attrs so a PassRole gated on a condition (vpc's flow logs) still fires.
	richAttrs := map[string]any{"flowLogs.enabled": true}
	declaresPassRole := func(capability string) bool {
		for _, op := range []string{"create", "adopt", "update"} {
			for _, p := range provider.PermissionsFor("aws", capability, op, richAttrs) {
				if p == "iam:PassRole" {
					return true
				}
			}
		}
		return false
	}

	var problems []string
	for capability, why := range rolePassers {
		if _, both := register[capability]; both {
			problems = append(problems, capability+" is in BOTH rolePassers and the register")
			continue
		}
		if !declaresPassRole(capability) {
			problems = append(problems, capability+" passes a role ("+why+
				") but no arm declares iam:PassRole — the preflight passes and the pass 403s mid-apply")
		}
	}
	for capability, reason := range register {
		if declaresPassRole(capability) {
			problems = append(problems, capability+" now declares iam:PassRole — drop it from the register ("+reason+")")
		}
	}
	sort.Strings(problems)
	if len(problems) > 0 {
		t.Errorf("iam:PassRole coverage drifted:\n  %s", strings.Join(problems, "\n  "))
	}
}
