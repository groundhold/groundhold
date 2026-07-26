// IAM role-policy attachment request building (D104): the semantic core of the AWS
// capability.authorization.grant driver — the SAME vocabulary GCP IAM bindings and
// Azure role assignments fulfil. On AWS a grant is a MANAGED POLICY attached to a
// ROLE (AttachRolePolicy); the policy is a NAMED role reference (an ARN), never an
// inline document (invariant #4). The attachment is content-addressed by
// (roleName, policyArn), so there are no ownership tags — groundhold detaches only the
// exact policy it attached. AWS grants are principal-attached with the resource set
// INSIDE the policy, so access.scope=resource is REFUSED (that needs an inline
// policy v0 excludes) and account is the honest breadth — an honest one-cloud gap.
package aws

import (
	"fmt"
	"regexp"
	"strings"
)

// awsPolicyArnOK bounds a managed-policy ARN before it is placed in a request body
// (AWS-managed arn:aws:iam::aws:policy/... or a customer arn:aws:iam::<acct>:policy/...).
var awsPolicyArnOK = regexp.MustCompile(`^arn:aws:iam::(aws|[0-9]{12}):policy/[A-Za-z0-9+=,.@_/-]+$`)

// awsGrantRoleNameOK bounds the role name a policy attaches to.
var awsGrantRoleNameOK = regexp.MustCompile(`^[A-Za-z0-9_+=,.@-]{1,64}$`)

// RolePolicyPlan is the attribute-derived shape a create assembles.
type RolePolicyPlan struct {
	RoleName  string
	PolicyArn string
}

// BuildRolePolicyAttachment maps capability.authorization.grant attributes to an
// attachment plan. Every error is a preflight refusal, never a silent drop.
func BuildRolePolicyAttachment(environment, capability string,
	attrs, impl map[string]any, generation int) (RolePolicyPlan, error) {
	p := RolePolicyPlan{}
	declaredPriv, privSet := false, false
	for _, path := range sortedKeys(attrs) {
		raw := attrs[path]
		switch path {
		case "grant.role":
			p.PolicyArn, _ = raw.(string)
		case "grant.principal":
			p.RoleName, _ = raw.(string)
		case "access.scope":
			switch raw {
			case "account":
				// a managed-policy attachment is principal-scoped (the v0 path)
			case "resource":
				return RolePolicyPlan{}, fmt.Errorf(
					"access.scope=resource cannot be honored on AWS — a managed-policy attachment is " +
						"principal-scoped with the resource set INSIDE the policy; resource-scoping needs an " +
						"inline policy (the expression language v0 excludes). account is the honest breadth")
			default:
				return RolePolicyPlan{}, fmt.Errorf("access.scope %v has no mapping", raw)
			}
		case "access.privileged":
			declaredPriv, _ = raw.(bool)
			privSet = true
		case "service.managed":
			if raw != true {
				return RolePolicyPlan{}, fmt.Errorf("service.managed=false cannot be honored by IAM")
			}
		default:
			return RolePolicyPlan{}, fmt.Errorf(
				"attribute %s has no IAM attachment mapping — refusing rather than silently dropping it "+
					"(a grant references a NAMED policy, never an inline document)", path)
		}
	}
	if p.PolicyArn == "" || !awsPolicyArnOK.MatchString(p.PolicyArn) {
		return RolePolicyPlan{}, fmt.Errorf("grant.role %q is missing or not a valid managed-policy ARN", p.PolicyArn)
	}
	// the principal may arrive as an OPERAND (D277): implementation.principal —
	// typically a $ref to a same-plan role's roleName output (D226), which also
	// orders the attach AFTER the role's create. One truth only: if the
	// grant.principal ATTRIBUTE is also declared, the two must agree, else the
	// verified claim and the wired reality would diverge.
	if given, ok := impl["principal"]; ok {
		name, isStr := given.(string)
		if !isStr || name == "" {
			return RolePolicyPlan{}, fmt.Errorf(
				"implementation.principal %v is not a role name (a $ref resolves before the driver sees it)", given)
		}
		if p.RoleName != "" && p.RoleName != name {
			return RolePolicyPlan{}, fmt.Errorf(
				"grant.principal %q and implementation.principal %q disagree — one source of truth, refusing",
				p.RoleName, name)
		}
		p.RoleName = name
	}
	if p.RoleName == "" || !awsGrantRoleNameOK.MatchString(p.RoleName) {
		return RolePolicyPlan{}, fmt.Errorf("grant.principal %q is missing or not a valid IAM role name (declare the attribute or wire implementation.principal)", p.RoleName)
	}
	if privSet {
		priv, known := classifyAWSPolicy(p.PolicyArn)
		if known && priv != declaredPriv {
			return RolePolicyPlan{}, fmt.Errorf(
				"access.privileged=%t contradicts policy %q (classified privileged=%t) — refusing a false "+
					"least-privilege claim", declaredPriv, p.PolicyArn, priv)
		}
	}
	return p, nil
}

// classifyAWSPolicy reports whether a managed policy confers privileged access and
// whether groundhold can classify it. A curated v0 set: AdministratorAccess /
// PowerUserAccess / any *FullAccess* are privileged; *ReadOnly* is least-privilege;
// everything else is UNKNOWN (the four-valued honest answer).
func classifyAWSPolicy(arn string) (privileged, known bool) {
	name := arn[strings.LastIndex(arn, "/")+1:]
	switch name {
	case "AdministratorAccess", "PowerUserAccess", "IAMFullAccess":
		return true, true
	}
	if strings.Contains(name, "FullAccess") {
		return true, true
	}
	if strings.Contains(name, "ReadOnly") {
		return false, true
	}
	return false, false
}
