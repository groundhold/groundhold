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
	"errors"
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

// grantPrivilegeFromDocument classifies a grant's privilege by READING the policy
// document, for the policies whose NAME proves nothing (D1228: a customer-managed
// policy's name is whatever its author typed).
//
// D1231. This is the evidence standard `capability.authorization.role` has always
// held — it derives privilege from the ACTION VERBS — brought to the capability that
// was guessing from a substring. Two reviews recommended it independently; what
// changed the calculus was that `iam:GetPolicy`/`iam:GetPolicyVersion` ship inside
// AWS's own `ReadOnlyAccess` and `SecurityAudit`, so the read costs an identity
// nothing it does not already have.
//
// The asymmetry is the whole design. `true` is emitted on POSITIVE evidence only —
// an action that confers control. Absence of such an action is NOT evidence of least
// privilege: the pattern set is a curated list, not a proof, and known escalation
// paths (`lambda:UpdateFunctionCode` on a privileged function, `ssm:SendCommand`)
// match nothing in it. So "no match" WITHHOLDS. Under-reporting privilege is the
// direction D797 called the most dangerous this tool has, and a verb table cannot
// rule it out.
//
// Returns (privileged, known, why). known=false always carries a `why` naming what
// stopped it — a read that failed, or a document that granted no matching action.
func (d *Driver) grantPrivilegeFromDocument(policyArn string) (privileged, known bool, why string) {
	actions, err := d.policyActionsCached(policyArn)
	switch {
	case errors.Is(err, errPolicyComplement):
		// `Allow` with `NotAction` — "everything EXCEPT these". The sibling refuses to
		// ENUMERATE that set, and rightly; but refusing to enumerate is not a reason to
		// withhold the CLASSIFICATION. A complement is the widest grant there is.
		return true, true, ""
	case errors.Is(err, errPolicyAbsent):
		return false, false, "the policy document is gone"
	case err != nil:
		return false, false, "its document did not read (" + err.Error() + ")"
	}
	if awsPolicyPrivileged(actions) {
		return true, true, ""
	}
	return false, false, "its document grants no action in groundhold's escalation set " +
		"(that set is curated, not exhaustive, so this is NOT proof of least privilege)"
}

// policyActionsCached memoizes the document read for ONE observe sweep. Grants share
// policies heavily — a real account showed 87 grants over far fewer distinct policies
// — so without this the same document is fetched once per attachment.
//
// The cache is per-SWEEP, deliberately, not per-process: the runtime's thesis is
// measuring reality at an instant (`--at`), and a long-lived driver (the MCP server,
// the console BFF) would otherwise serve one instant's document under another
// instant's clock. Failures are cached too — 87 grants re-asking one denied policy
// produces 87 identical diagnostics and invites throttling.
func (d *Driver) policyActionsCached(policyArn string) ([]string, error) {
	if d.policyDocs == nil {
		d.policyDocs = map[string]cachedActions{}
	}
	if c, ok := d.policyDocs[policyArn]; ok {
		return c.actions, c.err
	}
	a, e := d.getCustomPolicyActions(policyArn)
	d.policyDocs[policyArn] = cachedActions{actions: a, err: e}
	return a, e
}

type cachedActions struct {
	actions []string
	err     error
}

// awsPolicyIsAWSManaged reports whether a managed-policy ARN names a policy AWS
// publishes rather than one the account wrote. AWS-managed policies carry the
// literal account segment `aws` (`arn:<partition>:iam::aws:policy/<name>`), so the
// ARN itself settles it in every partition — the partition is NOT hardcoded, or
// aws-us-gov and aws-cn would read as customer-managed. See D1225: the diagnostic
// must name the cause it checked, not the one it assumed.
func awsPolicyIsAWSManaged(arn string) bool {
	p := strings.Split(arn, ":")
	return len(p) >= 6 && p[0] == "arn" && p[2] == "iam" && p[4] == "aws"
}

// classifyAWSPolicy reports whether a managed policy confers privileged access and
// whether groundhold can classify it. A curated v0 set: AdministratorAccess /
// PowerUserAccess / any *FullAccess* are privileged; *ReadOnly* is least-privilege;
// everything else is UNKNOWN (the four-valued honest answer).
func classifyAWSPolicy(arn string) (privileged, known bool) {
	// D1228. The heuristic below reads a NAME. That is evidence only when AWS chose
	// the name: for a customer-managed policy the name is whatever its author typed,
	// so `CompanyReadOnlyBaseline` matched "ReadOnly" and reported
	// access.privileged=FALSE — measured — over a document that may hold
	// `"Action": "*"`. Under-reporting privilege is, in D797's own words about the
	// sibling capability, "the most dangerous direction this tool has", and that
	// sibling (capability.authorization.role) already derives privilege from the
	// ACTION VERBS rather than the name. Until this one can read the document too,
	// an author-chosen name buys nothing and the answer is UNKNOWN.
	if !awsPolicyIsAWSManaged(arn) {
		return false, false
	}
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
