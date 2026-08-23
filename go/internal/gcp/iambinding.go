// GCP IAM binding request building (D104): the semantic core of the GCP
// capability.authorization.grant driver — the SAME vocabulary AWS role-policy
// attachments and Azure role assignments fulfil. A grant is a NAMED ROLE conferred
// on a MEMBER at a scope; groundhold adds/removes exactly that {role, member} pair in
// the scope's IAM policy (a read-modify-write), never authoring a policy document
// (invariant #4). v0 targets ACCOUNT scope (the project IAM policy); resource-scoped
// bindings need each target resource's own IAM API and are deferred. The binding is
// CONTENT-ADDRESSED — its identity IS (project, role, member), so groundhold removes
// only the exact member it granted, never another principal's access.
package gcp

import (
	"fmt"
	"regexp"
	"strings"
)

// gcpRoleOK bounds a role id before it is placed in a policy body: a predefined
// role (roles/X) or a project/org custom role.
var gcpRoleOK = regexp.MustCompile(`^(roles/[a-zA-Z0-9_.]+|projects/[a-z0-9-]+/roles/[a-zA-Z0-9_.]+|organizations/[0-9]+/roles/[a-zA-Z0-9_.]+)$`)

// gcpMemberOK bounds an IAM member. The id part carries no ':' so it survives the
// providerId split; v0 is the typed principal forms (a workload grant is a
// serviceAccount). allUsers/allAuthenticatedUsers (public) are a different concern
// and are not this capability.
var gcpMemberOK = regexp.MustCompile(`^(serviceAccount|user|group|domain):[^:]+$`)

// IAMBindingPlan is the attribute-derived shape a create assembles.
type IAMBindingPlan struct {
	Role   string
	Member string
}

// BuildIAMBinding maps capability.authorization.grant attributes to a binding plan.
// Every error is a preflight refusal, never a silent drop.
func BuildIAMBinding(project, environment, capability string,
	attrs, impl map[string]any, generation int) (IAMBindingPlan, error) {
	p := IAMBindingPlan{}
	declaredPriv, privSet := false, false
	for _, path := range sortedKeysG(attrs) {
		raw := attrs[path]
		switch path {
		case "grant.role":
			p.Role, _ = raw.(string)
		case "grant.principal":
			p.Member, _ = raw.(string)
		case "access.scope":
			switch raw {
			case "account":
				// project-level binding (the v0 path)
			case "resource":
				return IAMBindingPlan{}, fmt.Errorf(
					"access.scope=resource is deferred for GCP in v0 — a resource-scoped binding needs " +
						"the target resource's own getIamPolicy/setIamPolicy API; v0 grants at account scope")
			default:
				return IAMBindingPlan{}, fmt.Errorf("access.scope %v has no mapping", raw)
			}
		case "access.privileged":
			declaredPriv, _ = raw.(bool)
			privSet = true
		case "service.managed":
			if raw != true {
				return IAMBindingPlan{}, fmt.Errorf("service.managed=false cannot be honored by IAM")
			}
		default:
			return IAMBindingPlan{}, fmt.Errorf(
				"attribute %s has no IAM binding mapping — refusing rather than silently dropping it "+
					"(a grant references a NAMED role, never an inline policy)", path)
		}
	}
	if p.Role == "" || !gcpRoleOK.MatchString(p.Role) {
		return IAMBindingPlan{}, fmt.Errorf("grant.role %q is missing or not a valid IAM role id", p.Role)
	}
	if p.Member == "" || !gcpMemberOK.MatchString(p.Member) {
		return IAMBindingPlan{}, fmt.Errorf(
			"grant.principal %q is missing or not a valid typed IAM member (e.g. serviceAccount:x@y)", p.Member)
	}
	// least-privilege honesty: a KNOWN role whose privilege contradicts the
	// declared access.privileged is refused (never silently granted under a false
	// least-privilege claim); an unclassifiable role is accepted (observe leaves
	// access.privileged unverifiable rather than guessing).
	if privSet {
		priv, known := classifyGCPRole(p.Role)
		if known && priv != declaredPriv {
			return IAMBindingPlan{}, fmt.Errorf(
				"access.privileged=%t contradicts role %q (classified privileged=%t) — refusing a false "+
					"least-privilege claim", declaredPriv, p.Role, priv)
		}
	}
	if !projectOK.MatchString(project) {
		return IAMBindingPlan{}, fmt.Errorf("project %q is invalid", project)
	}
	return p, nil
}

// gcpRoleIsPredefined reports whether a role id names a role GOOGLE defines
// (`roles/...`) rather than one the customer wrote (`projects/<p>/roles/...` or
// `organizations/<o>/roles/...`). The id itself carries the distinction, which is
// why the unclassifiable-privilege diagnostic can name the TRUE cause instead of
// asserting one it never checked (D1225): calling a predefined role "custom" points
// the operator at their own estate for a gap that is groundhold's curated set.
func gcpRoleIsPredefined(role string) bool { return strings.HasPrefix(role, "roles/") }

// classifyGCPRole reports whether a role confers privileged/administrative access
// and whether groundhold can classify it at all. A curated v0 set: owner/editor and
// any *admin* role are privileged; well-known viewer/reader roles are least-
// privilege; everything else is UNKNOWN (the four-valued honest answer).
func classifyGCPRole(role string) (privileged, known bool) {
	// D1228, the GCP half. The substring tests below ("admin", a viewer/reader
	// suffix) read a name Google chose for a PREDEFINED role. A custom role's name is
	// chosen by whoever wrote it, so `projects/p/roles/companyViewer` matched the
	// least-privilege branch and reported access.privileged=FALSE over a role that
	// can hold any permission at all. A name only its author picked is not evidence
	// about the permissions behind it.
	if !gcpRoleIsPredefined(role) {
		return false, false
	}
	switch role {
	case "roles/owner", "roles/editor":
		return true, true
	case "roles/viewer":
		return false, true
	}
	lower := strings.ToLower(role)
	if strings.Contains(lower, "admin") {
		return true, true
	}
	if strings.HasSuffix(lower, "viewer") || strings.HasSuffix(lower, "reader") ||
		strings.Contains(lower, "objectviewer") {
		return false, true
	}
	return false, false
}

// bindingPrivilegeFromRole classifies a grant's privilege by READING the role
// definition, for the roles whose ID proves nothing.
//
// D1231, the GCP half of the AWS change. Two populations reach here and BOTH are
// large in the field: custom roles (whose id its author chose — D1228) and the
// predefined roles outside groundhold's curated pattern set, which in a real project
// was 37 of 49 bindings. `roles.get` answers for both: it returns the role's
// `includedPermissions`, expanded to concrete permission strings even for predefined
// roles (verified against the live API — `roles/owner` returns 13,568 of them, and
// not one contains a wildcard).
//
// The asymmetry matches AWS: `true` on POSITIVE evidence only. `gcPermPrivileged`
// recognises escalation CONTROL — `*.setIamPolicy`, the `iam.` namespace — and that
// list is curated rather than exhaustive (`cloudbuild.builds.create` and
// `deploymentmanager.deployments.create` are escalation paths matching nothing in
// it), so a miss WITHHOLDS instead of concluding least privilege.
//
// Returns (privileged, known, why); known=false always carries a why.
func (d *Driver) bindingPrivilegeFromRole(role string) (privileged, known bool, why string) {
	perms, err := d.rolePermissionsCached(role)
	if err != nil {
		return false, false, "its definition did not read (" + err.Error() + ")"
	}
	if len(perms) == 0 {
		return false, false, "its definition lists no permissions"
	}
	if gcRolePrivilegedSet(perms) {
		return true, true, ""
	}
	return false, false, "its definition includes no permission in groundhold's escalation " +
		"set (that set is curated, not exhaustive, so this is NOT proof of least privilege)"
}
