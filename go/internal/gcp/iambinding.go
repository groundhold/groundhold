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

// classifyGCPRole reports whether a role confers privileged/administrative access
// and whether groundhold can classify it at all. A curated v0 set: owner/editor and
// any *admin* role are privileged; well-known viewer/reader roles are least-
// privilege; everything else is UNKNOWN (the four-valued honest answer).
func classifyGCPRole(role string) (privileged, known bool) {
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
