// GCP IAM custom role request building (D105): the semantic core of the GCP
// capability.authorization.role driver — the SAME vocabulary AWS customer policies
// and Azure custom roleDefinitions fulfil. A custom role is a flat SET OF NAMED
// PERMISSIONS (includedPermissions), never an inline policy with resources/conditions/
// effects (invariant #4). The role is content-addressed by a deterministic roleId.
// access.mutating / access.privileged are DERIVED from the permission verbs, and a
// candidate that declares a false read-only / unprivileged claim is refused.
package gcp

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"
)

// gcRoleIDBad collapses everything outside the custom-role id charset ([a-zA-Z0-9_.]);
// note dashes are NOT allowed in a role id (unlike most GCP resource names).
var gcRoleIDBad = regexp.MustCompile(`[^a-z0-9_]+`)

// gcPermOK bounds a GCP permission string (service.resource.verb) before it enters a
// request body.
var gcPermOK = regexp.MustCompile(`^[a-z][a-z0-9]*(\.[a-zA-Z0-9]+)+$`)

// CustomRolePlan is the attribute-derived shape a create assembles.
type CustomRolePlan struct {
	RoleID      string
	Permissions []string
}

// gcRoleID is the deterministic custom-role id (letters/digits/underscores only).
func gcRoleID(environment, capability string, generation int) string {
	slug := capability
	if environment != "" {
		slug += "_" + environment
	}
	slug = gcRoleIDBad.ReplaceAllString(strings.ToLower(slug), "_")
	hashInput := environment + "|" + capability
	if generation >= 2 {
		hashInput += fmt.Sprintf("|g%d", generation)
	}
	sum := sha256.Sum256([]byte(hashInput))
	tail := "_" + hex.EncodeToString(sum[:])[:8]
	const maxLen = 64
	if len(slug)+len(tail) > maxLen {
		slug = slug[:maxLen-len(tail)]
	}
	id := "pv_" + strings.Trim(slug, "_") + tail
	return id
}

// BuildCustomRole maps capability.authorization.role attributes to a role plan.
// Every error is a preflight refusal, never a silent drop.
func BuildCustomRole(project, environment, capability string,
	attrs, impl map[string]any, generation int) (CustomRolePlan, error) {
	p := CustomRolePlan{RoleID: gcRoleID(environment, capability, generation)}
	declaredMut, mutSet := false, false
	declaredPriv, privSet := false, false
	for _, path := range sortedKeysG(attrs) {
		raw := attrs[path]
		switch path {
		case "role.permissions":
			perms, err := toStringList(raw)
			if err != nil {
				return CustomRolePlan{}, fmt.Errorf("role.permissions is not a list of strings: %v", err)
			}
			for _, perm := range perms {
				if !gcPermOK.MatchString(perm) {
					return CustomRolePlan{}, fmt.Errorf("permission %q is not a valid GCP permission (service.resource.verb)", perm)
				}
			}
			p.Permissions = perms
		case "access.mutating":
			declaredMut, _ = raw.(bool)
			mutSet = true
		case "access.privileged":
			declaredPriv, _ = raw.(bool)
			privSet = true
		case "service.managed":
			if raw != true {
				return CustomRolePlan{}, fmt.Errorf("service.managed=false cannot be honored by IAM")
			}
		default:
			return CustomRolePlan{}, fmt.Errorf(
				"attribute %s has no custom-role mapping — refusing rather than silently dropping it "+
					"(a role is a flat permission SET, never an inline policy with resources/conditions)", path)
		}
	}
	if len(p.Permissions) == 0 {
		return CustomRolePlan{}, fmt.Errorf("a custom role requires a non-empty role.permissions set")
	}
	// least-privilege honesty: a declared derived-property that contradicts the
	// actual permission set is a false claim — refused, never silently granted.
	if mutSet && gcRoleMutating(p.Permissions) != declaredMut {
		return CustomRolePlan{}, fmt.Errorf(
			"access.mutating=%t contradicts the permission set (it %s a write action) — refusing a false claim",
			declaredMut, ifThen(gcRoleMutating(p.Permissions), "includes", "excludes"))
	}
	if privSet && gcRolePrivilegedSet(p.Permissions) != declaredPriv {
		return CustomRolePlan{}, fmt.Errorf(
			"access.privileged=%t contradicts the permission set (it %s an IAM/admin action) — refusing a false claim",
			declaredPriv, ifThen(gcRolePrivilegedSet(p.Permissions), "includes", "excludes"))
	}
	if !projectOK.MatchString(project) {
		return CustomRolePlan{}, fmt.Errorf("project %q is invalid", project)
	}
	return p, nil
}

// gcPermMutating: a GCP permission is a read iff its verb is get/list (or a
// getIamPolicy read); anything else mutates.
func gcPermMutating(perm string) bool {
	verb := perm[strings.LastIndex(perm, ".")+1:]
	switch verb {
	case "get", "list", "getIamPolicy", "testIamPermissions":
		return false
	}
	return true
}

func gcRoleMutating(perms []string) bool {
	for _, p := range perms {
		if gcPermMutating(p) {
			return true
		}
	}
	return false
}

// gcPermPrivileged: a permission confers IAM/admin control iff it sets an IAM
// policy, is an iam.* permission, or is a wildcard.
func gcPermPrivileged(perm string) bool {
	if strings.HasSuffix(perm, ".setIamPolicy") || strings.HasPrefix(perm, "iam.") {
		return true
	}
	return strings.Contains(perm, "*")
}

func gcRolePrivilegedSet(perms []string) bool {
	for _, p := range perms {
		if gcPermPrivileged(p) {
			return true
		}
	}
	return false
}

func ifThen(cond bool, a, b string) string {
	if cond {
		return a
	}
	return b
}

// toStringList converts a candidate list attribute ([]any of strings) to []string.
func toStringList(raw any) ([]string, error) {
	items, ok := raw.([]any)
	if !ok {
		// already a []string?
		if ss, ok := raw.([]string); ok {
			return ss, nil
		}
		return nil, fmt.Errorf("not a list")
	}
	out := make([]string, 0, len(items))
	for _, it := range items {
		s, ok := it.(string)
		if !ok {
			return nil, fmt.Errorf("element %v is not a string", it)
		}
		out = append(out, s)
	}
	return out, nil
}
