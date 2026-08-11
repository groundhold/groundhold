// Azure custom roleDefinition request building (D105): the Azure half of the
// capability.authorization.role driver — the SAME vocabulary GCP custom roles and AWS
// customer policies fulfil. On Azure a custom role is a roleDefinition whose
// permissions[].actions is a flat SET; the driver builds exactly that and refuses the
// non-flat siblings (notActions/dataActions/conditions) — the expression language
// invariant #4 excludes. access.mutating / access.privileged are DERIVED from the
// action verbs. The role is content-addressed by a deterministic GUID name.
package azure

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"sort"
	"strings"
)

const customRoleAPIVersion = "2022-04-01"

// azActionOK bounds an Azure action string: a lone *, or a provider path with
// segments (Microsoft.Storage/storageAccounts/read, */read, Microsoft.Storage/*).
var azActionOK = regexp.MustCompile(`^(\*|[A-Za-z0-9.*]+(/[A-Za-z0-9.*]+)+)$`)

// AzureCustomRolePlan is the attribute-derived shape a create assembles.
type AzureCustomRolePlan struct {
	RoleName    string
	Permissions []string
}

// BuildAzureCustomRole maps capability.authorization.role attributes to a plan.
// Every error is a preflight refusal, never a silent drop.
func BuildAzureCustomRole(environment, capability string,
	attrs, impl map[string]any, generation int) (AzureCustomRolePlan, error) {
	p := AzureCustomRolePlan{RoleName: azCustomRoleName(capability, environment)}
	declaredMut, mutSet := false, false
	declaredPriv, privSet := false, false
	paths := make([]string, 0, len(attrs))
	for k := range attrs {
		paths = append(paths, k)
	}
	sort.Strings(paths)

	for _, path := range paths {
		raw := attrs[path]
		switch path {
		case "role.permissions":
			perms, err := toStringListAz(raw)
			if err != nil {
				return AzureCustomRolePlan{}, fmt.Errorf("role.permissions is not a list of strings: %v", err)
			}
			for _, a := range perms {
				if !azActionOK.MatchString(a) {
					return AzureCustomRolePlan{}, fmt.Errorf("action %q is not a valid Azure action", a)
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
				return AzureCustomRolePlan{}, fmt.Errorf("service.managed=false cannot be honored by Azure RBAC")
			}
		default:
			return AzureCustomRolePlan{}, fmt.Errorf(
				"attribute %s has no custom-role mapping — refusing rather than silently dropping it "+
					"(a role is a flat actions SET; notActions/dataActions/conditions are refused)", path)
		}
	}
	if len(p.Permissions) == 0 {
		return AzureCustomRolePlan{}, fmt.Errorf("a custom role requires a non-empty role.permissions set")
	}
	if mutSet && azRoleMutating(p.Permissions) != declaredMut {
		return AzureCustomRolePlan{}, fmt.Errorf(
			"access.mutating=%t contradicts the action set — refusing a false claim", declaredMut)
	}
	if privSet && azRolePrivileged(p.Permissions) != declaredPriv {
		return AzureCustomRolePlan{}, fmt.Errorf(
			"access.privileged=%t contradicts the action set — refusing a false claim", declaredPriv)
	}
	return p, nil
}

func azActionMutating(a string) bool {
	if a == "*" {
		return true
	}
	return !strings.HasSuffix(a, "/read")
}

// azRoleActions unions the Actions of EVERY permission block on a role definition.
//
// D797. It used to read Permissions[0].Actions. Azure allows a role to carry several
// permission blocks, and discover reverse-maps roles this driver did not author, so a
// role whose wildcard lived in the second block reported access.privileged=false.
//
// NotActions are deliberately NOT subtracted. They can only NARROW what a role grants,
// so ignoring them over-reports privilege — the safe side of a security attribute — and
// the diagnostic says the narrowing exists rather than pretending the set is exact.
func azRoleActions(doc azureCustomRoleDoc) (actions []string, narrowed bool) {
	seen := map[string]bool{}
	for _, p := range doc.Properties.Permissions {
		if len(p.NotActions) > 0 {
			narrowed = true
		}
		for _, a := range p.Actions {
			if !seen[a] {
				seen[a] = true
				actions = append(actions, a)
			}
		}
	}
	sort.Strings(actions)
	return actions, narrowed
}

func azRoleMutating(perms []string) bool {
	for _, a := range perms {
		if azActionMutating(a) {
			return true
		}
	}
	return false
}

func azActionPrivileged(a string) bool {
	if a == "*" {
		return true
	}
	if strings.HasPrefix(a, "Microsoft.Authorization/") && !strings.HasSuffix(a, "/read") {
		return true
	}
	return strings.HasSuffix(a, "/*")
}

func azRolePrivileged(perms []string) bool {
	for _, a := range perms {
		if azActionPrivileged(a) {
			return true
		}
	}
	return false
}

// azCustomRoleName is the role's display name, and — through azRoleDefGUID — half of
// its content-addressed identity. The delete path re-derives it to answer "is this
// role one of ours?" without a read (D458), so it must stay a pure function of
// (capability, environment).
func azCustomRoleName(capability, environment string) string {
	return "groundhold " + capability + " (" + environment + ")"
}

// azRoleDefGUID is the DETERMINISTIC roleDefinition name from (scope, roleName) — a
// stable GUID so create is idempotent and the role is content-addressed.
func azRoleDefGUID(scope, roleName string) string {
	sum := sha256.Sum256([]byte("roledef|" + scope + "|" + roleName))
	h := hex.EncodeToString(sum[:])
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:32]
}

func toStringListAz(raw any) ([]string, error) {
	if ss, ok := raw.([]string); ok {
		return ss, nil
	}
	items, ok := raw.([]any)
	if !ok {
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
