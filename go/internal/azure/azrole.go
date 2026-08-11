// Azure RBAC role-assignment request building (D104): the Azure half of the
// capability.authorization.grant driver — the SAME vocabulary GCP IAM bindings and
// AWS role-policy attachments fulfil. On Azure a grant is the cleanest of the three:
// a real roleAssignment object binding a principal to a role definition at a scope.
// grant.role names a role (a built-in role like "Reader", or a raw role-definition
// GUID) — never an inline policy (invariant #4). The assignment NAME is a
// DETERMINISTIC GUID from (scope, principal, role), so a create is idempotent and the
// binding is content-addressed (no ownership tags). v0 targets account (subscription)
// scope; resource-scoped assignments are deferred.
package azure

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"sort"
)

const roleAssignmentAPIVersion = "2022-04-01"

// azGUIDOK bounds a raw GUID (role-definition id or principal id).
var azGUIDOK = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

// azBuiltinRole maps a named built-in role to its well-known role-definition GUID
// and privilege classification — the curated v0 set.
var azBuiltinRole = map[string]struct {
	guid       string
	privileged bool
}{
	"Owner":                     {"8e3af657-a8ff-443c-a75c-2fe8c4bcb635", true},
	"Contributor":               {"b24988ac-6180-42a0-ab88-20f7382dd24c", true},
	"User Access Administrator": {"18d7d88d-d35e-4fb5-a5c3-7773c20a72d9", true},
	"Reader":                    {"acdd72a7-3385-48ef-bd42-f606fba81ae7", false},
}

// AzureRolePlan is the attribute-derived shape a create assembles.
type AzureRolePlan struct {
	RoleGuid      string // the role-definition GUID
	PrincipalID   string // the principal object id (a GUID)
	PrincipalType string // D896: User | Group | ServicePrincipal — Azure rejects a wrong type
}

// BuildAzureRole maps capability.authorization.grant attributes to an assignment
// plan. Every error is a preflight refusal, never a silent drop.
func BuildAzureRole(environment, capability string,
	attrs, impl map[string]any, generation int) (AzureRolePlan, error) {
	p := AzureRolePlan{}
	declaredPriv, privSet := false, false
	var roleRaw string
	paths := make([]string, 0, len(attrs))
	for k := range attrs {
		paths = append(paths, k)
	}
	sort.Strings(paths)

	for _, path := range paths {
		raw := attrs[path]
		switch path {
		case "grant.role":
			roleRaw, _ = raw.(string)
		case "grant.principal":
			p.PrincipalID, _ = raw.(string)
		case "access.scope":
			switch raw {
			case "account":
				// subscription-scope assignment (the v0 path)
			case "resource":
				return AzureRolePlan{}, fmt.Errorf(
					"access.scope=resource is deferred for Azure in v0 — a resource-scoped assignment " +
						"targets the resource id as its scope; v0 grants at subscription (account) scope")
			default:
				return AzureRolePlan{}, fmt.Errorf("access.scope %v has no mapping", raw)
			}
		case "access.privileged":
			declaredPriv, _ = raw.(bool)
			privSet = true
		case "service.managed":
			if raw != true {
				return AzureRolePlan{}, fmt.Errorf("service.managed=false cannot be honored by Azure RBAC")
			}
		default:
			return AzureRolePlan{}, fmt.Errorf(
				"attribute %s has no role-assignment mapping — refusing rather than silently dropping it "+
					"(a grant references a NAMED role, never an inline policy)", path)
		}
	}
	// resolve grant.role -> role-definition GUID + (optional) known privilege.
	roleKnownPriv, roleKnown := false, false
	if b, ok := azBuiltinRole[roleRaw]; ok {
		p.RoleGuid, roleKnownPriv, roleKnown = b.guid, b.privileged, true
	} else if azGUIDOK.MatchString(roleRaw) {
		p.RoleGuid = roleRaw // a raw role-definition GUID; privilege unclassifiable
	} else {
		return AzureRolePlan{}, fmt.Errorf(
			"grant.role %q is missing or not a known built-in role name / role-definition GUID", roleRaw)
	}
	if p.PrincipalID == "" || !azGUIDOK.MatchString(p.PrincipalID) {
		return AzureRolePlan{}, fmt.Errorf(
			"grant.principal %q is missing or not a valid principal object id (a GUID)", p.PrincipalID)
	}
	// D896: an object GUID does not encode its principal type, and Azure REJECTS a role
	// assignment whose declared principalType does not match the real principal ("has type
	// 'User', which is different from specified PrincipalType 'ServicePrincipal'"). The
	// driver used to hardcode ServicePrincipal, so a grant to a User or Group was
	// uncreatable. The operator names the type (default ServicePrincipal — the workload
	// grant, the common case); a wrong value is refused rather than sent to a 400.
	p.PrincipalType, _ = impl["principal_type"].(string)
	if p.PrincipalType == "" {
		p.PrincipalType = "ServicePrincipal"
	}
	switch p.PrincipalType {
	case "User", "Group", "ServicePrincipal":
	default:
		return AzureRolePlan{}, fmt.Errorf(
			"implementation.principal_type %q must be User, Group, or ServicePrincipal", p.PrincipalType)
	}
	if privSet && roleKnown && roleKnownPriv != declaredPriv {
		return AzureRolePlan{}, fmt.Errorf(
			"access.privileged=%t contradicts role %q (classified privileged=%t) — refusing a false "+
				"least-privilege claim", declaredPriv, roleRaw, roleKnownPriv)
	}
	return p, nil
}

// classifyAzureRoleGuid reverse-classifies a role-definition GUID's privilege for
// observe: known built-in GUID -> its classification; anything else UNKNOWN (the
// four-valued honest answer — a custom role's privilege is not guessed).
func classifyAzureRoleGuid(guid string) (privileged, known bool) {
	for _, b := range azBuiltinRole {
		if b.guid == guid {
			return b.privileged, true
		}
	}
	return false, false
}

// azRoleNameForGuid reverse-maps a known built-in GUID to its name (for observe);
// an unknown GUID reports itself.
func azRoleNameForGuid(guid string) string {
	for name, b := range azBuiltinRole {
		if b.guid == guid {
			return name
		}
	}
	return guid
}

// azAssignmentGUID is the DETERMINISTIC assignment name from (scope, principal,
// role) — a stable GUID so a create is idempotent and the binding is
// content-addressed. Formatted 8-4-4-4-12 from a sha256 of the operands.
func azAssignmentGUID(scope, principal, roleGuid string) string {
	sum := sha256.Sum256([]byte(scope + "|" + principal + "|" + roleGuid))
	h := hex.EncodeToString(sum[:])
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:32]
}
