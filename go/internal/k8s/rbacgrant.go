// k8s RBAC RoleBinding -> capability.authorization.grant (D104 vocabulary, third
// twin after gcp.iam and aws.iam). A RoleBinding confers a NAMED role on
// principals within a namespace: roleRef is grant.role, the subject is
// grant.principal, the namespace is the scope (access.scope=resource — a
// ClusterRoleBinding's account breadth is a later slice). access.privileged is
// classified from a CURATED set of well-known privileged built-in ClusterRoles;
// a custom role groundhold cannot classify is left UNVERIFIABLE, never guessed
// (four-valued honesty, exactly as the vocab requires).
package k8s

import (
	"fmt"
	"strings"
)

// roleRef is a RoleBinding's reference to the role it confers.
type roleRef struct {
	APIGroup string `json:"apiGroup"`
	Kind     string `json:"kind"` // Role | ClusterRole
	Name     string `json:"name"`
}

// subject is one entity a RoleBinding grants access to.
type subject struct {
	Kind      string `json:"kind"` // User | Group | ServiceAccount
	Name      string `json:"name"`
	Namespace string `json:"namespace,omitempty"`
}

// grantRole renders roleRef as "<Kind>/<name>" (e.g. ClusterRole/edit) — the named
// role the grant confers, never an inline policy.
func grantRole(rr roleRef) string { return rr.Kind + "/" + rr.Name }

// principalOf renders a single subject as "<Kind>:[<namespace>/]<name>".
func principalOf(s subject) string {
	if s.Namespace != "" {
		return s.Kind + ":" + s.Namespace + "/" + s.Name
	}
	return s.Kind + ":" + s.Name
}

// wellKnownPrivileged / wellKnownReadOnly are the curated built-in ClusterRoles
// groundhold can classify with certainty. Everything else stays unverifiable.
var wellKnownPrivileged = map[string]bool{"cluster-admin": true, "admin": true, "edit": true}
var wellKnownReadOnly = map[string]bool{"view": true}

// classifyGrantPrivilege returns (privileged, known). known=false means the role is
// outside the curated set and privilege must be left UNVERIFIABLE, not guessed.
func classifyGrantPrivilege(rr roleRef) (privileged bool, known bool) {
	if rr.Kind == "ClusterRole" {
		if wellKnownPrivileged[rr.Name] {
			return true, true
		}
		if wellKnownReadOnly[rr.Name] {
			return false, true
		}
	}
	return false, false
}

// parseGrantRole is the inverse of grantRole for the build path.
func parseGrantRole(s string) (roleRef, error) {
	i := strings.Index(s, "/")
	if i <= 0 || i == len(s)-1 {
		return roleRef{}, fmt.Errorf("grant.role %q is not <Kind>/<name> (e.g. ClusterRole/edit)", s)
	}
	kind := s[:i]
	if kind != "Role" && kind != "ClusterRole" {
		return roleRef{}, fmt.Errorf("grant.role kind %q must be Role or ClusterRole", kind)
	}
	return roleRef{APIGroup: rbacGroup, Kind: kind, Name: s[i+1:]}, nil
}

// parsePrincipal is the inverse of principalOf for the build path.
func parsePrincipal(s string) (subject, error) {
	c := strings.Index(s, ":")
	if c <= 0 || c == len(s)-1 {
		return subject{}, fmt.Errorf("grant.principal %q is not <Kind>:[<namespace>/]<name>", s)
	}
	kind, rest := s[:c], s[c+1:]
	if kind != "User" && kind != "Group" && kind != "ServiceAccount" {
		return subject{}, fmt.Errorf("grant.principal kind %q must be User, Group or ServiceAccount", kind)
	}
	sub := subject{Kind: kind}
	if slash := strings.Index(rest, "/"); slash >= 0 {
		sub.Namespace, sub.Name = rest[:slash], rest[slash+1:]
	} else {
		sub.Name = rest
	}
	if sub.Name == "" {
		return subject{}, fmt.Errorf("grant.principal %q has no name", s)
	}
	if sub.Kind == "ServiceAccount" && sub.Namespace == "" {
		return subject{}, fmt.Errorf("grant.principal ServiceAccount %q needs a namespace (ServiceAccount:<ns>/<name>)", s)
	}
	if sub.Kind != "ServiceAccount" && sub.Namespace != "" {
		return subject{}, fmt.Errorf("grant.principal %s %q takes no namespace", sub.Kind, s)
	}
	return sub, nil
}

// reverseGrant maps a live RoleBinding to grant observations + diagnostics for what
// does not fit the single-principal grant model (multiple subjects) or cannot be
// classified (a custom role's privilege).
func reverseGrant(rr roleRef, subjects []subject, scope string) (obs map[string]any, diags []string) {
	obs = map[string]any{
		"access.scope":    scope, // resource (RoleBinding) or account (ClusterRoleBinding)
		"service.managed": true,
	}
	// roleRef is a required, immutable field, but a partial/malformed object could
	// decode to an empty roleRef — grantRole would then fabricate "/". Refuse:
	// an absent roleRef is not a grant to the "/" role.
	if rr.Kind == "" && rr.Name == "" {
		diags = append(diags, "RoleBinding has no roleRef — grant.role not observable (not fabricated)")
	} else {
		obs["grant.role"] = grantRole(rr)
	}
	switch len(subjects) {
	case 0:
		diags = append(diags, "RoleBinding has no subjects — grant.principal not observable")
	case 1:
		obs["grant.principal"] = principalOf(subjects[0])
	default:
		diags = append(diags, fmt.Sprintf("RoleBinding binds %d subjects; the grant model is one principal per binding — grant.principal left unobserved", len(subjects)))
	}
	if priv, known := classifyGrantPrivilege(rr); known {
		obs["access.privileged"] = priv
	} else {
		diags = append(diags, fmt.Sprintf("access.privileged is UNVERIFIABLE for %s (outside the curated well-known set) — groundhold will not guess a custom role's privilege", grantRole(rr)))
	}
	return obs, diags
}

// buildGrant assembles a RoleBinding's roleRef + subjects from grant attributes,
// refusing (never dropping) anything unmapped or a false privilege/scope claim.
func buildGrant(attrs map[string]any, wantScope string) (rr roleRef, subjects []subject, err error) {
	var haveRole, havePrincipal bool
	var declaredPriv, privSet bool
	for _, path := range sortedKeys(attrs) {
		raw := attrs[path]
		switch path {
		case "grant.role":
			s, _ := raw.(string)
			rr, err = parseGrantRole(s)
			if err != nil {
				return roleRef{}, nil, err
			}
			haveRole = true
		case "grant.principal":
			s, _ := raw.(string)
			sub, e := parsePrincipal(s)
			if e != nil {
				return roleRef{}, nil, e
			}
			subjects = []subject{sub}
			havePrincipal = true
		case "access.scope":
			if raw != wantScope {
				return roleRef{}, nil, fmt.Errorf("access.scope=%v does not match this binding kind (it confers %s breadth): a namespaced RoleBinding is resource-scoped, a ClusterRoleBinding is account-scoped", raw, wantScope)
			}
		case "access.privileged":
			declaredPriv, _ = raw.(bool)
			privSet = true
		case "service.managed":
			if raw != true {
				return roleRef{}, nil, fmt.Errorf("service.managed=false cannot be honored by k8s RBAC")
			}
		default:
			return roleRef{}, nil, fmt.Errorf("attribute %s has no k8s RBAC RoleBinding mapping — refusing rather than silently dropping it", path)
		}
	}
	if !haveRole {
		return roleRef{}, nil, fmt.Errorf("a grant requires grant.role (<Kind>/<name>)")
	}
	if !havePrincipal {
		return roleRef{}, nil, fmt.Errorf("a grant requires grant.principal (<Kind>:[<namespace>/]<name>)")
	}
	// least-privilege honesty: a false privilege claim about a role we CAN classify
	// is refused; a custom role we cannot classify accepts the declared value.
	if privSet {
		if priv, known := classifyGrantPrivilege(rr); known && priv != declaredPriv {
			return roleRef{}, nil, fmt.Errorf("access.privileged=%t contradicts the well-known privilege of %s — refusing a false claim", declaredPriv, grantRole(rr))
		}
	}
	return rr, subjects, nil
}

// grantSpec builds the roleRef + subjects a (Cluster)RoleBinding carries — the
// structural half the closed op set cannot express, so the k8s.rbac.grant write-
// lens calls it. A ServiceAccount subject carries the core-group apiGroup + its
// namespace; every other principal kind is an rbac.authorization.k8s.io reference.
func grantSpec(rr roleRef, subjects []subject) (roleRefMap map[string]any, subjectsList []any) {
	subs := make([]any, 0, len(subjects))
	for _, s := range subjects {
		m := map[string]any{"kind": s.Kind, "name": s.Name, "apiGroup": "rbac.authorization.k8s.io"}
		if s.Kind == "ServiceAccount" {
			m["apiGroup"] = ""
			m["namespace"] = s.Namespace
		}
		subs = append(subs, m)
	}
	return map[string]any{
		"apiGroup": "rbac.authorization.k8s.io",
		"kind":     rr.Kind,
		"name":     rr.Name,
	}, subs
}
