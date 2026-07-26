// The four RBAC kinds groundhold governs, and the scope arithmetic that separates
// them. Role/RoleBinding are namespaced (their providerId and REST path carry a
// namespace, their grant breadth is `resource`); ClusterRole/ClusterRoleBinding
// are cluster-scoped (no namespace, breadth `account`). Everything downstream —
// URL building, providerId parsing, the grant scope — reads from here so the
// role and grant code paths stay single, parameterised by kind.
package k8s

import "fmt"

type rbacKind struct {
	Kind       string
	Plural     string
	Namespaced bool
}

func kindInfo(service string) (rbacKind, error) {
	switch service {
	case "rbac-role":
		return rbacKind{"Role", "roles", true}, nil
	case "rbac-clusterrole":
		return rbacKind{"ClusterRole", "clusterroles", false}, nil
	case "rbac-grant":
		return rbacKind{"RoleBinding", "rolebindings", true}, nil
	case "rbac-clustergrant":
		return rbacKind{"ClusterRoleBinding", "clusterrolebindings", false}, nil
	}
	return rbacKind{}, fmt.Errorf("unknown rbac service %q", service)
}

// isNamespacedKind reports whether a Kind carries a namespace (governs the
// providerId shape: 5 fields namespaced, 4 cluster-scoped).
func isNamespacedKind(kind string) bool {
	return kind == "Role" || kind == "RoleBinding" || kind == "NetworkPolicy" || kind == "ResourceQuota"
}

// grantScope is the access.scope a binding of this kind confers: a namespaced
// RoleBinding is `resource` (namespace-bounded), a ClusterRoleBinding is `account`
// (cluster-wide) — the exact resource/account breadth the vocab distinguishes.
func grantScope(k rbacKind) string {
	if k.Namespaced {
		return "resource"
	}
	return "account"
}

// objPath is the REST path for a single object; namespace is ignored for a
// cluster-scoped kind.
func (k rbacKind) objPath(namespace, name string) string {
	if k.Namespaced {
		return fmt.Sprintf("/apis/%s/%s/namespaces/%s/%s/%s", rbacGroup, rbacVersion, namespace, k.Plural, name)
	}
	return fmt.Sprintf("/apis/%s/%s/%s/%s", rbacGroup, rbacVersion, k.Plural, name)
}

// collPath is the collection (list) path; a namespaced kind narrows to region
// when given, a cluster-scoped kind is always cluster-wide.
func (k rbacKind) collPath(region string) (string, error) {
	if !k.Namespaced || region == "" {
		return fmt.Sprintf("/apis/%s/%s/%s", rbacGroup, rbacVersion, k.Plural), nil
	}
	if !k8sNameOK.MatchString(region) {
		return "", fmt.Errorf("namespace %q is invalid", region)
	}
	return fmt.Sprintf("/apis/%s/%s/namespaces/%s/%s", rbacGroup, rbacVersion, region, k.Plural), nil
}
