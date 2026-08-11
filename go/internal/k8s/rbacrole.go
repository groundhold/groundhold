// k8s RBAC Role -> capability.authorization.role (D105 vocabulary, third twin
// after gcp.iam and aws.iam). A Role's cloud-native form is a POLICY DOCUMENT
// (rules of apiGroups x resources x verbs) — an expression language. Per invariant
// #4 and the vocab, groundhold admits a role ONLY as a FLAT SET of named permissions:
// each rule is flattened to "<group>/<resource>:<verb>" strings (the cartesian
// product), which has no connectives, no interpolation, no conditions. resourceNames
// (per-object scoping) belong to the GRANT's scope, not the role, so a rule that
// carries them is reported as a diagnostic, never silently folded into the flat set.
// access.mutating / access.privileged are DERIVED deterministically from the verbs.
package k8s

import (
	"sort"
	"strconv"
	"strings"
)

// rbacRule is one entry of a Role's rules[].
type rbacRule struct {
	APIGroups     []string `json:"apiGroups"`
	Resources     []string `json:"resources"`
	Verbs         []string `json:"verbs"`
	ResourceNames []string `json:"resourceNames,omitempty"`
	NonResource   []string `json:"nonResourceURLs,omitempty"`
}

// flattenRules turns a Role's rules into the flat permission set + diagnostics for
// anything that does not fit the flat-set model (resource-name scoping, non-resource
// URLs). Empty apiGroup (the core group) renders as "core" for a readable, reversible
// string. The set is sorted and de-duplicated so the reverse-map is deterministic.
func flattenRules(rules []rbacRule) (perms []string, diags []string) {
	seen := map[string]bool{}
	for i, r := range rules {
		if len(r.NonResource) > 0 {
			diags = append(diags, "rule "+strconv.Itoa(i)+": nonResourceURLs are not part of the flat permission set — not represented")
		}
		if len(r.ResourceNames) > 0 {
			diags = append(diags, "rule "+strconv.Itoa(i)+": resourceNames (per-object scoping) belong to the grant's scope, not the role (D105) — not represented")
		}
		groups := r.APIGroups
		if len(groups) == 0 {
			groups = []string{""}
		}
		for _, g := range groups {
			gi := g
			if gi == "" {
				gi = "core"
			}
			for _, res := range r.Resources {
				for _, v := range r.Verbs {
					p := gi + "/" + res + ":" + v
					if !seen[p] {
						seen[p] = true
						perms = append(perms, p)
					}
				}
			}
		}
	}
	sort.Strings(perms)
	return perms, diags
}

// verbOf / resourceOf / groupOf pull the pieces back out of a "<group>/<res>:<verb>"
// permission string for the derivations below.
func verbOf(perm string) string {
	if i := strings.LastIndex(perm, ":"); i >= 0 {
		return perm[i+1:]
	}
	return ""
}

func groupResOf(perm string) (group, res string) {
	head := perm
	if i := strings.LastIndex(perm, ":"); i >= 0 {
		head = perm[:i]
	}
	if i := strings.Index(head, "/"); i >= 0 {
		return head[:i], head[i+1:]
	}
	return "", head
}

// k8s read verbs. Anything else (create/update/patch/delete/deletecollection, or a
// "*" wildcard) mutates.
func permReadOnly(perm string) bool {
	switch verbOf(perm) {
	case "get", "list", "watch":
		return true
	}
	return false
}

func rulesMutating(perms []string) bool {
	for _, p := range perms {
		if !permReadOnly(p) {
			return true
		}
	}
	return false
}

// permPrivileged: a permission confers privilege-escalation / administrative
// CONTROL iff it is a full wildcard, an rbac write (create/update/patch/delete/bind/
// escalate on roles/bindings), an impersonate, or a bind/escalate verb. Derived
// deterministically — never guessed.
func permPrivileged(perm string) bool {
	group, res := groupResOf(perm)
	verb := verbOf(perm)
	// D988 (user-directed): full control of ALL resources of ANY apiGroup (verb:*
	// resource:*) is admin-shaped over that group — e.g. apps/*:* lets the holder
	// schedule an arbitrary privileged pod, an escalation-to-node vector. The check
	// used to fire only for group "*"/"core", under-implementing its own intent and
	// reporting apps/*:* as access.privileged=false. Any group now counts; this
	// over-reports a benign full-control-of-a-CRD-group role as privileged, which is
	// the safe direction.
	if verb == "*" && res == "*" {
		return true
	}
	switch verb {
	case "bind", "escalate", "impersonate":
		return true
	}
	// writing RBAC objects is a re-grant vector
	if strings.HasPrefix(group, "rbac.authorization.k8s.io") {
		switch res {
		case "roles", "clusterroles", "rolebindings", "clusterrolebindings", "*":
			if !permReadOnly(perm) {
				return true
			}
		}
	}
	return false
}

func rulesPrivileged(perms []string) bool {
	for _, p := range perms {
		if permPrivileged(p) {
			return true
		}
	}
	return false
}
