// k8s RBAC Role write path: the authoring half of the capability.authorization.role
// driver. groundhold builds a Role's rules from the FLAT permission set (the reverse of
// the reverse-map), stamps its ownership as labels, and writes through server-side
// apply (fieldManager=groundhold). Ownership is the read/write invariant: update and
// delete refuse an object that is not ours (matching every cloud driver's
// "not ours" guard). claim (D140) is the one-time takeover stamp — it adds the
// ownership labels to an adopted object so subsequent writes recognise it.
package k8s

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"

	"groundhold/internal/provider"
)

var _ provider.Claimer = (*Driver)(nil)

const (
	rbacVersion = "v1"
	fieldMgr    = "groundhold"
	capLabel    = "app.kubernetes.io/managed-by-groundhold-capability"
	envLabel    = "app.kubernetes.io/managed-by-groundhold-environment"
)

// sanitizeLabel coerces an identifier into a valid label value (lowercased,
// out-of-charset runs collapsed to '-', trimmed, hashed suffix if truncated).
func sanitizeLabel(s string) string {
	low := strings.ToLower(s)
	var b strings.Builder
	for _, r := range low {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '.' || r == '_' || r == '-' {
			b.WriteRune(r)
		} else {
			b.WriteByte('-')
		}
	}
	v := strings.Trim(b.String(), "-._")
	if v == "" {
		v = "x"
	}
	if len(v) > 63 {
		sum := sha256.Sum256([]byte(s))
		v = v[:55] + "-" + hex.EncodeToString(sum[:])[:7]
	}
	return v
}

func ownershipLabels(capability, environment string) map[string]any {
	return map[string]any{
		capLabel: sanitizeLabel(capability),
		envLabel: sanitizeLabel(environment),
	}
}

// roleName is the deterministic Role name for a greenfield create — dns-1123
// (lowercase alnum + dashes, <=63). Takeover paths use the adopted providerId's
// name instead, so this only feeds Create.
func roleName(capability, environment string) string {
	slug := sanitizeLabel(capability)
	if environment != "" {
		slug = sanitizeLabel(capability + "-" + environment)
	}
	slug = strings.ReplaceAll(slug, "_", "-")
	slug = strings.ReplaceAll(slug, ".", "-")
	slug = strings.Trim(slug, "-")
	if !k8sNameOK.MatchString(slug) || slug == "" {
		sum := sha256.Sum256([]byte(capability + "|" + environment))
		slug = "pv-" + hex.EncodeToString(sum[:])[:12]
	}
	if len(slug) > 63 {
		slug = slug[:63]
	}
	return slug
}

// buildRoleRules turns the flat permission set back into RBAC rules, grouped by
// (apiGroup, resource) so verbs collapse into one rule — the deterministic inverse
// of flattenRules. "core" maps back to the empty core group.
func buildRoleRules(perms []string) ([]map[string]any, error) {
	type key struct{ group, res string }
	verbs := map[key]map[string]bool{}
	var order []key
	for _, p := range perms {
		g, r := groupResOf(p)
		v := verbOf(p)
		if r == "" || v == "" {
			return nil, fmt.Errorf("permission %q is not <group>/<resource>:<verb>", p)
		}
		// The core API group is spelled "core" here, never blank. RBAC's own YAML
		// writes it as the empty string, so `/nodes:get` is the natural thing to
		// declare and it USED to be accepted — it wrote the correct rule, and then
		// observe read it back as "core/nodes:get", because the reverse mapping has
		// exactly one spelling. The two could never agree, so converge planned the
		// same update on every run, forever, on a cluster nobody had touched (D509).
		// Refuse it the way a malformed grant principal is refused: name the form
		// that works rather than guess, since guessing is what made the loop.
		if g == "" {
			return nil, fmt.Errorf("permission %q leaves the API group blank — spell the "+
				"core group %q (RBAC's own empty string is not the spelling observations "+
				"use, and a value that does not round-trip can never converge)",
				p, "core/"+r+":"+v)
		}
		if g == "core" {
			g = ""
		}
		k := key{g, r}
		if verbs[k] == nil {
			verbs[k] = map[string]bool{}
			order = append(order, k)
		}
		verbs[k][v] = true
	}
	sort.Slice(order, func(i, j int) bool {
		if order[i].group != order[j].group {
			return order[i].group < order[j].group
		}
		return order[i].res < order[j].res
	})
	rules := make([]map[string]any, 0, len(order))
	for _, k := range order {
		vs := make([]string, 0, len(verbs[k]))
		for v := range verbs[k] {
			vs = append(vs, v)
		}
		sort.Strings(vs)
		rules = append(rules, map[string]any{
			"apiGroups": []any{k.group},
			"resources": []any{k.res},
			"verbs":     toAnyList(vs),
		})
	}
	return rules, nil
}

func toAnyList(ss []string) []any {
	out := make([]any, len(ss))
	for i, s := range ss {
		out[i] = s
	}
	return out
}

// buildRole assembles the Role rules from capability.authorization.role attributes
// and refuses (never silently drops) anything with no mapping or a false derived
// claim — the same least-privilege honesty gcp.iam enforces (D105).
func buildRole(attrs map[string]any) ([]map[string]any, error) {
	var perms []string
	declaredMut, mutSet := false, false
	declaredPriv, privSet := false, false
	for _, path := range sortedKeys(attrs) {
		raw := attrs[path]
		switch path {
		case "role.permissions":
			ps, err := toStrings(raw)
			if err != nil {
				return nil, fmt.Errorf("role.permissions is not a list of strings: %v", err)
			}
			perms = ps
		case "access.mutating":
			declaredMut, _ = raw.(bool)
			mutSet = true
		case "access.privileged":
			declaredPriv, _ = raw.(bool)
			privSet = true
		case "service.managed":
			if raw != true {
				return nil, fmt.Errorf("service.managed=false cannot be honored by k8s RBAC")
			}
		default:
			return nil, fmt.Errorf("attribute %s has no k8s RBAC Role mapping — refusing "+
				"rather than silently dropping it (a role is a flat permission SET, never an "+
				"inline policy with resourceNames/conditions)", path)
		}
	}
	if len(perms) == 0 {
		return nil, fmt.Errorf("a Role requires a non-empty role.permissions set")
	}
	if mutSet && rulesMutating(perms) != declaredMut {
		return nil, fmt.Errorf("access.mutating=%t contradicts the permission set — refusing a false claim", declaredMut)
	}
	if privSet && rulesPrivileged(perms) != declaredPriv {
		return nil, fmt.Errorf("access.privileged=%t contradicts the permission set — refusing a false claim", declaredPriv)
	}
	return buildRoleRules(perms)
}

// Role create/update/delete + the object body + the RBAC server-side apply are now
// the schema-driven engine's (createMapped/updateMapped/deleteMapped in
// generic_write.go, via mappings/k8s.role.yaml + k8s.clusterrole.yaml). buildRole
// remains: the k8s.rbac.roleRules write-lens calls it to author rules[].

// The per-kind ownership pre-read (getMeta/ours) went with the hand-coded twins;
// the generic engine's updateMapped/deleteMapped guard via oursAt (path-based).

// Claim (D140): the one-time takeover stamp. It adds groundhold's ownership labels to
// an adopted object via a merge patch — after it, update/delete recognise it as
// ours. It changes no attribute and loses no data. Works across every governance
// kind (RBAC + NetworkPolicy), which live in different API groups.
func (d *Driver) Claim(service, capability, environment, providerID string) provider.CreateResult {
	// a mapped service claims via its mapping's object path — the same one-time
	// label stamp, driven by the mapping's scope/GVK rather than a hand-coded case.
	if m, _ := d.serviceMapping(service, forRead); m != nil { // Claim is a read-shaped write of our own label
		ns, name, err := m.parseProviderID(providerID)
		if err != nil {
			return provider.CreateResult{Status: "failed", Reason: err.Error()}
		}
		return d.claimAt(m.objectPath(ns, name), capability, environment, providerID)
	}
	if err := d.requireService(service); err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	var path string
	switch service {
	case "namespace":
		_, _, _, name, err := splitRBACProviderID(providerID, "Namespace")
		if err != nil {
			return provider.CreateResult{Status: "failed", Reason: err.Error()}
		}
		path = corePathCluster("namespaces", name)
	default:
		ki, err := kindInfo(service)
		if err != nil {
			return provider.CreateResult{Status: "failed", Reason: err.Error()}
		}
		_, _, ns, name, err := splitRBACProviderID(providerID, ki.Kind)
		if err != nil {
			return provider.CreateResult{Status: "failed", Reason: err.Error()}
		}
		path = ki.objPath(ns, name)
	}
	return d.claimAt(path, capability, environment, providerID)
}

// claimAt stamps groundhold's ownership labels on the object at path via a merge patch.
func (d *Driver) claimAt(path, capability, environment, providerID string) provider.CreateResult {
	patch, _ := json.Marshal(map[string]any{
		"metadata": map[string]any{"labels": ownershipLabels(capability, environment)},
	})
	st, b, e := d.callCT("PATCH", path, patch, "application/merge-patch+json")
	switch {
	case e != nil:
		return provider.CreateResult{ProviderID: providerID, Status: "unknown", Reason: fmt.Sprintf("claim outcome unknown: %v", e)}
	case st == http.StatusOK:
		return provider.CreateResult{ProviderID: providerID, Status: "succeeded"}
	case st == http.StatusNotFound:
		return provider.CreateResult{Status: "failed", Reason: "object no longer exists — cannot claim"}
	case st >= 500:
		return provider.CreateResult{ProviderID: providerID, Status: "unknown", Reason: fmt.Sprintf("claim HTTP %d (server error) — reconcile", st)}
	default:
		return provider.CreateResult{Status: "failed", Reason: fmt.Sprintf("claim HTTP %d: %s", st, mutDetail(b))}
	}
}

// namespaceOf reads the target namespace from the candidate implementation block
// (the k8s analog of --project scope); defaults to "default".
func namespaceOf(impl map[string]any) string {
	if impl != nil {
		if ns, _ := impl["namespace"].(string); ns != "" {
			return ns
		}
	}
	return "default"
}

func sortedKeys(m map[string]any) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	return ks
}

func toStrings(raw any) ([]string, error) {
	switch v := raw.(type) {
	case []string:
		return v, nil
	case []any:
		out := make([]string, 0, len(v))
		for _, it := range v {
			s, ok := it.(string)
			if !ok {
				return nil, fmt.Errorf("element %v is not a string", it)
			}
			out = append(out, s)
		}
		return out, nil
	}
	return nil, fmt.Errorf("not a list")
}

// mutDetail renders a failed API-server write as the Kubernetes Status object's
// own message/reason, bounded and newline-free — never the raw body (D309). A
// CreateResult.Reason is copied into receipt["reason"], which is a persisted
// ledger event that `export` publishes and `capsule` signs.
func mutDetail(b []byte) string {
	var st struct {
		Message string `json:"message"`
		Reason  string `json:"reason"`
	}
	_ = json.Unmarshal(b, &st)
	msg := strings.TrimSpace(st.Message)
	if msg == "" {
		msg = strings.TrimSpace(st.Reason)
	}
	if msg == "" {
		return "(the API server returned no Status message or reason)"
	}
	if len(msg) > 200 {
		msg = msg[:200] + "…"
	}
	return strings.ReplaceAll(msg, "\n", " ")
}
