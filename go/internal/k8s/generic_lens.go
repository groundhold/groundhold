// Named lenses (learn-from-API-contract, slice 4). A lens is the escape valve the
// op/lens split reserves for CONDITIONAL semantics the closed op set deliberately
// cannot express — NetworkPolicy's "default-deny only when policyTypes has Ingress
// and the rule list is empty", RBAC's verb-class derivation. It is an in-tree Go
// function referenced BY NAME from a mapping's `lenses:` list, golden-tested
// individually. This is invariant #4 at the driver layer: complexity is met with
// more named lenses, never a richer expression language in the mapping document. A
// mapping naming an unregistered lens refuses at load, by name (D132).
package k8s

import (
	"encoding/json"
	"fmt"

	"groundhold/internal/mapping"
	"groundhold/internal/provider"
)

// lensFunc reads the whole object and returns observations + diagnostics. It sees
// the raw object, never the schema — it derives no meaning the human did not encode
// in the function; the function is reviewed like any driver code.
type lensFunc func(obj map[string]any) ([]provider.Observation, []string)

// writeLensFunc is the inverse: it builds object fields from the candidate's
// attribute values (+ the free-form implementation block). A lens with a write
// function makes its mapping writeSafe — the generic engine can then author the
// resource, and the hand-coded write twin can be deleted.
type writeLensFunc func(obj, attrs, impl map[string]any) error

type lensDef struct {
	fn    lensFunc
	write writeLensFunc // optional; present => the mapping can write generically
	// fields the lens reads — folded into the mapped-surface fingerprint so drift
	// on a lens's inputs is caught the same as drift on a copy op's field.
	fields []string
}

var lensRegistry = map[string]lensDef{
	"k8s.netpol.defaultDenyIngress": {
		fn:     lensNetpolDefaultDeny,
		write:  writeLensNetpolDefaultDeny,
		fields: []string{"spec.policyTypes", "spec.ingress", "spec.egress", "spec.podSelector"},
	},
	// slice 5: the first CRD (cert-manager Certificate) with no hand-coded twin.
	// The primary domain is spec.dnsNames[0] — array indexing is deliberately NOT
	// in fieldpath/v1 (that would be a richer language), so it is a lens.
	"k8s.certmanager.primaryDomain": {
		fn:     lensCertmanagerPrimaryDomain,
		write:  writeLensCertmanagerPrimaryDomain,
		fields: []string{"spec.dnsNames"},
	},
	// GitOps WITNESS (controller-AGNOSTIC): normalise a controller's own status
	// vocabulary onto the neutral sync/health enums. A conditional value mapping the
	// closed op set cannot express, so a lens. Observe-only (no write) — groundhold
	// witnesses the reconciler, never authors it (author-vs-witness). ArgoCD and Flux
	// are EQUAL citizens; each is one lens, no vendor privileged.
	"k8s.gitops.argocdStatus": {
		fn:     lensGitopsArgocdStatus,
		fields: []string{"status.sync.status", "status.health.status"},
	},
	"k8s.gitops.fluxStatus": {
		fn:     lensGitopsFluxStatus,
		fields: []string{"status.conditions"},
	},
	// Namespace's only capability semantics is the Pod Security Standard it
	// enforces, carried on a LABEL (metadata.labels[pod-security.../enforce]) whose
	// value is validated against a closed enum — conditional, so a lens, not a copy.
	"k8s.namespace.podSecurity": {
		fn:     lensNamespacePodSecurity,
		write:  writeLensNamespacePodSecurity,
		fields: []string{`metadata.labels["` + podSecurityEnforceLabel + `"]`},
	},
	// An RBAC Role/ClusterRole is a POLICY DOCUMENT (rules[] = apiGroups x resources
	// x verbs), which the closed op set cannot flatten — so the reverse-map (flat
	// permission set + derived mutating/privileged signals) and its inverse are a
	// lens wrapping the reviewed reverse/build helpers. Shared by both role kinds.
	"k8s.rbac.roleRules": {
		fn:     lensRoleRules,
		write:  writeLensRoleRules,
		fields: []string{"rules", "aggregationRule"},
	},
	// An RBAC (Cluster)RoleBinding confers a NAMED role on principals; the reverse-
	// map (grant.role/principal/scope/privileged, with the curated privilege
	// classification and the multi-subject/custom-role caveats) and its inverse are
	// a lens. The binding's account/resource breadth comes from the object's kind.
	"k8s.rbac.grant": {
		fn:     lensRbacGrant,
		write:  writeLensRbacGrant,
		fields: []string{"roleRef", "subjects"},
	},
}

// grantScopeFromObj derives the access.scope breadth from the object's own kind —
// a ClusterRoleBinding is account-wide, a RoleBinding namespace-bounded. The kind is
// in the object on read (the API returns it) and stamped by the engine on write.
func grantScopeFromObj(obj map[string]any) string {
	if k, _ := obj["kind"].(string); k == "ClusterRoleBinding" {
		return "account"
	}
	return "resource"
}

// grantBindingOf re-types the generic object's roleRef + subjects into the shapes
// the reverse map reads — the same slice getRoleBinding unmarshaled.
func grantBindingOf(obj map[string]any) (roleRef, []subject) {
	var d struct {
		RoleRef  roleRef   `json:"roleRef"`
		Subjects []subject `json:"subjects"`
	}
	raw, _ := json.Marshal(obj)
	_ = json.Unmarshal(raw, &d)
	return d.RoleRef, d.Subjects
}

// lensRbacGrant reproduces observeRoleBinding: reverseGrant's obsMap emitted in
// sorted path order, with its diagnostics.
func lensRbacGrant(obj map[string]any) ([]provider.Observation, []string) {
	rr, subs := grantBindingOf(obj)
	obsMap, diags := reverseGrant(rr, subs, grantScopeFromObj(obj))
	var obs []provider.Observation
	for _, path := range sortedKeys(obsMap) {
		obs = append(obs, provider.Observation{Path: path, Value: obsMap[path], Derivation: "measured"})
	}
	return obs, diags
}

// writeLensRbacGrant authors roleRef + subjects from the grant attributes via
// buildGrant (which enforces the scope match + false-privilege refusal), the
// inverse of the read lens.
func writeLensRbacGrant(obj, attrs, impl map[string]any) error {
	rr, subs, err := buildGrant(attrs, grantScopeFromObj(obj))
	if err != nil {
		return err
	}
	obj["roleRef"], obj["subjects"] = grantSpec(rr, subs)
	return nil
}

// rbacRulesOf re-types the generic object's rules[] into the []rbacRule the reverse
// map reads — the same shape getRole unmarshaled, via a JSON round-trip.
func rbacRulesOf(obj map[string]any) []rbacRule {
	raw, _ := json.Marshal(obj["rules"])
	var rules []rbacRule
	_ = json.Unmarshal(raw, &rules)
	return rules
}

// lensRoleRules reproduces observeRole: the flat permission set + the derived
// least-privilege signals + the aggregationRule caveat, in the same order.
func lensRoleRules(obj map[string]any) ([]provider.Observation, []string) {
	perms, diags := flattenRules(rbacRulesOf(obj))
	if obj["aggregationRule"] != nil {
		diags = append(diags, "ClusterRole has an aggregationRule — its rules are assembled by the controller from matching ClusterRoles; the flat set is the current aggregation, not an authored intent")
	}
	return []provider.Observation{
		{Path: "role.permissions", Value: toAnyList(perms), Derivation: "measured"},
		{Path: "access.mutating", Value: rulesMutating(perms), Derivation: "measured"},
		{Path: "access.privileged", Value: rulesPrivileged(perms), Derivation: "measured"},
		{Path: "service.managed", Value: true, Derivation: "measured"},
	}, diags
}

// writeLensRoleRules authors rules[] from the flat permission set via buildRole,
// which also enforces the mutating/privileged contradiction checks and refuses an
// unmapped attribute — the same honesty the hand-coded write path had.
func writeLensRoleRules(obj, attrs, impl map[string]any) error {
	rules, err := buildRole(attrs)
	if err != nil {
		return err
	}
	obj["rules"] = rules
	return nil
}

// lensNamespacePodSecurity reads the enforce label, admitting only a known Pod
// Security Standard — an unknown value or an absent label is a diagnostic, never a
// fabricated posture. Reproduces observeNamespace's label branch byte-for-byte.
// lensGitopsArgocdStatus normalises an ArgoCD Application's own status onto the
// controller-neutral sync/health enums. Read-only (witness). An absent status is
// honest: the controller has not reported yet -> unknown, never a fabricated
// synced/healthy. Suspended maps to unknown (a paused app is neither healthy nor
// failing — groundhold will not assert either).
func lensGitopsArgocdStatus(obj map[string]any) ([]provider.Observation, []string) {
	status, _ := obj["status"].(map[string]any)
	sync, _ := status["sync"].(map[string]any)
	health, _ := status["health"].(map[string]any)
	syncRaw, _ := sync["status"].(string)
	healthRaw, _ := health["status"].(string)

	var out []provider.Observation
	var diags []string

	switch syncRaw {
	case "Synced":
		out = append(out, provider.Observation{Path: "sync.status", Value: "synced", Derivation: "measured"})
	case "OutOfSync":
		out = append(out, provider.Observation{Path: "sync.status", Value: "drifted", Derivation: "measured"})
	case "":
		diags = append(diags, "argocd Application reports no status.sync.status yet — sync.status unknown (not fabricated)")
	default:
		out = append(out, provider.Observation{Path: "sync.status", Value: "unknown", Derivation: "measured"})
	}

	switch healthRaw {
	case "Healthy":
		out = append(out, provider.Observation{Path: "health.status", Value: "healthy", Derivation: "measured"})
	case "Progressing":
		out = append(out, provider.Observation{Path: "health.status", Value: "progressing", Derivation: "measured"})
	case "Degraded", "Missing":
		out = append(out, provider.Observation{Path: "health.status", Value: "degraded", Derivation: "measured"})
	case "":
		diags = append(diags, "argocd Application reports no status.health.status yet — health.status unknown (not fabricated)")
	default: // Suspended, Unknown, or any future value
		out = append(out, provider.Observation{Path: "health.status", Value: "unknown", Derivation: "measured"})
	}

	return out, diags
}

// lensGitopsFluxStatus normalises a Flux resource (Kustomization/HelmRelease) onto
// the same neutral sync/health enums as ArgoCD — the proof the abstraction is
// vendor-agnostic. Flux is condition-based: the Ready condition carries both
// reconcile success and health, a Reconciling condition marks a rollout in flight.
// Read-only (witness). No Ready condition yet -> unknown, never fabricated.
func lensGitopsFluxStatus(obj map[string]any) ([]provider.Observation, []string) {
	status, _ := obj["status"].(map[string]any)
	conds, _ := status["conditions"].([]any)
	cond := func(typ string) (string, bool) {
		for _, c := range conds {
			m, _ := c.(map[string]any)
			if t, _ := m["type"].(string); t == typ {
				s, _ := m["status"].(string)
				return s, true
			}
		}
		return "", false
	}

	var out []provider.Observation
	var diags []string
	ready, haveReady := cond("Ready")
	reconciling, _ := cond("Reconciling")

	// sync: a k8s condition status is THREE-valued (True|False|Unknown). Ready True
	// => the declared revision applied cleanly (synced); Ready False => it could not
	// reconcile (drifted); Ready Unknown (a reconcile in flight / indeterminate) or
	// any future status => NEUTRAL unknown, never a fabricated drifted — the same
	// four-valued honesty the ArgoCD twin keeps. No Ready condition => unknown.
	switch {
	case !haveReady:
		diags = append(diags, "flux resource reports no Ready condition yet — sync.status unknown (not fabricated)")
	case ready == "True":
		out = append(out, provider.Observation{Path: "sync.status", Value: "synced", Derivation: "measured"})
	case ready == "False":
		out = append(out, provider.Observation{Path: "sync.status", Value: "drifted", Derivation: "measured"})
	default: // Unknown, or any future status — the controller does not know yet
		out = append(out, provider.Observation{Path: "sync.status", Value: "unknown", Derivation: "measured"})
	}

	// health: a rollout in flight (Reconciling True) is progressing; else Ready True
	// => healthy, Ready False => degraded, Ready Unknown/future => neutral unknown
	// (indeterminate is NOT degraded), no Ready => unknown.
	switch {
	case reconciling == "True":
		out = append(out, provider.Observation{Path: "health.status", Value: "progressing", Derivation: "measured"})
	case !haveReady:
		diags = append(diags, "flux resource reports no Ready condition yet — health.status unknown (not fabricated)")
	case ready == "True":
		out = append(out, provider.Observation{Path: "health.status", Value: "healthy", Derivation: "measured"})
	case ready == "False":
		out = append(out, provider.Observation{Path: "health.status", Value: "degraded", Derivation: "measured"})
	default: // Ready=Unknown or a future status — indeterminate, not degraded
		out = append(out, provider.Observation{Path: "health.status", Value: "unknown", Derivation: "measured"})
	}

	return out, diags
}

func lensNamespacePodSecurity(obj map[string]any) ([]provider.Observation, []string) {
	meta, _ := obj["metadata"].(map[string]any)
	labels, _ := meta["labels"].(map[string]any)
	lvl, _ := labels[podSecurityEnforceLabel].(string)
	if lvl == "" {
		return nil, []string{"namespace declares no pod-security.kubernetes.io/enforce label — security.podSecurity is unset (the boundary enforces no standard)"}
	}
	if !validPodSecurity[lvl] {
		return nil, []string{"pod-security enforce level " + lvl + " is not a known standard — not represented"}
	}
	return []provider.Observation{{Path: "security.podSecurity", Value: lvl, Derivation: "measured"}}, nil
}

// writeLensNamespacePodSecurity stamps the validated enforce label, merging into
// the ownership labels already on the object. No posture declared = no label (a
// namespace enforcing no standard is valid) — the inverse of buildNamespace.
func writeLensNamespacePodSecurity(obj, attrs, impl map[string]any) error {
	raw, ok := attrs["security.podSecurity"]
	if !ok {
		return nil
	}
	s, _ := raw.(string)
	if !validPodSecurity[s] {
		return fmt.Errorf("security.podSecurity=%q is not restricted|baseline|privileged", s)
	}
	return mapping.SetField(obj, `metadata.labels["`+podSecurityEnforceLabel+`"]`, s)
}

// writeLensNetpolDefaultDeny authors the default-deny NetworkPolicy spec from the
// network.private intent — the inverse of the read lens (and of the deleted
// buildNetpol). A fully-permissive request is the absence of a policy: refuse.
func writeLensNetpolDefaultDeny(obj, attrs, impl map[string]any) error {
	ingressDeny, egressRestrict, haveSignal := false, false, false
	if v, ok := attrs["ingress.public"]; ok {
		if b, _ := v.(bool); !b {
			ingressDeny, haveSignal = true, true
		}
	}
	if v, ok := attrs["egress.restricted"]; ok {
		if b, _ := v.(bool); b {
			egressRestrict, haveSignal = true, true
		}
	}
	if !haveSignal {
		return fmt.Errorf("a NetworkPolicy expresses RESTRICTION — declare ingress.public=false and/or egress.restricted=true; a fully-permissive request is the absence of a policy, nothing to author")
	}
	policyTypes := []any{}
	spec := map[string]any{"podSelector": map[string]any{}}
	if ingressDeny {
		policyTypes = append(policyTypes, "Ingress")
		spec["ingress"] = []any{}
	}
	if egressRestrict {
		policyTypes = append(policyTypes, "Egress")
		spec["egress"] = []any{}
	}
	spec["policyTypes"] = policyTypes
	obj["spec"] = spec
	return nil
}

// writeLensCertmanagerPrimaryDomain authors a Certificate's dnsNames from `domain`.
// The issuer and target secret are operands (D26 implementation), not capability
// semantics — a Certificate without an issuer is invalid, so it refuses.
func writeLensCertmanagerPrimaryDomain(obj, attrs, impl map[string]any) error {
	domain, _ := attrs["domain"].(string)
	if domain == "" {
		return fmt.Errorf("a Certificate requires the domain attribute")
	}
	issuer, _ := impl["issuerRef"].(map[string]any)
	if issuer == nil {
		return fmt.Errorf("a Certificate requires implementation.issuerRef (the issuer is an operand, not a capability attribute — D26)")
	}
	spec := map[string]any{"dnsNames": []any{domain}, "issuerRef": issuer}
	if sn, _ := impl["secretName"].(string); sn != "" {
		spec["secretName"] = sn
	}
	obj["spec"] = spec
	return nil
}

// lensCertmanagerPrimaryDomain maps a cert-manager Certificate's first SAN to
// capability.certificate.tls's `domain`; additional SANs are implementation detail
// (D117), surfaced as a diagnostic, never over-claimed.
func lensCertmanagerPrimaryDomain(obj map[string]any) ([]provider.Observation, []string) {
	spec, _ := obj["spec"].(map[string]any)
	dns, _ := spec["dnsNames"].([]any)
	if len(dns) == 0 {
		return nil, []string{"Certificate has no spec.dnsNames — no primary domain to observe"}
	}
	primary, _ := dns[0].(string)
	if primary == "" {
		return nil, []string{"Certificate spec.dnsNames[0] is not a string — not represented"}
	}
	var diags []string
	if len(dns) > 1 {
		diags = append(diags, fmt.Sprintf("Certificate carries %d SANs; additional SANs are implementation detail (D117) — only the primary domain is a capability path", len(dns)))
	}
	return []provider.Observation{{Path: "domain", Value: primary, Derivation: "measured"}}, diags
}

func anyToStrings(v any) []string {
	items, ok := v.([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(items))
	for _, it := range items {
		if s, ok := it.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

// lensNetpolDefaultDeny reproduces observeNetpol's conditional config-intent
// semantics verbatim (minus service.managed, which the mapping supplies as a
// const). The differential test pins it byte-identical to the hand-coded driver.
func lensNetpolDefaultDeny(obj map[string]any) ([]provider.Observation, []string) {
	spec, _ := obj["spec"].(map[string]any)
	policyTypes := anyToStrings(spec["policyTypes"])
	ingress, _ := spec["ingress"].([]any)
	podSel, _ := spec["podSelector"].(map[string]any)
	allPods := len(podSel) == 0

	var obs []provider.Observation
	var diags []string
	if hasType(policyTypes, "Ingress") {
		if len(ingress) == 0 {
			obs = append(obs, provider.Observation{Path: "ingress.public", Value: false, Derivation: "config-intent"})
			if !allPods {
				diags = append(diags, "the default-deny ingress selects only some pods (podSelector is non-empty) — ingress.public=false is config-intent for THOSE pods, not the whole namespace")
			}
		} else {
			diags = append(diags, "the policy allows specific ingress rules — a single policy cannot express the namespace's aggregate ingress posture; ingress.public is left to the Prober outcome")
		}
	}
	if hasType(policyTypes, "Egress") {
		obs = append(obs, provider.Observation{Path: "egress.restricted", Value: true, Derivation: "config-intent"})
	}
	diags = append(diags, "network.private from a NetworkPolicy is CONFIG-INTENT: enforcement depends on the CNI — probe (verify: probe) to prove the actual reachability outcome")
	return obs, diags
}
