// Read-only discovery of the four RBAC governance kinds for the brownfield
// takeover loop (discover -> adopt -> claim). The Discoverer's "region" argument is
// the NAMESPACE to sweep (k8s has no region): a namespace narrows to Role +
// RoleBinding in it; empty sweeps everything cluster-wide, including ClusterRole +
// ClusterRoleBinding. Each object becomes a Discovered with the same reverse-mapped
// observations Observe produces, so a discovery can be adopted verbatim.
package k8s

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sort"

	"groundhold/internal/provider"
)

var _ provider.Discoverer = (*Driver)(nil)
var _ provider.Enumerator = (*Driver)(nil)

// Enumerate lists the cluster's CRAWLABLE SCOPES: its namespace names (D141). A
// scopeless pairing fans out over these — discover.Run(prov, ns, ns) sweeps each,
// and the Discoverer treats an empty region as cluster-wide. It reads the core API
// (GET /api/v1/namespaces) through the same bearer-signed request path as the rest
// of the driver. A transport or permission failure is an ERROR, never a fabricated
// empty list — the crawl records the enumeration as incomplete rather than pretend
// the cluster has no namespaces. Namespaces the caller cannot read are simply not
// returned by the API server; that omission is honest.
func (d *Driver) Enumerate() ([]string, []string, error) {
	st, body, err := d.call("GET", "/api/v1/namespaces", nil)
	if err != nil {
		return nil, nil, fmt.Errorf("namespaces.enumerate: %v", err)
	}
	if st != http.StatusOK {
		return nil, nil, fmt.Errorf("namespaces.enumerate: HTTP %d", st)
	}
	var doc struct {
		Items []namespaceDoc `json:"items"`
	}
	if json.Unmarshal(body, &doc) != nil {
		return nil, nil, fmt.Errorf("namespaces.enumerate: unreadable")
	}
	scopes := make([]string, 0, len(doc.Items))
	for _, it := range doc.Items {
		scopes = append(scopes, it.Metadata.Name)
	}
	return scopes, nil, nil
}

type roleListDoc struct {
	Items []struct {
		Metadata objectMeta `json:"metadata"`
		Rules    []rbacRule `json:"rules"`
	} `json:"items"`
}

type roleBindingListDoc struct {
	Items []roleBindingDoc `json:"items"`
}

// List sweeps the RBAC governance kinds. A namespaced region covers Role +
// RoleBinding; the cluster-wide sweep (empty region) adds ClusterRole +
// ClusterRoleBinding, so a takeover sees permission sets and the grants that
// confer them at both scopes.
func (d *Driver) List(region string) ([]provider.Discovered, []string, error) {
	var out []provider.Discovered
	var diags []string
	reg := d.serviceDiscoverers()
	for _, tok := range d.DiscoverableServices() { // sorted, deterministic
		sw := reg[tok]
		// a cluster-scoped kind is only meaningful on a cluster-wide sweep; a
		// namespace-narrowed List skips it (parity with the prior scope logic).
		if sw.clusterScoped && region != "" {
			continue
		}
		part, d2, err := sw.fn(region)
		if err != nil {
			// resilient like the cloud drivers: a service the identity cannot list
			// (or a CRD that is not installed — e.g. cert-manager absent) becomes a
			// diagnostic, never a hard failure that hides every other kind.
			diags = append(diags, tok+": "+err.Error())
			continue
		}
		out = append(out, part...)
		diags = append(diags, d2...)
	}
	return out, diags, nil
}

// k8sSweep pairs a discovery sweep with whether the kind is cluster-scoped (swept
// only on a cluster-wide List). Pairing keeps the scope class beside the function.
type k8sSweep struct {
	fn            func(region string) ([]provider.Discovered, []string, error)
	clusterScoped bool
}

// serviceDiscoverers is the k8s discovery registry, keyed by the SERVICE token
// (the mapping's service key / RBAC kind token). List iterates it;
// TestK8sDiscoverabilityComplete asserts via provider.CertifyDiscoverability that
// every MAPPED service is a key here — so a new mapped kind cannot ship without a
// discoverer (spec/drivers.md §2). netpol and certmanager-cert route through the
// generic sweepMapped (reusing observeMapped); the RBAC/quota/namespace kinds keep
// their hand-coded sweeps.
func (d *Driver) serviceDiscoverers() map[string]k8sSweep {
	rbac := func(svc string) func(string) ([]provider.Discovered, []string, error) {
		return func(region string) ([]provider.Discovered, []string, error) {
			ki, err := kindInfo(svc)
			if err != nil {
				return nil, nil, err
			}
			return d.sweep(ki, region)
		}
	}
	mapped := func(svc string) func(string) ([]provider.Discovered, []string, error) {
		return func(region string) ([]provider.Discovered, []string, error) {
			m := d.mappingFor(svc)
			if m == nil {
				return nil, nil, fmt.Errorf("k8s: no mapping for %q", svc)
			}
			return d.sweepMapped(m, region)
		}
	}
	return map[string]k8sSweep{
		"rbac-role":         {rbac("rbac-role"), false},
		"rbac-grant":        {rbac("rbac-grant"), false},
		"rbac-clusterrole":  {rbac("rbac-clusterrole"), true},
		"rbac-clustergrant": {rbac("rbac-clustergrant"), true},
		"quota":             {d.sweepQuotas, false},
		"namespace":         {func(string) ([]provider.Discovered, []string, error) { return d.sweepNamespaces() }, true},
		"netpol":            {mapped("netpol"), false},
		"certmanager-cert":  {mapped("certmanager-cert"), false},
		// GitOps reconciliation witness (controller-agnostic, equal citizens).
		"argocd-application": {mapped("argocd-application"), false},
		"flux-kustomization": {mapped("flux-kustomization"), false},
	}
}

// DiscoverableServices reports the tokens serviceDiscoverers covers (sorted), so
// the discoverability gate proves coverage rather than trusting it.
func (d *Driver) DiscoverableServices() []string {
	reg := d.serviceDiscoverers()
	out := make([]string, 0, len(reg))
	for tok := range reg {
		out = append(out, tok)
	}
	sort.Strings(out)
	return out
}

// MappedServiceTokens is the authoritative k8s service set for the discoverability
// gate: the keys of the mapping registry (the schema-mapping-driven "services").
// A new mapping (a new observed kind) grows this set, which fails the gate until it
// has a discoverer — the k8s equivalent of a new Observe adding a certified service.
func (d *Driver) MappedServiceTokens() []string {
	out := make([]string, 0, len(d.Mappings))
	for svc := range d.Mappings {
		out = append(out, svc)
	}
	sort.Strings(out)
	return out
}

// sweepMapped lists a mapped kind's collection and reverse-maps each object through
// observeMapped — the generic two-step, so a new mapping is discoverable for free.
func (d *Driver) sweepMapped(m *Mapping, region string) ([]provider.Discovered, []string, error) {
	st, body, err := d.call("GET", m.collectionPath(region), nil)
	if err != nil {
		return nil, nil, fmt.Errorf("%s.list: %v", m.Resource.Plural, err)
	}
	if st != http.StatusOK {
		return nil, nil, fmt.Errorf("%s.list: HTTP %d", m.Resource.Plural, st)
	}
	var doc struct {
		Items []struct {
			Metadata struct {
				Namespace string `json:"namespace"`
				Name      string `json:"name"`
			} `json:"metadata"`
		} `json:"items"`
	}
	if json.Unmarshal(body, &doc) != nil {
		return nil, nil, fmt.Errorf("%s.list: unreadable", m.Resource.Plural)
	}
	var out []provider.Discovered
	var diags []string
	for _, it := range doc.Items {
		pid := m.buildProviderID(it.Metadata.Namespace, it.Metadata.Name)
		obs, od, oerr := d.observeMapped(m, pid)
		if oerr != nil {
			diags = append(diags, it.Metadata.Name+": "+oerr.Error())
			continue
		}
		diags = append(diags, od...)
		out = append(out, provider.Discovered{ProviderID: pid, ResourceType: m.Capability, Observations: obs})
	}
	return out, diags, nil
}

func (d *Driver) sweepQuotas(region string) ([]provider.Discovered, []string, error) {
	path := "/api/v1/resourcequotas"
	if region != "" {
		if !k8sNameOK.MatchString(region) {
			return nil, nil, fmt.Errorf("namespace %q is invalid", region)
		}
		path = fmt.Sprintf("/api/v1/namespaces/%s/resourcequotas", region)
	}
	st, body, err := d.call("GET", path, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("resourcequotas.list: %v", err)
	}
	if st != http.StatusOK {
		return nil, nil, fmt.Errorf("resourcequotas.list: HTTP %d", st)
	}
	var doc struct {
		Items []quotaDoc `json:"items"`
	}
	if json.Unmarshal(body, &doc) != nil {
		return nil, nil, fmt.Errorf("resourcequotas.list: unreadable")
	}
	var out []provider.Discovered
	for _, it := range doc.Items {
		ns := nsOr(it.Metadata.Namespace, rbacKind{Namespaced: true}, region)
		var obs []provider.Observation
		if v, ok := it.Spec.Hard["limits.cpu"].(string); ok && v != "" {
			obs = append(obs, provider.Observation{Path: "cpu.limit", Value: v, Derivation: "measured"})
		}
		if v, ok := it.Spec.Hard["limits.memory"].(string); ok && v != "" {
			obs = append(obs, provider.Observation{Path: "memory.limit", Value: v, Derivation: "measured"})
		}
		obs = append(obs, provider.Observation{Path: "service.managed", Value: true, Derivation: "measured"})
		out = append(out, provider.Discovered{
			ProviderID:   quotaProviderID(ns, it.Metadata.Name),
			ResourceType: "capability.compute.quota",
			Observations: obs,
		})
	}
	return out, nil, nil
}

func (d *Driver) sweepNamespaces() ([]provider.Discovered, []string, error) {
	st, body, err := d.call("GET", "/api/v1/namespaces", nil)
	if err != nil {
		return nil, nil, fmt.Errorf("namespaces.list: %v", err)
	}
	if st != http.StatusOK {
		return nil, nil, fmt.Errorf("namespaces.list: HTTP %d", st)
	}
	var doc struct {
		Items []namespaceDoc `json:"items"`
	}
	if json.Unmarshal(body, &doc) != nil {
		return nil, nil, fmt.Errorf("namespaces.list: unreadable")
	}
	var out []provider.Discovered
	var diags []string
	for _, it := range doc.Items {
		obs := []provider.Observation{{Path: "service.managed", Value: true, Derivation: "measured"}}
		if lvl := it.Metadata.Labels[podSecurityEnforceLabel]; lvl != "" && validPodSecurity[lvl] {
			obs = append(obs, provider.Observation{Path: "security.podSecurity", Value: lvl, Derivation: "measured"})
		}
		out = append(out, provider.Discovered{
			ProviderID:   nsProviderID(it.Metadata.Name),
			ResourceType: "capability.cluster.namespace",
			Observations: obs,
		})
	}
	return out, diags, nil
}

// sweep lists one kind and reverse-maps every item — rules for the role family,
// roleRef/subjects for the grant family. Cluster-scoped items carry no namespace,
// yielding a 4-field providerId.
func (d *Driver) sweep(ki rbacKind, region string) ([]provider.Discovered, []string, error) {
	path, err := ki.collPath(region)
	if err != nil {
		return nil, nil, err
	}
	st, body, err := d.call("GET", path, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("%s.list: %v", ki.Plural, err)
	}
	if st != http.StatusOK {
		return nil, nil, fmt.Errorf("%s.list: HTTP %d", ki.Plural, st)
	}
	var out []provider.Discovered
	var diags []string
	switch ki.Kind {
	case "Role", "ClusterRole":
		var doc roleListDoc
		if json.Unmarshal(body, &doc) != nil {
			return nil, nil, fmt.Errorf("%s.list: unreadable", ki.Plural)
		}
		for _, it := range doc.Items {
			ns := nsOr(it.Metadata.Namespace, ki, region)
			perms, d2 := flattenRules(it.Rules)
			diags = append(diags, d2...)
			out = append(out, provider.Discovered{
				ProviderID:   rbacProviderID(rbacGroup, rbacVersion, ki.Kind, ns, it.Metadata.Name),
				ResourceType: "capability.authorization.role",
				Observations: []provider.Observation{
					{Path: "role.permissions", Value: toAnyList(perms), Derivation: "measured"},
					{Path: "access.mutating", Value: rulesMutating(perms), Derivation: "measured"},
					{Path: "access.privileged", Value: rulesPrivileged(perms), Derivation: "measured"},
					{Path: "service.managed", Value: true, Derivation: "measured"},
				},
			})
		}
	default: // RoleBinding, ClusterRoleBinding
		var doc roleBindingListDoc
		if json.Unmarshal(body, &doc) != nil {
			return nil, nil, fmt.Errorf("%s.list: unreadable", ki.Plural)
		}
		for _, it := range doc.Items {
			ns := nsOr(it.Metadata.Namespace, ki, region)
			obsMap, d2 := reverseGrant(it.RoleRef, it.Subjects, grantScope(ki))
			diags = append(diags, d2...)
			var obs []provider.Observation
			for _, p := range sortedKeys(obsMap) {
				obs = append(obs, provider.Observation{Path: p, Value: obsMap[p], Derivation: "measured"})
			}
			out = append(out, provider.Discovered{
				ProviderID:   rbacProviderID(rbacGroup, rbacVersion, ki.Kind, ns, it.Metadata.Name),
				ResourceType: "capability.authorization.grant",
				Observations: obs,
			})
		}
	}
	return out, diags, nil
}

// nsOr falls a namespaced item's namespace back to the swept region; a
// cluster-scoped kind is always namespaceless.
func nsOr(got string, ki rbacKind, region string) string {
	if !ki.Namespaced {
		return ""
	}
	if got != "" {
		return got
	}
	return region
}
