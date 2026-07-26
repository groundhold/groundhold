// The generic engine's write path (learn-from-API-contract, slice 3). It is the
// inverse of observeMapped: build a k8s object from the contract's attribute values
// via the same closed op set, then write it through the ONE ownership strategy
// (groundhold labels + server-side apply as fieldManager=groundhold), written here once
// for every GVK. create/update/delete reuse the drift guard and the path-based
// ownership guard already shared with the hand-coded drivers. The request body is
// pinned byte-identical to the hand-coded twin.
package k8s

import (
	"fmt"

	"groundhold/internal/mapping"
	"groundhold/internal/provider"
)

// apiVersion renders the object's apiVersion: bare version for the core group,
// group/version otherwise.
func (m *Mapping) apiVersion() string {
	if m.Resource.Group == "" || m.Resource.Group == "core" {
		return m.Resource.Version
	}
	return m.Resource.Group + "/" + m.Resource.Version
}

// pidGroup is the providerId group token — "core" for the empty core group.
func (m *Mapping) pidGroup() string {
	if m.Resource.Group == "" {
		return "core"
	}
	return m.Resource.Group
}

func (m *Mapping) providerID(ns, name string) string {
	return rbacProviderID(m.pidGroup(), m.Resource.Version, m.Resource.Kind, ns, name)
}

// buildMappedObject assembles the apply body from the candidate's attribute values.
// const attributes are assert-only (a contradicting declaration refuses, never
// written); copy/quantity-int set their field. An undeclared attribute writes
// nothing (the object simply omits it).
func (m *Mapping) buildMappedObject(ns, name, capability, environment string, attrs, impl map[string]any) (map[string]any, error) {
	obj := map[string]any{"apiVersion": m.apiVersion(), "kind": m.Resource.Kind}
	meta := map[string]any{"name": name, "labels": ownershipLabels(capability, environment)}
	if m.Resource.Scope == "Namespaced" {
		meta["namespace"] = ns
	}
	obj["metadata"] = meta
	for _, path := range sortedAttrKeys(m.Attributes) {
		a := m.Attributes[path]
		val, present := attrs[path]
		switch a.Op {
		case "const":
			if present && fmt.Sprintf("%v", val) != fmt.Sprintf("%v", a.Value) {
				return nil, fmt.Errorf("%s must equal %v (const) but the candidate declares %v", path, a.Value, val)
			}
		case "copy":
			if present {
				if err := mapping.SetField(obj, a.Field, val); err != nil {
					return nil, err
				}
			}
		case "quantity-int":
			if present {
				if err := mapping.SetField(obj, a.Field, fmt.Sprintf("%v", val)); err != nil {
					return nil, err
				}
			}
		}
	}
	// write-lenses author the conditional/structural fields the closed ops cannot
	// (a NetworkPolicy's default-deny spec, a Certificate's dnsNames + issuer).
	for _, lens := range m.Lenses {
		if w := lensRegistry[lens].write; w != nil {
			if err := w(obj, attrs, impl); err != nil {
				return nil, err
			}
		}
	}
	return obj, nil
}

// validateMapped is the refuse-before-mutate hook: it builds the object (surfacing
// a const contradiction, an unresolvable field, or a write-lens refusal) without
// writing.
func (m *Mapping) validateMapped(attrs, impl map[string]any) error {
	_, err := m.buildMappedObject("_", "_", "_", "_", attrs, impl)
	return err
}

func (d *Driver) createMapped(m *Mapping, capability, environment string, attrs, impl map[string]any) provider.CreateResult {
	if _, err := d.guardDrift(m); err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	ns := ""
	if m.Resource.Scope == "Namespaced" {
		ns = namespaceOf(impl)
	}
	name := roleName(capability, environment)
	if impl != nil {
		if n, _ := impl["name"].(string); n != "" {
			name = n // a cluster-scoped object's name IS its identity (e.g. Namespace)
		}
	}
	obj, err := m.buildMappedObject(ns, name, capability, environment, attrs, impl)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	st, b, e := d.ssaApplyAt(m.objectPath(ns, name), obj)
	return netpolApplyResult(m.providerID(ns, name), st, b, e)
}

func (d *Driver) updateMapped(m *Mapping, capability, environment, providerID string, attrs, impl map[string]any) provider.CreateResult {
	if _, err := d.guardDrift(m); err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	ns, name, err := m.parseProviderID(providerID)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	owned, exists, err := d.oursAt(m.objectPath(ns, name), capability)
	if err != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown", Reason: err.Error()}
	}
	if !exists {
		return provider.CreateResult{Status: "failed", Reason: m.Resource.Kind + " no longer exists — re-observe and re-seal"}
	}
	if !owned {
		return provider.CreateResult{Status: "failed", Reason: "labels do not match — refusing to patch a " + m.Resource.Kind + " that is not ours (claim it first)"}
	}
	obj, err := m.buildMappedObject(ns, name, capability, environment, attrs, impl)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	st, b, e := d.ssaApplyAt(m.objectPath(ns, name), obj)
	return netpolApplyResult(providerID, st, b, e)
}

func (d *Driver) deleteMapped(m *Mapping, capability, providerID string) provider.CreateResult {
	ns, name, err := m.parseProviderID(providerID)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	owned, exists, err := d.oursAt(m.objectPath(ns, name), capability)
	if err != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown", Reason: err.Error()}
	}
	if !exists {
		return provider.CreateResult{ProviderID: providerID, Status: "succeeded"} // idempotent
	}
	if !owned {
		return provider.CreateResult{Status: "failed", Reason: "labels do not match — refusing to delete a " + m.Resource.Kind + " that is not ours"}
	}
	st, b, e := d.call("DELETE", m.objectPath(ns, name), nil)
	if e != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown", Reason: fmt.Sprintf("delete outcome unknown: %v", e)}
	}
	if st == 200 || st == 404 {
		return provider.CreateResult{ProviderID: providerID, Status: "succeeded"}
	}
	if st >= 500 {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown", Reason: fmt.Sprintf("delete HTTP %d (server error) — reconcile", st)}
	}
	return provider.CreateResult{ProviderID: providerID, Status: "failed", Reason: fmt.Sprintf("delete HTTP %d: %s", st, mutDetail(b))}
}
