// k8s ResourceQuota -> capability.compute.quota: a namespace's resource BUDGET.
// ResourceQuota is a CORE-group resource (/api/v1/...), so it uses the core path
// helpers below rather than the /apis/<group>/v1 shape the RBAC/networking kinds
// use. groundhold maps only the budget semantics — the compute ceiling (cpu/memory)
// and the pod ceiling — never the per-object counts that are operational noise.
package k8s

import (
	"encoding/json"
	"fmt"
	"net/http"
)

// --- shared core-group + path-based helpers (used by quota and namespace) -----

func corePathNS(plural, namespace, name string) string {
	return fmt.Sprintf("/api/v1/namespaces/%s/%s/%s", namespace, plural, name)
}

func corePathCluster(plural, name string) string {
	return fmt.Sprintf("/api/v1/%s/%s", plural, name)
}

// oursAt is the path-based ownership guard: does the object at this REST path
// carry groundhold's ownership label for the capability?
func (d *Driver) oursAt(path, capability string) (owned, exists bool, err error) {
	st, body, e := d.call("GET", path, nil)
	if e != nil {
		return false, false, fmt.Errorf("ownership pre-read failed (transport/permission)")
	}
	if st == http.StatusNotFound {
		return false, false, nil
	}
	if st != http.StatusOK {
		return false, false, fmt.Errorf("ownership pre-read HTTP %d", st)
	}
	var doc struct {
		Metadata objectMeta `json:"metadata"`
	}
	if json.Unmarshal(body, &doc) != nil {
		return false, false, fmt.Errorf("ownership pre-read: unreadable")
	}
	return doc.Metadata.Labels[capLabel] == sanitizeLabel(capability), true, nil
}

// ssaApplyAt server-side-applies obj at the given path as fieldManager=groundhold.
// force=false ALWAYS: a write that would stomp another manager's field must come back
// as a 409 so the caller can decide, and the only caller allowed to decide is one
// holding sealed consent (ssaApplyForced, D699).
func (d *Driver) ssaApplyAt(path string, obj map[string]any) (int, []byte, error) {
	body, err := json.Marshal(obj)
	if err != nil {
		return 0, nil, err
	}
	return d.callCT("PATCH", path+"?fieldManager="+fieldMgr+"&force=false", body, "application/apply-patch+yaml")
}

// ssaApplyForced re-sends the SAME object with force=true (D699). It takes exactly the
// fields the patch carries — the ones the mapping declares — and nothing else; there
// is no call here that forces a broader object.
func (d *Driver) ssaApplyForced(path string, obj map[string]any) (int, []byte, error) {
	body, err := json.Marshal(obj)
	if err != nil {
		return 0, nil, err
	}
	return d.callCT("PATCH", path+"?fieldManager="+fieldMgr+"&force=true", body, "application/apply-patch+yaml")
}

// --- ResourceQuota ------------------------------------------------------------

type quotaDoc struct {
	Metadata objectMeta `json:"metadata"`
	Spec     struct {
		Hard map[string]any `json:"hard"`
	} `json:"spec"`
}

func quotaProviderID(namespace, name string) string {
	return rbacProviderID("core", "v1", "ResourceQuota", namespace, name)
}

// The ResourceQuota observe/build/create/update/delete twin was DELETED once the
// generic engine reproduced it byte-identically (spec/mapping migration): the
// service "quota" now routes through the schema-driven mapping (mappings/
// k8s.resourcequota.yaml). quotaDoc + quotaProviderID remain for discovery.
