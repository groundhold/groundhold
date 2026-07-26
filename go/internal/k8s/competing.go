// Competing-reconciler detection (the provider.CompetingManagers capability).
// Before groundhold adopts a governance object, it must know whether a CONTINUOUS
// reconciler (ArgoCD, Flux, Helm) already owns it — binding to something that
// another controller will keep re-applying is an apply war, and D52 refuses it
// fail-closed. Signals are all observable on the object itself: tracking
// labels/annotations, and managedFields managers known to be continuous
// reconcilers. A one-shot writer (kubectl, or Terraform's own manager entry —
// which is EXPECTED, since TF created the object we are taking over) is NOT a
// competitor; only continuous reconcilers are.
package k8s

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sort"

	"groundhold/internal/provider"
)

var _ provider.CompetingManagers = (*Driver)(nil)

// continuousReconcilerManagers are managedFields[].manager values that belong to
// controllers which re-apply on drift. kubectl / terraform / groundhold are not here:
// they write once, they do not fight.
var continuousReconcilerManagers = map[string]bool{
	"argocd-controller":             true,
	"argocd-application-controller": true,
	"helm":                          true,
	"helm-controller":               true, // Flux Helm
	"kustomize-controller":          true, // Flux
	"flux":                          true,
}

// metaWithManagedFields extends the object metadata we read with managedFields.
type managedField struct {
	Manager string `json:"manager"`
}

type competeMeta struct {
	Labels      map[string]string `json:"labels,omitempty"`
	Annotations map[string]string `json:"annotations,omitempty"`
	Managed     []managedField    `json:"managedFields,omitempty"`
}

type competeDoc struct {
	Metadata competeMeta `json:"metadata"`
}

// CompetingManagers reports foreign continuous reconcilers owning the object.
func (d *Driver) CompetingManagers(service, providerID string) ([]string, error) {
	if err := d.requireService(service); err != nil {
		return nil, err
	}
	ki, err := kindInfo(service)
	if err != nil {
		return nil, err
	}
	_, _, namespace, name, err := splitRBACProviderID(providerID, ki.Kind)
	if err != nil {
		return nil, err
	}
	st, body, err := d.call("GET", ki.objPath(namespace, name), nil)
	if err != nil {
		return nil, fmt.Errorf("read for competing-reconciler check failed: %w", err)
	}
	if st == http.StatusNotFound {
		return nil, nil // nothing there yet — no competitor
	}
	if st != http.StatusOK {
		return nil, fmt.Errorf("read for competing-reconciler check: HTTP %d", st)
	}
	var doc competeDoc
	if json.Unmarshal(body, &doc) != nil {
		return nil, fmt.Errorf("competing-reconciler check: object unreadable")
	}
	return competingManagersOf(doc.Metadata), nil
}

// competingManagersOf is the pure detector, unit-testable without a server.
func competingManagersOf(m competeMeta) []string {
	found := map[string]bool{}
	// ArgoCD tracking
	if _, ok := m.Annotations["argocd.argoproj.io/tracking-id"]; ok {
		found["argocd"] = true
	}
	if v := m.Labels["app.kubernetes.io/instance"]; v != "" {
		// ArgoCD's default tracking label; Helm also sets instance but is caught below
		found["argocd"] = true
	}
	// Helm release ownership
	if m.Labels["app.kubernetes.io/managed-by"] == "Helm" {
		found["helm"] = true
	}
	if _, ok := m.Annotations["meta.helm.sh/release-name"]; ok {
		found["helm"] = true
	}
	// managedFields owned by a known continuous reconciler
	for _, f := range m.Managed {
		if continuousReconcilerManagers[f.Manager] {
			found[f.Manager] = true
		}
	}
	if len(found) == 0 {
		return nil
	}
	out := make([]string, 0, len(found))
	for k := range found {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
