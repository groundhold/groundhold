// Azure Portal dashboard network shell (D107): the ARM half of the
// capability.monitoring.dashboard driver. A single PUT of a Portal dashboard,
// ownership by tags. observe counts the chart tiles across the lens and reverse-maps
// the metric set from each tile's inputs. A lost PUT is unknown (D29).
package azure

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"groundhold/internal/provider"
)

func azureDashProviderID(sub, rg, name string) string { return "azdash:" + sub + ":" + rg + ":" + name }

func splitAzureDashProviderID(providerID string) (sub, rg, name string, err error) {
	parts := strings.SplitN(providerID, ":", 4)
	if len(parts) != 4 || parts[0] != "azdash" {
		return "", "", "", fmt.Errorf("providerId %q is not azdash:sub:rg:name", providerID)
	}
	if !subOK.MatchString(parts[1]) || !rgOK.MatchString(parts[2]) {
		return "", "", "", fmt.Errorf("providerId %q has an invalid sub/rg", providerID)
	}
	if parts[3] == "" {
		return "", "", "", fmt.Errorf("providerId %q has an empty name", providerID)
	}
	return parts[1], parts[2], parts[3], nil
}

func (d *Driver) createAzureDashboard(environment, capability string,
	attrs, impl map[string]any, generation int) provider.CreateResult {
	plan, err := BuildAzureDashboard(environment, capability, attrs, impl, generation)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	rg, _ := impl["resource_group"].(string)
	if !rgOK.MatchString(rg) {
		return provider.CreateResult{Status: "failed", Reason: "azure dashboard requires implementation.resource_group"}
	}
	if !subOK.MatchString(d.Subscription) {
		return provider.CreateResult{Status: "failed",
			Reason: fmt.Sprintf("azure subscription %q is not a valid GUID", d.Subscription)}
	}
	pid := azureDashProviderID(d.Subscription, rg, plan.Name)
	iURL, _ := d.armURL(rg, "Microsoft.Portal/dashboards/"+plan.Name, portalDashAPIVersion)
	body, _ := json.Marshal(plan.createBody(d.tags(capability, environment)))
	if r := d.refuseForeignUpsert(iURL, body); r != nil { // D254
		return *r
	}
	st, resp, e := d.doARM("PUT", iURL, body)
	if e != nil {
		return provider.CreateResult{ProviderID: pid, Status: "unknown", Reason: fmt.Sprintf("create outcome unknown (may have landed): %v", e)}
	}
	switch {
	case st == http.StatusOK || st == http.StatusCreated:
		return provider.CreateResult{ProviderID: pid, Status: "succeeded"}
	case st >= 500:
		return provider.CreateResult{ProviderID: pid, Status: "unknown", Reason: fmt.Sprintf("create HTTP %d (server error — may have landed) — reconcile", st)}
	default:
		if r := provider.MutationResult(st, azErrCode(resp), nil, pid, "create"); r != nil {
			return *r
		}
		return provider.CreateResult{Status: "failed", Reason: fmt.Sprintf("create HTTP %d: %s", st, mutDetailAz(resp))}
	}
}

type azureDashDoc struct {
	Tags       map[string]string `json:"tags"`
	Properties struct {
		Lenses []struct {
			Parts []struct {
				Metadata struct {
					Inputs []struct {
						Value struct {
							Chart struct {
								Metrics []struct {
									Name string `json:"name"`
								} `json:"metrics"`
							} `json:"chart"`
						} `json:"value"`
					} `json:"inputs"`
				} `json:"metadata"`
			} `json:"parts"`
		} `json:"lenses"`
	} `json:"properties"`
}

func (d *Driver) observeAzureDashboard(capability, providerID string) ([]provider.Observation, []string, error) {
	sub, rg, name, err := splitAzureDashProviderID(providerID)
	if err != nil {
		return nil, nil, err
	}
	if sub != d.Subscription && d.Subscription != "" {
		return nil, nil, fmt.Errorf("providerId subscription %q is not the driver's", sub)
	}
	iURL, _ := d.armURL(rg, "Microsoft.Portal/dashboards/"+name, portalDashAPIVersion)
	st, resp, e := d.doARM("GET", iURL, nil)
	if e != nil {
		return nil, nil, fmt.Errorf("dashboards.get: %v", e)
	}
	if st == http.StatusNotFound {
		// F-LC3 (D518): a BOUND resource the API authoritatively 404s is GONE.
		// A diagnostic alone leaves the binding a no-op forever (D513).
		return []provider.Observation{
			{Path: provider.ResourceAbsentPath, Value: true, Derivation: "measured"},
		}, []string{"dashboard not found — bound resource is gone (will re-create)"}, nil
	}
	if st != http.StatusOK {
		return nil, nil, fmt.Errorf("dashboards.get: HTTP %d", st)
	}
	var doc azureDashDoc
	if json.Unmarshal(resp, &doc) != nil {
		return nil, nil, &armReadError{Op: "dashboards.get", Cause: "body", Status: st}
	}
	metrics := []string{}
	count := 0
	for _, lens := range doc.Properties.Lenses {
		for _, part := range lens.Parts {
			count++
			for _, in := range part.Metadata.Inputs {
				for _, mt := range in.Value.Chart.Metrics {
					if mt.Name != "" {
						metrics = append(metrics, mt.Name)
					}
				}
			}
		}
	}
	return []provider.Observation{
		// Present: clear the marker (F-LC3), or a stale "gone" survives a re-create.
		{Path: provider.ResourceAbsentPath, Value: false, Derivation: "measured"},
		{Path: "dashboard.metrics", Value: metrics, Derivation: "measured"},
		{Path: "dashboard.widgetCount", Value: float64(count), Derivation: "measured"},
		{Path: "service.managed", Value: true, Derivation: "measured"},
	}, nil, nil
}

func (d *Driver) deleteAzureDashboard(capability, environment, providerID string) provider.CreateResult {
	_, rg, name, err := splitAzureDashProviderID(providerID)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	iURL, _ := d.armURL(rg, "Microsoft.Portal/dashboards/"+name, portalDashAPIVersion)
	st, resp, e := d.doARM("GET", iURL, nil)
	if e != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown", Reason: "pre-delete read gave no answer — reconcile: " + azReadWhy(st, resp, e)}
	}
	if st == http.StatusNotFound {
		return provider.CreateResult{ProviderID: providerID, Status: "succeeded"} // idempotent
	}
	if st != http.StatusOK {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown", Reason: fmt.Sprintf("pre-delete read HTTP %d — reconcile", st)}
	}
	var doc azureDashDoc
	if json.Unmarshal(resp, &doc) != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown", Reason: "pre-delete read answered HTTP 200 with an unparseable body — reconcile"}
	}
	if doc.Tags["groundhold-capability"] != sanitizeAzTag(capability) ||
		doc.Tags["groundhold-environment"] != sanitizeAzTag(environment) {
		return provider.CreateResult{Status: "failed", Reason: "dashboard tags do not match — refusing to delete a resource that is not ours"}
	}
	dst, dresp, de := d.doARM("DELETE", iURL, nil)
	if de != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown", Reason: fmt.Sprintf("delete outcome unknown: %v", de)}
	}
	if dst == http.StatusNotFound {
		return provider.CreateResult{ProviderID: providerID, Status: "succeeded"}
	}
	if dst >= 500 {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown", Reason: fmt.Sprintf("delete HTTP %d (server error) — reconcile", dst)}
	}
	if dst < 200 || dst >= 300 {
		if r := provider.MutationResult(dst, azErrCode(dresp), nil, providerID, "delete"); r != nil {
			return *r
		}
		return provider.CreateResult{ProviderID: providerID, Status: "failed", Reason: fmt.Sprintf("delete HTTP %d: %s", dst, mutDetailAz(dresp))}
	}
	return provider.CreateResult{ProviderID: providerID, Status: "succeeded"}
}
