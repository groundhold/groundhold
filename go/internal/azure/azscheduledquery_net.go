// Azure scheduled query rule network shell (D109): the ARM half of the
// capability.monitoring.logmetric driver. A single PUT of a scheduled query rule,
// ownership by tags. observe reverse-maps name/filter/kind from the rule's displayName +
// criteria. A lost PUT is unknown (D29). NOT live-validated (no Azure creds here).
package azure

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"groundhold/internal/provider"
)

func azureSQProviderID(sub, rg, name string) string { return "azlm:" + sub + ":" + rg + ":" + name }

func splitAzureSQProviderID(providerID string) (sub, rg, name string, err error) {
	parts := strings.SplitN(providerID, ":", 4)
	if len(parts) != 4 || parts[0] != "azlm" {
		return "", "", "", fmt.Errorf("providerId %q is not azlm:sub:rg:name", providerID)
	}
	if !subOK.MatchString(parts[1]) || !rgOK.MatchString(parts[2]) {
		return "", "", "", fmt.Errorf("providerId %q has an invalid sub/rg", providerID)
	}
	if parts[3] == "" {
		return "", "", "", fmt.Errorf("providerId %q has an empty name", providerID)
	}
	return parts[1], parts[2], parts[3], nil
}

func (d *Driver) createAzureScheduledQuery(environment, capability string,
	attrs, impl map[string]any, generation int) provider.CreateResult {
	plan, err := BuildAzureScheduledQuery(environment, capability, attrs, impl, generation)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	rg, _ := impl["resource_group"].(string)
	if !rgOK.MatchString(rg) {
		return provider.CreateResult{Status: "failed", Reason: "azure scheduled query rule requires implementation.resource_group"}
	}
	if !subOK.MatchString(d.Subscription) {
		return provider.CreateResult{Status: "failed",
			Reason: fmt.Sprintf("azure subscription %q is not a valid GUID", d.Subscription)}
	}
	pid := azureSQProviderID(d.Subscription, rg, plan.Name)
	iURL, _ := d.armURL(rg, "Microsoft.Insights/scheduledQueryRules/"+plan.Name, scheduledQueryAPIVersion)
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

type azureSQDoc struct {
	Tags       map[string]string `json:"tags"`
	Properties struct {
		DisplayName string `json:"displayName"`
		Criteria    struct {
			AllOf []struct {
				Query               string `json:"query"`
				MetricMeasureColumn string `json:"metricMeasureColumn"`
			} `json:"allOf"`
		} `json:"criteria"`
	} `json:"properties"`
}

func (d *Driver) observeAzureScheduledQuery(capability, providerID string) ([]provider.Observation, []string, error) {
	sub, rg, name, err := splitAzureSQProviderID(providerID)
	if err != nil {
		return nil, nil, err
	}
	if sub != d.Subscription && d.Subscription != "" {
		return nil, nil, fmt.Errorf("providerId subscription %q is not the driver's", sub)
	}
	iURL, _ := d.armURL(rg, "Microsoft.Insights/scheduledQueryRules/"+name, scheduledQueryAPIVersion)
	st, resp, e := d.doARM("GET", iURL, nil)
	if e != nil {
		return nil, nil, fmt.Errorf("scheduledQueryRules.get: %v", e)
	}
	if st == http.StatusNotFound {
		return nil, []string{"scheduled query rule not found — nothing to observe"}, nil
	}
	if st != http.StatusOK {
		return nil, nil, fmt.Errorf("scheduledQueryRules.get: HTTP %d", st)
	}
	var doc azureSQDoc
	if json.Unmarshal(resp, &doc) != nil || len(doc.Properties.Criteria.AllOf) == 0 {
		return nil, nil, fmt.Errorf("scheduledQueryRules.get: empty criteria — %w", armBody("scheduledQueryRules.get", st))
	}
	c := doc.Properties.Criteria.AllOf[0]
	kind := "counter"
	if c.MetricMeasureColumn != "" {
		kind = "gauge"
	}
	return []provider.Observation{
		{Path: "metric.name", Value: doc.Properties.DisplayName, Derivation: "measured"},
		{Path: "metric.filter", Value: c.Query, Derivation: "measured"},
		{Path: "metric.kind", Value: kind, Derivation: "measured"},
		{Path: "service.managed", Value: true, Derivation: "measured"},
	}, nil, nil
}

func (d *Driver) deleteAzureScheduledQuery(capability, environment, providerID string) provider.CreateResult {
	_, rg, name, err := splitAzureSQProviderID(providerID)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	iURL, _ := d.armURL(rg, "Microsoft.Insights/scheduledQueryRules/"+name, scheduledQueryAPIVersion)
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
	var doc azureSQDoc
	if json.Unmarshal(resp, &doc) != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown", Reason: "pre-delete read answered HTTP 200 with an unparseable body — reconcile"}
	}
	if doc.Tags["groundhold-capability"] != sanitizeAzTag(capability) ||
		doc.Tags["groundhold-environment"] != sanitizeAzTag(environment) {
		return provider.CreateResult{Status: "failed", Reason: "scheduled query rule tags do not match — refusing to delete a resource that is not ours"}
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
