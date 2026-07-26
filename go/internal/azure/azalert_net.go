// Azure Monitor metric alert network shell (D106): the ARM half of the
// capability.monitoring.alert driver. A single PUT of a metricAlert, ownership by
// tags, observe reverse-maps the single criterion. A lost PUT is unknown (D29).
package azure

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"groundhold/internal/provider"
)

func azureAlertProviderID(sub, rg, name string) string {
	return "azalert:" + sub + ":" + rg + ":" + name
}

func splitAzureAlertProviderID(providerID string) (sub, rg, name string, err error) {
	parts := strings.SplitN(providerID, ":", 4)
	if len(parts) != 4 || parts[0] != "azalert" {
		return "", "", "", fmt.Errorf("providerId %q is not azalert:sub:rg:name", providerID)
	}
	if !subOK.MatchString(parts[1]) || !rgOK.MatchString(parts[2]) {
		return "", "", "", fmt.Errorf("providerId %q has an invalid sub/rg", providerID)
	}
	if parts[3] == "" {
		return "", "", "", fmt.Errorf("providerId %q has an empty name", providerID)
	}
	return parts[1], parts[2], parts[3], nil
}

func (d *Driver) createAzureAlert(environment, capability string,
	attrs, impl map[string]any, generation int) provider.CreateResult {
	plan, err := BuildAzureAlert(environment, capability, attrs, impl, generation)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	rg, _ := impl["resource_group"].(string)
	if !rgOK.MatchString(rg) {
		return provider.CreateResult{Status: "failed", Reason: "azure metric alert requires implementation.resource_group"}
	}
	if !subOK.MatchString(d.Subscription) {
		return provider.CreateResult{Status: "failed",
			Reason: fmt.Sprintf("azure subscription %q is not a valid GUID", d.Subscription)}
	}
	pid := azureAlertProviderID(d.Subscription, rg, plan.Name)
	iURL, _ := d.armURL(rg, "Microsoft.Insights/metricAlerts/"+plan.Name, metricAlertAPIVersion)
	criterion := map[string]any{
		"name":            "cond1",
		"metricName":      plan.MetricName,
		"operator":        plan.Operator,
		"threshold":       plan.Threshold,
		"timeAggregation": "Average",
		"criterionType":   "StaticThresholdCriterion",
	}
	props := map[string]any{
		"severity":            3,
		"enabled":             true,
		"scopes":              []any{plan.Scope},
		"evaluationFrequency": "PT1M",
		"windowSize":          "PT5M",
		"criteria": map[string]any{
			"odata.type": "Microsoft.Azure.Monitor.SingleResourceMultipleMetricCriteria",
			"allOf":      []any{criterion},
		},
	}
	if plan.Notify {
		props["actions"] = []any{map[string]any{"actionGroupId": plan.ActionGroup}}
	}
	body, _ := json.Marshal(map[string]any{
		"location":   "global",
		"tags":       d.tags(capability, environment),
		"properties": props,
	})
	if r := d.refuseForeignUpsert(iURL, body); r != nil { // D254
		return *r
	}
	st, resp, e := d.doARM("PUT", iURL, body)
	if e != nil {
		return provider.CreateResult{ProviderID: pid, Status: "unknown",
			Reason: fmt.Sprintf("create outcome unknown (may have landed): %v", e)}
	}
	switch {
	case st == http.StatusOK || st == http.StatusCreated:
		return provider.CreateResult{ProviderID: pid, Status: "succeeded"}
	case st >= 500:
		return provider.CreateResult{ProviderID: pid, Status: "unknown",
			Reason: fmt.Sprintf("create HTTP %d (server error — may have landed) — reconcile", st)}
	default:
		if r := provider.MutationResult(st, azErrCode(resp), nil, pid, "create"); r != nil {
			return *r
		}
		return provider.CreateResult{Status: "failed", Reason: fmt.Sprintf("create HTTP %d: %s", st, mutDetailAz(resp))}
	}
}

type azureAlertDoc struct {
	Tags       map[string]string `json:"tags"`
	Properties struct {
		Criteria struct {
			AllOf []struct {
				MetricName string  `json:"metricName"`
				Operator   string  `json:"operator"`
				Threshold  float64 `json:"threshold"`
			} `json:"allOf"`
		} `json:"criteria"`
		Actions []struct {
			ActionGroupID string `json:"actionGroupId"`
		} `json:"actions"`
	} `json:"properties"`
}

func (d *Driver) observeAzureAlert(capability, providerID string) ([]provider.Observation, []string, error) {
	sub, rg, name, err := splitAzureAlertProviderID(providerID)
	if err != nil {
		return nil, nil, err
	}
	if sub != d.Subscription && d.Subscription != "" {
		return nil, nil, fmt.Errorf("providerId subscription %q is not the driver's", sub)
	}
	iURL, _ := d.armURL(rg, "Microsoft.Insights/metricAlerts/"+name, metricAlertAPIVersion)
	st, resp, e := d.doARM("GET", iURL, nil)
	if e != nil {
		return nil, nil, fmt.Errorf("metricAlerts.get: %v", e)
	}
	if st == http.StatusNotFound {
		return nil, []string{"metric alert not found — nothing to observe"}, nil
	}
	if st != http.StatusOK {
		return nil, nil, fmt.Errorf("metricAlerts.get: HTTP %d", st)
	}
	var doc azureAlertDoc
	if json.Unmarshal(resp, &doc) != nil || len(doc.Properties.Criteria.AllOf) == 0 {
		return nil, nil, fmt.Errorf("metricAlerts.get: empty criteria — %w", armBody("metricAlerts.get", st))
	}
	c := doc.Properties.Criteria.AllOf[0]
	obs := []provider.Observation{
		{Path: "alert.metric", Value: c.MetricName, Derivation: "measured"},
		{Path: "alert.threshold", Value: c.Threshold, Derivation: "measured"},
		{Path: "alert.notify", Value: len(doc.Properties.Actions) > 0, Derivation: "measured"},
		{Path: "service.managed", Value: true, Derivation: "measured"},
	}
	switch c.Operator {
	case "GreaterThan":
		obs = append(obs, provider.Observation{Path: "alert.comparison", Value: "greater-than", Derivation: "measured"})
	case "LessThan":
		obs = append(obs, provider.Observation{Path: "alert.comparison", Value: "less-than", Derivation: "measured"})
	}
	return obs, nil, nil
}

func (d *Driver) deleteAzureAlert(capability, environment, providerID string) provider.CreateResult {
	sub, rg, name, err := splitAzureAlertProviderID(providerID)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	_ = sub
	iURL, _ := d.armURL(rg, "Microsoft.Insights/metricAlerts/"+name, metricAlertAPIVersion)
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
	var doc azureAlertDoc
	if json.Unmarshal(resp, &doc) != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown", Reason: "pre-delete read answered HTTP 200 with an unparseable body — reconcile"}
	}
	if doc.Tags["groundhold-capability"] != sanitizeAzTag(capability) ||
		doc.Tags["groundhold-environment"] != sanitizeAzTag(environment) {
		return provider.CreateResult{Status: "failed", Reason: "metric alert tags do not match — refusing to delete a resource that is not ours"}
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
