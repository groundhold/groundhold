// GCP Cloud Monitoring alerting policy network shell (D106): the bearer-signed half
// of the capability.monitoring.alert driver. The policy id is SERVER-ASSIGNED, so the
// providerId is parsed from the response (a lost create is unknown, reconcile by
// displayName). Ownership is userLabels; observe reverse-maps the single condition.
package gcp

import (
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strings"

	"groundhold/internal/provider"
)

var alertPolicyIDOK = regexp.MustCompile(`^[0-9A-Za-z_-]+$`)
var metricFromFilter = regexp.MustCompile(`metric\.type="([^"]+)"`)

func (d *Driver) monitoringBase() string {
	if d.MonitoringBaseURL != "" {
		return d.MonitoringBaseURL
	}
	return monitoringBaseURL
}

func galertProviderID(project, policyID string) string { return "galert:" + project + ":" + policyID }

func splitGAlertProviderID(providerID string) (project, policyID string, err error) {
	parts := strings.SplitN(providerID, ":", 3)
	if len(parts) != 3 || parts[0] != "galert" {
		return "", "", fmt.Errorf("providerId %q is not galert:project:policyId", providerID)
	}
	if !projectOK.MatchString(parts[1]) {
		return "", "", fmt.Errorf("providerId project %q is invalid", parts[1])
	}
	if !alertPolicyIDOK.MatchString(parts[2]) {
		return "", "", fmt.Errorf("providerId policyId %q is invalid", parts[2])
	}
	return parts[1], parts[2], nil
}

func (d *Driver) createAlertPolicy(capability, environment string,
	attrs, impl map[string]any, generation int) provider.CreateResult {
	plan, err := BuildAlertPolicy(d.Project, environment, capability, attrs, impl, generation)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	url := fmt.Sprintf("%s/projects/%s/alertPolicies", d.monitoringBase(), d.Project)
	// create-adoption (D255): server-assigned id — bind an existing policy with our
	// displayName instead of minting a duplicate.
	if id, found, ok := d.findByDisplayName(url, "alertPolicies", plan.DisplayName); ok && found {
		return provider.CreateResult{ProviderID: galertProviderID(d.Project, id), Status: "succeeded"}
	}
	st, body, e := d.call("POST", url, plan.createBody(capability, environment))
	if e != nil {
		if id, found, ok := d.findByDisplayName(url, "alertPolicies", plan.DisplayName); ok && found {
			return provider.CreateResult{ProviderID: galertProviderID(d.Project, id), Status: "succeeded"}
		}
		return provider.CreateResult{Status: "unknown",
			Reason: fmt.Sprintf("create outcome unknown (may have landed; reconcile by displayName %q): %v", plan.DisplayName, e)}
	}
	if st == http.StatusOK || st == http.StatusCreated {
		var doc struct {
			Name string `json:"name"`
		}
		if json.Unmarshal(body, &doc) != nil || doc.Name == "" {
			return provider.CreateResult{Status: "unknown", Reason: "create response carried no policy name — reconcile"}
		}
		id := doc.Name[strings.LastIndex(doc.Name, "/")+1:]
		return provider.CreateResult{ProviderID: galertProviderID(d.Project, id), Status: "succeeded"}
	}
	if st >= 500 {
		return provider.CreateResult{Status: "unknown",
			Reason: fmt.Sprintf("create HTTP %d (server error — may have landed; reconcile by displayName) — %s", st, mutDetail(body))}
	}
	if r := provider.MutationResult(st, gcpErrCode(body), nil, "", "create"); r != nil {
		return *r
	}
	return provider.CreateResult{Status: "failed", Reason: fmt.Sprintf("create HTTP %d: %s", st, mutDetail(body))}
}

type alertPolicyDoc struct {
	UserLabels map[string]string `json:"userLabels"`
	Conditions []struct {
		ConditionThreshold struct {
			Filter         string  `json:"filter"`
			Comparison     string  `json:"comparison"`
			ThresholdValue float64 `json:"thresholdValue"`
		} `json:"conditionThreshold"`
	} `json:"conditions"`
	NotificationChannels []string `json:"notificationChannels"`
}

func (d *Driver) getAlertPolicy(project, policyID string) (alertPolicyDoc, bool, error) {
	const op = "alertPolicy.get"
	url := fmt.Sprintf("%s/projects/%s/alertPolicies/%s", d.monitoringBase(), project, policyID)
	st, body, err := d.call("GET", url, nil)
	if err != nil {
		return alertPolicyDoc{}, false, readTransport(op, err)
	}
	if st == http.StatusNotFound {
		return alertPolicyDoc{}, false, nil
	}
	if st != http.StatusOK {
		return alertPolicyDoc{}, false, readHTTP(op, st, gcpErrCode(body))
	}
	var doc alertPolicyDoc
	if json.Unmarshal(body, &doc) != nil {
		return alertPolicyDoc{}, false, readBody(op, st)
	}
	return doc, true, nil
}

func (d *Driver) observeAlertPolicy(capability, providerID string) ([]provider.Observation, []string, error) {
	project, policyID, err := splitGAlertProviderID(providerID)
	if err != nil {
		return nil, nil, err
	}
	if err := d.sameProject(project); err != nil {
		return nil, nil, err
	}
	doc, found, rerr := d.getAlertPolicy(project, policyID)
	if rerr != nil {
		return nil, nil, rerr
	}
	if !found || len(doc.Conditions) == 0 {
		return nil, []string{"alert policy not found (or has no condition) — nothing to observe"}, nil
	}
	cond := doc.Conditions[0].ConditionThreshold
	obs := []provider.Observation{
		{Path: "alert.threshold", Value: cond.ThresholdValue, Derivation: "measured"},
		{Path: "alert.notify", Value: len(doc.NotificationChannels) > 0, Derivation: "measured"},
		{Path: "service.managed", Value: true, Derivation: "measured"},
	}
	if m := metricFromFilter.FindStringSubmatch(cond.Filter); m != nil {
		obs = append(obs, provider.Observation{Path: "alert.metric", Value: m[1], Derivation: "measured"})
	}
	switch cond.Comparison {
	case "COMPARISON_GT":
		obs = append(obs, provider.Observation{Path: "alert.comparison", Value: "greater-than", Derivation: "measured"})
	case "COMPARISON_LT":
		obs = append(obs, provider.Observation{Path: "alert.comparison", Value: "less-than", Derivation: "measured"})
	}
	return obs, nil, nil
}

func (d *Driver) deleteAlertPolicy(capability, environment, providerID string) provider.CreateResult {
	project, policyID, err := splitGAlertProviderID(providerID)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	if err := d.sameProject(project); err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	doc, found, rerr := d.getAlertPolicy(project, policyID)
	if rerr != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown", Reason: "pre-delete read gave no answer — reconcile: " + rerr.Error()}
	}
	if !found {
		return provider.CreateResult{ProviderID: providerID, Status: "succeeded"} // idempotent
	}
	if doc.UserLabels["groundhold-capability"] != sanitizeLabel(capability) ||
		doc.UserLabels["groundhold-environment"] != sanitizeLabel(environment) {
		return provider.CreateResult{Status: "failed", Reason: "alert policy labels do not match — refusing to delete a resource that is not ours"}
	}
	url := fmt.Sprintf("%s/projects/%s/alertPolicies/%s", d.monitoringBase(), project, policyID)
	st, body, e := d.call("DELETE", url, nil)
	if e != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown", Reason: fmt.Sprintf("delete outcome unknown: %v", e)}
	}
	if st == http.StatusNotFound {
		return provider.CreateResult{ProviderID: providerID, Status: "succeeded"}
	}
	if st >= 500 {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown", Reason: fmt.Sprintf("delete HTTP %d (server error) — reconcile", st)}
	}
	if st < 200 || st >= 300 {
		if r := provider.MutationResult(st, gcpErrCode(body), nil, providerID, "delete"); r != nil {
			return *r
		}
		return provider.CreateResult{ProviderID: providerID, Status: "failed", Reason: fmt.Sprintf("delete HTTP %d: %s", st, mutDetail(body))}
	}
	return provider.CreateResult{ProviderID: providerID, Status: "succeeded"}
}
