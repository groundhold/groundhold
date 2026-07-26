// CloudWatch Logs metric filter network shell (D109): the SigV4-signed (regional, JSON
// protocol) half of the AWS capability.monitoring.logmetric driver. PutMetricFilter is an
// upsert; the filter is content-addressed by (logGroup, filterName), both deterministic.
// observe reads the pattern + metricValue back via DescribeMetricFilters.
package aws

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"groundhold/internal/provider"
)

const logsTarget = "Logs_20140328"

func (d *Driver) logsBase(region string) string {
	if d.LogsBaseURL != "" {
		return d.LogsBaseURL
	}
	return "https://logs." + region + ".amazonaws.com"
}

func (d *Driver) logsCall(region, action, body string) (int, []byte, error) {
	h := map[string]string{
		"Content-Type": "application/x-amz-json-1.1",
		"X-Amz-Target": logsTarget + "." + action,
	}
	return d.doSigned("POST", d.logsBase(region)+"/", "logs", region, h, []byte(body))
}

func cwLogFilterProviderID(region, logGroup, filterName string) string {
	return "cwlogfilter:" + region + ":" + logGroup + ":" + filterName
}

func splitCWLogFilterProviderID(providerID string) (region, logGroup, filterName string, err error) {
	parts := strings.SplitN(providerID, ":", 4)
	if len(parts) != 4 || parts[0] != "cwlogfilter" {
		return "", "", "", fmt.Errorf("providerId %q is not cwlogfilter:region:logGroup:filterName", providerID)
	}
	if !regionOK.MatchString(parts[1]) {
		return "", "", "", fmt.Errorf("providerId region %q is invalid", parts[1])
	}
	if !logGroupOK.MatchString(parts[2]) {
		return "", "", "", fmt.Errorf("providerId log group %q is invalid", parts[2])
	}
	if !logFilterNameOK.MatchString(parts[3]) {
		return "", "", "", fmt.Errorf("providerId filter name %q is invalid", parts[3])
	}
	return parts[1], parts[2], parts[3], nil
}

func (d *Driver) createCWLogFilter(environment, capability string,
	attrs, impl map[string]any, generation int) provider.CreateResult {
	plan, err := BuildCWLogFilter(environment, capability, attrs, impl, generation)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	pid := cwLogFilterProviderID(plan.Region, plan.LogGroup, plan.FilterName)
	st, resp, e := d.logsCall(plan.Region, "PutMetricFilter", plan.putBody())
	if e != nil {
		return provider.CreateResult{ProviderID: pid, Status: "unknown", Reason: fmt.Sprintf("PutMetricFilter outcome unknown: %v", e)}
	}
	if st == http.StatusOK {
		return provider.CreateResult{ProviderID: pid, Status: "succeeded"}
	}
	if strings.Contains(ecsErr(resp), "ResourceNotFound") {
		return provider.CreateResult{Status: "failed", Reason: fmt.Sprintf("log group %q does not exist", plan.LogGroup)}
	}
	if st >= 500 {
		return provider.CreateResult{ProviderID: pid, Status: "unknown", Reason: fmt.Sprintf("PutMetricFilter HTTP %d (server error — may have landed): %s", st, mutDetail(resp))}
	}
	if r := provider.MutationResult(st, ecsErr(resp), nil, pid, "create"); r != nil {
		return *r
	}
	return provider.CreateResult{Status: "failed", Reason: fmt.Sprintf("PutMetricFilter HTTP %d: %s", st, mutDetail(resp))}
}

func (d *Driver) observeCWLogFilter(capability, providerID string) ([]provider.Observation, []string, error) {
	region, logGroup, filterName, err := splitCWLogFilterProviderID(providerID)
	if err != nil {
		return nil, nil, err
	}
	body, _ := json.Marshal(map[string]any{"logGroupName": logGroup, "filterNamePrefix": filterName})
	st, resp, e := d.logsCall(region, "DescribeMetricFilters", string(body))
	if e != nil {
		return nil, nil, fmt.Errorf("DescribeMetricFilters: %v", e)
	}
	if strings.Contains(ecsErr(resp), "ResourceNotFound") {
		return nil, []string{"log group / metric filter not found — nothing to observe"}, nil
	}
	if st != http.StatusOK {
		return nil, nil, fmt.Errorf("DescribeMetricFilters: HTTP %d", st)
	}
	var r struct {
		MetricFilters []struct {
			FilterName            string `json:"filterName"`
			FilterPattern         string `json:"filterPattern"`
			MetricTransformations []struct {
				MetricName  string `json:"metricName"`
				MetricValue string `json:"metricValue"`
			} `json:"metricTransformations"`
		} `json:"metricFilters"`
	}
	if json.Unmarshal(resp, &r) != nil {
		return nil, nil, fmt.Errorf("DescribeMetricFilters: unparseable")
	}
	// match the exact filter name (prefix search may return more).
	for _, mf := range r.MetricFilters {
		if mf.FilterName != filterName || len(mf.MetricTransformations) == 0 {
			continue
		}
		kind := "counter"
		if mf.MetricTransformations[0].MetricValue != "1" {
			kind = "gauge"
		}
		return []provider.Observation{
			{Path: "metric.name", Value: mf.MetricTransformations[0].MetricName, Derivation: "measured"},
			{Path: "metric.filter", Value: mf.FilterPattern, Derivation: "measured"},
			{Path: "metric.kind", Value: kind, Derivation: "measured"},
			{Path: "service.managed", Value: true, Derivation: "measured"},
		}, nil, nil
	}
	return nil, []string{"metric filter not found — nothing to observe"}, nil
}

func (d *Driver) deleteCWLogFilter(capability, environment, providerID string) provider.CreateResult {
	region, logGroup, filterName, err := splitCWLogFilterProviderID(providerID)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	body, _ := json.Marshal(map[string]any{"logGroupName": logGroup, "filterName": filterName})
	st, resp, e := d.logsCall(region, "DeleteMetricFilter", string(body))
	if e != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown", Reason: fmt.Sprintf("delete outcome unknown: %v", e)}
	}
	if st == http.StatusOK || strings.Contains(ecsErr(resp), "ResourceNotFound") {
		return provider.CreateResult{ProviderID: providerID, Status: "succeeded"} // idempotent
	}
	if st >= 500 {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown", Reason: fmt.Sprintf("delete HTTP %d (server error) — reconcile", st)}
	}
	if r := provider.MutationResult(st, ecsErr(resp), nil, providerID, "delete"); r != nil {
		return *r
	}
	return provider.CreateResult{Status: "failed", Reason: fmt.Sprintf("delete HTTP %d: %s", st, mutDetail(resp))}
}
