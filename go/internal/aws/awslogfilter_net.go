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
	// D804: read before writing at a name anyone can compute (the D700 rule, applied to
	// the next entry of the register that names where it was not applied yet).
	//
	// PutMetricFilter is an UPSERT, and this create used to send it blind. The filter
	// name is derived from environment and capability alone, so a second groundhold
	// deployment over the same account — or anybody following the same convention —
	// computes the same one. A blind upsert therefore REPLACES whatever stands there
	// and reports `succeeded`, which says "I made this" about a filter somebody else
	// authored and has just lost.
	//
	// A metric filter carries no tags, so ownership cannot be read from one; what CAN
	// be read is the filter itself. Identical content means overwriting changes nothing
	// and binding is safe; different content means someone else authored it.
	if existing, found, rerr := d.metricFilterOf(plan.Region, plan.LogGroup, plan.FilterName); rerr != nil {
		return provider.CreateResult{Status: "unknown", Reason: "ownership pre-read gave " +
			"no answer, so a write at this deterministic name cannot be shown to be safe " +
			"— reconcile: " + rerr.Error()}
	} else if found {
		if existing == plan.putBody() {
			// already exactly what this contract describes: bind it, mutate nothing.
			return provider.CreateResult{ProviderID: pid, Status: "succeeded"}
		}
		return provider.CreateResult{Status: "unknown", Reason: "a metric filter already " +
			"exists at " + plan.FilterName + " on log group " + plan.LogGroup + " and its " +
			"pattern or metric is NOT what this contract describes — the name is derived " +
			"from environment and capability alone, so another deployment over this " +
			"account computes the same one. Refusing to overwrite it; adopt it explicitly " +
			"to take it over"}
	}
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

// metricFilterOf reads one metric filter and renders it in the shape the create would
// WRITE, so the comparison is between two bodies built the same way rather than between
// a body and a paraphrase of one (D804).
func (d *Driver) metricFilterOf(region, logGroup, filterName string) (string, bool, error) {
	body, _ := json.Marshal(map[string]any{"logGroupName": logGroup, "filterNamePrefix": filterName})
	st, resp, e := d.logsCall(region, "DescribeMetricFilters", string(body))
	if e != nil {
		return "", false, fmt.Errorf("DescribeMetricFilters: %v", e)
	}
	if strings.Contains(ecsErr(resp), "ResourceNotFound") {
		return "", false, nil // no log group / no filter: nothing stands at the name
	}
	if st != http.StatusOK {
		return "", false, fmt.Errorf("DescribeMetricFilters: HTTP %d", st)
	}
	var r struct {
		MetricFilters []struct {
			FilterName            string `json:"filterName"`
			FilterPattern         string `json:"filterPattern"`
			MetricTransformations []struct {
				MetricName      string `json:"metricName"`
				MetricNamespace string `json:"metricNamespace"`
				MetricValue     string `json:"metricValue"`
			} `json:"metricTransformations"`
		} `json:"metricFilters"`
	}
	if json.Unmarshal(resp, &r) != nil {
		return "", false, fmt.Errorf("DescribeMetricFilters: unparseable")
	}
	for _, mf := range r.MetricFilters {
		if mf.FilterName != filterName || len(mf.MetricTransformations) == 0 {
			continue
		}
		t := mf.MetricTransformations[0]
		rendered, _ := json.Marshal(map[string]any{
			"logGroupName":  logGroup,
			"filterName":    mf.FilterName,
			"filterPattern": mf.FilterPattern,
			"metricTransformations": []any{map[string]any{
				"metricName":      t.MetricName,
				"metricNamespace": t.MetricNamespace,
				"metricValue":     t.MetricValue,
			}},
		})
		return string(rendered), true, nil
	}
	return "", false, nil
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
		// F-LC3 (D522): GONE, said with the reserved marker.
		return []provider.Observation{
			{Path: provider.ResourceAbsentPath, Value: true, Derivation: "measured"},
		}, []string{"log group / metric filter not found — bound resource is gone (will re-create)"}, nil
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
	// F-LC3 (D522): GONE, said with the reserved marker.
	return []provider.Observation{
		{Path: provider.ResourceAbsentPath, Value: true, Derivation: "measured"},
	}, []string{"metric filter not found — bound resource is gone (will re-create)"}, nil
}

func (d *Driver) deleteCWLogFilter(capability, environment, providerID string) provider.CreateResult {
	region, logGroup, filterName, err := splitCWLogFilterProviderID(providerID)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	// OWNERSHIP (D444): a metric filter carries no tags, so its deterministic NAME is
	// the only ownership evidence. Without this a providerId naming any filter in any
	// log group removed that filter — including one another team relies on for alerting.
	if !nameLooksOurs(filterName, capability, environment, logFilterBad, 8, true) {
		return provider.CreateResult{Status: "failed",
			Reason: fmt.Sprintf("metric filter %q is not named by groundhold for %s/%s — "+
				"refusing to delete a filter this contract does not own",
				filterName, capability, environment)}
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
