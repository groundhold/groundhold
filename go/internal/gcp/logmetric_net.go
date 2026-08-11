// GCP Cloud Logging log-based metric network shell (D109): the bearer-signed half of
// the capability.monitoring.logmetric driver. The metric NAME is the id (author-provided),
// so the metric is content-addressed by (project, name); a 409 continues only if the
// existing metric is OURS (description marker). observe reverse-maps name/filter/kind.
package gcp

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"groundhold/internal/provider"
)

func (d *Driver) loggingBase() string {
	if d.LoggingBaseURL != "" {
		return d.LoggingBaseURL
	}
	return loggingBaseURL
}

func glogmetricProviderID(project, name string) string { return "glogmetric:" + project + ":" + name }

func splitGLogMetricProviderID(providerID string) (project, name string, err error) {
	parts := strings.SplitN(providerID, ":", 3)
	if len(parts) != 3 || parts[0] != "glogmetric" {
		return "", "", fmt.Errorf("providerId %q is not glogmetric:project:name", providerID)
	}
	if !projectOK.MatchString(parts[1]) {
		return "", "", fmt.Errorf("providerId project %q is invalid", parts[1])
	}
	if !logMetricNameOK.MatchString(parts[2]) {
		return "", "", fmt.Errorf("providerId metric name %q is invalid", parts[2])
	}
	return parts[1], parts[2], nil
}

type logMetricDoc struct {
	Name             string `json:"name"`
	Description      string `json:"description"`
	Filter           string `json:"filter"`
	ValueExtractor   string `json:"valueExtractor"`
	MetricDescriptor struct {
		ValueType string `json:"valueType"`
	} `json:"metricDescriptor"`
}

func (d *Driver) getLogMetric(project, name string) (logMetricDoc, bool, error) {
	const op = "logMetric.get"
	url := fmt.Sprintf("%s/projects/%s/metrics/%s", d.loggingBase(), project, name)
	st, body, err := d.call("GET", url, nil)
	if err != nil {
		return logMetricDoc{}, false, readTransport(op, err)
	}
	if st == http.StatusNotFound {
		return logMetricDoc{}, false, nil
	}
	if st != http.StatusOK {
		return logMetricDoc{}, false, readHTTP(op, st, gcpErrCode(body))
	}
	var doc logMetricDoc
	if json.Unmarshal(body, &doc) != nil {
		return logMetricDoc{}, false, readBody(op, st)
	}
	return doc, true, nil
}

func (d *Driver) createLogMetric(capability, environment string,
	attrs, impl map[string]any, generation int) provider.CreateResult {
	plan, err := BuildLogMetric(d.Project, environment, capability, attrs, impl, generation)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	pid := glogmetricProviderID(d.Project, plan.Name)
	url := fmt.Sprintf("%s/projects/%s/metrics", d.loggingBase(), d.Project)
	st, body, e := d.call("POST", url, plan.createBody())
	switch {
	case e != nil:
		return provider.CreateResult{ProviderID: pid, Status: "unknown",
			Reason: fmt.Sprintf("create outcome unknown (may have landed): %v", e)}
	case st == http.StatusOK || st == http.StatusCreated:
		return provider.CreateResult{ProviderID: pid, Status: "succeeded"}
	case st == http.StatusConflict:
		doc, found, rerr := d.getLogMetric(d.Project, plan.Name)
		if rerr != nil {
			return provider.CreateResult{ProviderID: pid, Status: "unknown", Reason: "name conflict, existing metric gave no answer — reconcile: " + rerr.Error()}
		}
		if !found || doc.Description != plan.Description {
			return provider.CreateResult{Status: "failed", Reason: "a log metric with this name exists and is not ours (description marker does not match)"}
		}
		return provider.CreateResult{ProviderID: pid, Status: "succeeded"}
	case st >= 500:
		return provider.CreateResult{ProviderID: pid, Status: "unknown",
			Reason: fmt.Sprintf("create HTTP %d (server error — may have landed) — reconcile", st)}
	default:
		if r := provider.MutationResult(st, gcpErrCode(body), nil, pid, "create"); r != nil {
			return *r
		}
		return provider.CreateResult{Status: "failed", Reason: fmt.Sprintf("create HTTP %d: %s", st, mutDetail(body))}
	}
}

func (d *Driver) observeLogMetric(capability, providerID string) ([]provider.Observation, []string, error) {
	project, name, err := splitGLogMetricProviderID(providerID)
	if err != nil {
		return nil, nil, err
	}
	if err := d.sameProject(project); err != nil {
		return nil, nil, err
	}
	doc, found, rerr := d.getLogMetric(project, name)
	if rerr != nil {
		return nil, nil, rerr
	}
	if !found {
		// F-LC3 (D519): a BOUND resource the API authoritatively 404s is GONE.
		// A diagnostic alone leaves the binding a no-op forever (D513).
		return []provider.Observation{
			{Path: provider.ResourceAbsentPath, Value: true, Derivation: "measured"},
		}, []string{"log metric not found — bound resource is gone (will re-create)"}, nil
	}
	kind := "counter"
	if doc.ValueExtractor != "" {
		kind = "gauge"
	}
	return []provider.Observation{
		// Present: clear the marker (F-LC3), or a stale "gone" survives a re-create.
		{Path: provider.ResourceAbsentPath, Value: false, Derivation: "measured"},
		{Path: "metric.name", Value: doc.Name, Derivation: "measured"},
		{Path: "metric.filter", Value: doc.Filter, Derivation: "measured"},
		{Path: "metric.kind", Value: kind, Derivation: "measured"},
		{Path: "service.managed", Value: true, Derivation: "measured"},
	}, nil, nil
}

func (d *Driver) deleteLogMetric(capability, environment, providerID string) provider.CreateResult {
	project, name, err := splitGLogMetricProviderID(providerID)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	if err := d.sameProject(project); err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	doc, found, rerr := d.getLogMetric(project, name)
	if rerr != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown", Reason: "pre-delete read gave no answer — reconcile: " + rerr.Error()}
	}
	if !found {
		return provider.CreateResult{ProviderID: providerID, Status: "succeeded"} // idempotent
	}
	if doc.Description != logMetricDescription(capability, environment) {
		return provider.CreateResult{Status: "failed", Reason: "log metric description marker does not match — refusing to delete a resource that is not ours"}
	}
	url := fmt.Sprintf("%s/projects/%s/metrics/%s", d.loggingBase(), project, name)
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
