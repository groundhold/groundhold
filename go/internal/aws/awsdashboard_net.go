// CloudWatch dashboard network shell (D107): the SigV4-signed half of the AWS
// capability.monitoring.dashboard driver. CloudWatch dashboards are GLOBAL (a single
// account-wide namespace), so the endpoint is us-east-1 and the dashboard is
// content-addressed by its deterministic name (PutDashboard is an upsert; the name is
// the handle). observe parses the DashboardBody JSON back into the metric set.
package aws

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"net/http"
	"strings"

	"groundhold/internal/provider"
)

const cwDashVersion = "2010-08-01"

func (d *Driver) cwDashBase() string {
	if d.CloudWatchDashBaseURL != "" {
		return d.CloudWatchDashBaseURL
	}
	return "https://monitoring.us-east-1.amazonaws.com"
}

func (d *Driver) cwDashPost(body string) (int, []byte, error) {
	return d.doSigned("POST", d.cwDashBase()+"/", "monitoring", "us-east-1",
		map[string]string{"Content-Type": "application/x-www-form-urlencoded"}, []byte(body))
}

func cwDashProviderID(name string) string { return "cwdash:" + name }

func splitCWDashProviderID(providerID string) (name string, err error) {
	parts := strings.SplitN(providerID, ":", 2)
	if len(parts) != 2 || parts[0] != "cwdash" {
		return "", fmt.Errorf("providerId %q is not cwdash:name", providerID)
	}
	if !dashNameOK.MatchString(parts[1]) {
		return "", fmt.Errorf("providerId dashboard name %q is invalid", parts[1])
	}
	return parts[1], nil
}

func (d *Driver) createCWDashboard(environment, capability string,
	attrs, impl map[string]any, generation int) provider.CreateResult {
	plan, err := BuildCWDashboard(environment, capability, attrs, impl, generation)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	pid := cwDashProviderID(plan.DashboardName)
	st, resp, e := d.cwDashPost(encodeForm(map[string]string{
		"Action": "PutDashboard", "Version": cwDashVersion,
		"DashboardName": plan.DashboardName, "DashboardBody": plan.body()}))
	if e != nil {
		return provider.CreateResult{ProviderID: pid, Status: "unknown", Reason: fmt.Sprintf("PutDashboard outcome unknown: %v", e)}
	}
	if st == http.StatusOK {
		return provider.CreateResult{ProviderID: pid, Status: "succeeded"}
	}
	if st >= 500 {
		return provider.CreateResult{ProviderID: pid, Status: "unknown", Reason: fmt.Sprintf("PutDashboard HTTP %d (server error — may have landed): %s", st, mutDetail(resp))}
	}
	if r := provider.MutationResult(st, rdsErrCode(resp), nil, pid, "create"); r != nil {
		return *r
	}
	return provider.CreateResult{Status: "failed", Reason: fmt.Sprintf("PutDashboard HTTP %d (%s): %s", st, rdsErrCode(resp), mutDetail(resp))}
}

func (d *Driver) observeCWDashboard(capability, providerID string) ([]provider.Observation, []string, error) {
	name, err := splitCWDashProviderID(providerID)
	if err != nil {
		return nil, nil, err
	}
	st, resp, e := d.cwDashPost(encodeForm(map[string]string{
		"Action": "GetDashboard", "Version": cwDashVersion, "DashboardName": name}))
	if e != nil {
		return nil, nil, fmt.Errorf("GetDashboard: %v", e)
	}
	if strings.Contains(rdsErrCode(resp), "NotFound") {
		return nil, []string{"dashboard not found — nothing to observe"}, nil
	}
	if st != http.StatusOK {
		return nil, nil, fmt.Errorf("GetDashboard: HTTP %d", st)
	}
	var r struct {
		Body string `xml:"GetDashboardResult>DashboardBody"`
	}
	if xml.Unmarshal(resp, &r) != nil {
		return nil, nil, fmt.Errorf("GetDashboard: unparseable")
	}
	var doc struct {
		Widgets []struct {
			Properties struct {
				Metrics [][]string `json:"metrics"`
			} `json:"properties"`
		} `json:"widgets"`
	}
	if json.Unmarshal([]byte(r.Body), &doc) != nil {
		return nil, nil, fmt.Errorf("GetDashboard: unparseable body")
	}
	metrics := []string{}
	for _, wdg := range doc.Widgets {
		if len(wdg.Properties.Metrics) > 0 && len(wdg.Properties.Metrics[0]) >= 2 {
			metrics = append(metrics, wdg.Properties.Metrics[0][0]+"/"+wdg.Properties.Metrics[0][1])
		}
	}
	return []provider.Observation{
		{Path: "dashboard.metrics", Value: metrics, Derivation: "measured"},
		{Path: "dashboard.widgetCount", Value: float64(len(doc.Widgets)), Derivation: "measured"},
		{Path: "service.managed", Value: true, Derivation: "measured"},
	}, nil, nil
}

func (d *Driver) deleteCWDashboard(capability, environment, providerID string) provider.CreateResult {
	name, err := splitCWDashProviderID(providerID)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	st, resp, e := d.cwDashPost(encodeForm(map[string]string{
		"Action": "DeleteDashboards", "Version": cwDashVersion, "DashboardNames.member.1": name}))
	if e != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown", Reason: fmt.Sprintf("delete outcome unknown: %v", e)}
	}
	if strings.Contains(rdsErrCode(resp), "NotFound") {
		return provider.CreateResult{ProviderID: providerID, Status: "succeeded"} // idempotent
	}
	if st == http.StatusOK {
		return provider.CreateResult{ProviderID: providerID, Status: "succeeded"}
	}
	if st >= 500 {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown", Reason: fmt.Sprintf("delete HTTP %d (server error) — reconcile", st)}
	}
	if r := provider.MutationResult(st, rdsErrCode(resp), nil, providerID, "delete"); r != nil {
		return *r
	}
	return provider.CreateResult{Status: "failed", Reason: fmt.Sprintf("delete HTTP %d (%s)", st, rdsErrCode(resp))}
}
