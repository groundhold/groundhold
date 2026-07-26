// GCP Cloud Monitoring dashboard network shell (D107): the bearer-signed half of the
// capability.monitoring.dashboard driver. The dashboard id is SERVER-ASSIGNED (parse
// from the response; a lost create is unknown). Ownership is a displayName marker.
// observe counts the tiles and reverse-maps the metric set from the tile filters.
package gcp

import (
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strings"

	"groundhold/internal/provider"
)

var dashIDOK = regexp.MustCompile(`^[0-9A-Za-z_-]+$`)

func (d *Driver) dashboardBase() string {
	if d.DashboardBaseURL != "" {
		return d.DashboardBaseURL
	}
	return dashboardBaseURL
}

func gdashProviderID(project, id string) string { return "gdash:" + project + ":" + id }

func splitGDashProviderID(providerID string) (project, id string, err error) {
	parts := strings.SplitN(providerID, ":", 3)
	if len(parts) != 3 || parts[0] != "gdash" {
		return "", "", fmt.Errorf("providerId %q is not gdash:project:id", providerID)
	}
	if !projectOK.MatchString(parts[1]) {
		return "", "", fmt.Errorf("providerId project %q is invalid", parts[1])
	}
	if !dashIDOK.MatchString(parts[2]) {
		return "", "", fmt.Errorf("providerId dashboard id %q is invalid", parts[2])
	}
	return parts[1], parts[2], nil
}

func (d *Driver) createDashboard(capability, environment string,
	attrs, impl map[string]any, generation int) provider.CreateResult {
	plan, err := BuildDashboard(d.Project, environment, capability, attrs, impl, generation)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	url := fmt.Sprintf("%s/projects/%s/dashboards", d.dashboardBase(), d.Project)
	// create-adoption (D255): the dashboard id is server-assigned, so bind an
	// existing dashboard with our displayName instead of minting a duplicate.
	if id, found, ok := d.findByDisplayName(url, "dashboards", plan.DisplayName); ok && found {
		return provider.CreateResult{ProviderID: gdashProviderID(d.Project, id), Status: "succeeded"}
	}
	st, body, e := d.call("POST", url, plan.createBody())
	if e != nil {
		// lost response — the dashboard MAY have landed; re-list to recover its id.
		if id, found, ok := d.findByDisplayName(url, "dashboards", plan.DisplayName); ok && found {
			return provider.CreateResult{ProviderID: gdashProviderID(d.Project, id), Status: "succeeded"}
		}
		return provider.CreateResult{Status: "unknown",
			Reason: fmt.Sprintf("create outcome unknown (may have landed; reconcile by displayName %q): %v", plan.DisplayName, e)}
	}
	if st == http.StatusOK || st == http.StatusCreated {
		var doc struct {
			Name string `json:"name"`
		}
		if json.Unmarshal(body, &doc) != nil || doc.Name == "" {
			return provider.CreateResult{Status: "unknown", Reason: "create response carried no dashboard name — reconcile"}
		}
		id := doc.Name[strings.LastIndex(doc.Name, "/")+1:]
		return provider.CreateResult{ProviderID: gdashProviderID(d.Project, id), Status: "succeeded"}
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

type dashboardDoc struct {
	DisplayName  string `json:"displayName"`
	MosaicLayout struct {
		Tiles []struct {
			Widget struct {
				XyChart struct {
					DataSets []struct {
						TimeSeriesQuery struct {
							TimeSeriesFilter struct {
								Filter string `json:"filter"`
							} `json:"timeSeriesFilter"`
						} `json:"timeSeriesQuery"`
					} `json:"dataSets"`
				} `json:"xyChart"`
			} `json:"widget"`
		} `json:"tiles"`
	} `json:"mosaicLayout"`
}

func (d *Driver) getDashboard(project, id string) (dashboardDoc, bool, error) {
	const op = "dashboard.get"
	url := fmt.Sprintf("%s/projects/%s/dashboards/%s", d.dashboardBase(), project, id)
	st, body, err := d.call("GET", url, nil)
	if err != nil {
		return dashboardDoc{}, false, readTransport(op, err)
	}
	if st == http.StatusNotFound {
		return dashboardDoc{}, false, nil
	}
	if st != http.StatusOK {
		return dashboardDoc{}, false, readHTTP(op, st, gcpErrCode(body))
	}
	var doc dashboardDoc
	if json.Unmarshal(body, &doc) != nil {
		return dashboardDoc{}, false, readBody(op, st)
	}
	return doc, true, nil
}

func (d *Driver) observeDashboard(capability, providerID string) ([]provider.Observation, []string, error) {
	project, id, err := splitGDashProviderID(providerID)
	if err != nil {
		return nil, nil, err
	}
	if err := d.sameProject(project); err != nil {
		return nil, nil, err
	}
	doc, found, rerr := d.getDashboard(project, id)
	if rerr != nil {
		return nil, nil, rerr
	}
	if !found {
		return nil, []string{"dashboard not found — nothing to observe"}, nil
	}
	metrics := []string{}
	for _, tile := range doc.MosaicLayout.Tiles {
		for _, ds := range tile.Widget.XyChart.DataSets {
			if m := metricFromFilterDash(ds.TimeSeriesQuery.TimeSeriesFilter.Filter); m != "" {
				metrics = append(metrics, m)
			}
		}
	}
	return []provider.Observation{
		{Path: "dashboard.metrics", Value: metrics, Derivation: "measured"},
		{Path: "dashboard.widgetCount", Value: float64(len(doc.MosaicLayout.Tiles)), Derivation: "measured"},
		{Path: "service.managed", Value: true, Derivation: "measured"},
	}, nil, nil
}

func metricFromFilterDash(filter string) string {
	const p = `metric.type="`
	i := strings.Index(filter, p)
	if i < 0 {
		return ""
	}
	rest := filter[i+len(p):]
	j := strings.IndexByte(rest, '"')
	if j < 0 {
		return ""
	}
	return rest[:j]
}

func (d *Driver) deleteDashboard(capability, environment, providerID string) provider.CreateResult {
	project, id, err := splitGDashProviderID(providerID)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	if err := d.sameProject(project); err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	doc, found, rerr := d.getDashboard(project, id)
	if rerr != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown", Reason: "pre-delete read gave no answer — reconcile: " + rerr.Error()}
	}
	if !found {
		return provider.CreateResult{ProviderID: providerID, Status: "succeeded"} // idempotent
	}
	if doc.DisplayName != dashDisplayName(capability, environment) {
		return provider.CreateResult{Status: "failed", Reason: "dashboard displayName marker does not match — refusing to delete a resource that is not ours"}
	}
	url := fmt.Sprintf("%s/projects/%s/dashboards/%s", d.dashboardBase(), project, id)
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
