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
	"sort"
	"strconv"
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
	DisplayName string `json:"displayName"`
	// D1236: the layout and the widget body are kept RAW and walked generically.
	//
	// A typed struct decodes exactly the shapes somebody thought of, and silently
	// returns zero values for the rest — which is how this driver came to read ONE of
	// the API's four layouts (`gridLayout`, `columnLayout`, `mosaicLayout`, `rowLayout`)
	// and ONE of its ~18 widget kinds. A dashboard in a grid layout, or one built from
	// scorecards, produced an EMPTY metric set, and an empty set satisfies the
	// `subset-of` constraint the vocabulary names as this attribute's purpose.
	Raw json.RawMessage `json:"-"`
}

// dashboardLayouts are the four containers the Monitoring API defines. Named as a set
// so a fifth is a build-time decision rather than a silent omission.
var dashboardLayouts = []string{"mosaicLayout", "gridLayout", "rowLayout", "columnLayout"}

// dashboardMetricWidgets are the widget kinds that CHART a metric and whose query this
// driver can read. dashboardInertWidgets chart nothing, so their presence is not a gap.
// Anything in NEITHER list is a widget that may chart a metric this driver cannot
// extract — the case that must be disclosed rather than skipped.
var dashboardMetricWidgets = map[string]bool{"xyChart": true, "scorecard": true}

var dashboardInertWidgets = map[string]bool{
	"text": true, "blank": true, "sectionHeader": true, "title": true,
	"filterControl": true, "id": true, "visibilityCondition": true,
	"logsPanel": true, "incidentList": true, "errorReportingPanel": true,
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
	// Keep the body: the layout and widget walk reads it generically (D1236), which is
	// what stops a shape nobody typed from becoming an empty answer.
	doc.Raw = append(json.RawMessage(nil), body...)
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
		// F-LC3 (D519): a BOUND resource the API authoritatively 404s is GONE.
		// A diagnostic alone leaves the binding a no-op forever (D513).
		return []provider.Observation{
			{Path: provider.ResourceAbsentPath, Value: true, Derivation: "measured"},
		}, []string{"dashboard not found — bound resource is gone (will re-create)"}, nil
	}
	obs := []provider.Observation{
		// Present: clear the marker (F-LC3), or a stale "gone" survives a re-create.
		{Path: provider.ResourceAbsentPath, Value: false, Derivation: "measured"},
		{Path: "service.managed", Value: true, Derivation: "measured"},
	}
	var diags []string
	metrics, unreadable, merr := dashboardMetrics(doc.Raw)
	switch {
	case merr != nil:
		diags = append(diags, "dashboard.metrics not observed: "+merr.Error())
	case len(unreadable) > 0:
		// D1236: a SET claimed from a partial read is not the set. The vocabulary names
		// `subset-of` as this attribute's purpose, and an omitted metric makes that
		// constraint read SATISFIED over a dashboard charting something unapproved — so
		// a partial answer is withheld rather than shipped as if it were complete.
		diags = append(diags, "dashboard.metrics not observed: this dashboard carries "+
			strconv.Itoa(len(unreadable))+" element(s) whose charted metric this driver "+
			"cannot read ("+strings.Join(unreadable, "; ")+"), so the set it does read is "+
			"INCOMPLETE — and an incomplete set satisfies a subset-of constraint it should not")
	default:
		obs = append(obs, provider.Observation{Path: "dashboard.metrics", Value: metrics, Derivation: "measured"})
	}
	if n, ok := dashboardWidgetCount(doc.Raw); ok {
		obs = append(obs, provider.Observation{Path: "dashboard.widgetCount",
			Value: float64(n), Derivation: "measured"})
	} else {
		diags = append(diags, "dashboard.widgetCount not observed: no layout this driver "+
			"recognises was present on the dashboard")
	}
	return obs, diags, nil
}

// dashboardWidgetCount counts widgets across every layout. It used to count the tiles
// of the ONE layout the driver decoded, so a dashboard in any other reported zero
// widgets — a number, stated as measured, about a dashboard full of them.
func dashboardWidgetCount(raw []byte) (int, bool) {
	var doc map[string]json.RawMessage
	if json.Unmarshal(raw, &doc) != nil {
		return 0, false
	}
	total, found := 0, false
	for _, layout := range dashboardLayouts {
		blob, ok := doc[layout]
		if !ok {
			continue
		}
		var l struct {
			Widgets []json.RawMessage `json:"widgets"`
			Tiles   []json.RawMessage `json:"tiles"`
		}
		if json.Unmarshal(blob, &l) != nil {
			continue
		}
		found = true
		total += len(l.Widgets) + len(l.Tiles)
	}
	return total, found
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

// dashboardMetrics walks EVERY layout and EVERY widget of a dashboard document and
// returns the metrics it could read, plus the widgets it could not.
//
// D1236. The attribute is a SET — the vocabulary says a contract constrains it with
// `subset-of` ("the dashboard charts only approved metrics") — and a set claimed from
// a partial read is not that set. Under-reporting is the dangerous direction here:
// omit a metric and `subset-of` reads SATISFIED over a dashboard charting something
// the allowlist never named.
//
// So the walk is generic rather than typed: layouts by name from a declared set,
// widgets by whichever key each carries. A widget kind that is neither known-readable
// nor known-inert is REPORTED, not skipped — including one Google adds tomorrow, which
// is the direction that keeps this from silently re-opening.
func dashboardMetrics(raw []byte) (metrics []string, unreadable []string, err error) {
	var doc map[string]json.RawMessage
	if e := json.Unmarshal(raw, &doc); e != nil {
		return nil, nil, fmt.Errorf("dashboard body: %v", e)
	}
	metrics = []string{}
	for _, layout := range dashboardLayouts {
		blob, ok := doc[layout]
		if !ok {
			continue
		}
		var l struct {
			Widgets []json.RawMessage `json:"widgets"`
			Tiles   []struct {
				Widget json.RawMessage `json:"widget"`
			} `json:"tiles"`
		}
		if json.Unmarshal(blob, &l) != nil {
			unreadable = append(unreadable, layout+" (its shape did not decode)")
			continue
		}
		widgets := l.Widgets
		for _, t := range l.Tiles {
			if len(t.Widget) > 0 {
				widgets = append(widgets, t.Widget)
			}
		}
		for _, w := range widgets {
			m, bad := widgetMetrics(w)
			metrics = append(metrics, m...)
			unreadable = append(unreadable, bad...)
		}
	}
	sort.Strings(metrics)
	sort.Strings(unreadable)
	return metrics, unreadable, nil
}

// widgetMetrics reads one widget. A collapsibleGroup / singleViewGroup nests more
// widgets, so it recurses rather than counting itself as unreadable.
func widgetMetrics(w json.RawMessage) (metrics []string, unreadable []string) {
	var kinds map[string]json.RawMessage
	if json.Unmarshal(w, &kinds) != nil {
		return nil, []string{"a widget whose body did not decode"}
	}
	for kind, body := range kinds {
		switch {
		case dashboardInertWidgets[kind]:
			// charts nothing; its absence from the set is correct
		case kind == "collapsibleGroup" || kind == "singleViewGroup":
			var grp struct {
				Widgets []json.RawMessage `json:"widgets"`
			}
			if json.Unmarshal(body, &grp) != nil {
				unreadable = append(unreadable, kind+" (its nested widgets did not decode)")
				continue
			}
			for _, inner := range grp.Widgets {
				m, bad := widgetMetrics(inner)
				metrics = append(metrics, m...)
				unreadable = append(unreadable, bad...)
			}
		case dashboardMetricWidgets[kind]:
			m, ok := widgetQueryMetrics(body)
			if !ok {
				unreadable = append(unreadable, kind+" (its query is not a metric.type filter this driver reads)")
				continue
			}
			metrics = append(metrics, m...)
		default:
			unreadable = append(unreadable, kind+" (a widget kind this driver does not read)")
		}
	}
	return metrics, unreadable
}

// widgetQueryMetrics pulls metric.type out of a widget's timeSeriesFilter queries —
// directly (scorecard) or per dataSet (xyChart). ok=false means the widget charts
// something this driver cannot name, which the caller discloses.
func widgetQueryMetrics(body json.RawMessage) (metrics []string, ok bool) {
	var w struct {
		DataSets        []json.RawMessage `json:"dataSets"`
		TimeSeriesQuery json.RawMessage   `json:"timeSeriesQuery"`
	}
	if json.Unmarshal(body, &w) != nil {
		return nil, false
	}
	queries := w.DataSets
	if len(w.TimeSeriesQuery) > 0 {
		queries = append(queries, body)
	}
	if len(queries) == 0 {
		return nil, false
	}
	for _, q := range queries {
		var ds struct {
			TimeSeriesQuery struct {
				TimeSeriesFilter struct {
					Filter string `json:"filter"`
				} `json:"timeSeriesFilter"`
			} `json:"timeSeriesQuery"`
		}
		if json.Unmarshal(q, &ds) != nil {
			return nil, false
		}
		m := metricFromFilterDash(ds.TimeSeriesQuery.TimeSeriesFilter.Filter)
		if m == "" {
			return nil, false
		}
		metrics = append(metrics, m)
	}
	return metrics, true
}
