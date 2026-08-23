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
	"sort"
	"strconv"
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
	// D700: read before writing at a name anyone can compute.
	//
	// PutDashboard is an upsert and this create used to send it blind, on the stated
	// grounds that "a dashboard present at cwDashName is ours by construction". D526
	// measured that reasoning and found it unearned: the name hashes environment and
	// capability and carries no estate identity, so two groundhold deployments over
	// one account compute the SAME name. The claim was about a name, and the name is
	// computable by anyone.
	//
	// A dashboard carries no tags, so ownership cannot be read from one. What CAN be
	// read is the dashboard itself, and that is enough for the only question that
	// matters here: if what stands at that name is byte-identical to what we would
	// write, overwriting it changes nothing and binding it is safe — the D525
	// identity-from-content reasoning, applied to content we actually read instead of
	// asserted. If it differs, something else authored it and this create refuses
	// rather than silently replacing someone's dashboard.
	if body, found, rerr := d.cwDashBody(plan.DashboardName); rerr != nil {
		return provider.CreateResult{Status: "unknown", Reason: "ownership pre-read " +
			"gave no answer, so a write at this deterministic name cannot be shown to " +
			"be safe — reconcile: " + rerr.Error()}
	} else if found {
		if body == plan.body() {
			// already exactly what this contract describes: bind it, mutate nothing.
			return provider.CreateResult{ProviderID: pid, Status: "succeeded"}
		}
		return provider.CreateResult{Status: "unknown", Reason: "a dashboard already " +
			"exists at " + plan.DashboardName + " and its content is NOT what this " +
			"contract describes — the name is derived from environment and capability " +
			"alone, so another deployment over this account computes the same one. " +
			"Refusing to overwrite it; adopt it explicitly to take it over"}
	}
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

// cwDashBody reads the dashboard at name. found=false with a nil error is an
// authoritative absence; any transport/HTTP/parse failure is an error, never an
// absence — the four-valued discipline, at the one read a create depends on.
func (d *Driver) cwDashBody(name string) (body string, found bool, err error) {
	st, resp, e := d.cwDashPost(encodeForm(map[string]string{
		"Action": "GetDashboard", "Version": cwDashVersion, "DashboardName": name}))
	if e != nil {
		return "", false, fmt.Errorf("GetDashboard: %v", e)
	}
	if strings.Contains(rdsErrCode(resp), "NotFound") {
		return "", false, nil
	}
	if st != http.StatusOK {
		return "", false, fmt.Errorf("GetDashboard: HTTP %d (%s)", st, rdsErrCode(resp))
	}
	var r struct {
		Body string `xml:"GetDashboardResult>DashboardBody"`
	}
	if xml.Unmarshal(resp, &r) != nil {
		return "", false, fmt.Errorf("GetDashboard: unparseable")
	}
	return r.Body, true, nil
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
		// F-LC3 (D521): a BOUND resource the API says is GONE. A diagnostic
		// alone leaves the binding a no-op forever (D513).
		return []provider.Observation{
			{Path: provider.ResourceAbsentPath, Value: true, Derivation: "measured"},
		}, []string{"dashboard not found — bound resource is gone (will re-create)"}, nil
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
			// Type decides whether a widget charts metrics at all: text/log/alarm/custom
			// do not, so their absence from the set is correct rather than a gap.
			Type       string `json:"type"`
			Properties struct {
				Metrics [][]string `json:"metrics"`
			} `json:"properties"`
		} `json:"widgets"`
	}
	if json.Unmarshal([]byte(r.Body), &doc) != nil {
		return nil, nil, fmt.Errorf("GetDashboard: unparseable body")
	}
	// D1236, the AWS twin. Two under-reports lived here, and `dashboard.metrics` is a
	// SET the vocabulary intends for `subset-of` — so omitting a metric makes that
	// constraint read SATISFIED over a dashboard charting something unapproved.
	//
	//   - `Metrics[0]` took the FIRST metric of each widget. A CloudWatch metric widget
	//     charts a LIST of them, so a widget with five contributed one. This is the D797
	//     shape (read Statement[0], miss the rest) in the dashboard driver.
	//   - a widget whose metrics could not be read was skipped in silence, which is
	//     indistinguishable from a widget that charts nothing.
	metrics := []string{}
	var unreadable []string
	for i, wdg := range doc.Widgets {
		if wdg.Type != "" && wdg.Type != "metric" {
			continue // text/log/alarm/custom chart no metric of their own
		}
		if len(wdg.Properties.Metrics) == 0 {
			continue // a metric widget with no series is empty, not unreadable
		}
		for _, series := range wdg.Properties.Metrics {
			if len(series) >= 2 && series[0] != "" && series[1] != "" {
				metrics = append(metrics, series[0]+"/"+series[1])
				continue
			}
			unreadable = append(unreadable, "widget "+strconv.Itoa(i)+
				" carries a metric series this driver cannot name")
		}
	}
	sort.Strings(metrics)
	obs := []provider.Observation{
		// Present: clear the marker (F-LC3), or a stale "gone" survives a re-create.
		{Path: provider.ResourceAbsentPath, Value: false, Derivation: "measured"},
		{Path: "dashboard.widgetCount", Value: float64(len(doc.Widgets)), Derivation: "measured"},
		{Path: "service.managed", Value: true, Derivation: "measured"},
	}
	var diags []string
	if len(unreadable) > 0 {
		diags = append(diags, "dashboard.metrics not observed: "+strings.Join(unreadable, "; ")+
			" — the set this driver can read is INCOMPLETE, and an incomplete set satisfies "+
			"a subset-of constraint it should not")
	} else {
		obs = append(obs, provider.Observation{Path: "dashboard.metrics", Value: metrics, Derivation: "measured"})
	}
	return obs, diags, nil
}

func (d *Driver) deleteCWDashboard(capability, environment, providerID string) provider.CreateResult {
	name, err := splitCWDashProviderID(providerID)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	// OWNERSHIP (D449). A CloudWatch dashboard carries NO TAGS — the API offers none —
	// so its deterministic NAME is the only ownership evidence, the fifth service in this
	// family with that shape (budgets D443, IAM policy and metric filter D444, SES
	// receipt rule D446). Deleting a stranger's dashboard destroys the view an on-call
	// rotation works from, and nothing about the failure is visible until someone opens
	// it during an incident.
	if !nameLooksOurs(name, capability, environment, cwDashBad, 8, true) {
		return provider.CreateResult{Status: "failed",
			Reason: fmt.Sprintf("dashboard %q is not named by groundhold for %s/%s — refusing "+
				"to delete a dashboard this contract does not own", name, capability, environment)}
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
