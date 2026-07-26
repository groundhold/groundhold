package azure

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"groundhold/internal/provider"
)

// azGapBServer answers the subscription-scope LIST for each gap-B service plus the
// per-resource GET that each service's observe reverse map reads. Every list is
// keyed on the subscription-scope path (no /resourceGroups/ segment); every observe
// GET is resource-group scoped. Metric alerts + FrontDoor WAF report location
// "global" (subscription-global). The regional services report "West Europe".
func azGapBServer(t *testing.T, sawBearer *bool) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("Authorization") == "Bearer test-token" {
				*sawBearer = true
			}
			p := r.URL.Path
			switch {
			// --- metric alerts (subscription-global, location "global") ---
			case strings.HasSuffix(p, "/providers/Microsoft.Insights/metricAlerts") &&
				!strings.Contains(p, "/resourceGroups/"):
				_, _ = w.Write([]byte(`{"value":[
					{"id":"/subscriptions/` + testSub + `/resourceGroups/rg1/providers/Microsoft.Insights/metricAlerts/cpu-high","name":"cpu-high","location":"global"}
				]}`))
			case strings.Contains(p, "/metricAlerts/cpu-high"):
				_, _ = w.Write([]byte(`{"location":"global","properties":{` +
					`"actions":[{"actionGroupId":"/x"}],` +
					`"criteria":{"allOf":[{"metricName":"Percentage CPU","operator":"GreaterThan","threshold":80}]}}}`))

			// --- FrontDoor WAF policies (subscription-global, location "global") ---
			case strings.HasSuffix(p, "/providers/Microsoft.Network/FrontDoorWebApplicationFirewallPolicies") &&
				!strings.Contains(p, "/resourceGroups/"):
				_, _ = w.Write([]byte(`{"value":[
					{"id":"/subscriptions/` + testSub + `/resourceGroups/rg1/providers/Microsoft.Network/FrontDoorWebApplicationFirewallPolicies/wafpolicy","name":"wafpolicy","location":"global"}
				]}`))
			case strings.Contains(p, "/FrontDoorWebApplicationFirewallPolicies/wafpolicy"):
				_, _ = w.Write([]byte(`{"properties":{"provisioningState":"Succeeded",` +
					`"policySettings":{"mode":"Prevention"},` +
					`"managedRules":{"managedRuleSets":[{"ruleSetType":"Microsoft_DefaultRuleSet"},{"ruleSetType":"Microsoft_BotManagerRuleSet"}]}}}`))

			// --- Portal dashboards (regional) ---
			case strings.HasSuffix(p, "/providers/Microsoft.Portal/dashboards") &&
				!strings.Contains(p, "/resourceGroups/"):
				_, _ = w.Write([]byte(`{"value":[
					{"id":"/subscriptions/` + testSub + `/resourceGroups/rg1/providers/Microsoft.Portal/dashboards/heredash","name":"heredash","location":"West Europe"},
					{"id":"/subscriptions/` + testSub + `/resourceGroups/rg2/providers/Microsoft.Portal/dashboards/fardash","name":"fardash","location":"eastus"}
				]}`))
			case strings.Contains(p, "/dashboards/heredash"):
				_, _ = w.Write([]byte(`{"location":"westeurope","properties":{"lenses":{"0":{"parts":` +
					`{"0":{"metadata":{"inputs":[{"value":{"chart":{"metrics":[{"name":"Requests"}]}}}]}}}}}}}`))

			// --- availability webtests (regional) ---
			case strings.HasSuffix(p, "/providers/Microsoft.Insights/webtests") &&
				!strings.Contains(p, "/resourceGroups/"):
				_, _ = w.Write([]byte(`{"value":[
					{"id":"/subscriptions/` + testSub + `/resourceGroups/rg1/providers/Microsoft.Insights/webtests/herewt","name":"herewt","location":"West Europe"},
					{"id":"/subscriptions/` + testSub + `/resourceGroups/rg2/providers/Microsoft.Insights/webtests/farwt","name":"farwt","location":"eastus"}
				]}`))
			case strings.Contains(p, "/webtests/herewt"):
				_, _ = w.Write([]byte(`{"location":"westeurope","properties":{"Frequency":300,` +
					`"Request":{"RequestUrl":"https://example.com/health"}}}`))

			// --- scheduled query rules (regional) ---
			case strings.HasSuffix(p, "/providers/Microsoft.Insights/scheduledQueryRules") &&
				!strings.Contains(p, "/resourceGroups/"):
				_, _ = w.Write([]byte(`{"value":[
					{"id":"/subscriptions/` + testSub + `/resourceGroups/rg1/providers/Microsoft.Insights/scheduledQueryRules/heresq","name":"heresq","location":"West Europe"},
					{"id":"/subscriptions/` + testSub + `/resourceGroups/rg2/providers/Microsoft.Insights/scheduledQueryRules/farsq","name":"farsq","location":"eastus"}
				]}`))
			case strings.Contains(p, "/scheduledQueryRules/heresq"):
				_, _ = w.Write([]byte(`{"location":"westeurope","properties":{"displayName":"errors",` +
					`"criteria":{"allOf":[{"query":"Heartbeat | count","metricMeasureColumn":"Count"}]}}}`))

			// --- Event Hubs (regional namespace, two-level) ---
			case strings.HasSuffix(p, "/providers/Microsoft.EventHub/namespaces") &&
				!strings.Contains(p, "/resourceGroups/"):
				_, _ = w.Write([]byte(`{"value":[
					{"id":"/subscriptions/` + testSub + `/resourceGroups/rg1/providers/Microsoft.EventHub/namespaces/ehns","name":"ehns","location":"West Europe"},
					{"id":"/subscriptions/` + testSub + `/resourceGroups/rg2/providers/Microsoft.EventHub/namespaces/farehns","name":"farehns","location":"eastus"}
				]}`))
			case strings.HasSuffix(p, "/namespaces/ehns/eventhubs/stream"):
				_, _ = w.Write([]byte(`{"properties":{"messageRetentionInDays":3}}`))
			case strings.HasSuffix(p, "/namespaces/ehns/eventhubs"):
				_, _ = w.Write([]byte(`{"value":[{"name":"stream"}]}`))
			case strings.HasSuffix(p, "/namespaces/ehns"):
				_, _ = w.Write([]byte(`{"location":"westeurope","properties":{"zoneRedundant":true,` +
					`"encryption":{"keySource":"Microsoft.Storage"}}}`))

			default:
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`{"value":[]}`))
			}
		}))
}

func gapBObs(d provider.Discovered) map[string]any {
	m := map[string]any{}
	for _, o := range d.Observations {
		m[o.Path] = o.Value
	}
	return m
}

func TestDiscoverMetricAlert(t *testing.T) {
	var bearer bool
	srv := azGapBServer(t, &bearer)
	defer srv.Close()
	d := discoverAzDriver(t, srv)

	// region-global: a region no regional resource lives in still surfaces the alert.
	found, diags, err := d.discoverMetricAlert("eastus")
	if err != nil {
		t.Fatal(err)
	}
	if !bearer {
		t.Fatal("metricAlerts.list not signed with the AAD bearer")
	}
	if len(found) != 1 {
		t.Fatalf("want 1 metric alert (subscription-global), got %d: %+v (diags %v)", len(found), found, diags)
	}
	if found[0].ResourceType != "capability.monitoring.alert" {
		t.Fatalf("resourceType = %q", found[0].ResourceType)
	}
	if found[0].ProviderID != "azalert:"+testSub+":rg1:cpu-high" {
		t.Fatalf("providerId = %q", found[0].ProviderID)
	}
	obs := gapBObs(found[0])
	if obs["alert.metric"] != "Percentage CPU" || obs["alert.comparison"] != "greater-than" || obs["alert.notify"] != true {
		t.Fatalf("reverse-mapped observations = %+v", obs)
	}
}

func TestDiscoverFrontDoorWAF(t *testing.T) {
	var bearer bool
	srv := azGapBServer(t, &bearer)
	defer srv.Close()
	d := discoverAzDriver(t, srv)

	found, diags, err := d.discoverFrontDoorWAF("eastus") // global — region ignored
	if err != nil {
		t.Fatal(err)
	}
	if len(found) != 1 {
		t.Fatalf("want 1 waf policy (subscription-global), got %d: %+v (diags %v)", len(found), found, diags)
	}
	if found[0].ResourceType != "capability.security.waf" {
		t.Fatalf("resourceType = %q", found[0].ResourceType)
	}
	if found[0].ProviderID != "fdwaf:"+testSub+":rg1:wafpolicy" {
		t.Fatalf("providerId = %q", found[0].ProviderID)
	}
	obs := gapBObs(found[0])
	if obs["policy.mode"] != "prevention" || obs["managed.ruleset"] != true || obs["bot.protection"] != true {
		t.Fatalf("reverse-mapped observations = %+v", obs)
	}
}

func TestDiscoverPortalDash(t *testing.T) {
	var bearer bool
	srv := azGapBServer(t, &bearer)
	defer srv.Close()
	d := discoverAzDriver(t, srv)

	found, diags, err := d.discoverPortalDash("westeurope")
	if err != nil {
		t.Fatal(err)
	}
	if len(found) != 1 { // fardash in eastus must be filtered out
		t.Fatalf("want 1 in-region dashboard, got %d: %+v (diags %v)", len(found), found, diags)
	}
	if found[0].ResourceType != "capability.monitoring.dashboard" ||
		found[0].ProviderID != "azdash:"+testSub+":rg1:heredash" {
		t.Fatalf("dashboard discovery = %+v", found[0])
	}
	obs := gapBObs(found[0])
	if obs["dashboard.widgetCount"] != float64(1) {
		t.Fatalf("reverse-mapped observations = %+v", obs)
	}
}

func TestDiscoverWebTest(t *testing.T) {
	var bearer bool
	srv := azGapBServer(t, &bearer)
	defer srv.Close()
	d := discoverAzDriver(t, srv)

	found, diags, err := d.discoverWebTest("westeurope")
	if err != nil {
		t.Fatal(err)
	}
	if len(found) != 1 { // farwt in eastus filtered out
		t.Fatalf("want 1 in-region webtest, got %d: %+v (diags %v)", len(found), found, diags)
	}
	if found[0].ResourceType != "capability.monitoring.uptime" ||
		found[0].ProviderID != "azwebtest:"+testSub+":rg1:herewt" {
		t.Fatalf("webtest discovery = %+v", found[0])
	}
	obs := gapBObs(found[0])
	if obs["check.period"] != "300s" || obs["check.target"] != "example.com" || obs["check.protocol"] != "https" {
		t.Fatalf("reverse-mapped observations = %+v", obs)
	}
}

func TestDiscoverScheduledQuery(t *testing.T) {
	var bearer bool
	srv := azGapBServer(t, &bearer)
	defer srv.Close()
	d := discoverAzDriver(t, srv)

	found, diags, err := d.discoverScheduledQuery("westeurope")
	if err != nil {
		t.Fatal(err)
	}
	if len(found) != 1 { // farsq in eastus filtered out
		t.Fatalf("want 1 in-region scheduled query, got %d: %+v (diags %v)", len(found), found, diags)
	}
	if found[0].ResourceType != "capability.monitoring.logmetric" ||
		found[0].ProviderID != "azlm:"+testSub+":rg1:heresq" {
		t.Fatalf("scheduled query discovery = %+v", found[0])
	}
	obs := gapBObs(found[0])
	if obs["metric.name"] != "errors" || obs["metric.kind"] != "gauge" {
		t.Fatalf("reverse-mapped observations = %+v", obs)
	}
}

func TestDiscoverEventHubs(t *testing.T) {
	var bearer bool
	srv := azGapBServer(t, &bearer)
	defer srv.Close()
	d := discoverAzDriver(t, srv)

	found, diags, err := d.discoverEventHubs("westeurope")
	if err != nil {
		t.Fatal(err)
	}
	if !bearer {
		t.Fatal("eventhub namespaces.list not signed with the AAD bearer")
	}
	if len(found) != 1 { // farehns in eastus filtered out
		t.Fatalf("want 1 in-region event hub, got %d: %+v (diags %v)", len(found), found, diags)
	}
	if found[0].ResourceType != "capability.streaming.pipe" ||
		found[0].ProviderID != "eventhubs:"+testSub+":rg1:ehns:stream" {
		t.Fatalf("event hub discovery = %+v", found[0])
	}
	obs := gapBObs(found[0])
	if obs["location.region"] != "westeurope" || obs["availability.class"] != "regional" || obs["retention.window"] != "72h" {
		t.Fatalf("reverse-mapped observations = %+v", obs)
	}
}

// TestDiscoverGapBListErrorIsDiagnosticNotAbsence guards the four-valued rule: a
// non-200 LIST must surface as an error, never a fabricated empty slice.
func TestDiscoverGapBListErrorIsDiagnosticNotAbsence(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"error":"boom"}`))
	}))
	defer srv.Close()
	d := discoverAzDriver(t, srv)

	for name, sweep := range map[string]func(string) ([]provider.Discovered, []string, error){
		"metricAlert":    d.discoverMetricAlert,
		"frontDoorWAF":   d.discoverFrontDoorWAF,
		"portalDash":     d.discoverPortalDash,
		"webTest":        d.discoverWebTest,
		"scheduledQuery": d.discoverScheduledQuery,
		"eventHubs":      d.discoverEventHubs,
	} {
		found, _, err := sweep("westeurope")
		if err == nil {
			t.Fatalf("%s: HTTP 500 list must return an error, got found=%+v", name, found)
		}
		if found != nil {
			t.Fatalf("%s: error path must not fabricate results, got %+v", name, found)
		}
	}
}
