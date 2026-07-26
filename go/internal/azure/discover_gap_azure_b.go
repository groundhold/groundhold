// More Azure discovery sweeps (D52 brownfield): the driver PROVISIONS + OBSERVES
// several monitoring, streaming and security services whose LIST was never wired
// into `groundhold discover --provider azure`. These sweeps close that gap by ADDING
// the subscription-scope LIST and REUSING each service's existing observe reverse
// map — the two-step (List gives IDs, observe gives attributes) every other sweep
// already follows. No new semantics are introduced here.
//
// Region handling mirrors discover_azure_expand.go: REGIONAL resource types
// (Portal dashboards, availability webtests, scheduled query rules, Event Hub
// namespaces) are filtered to the requested region by `location`; subscription-
// GLOBAL types (metric alerts and FrontDoor WAF policies both report location
// "global") carry no meaningful region and are surfaced regardless — the same
// choice roles + role assignments already make.
//
// Four-valued discipline: a List that errors is a diagnostic for THAT sweep, never
// a fabricated absence; per-item observe failures append a diagnostic and skip,
// never hide a sibling. D53: no observation carries a secret/key value — every
// reused observe is a metadata-only reverse map.
package azure

import (
	"encoding/json"
	"fmt"
	"net/http"

	"groundhold/internal/provider"
)

// discoverGapBGlobal is the shared subscription-GLOBAL sweep: list one resource
// type at subscription scope and reverse-map each through the service's OWN observe
// (reuse, never re-derive), WITHOUT a region filter. Used for ARM types whose
// location is "global" (metric alerts, FrontDoor WAF policies) — filtering them by
// the requested region would drop every one. The providerId is built from the
// (sub, rg, name) the service's observe expects.
func (d *Driver) discoverGapBGlobal(providerPath, apiVersion, resourceType, label string,
	pid func(sub, rg, name string) string,
	observe func(capability, providerID string) ([]provider.Observation, []string, error),
) ([]provider.Discovered, []string, error) {
	listURL := fmt.Sprintf("%s/subscriptions/%s/providers/%s?api-version=%s",
		d.BaseURL, d.Subscription, providerPath, apiVersion)
	st, resp, err := d.doARM("GET", listURL, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("%s.list: %v", label, err)
	}
	if st != http.StatusOK {
		return nil, nil, fmt.Errorf("%s.list: HTTP %d", label, st)
	}
	var page struct {
		Value []azListItem `json:"value"`
	}
	if json.Unmarshal(resp, &page) != nil {
		return nil, nil, fmt.Errorf("%s: %w", label, armBody("list", st))
	}
	var out []provider.Discovered
	var diags []string
	for _, it := range page.Value {
		rg := resourceGroupOf(it.ID)
		if rg == "" {
			diags = append(diags, it.Name+": resource group unparseable from id")
			continue
		}
		p := pid(d.Subscription, rg, it.Name)
		obs, odiags, oerr := observe("", p)
		if oerr != nil {
			diags = append(diags, it.Name+": "+oerr.Error())
			continue
		}
		for _, dg := range odiags {
			diags = append(diags, it.Name+": "+dg)
		}
		out = append(out, provider.Discovered{
			ProviderID:   p,
			ResourceType: resourceType,
			Observations: obs,
		})
	}
	return out, diags, nil
}

// discoverMetricAlert enumerates metric alert rules as capability.monitoring.alert
// (Microsoft.Insights/metricAlerts). Metric alerts are subscription-GLOBAL (their
// location is "global") — every one is surfaced regardless of the requested region.
// The reverse map is observeAzureAlert.
func (d *Driver) discoverMetricAlert(_ string) ([]provider.Discovered, []string, error) {
	return d.discoverGapBGlobal("Microsoft.Insights/metricAlerts", metricAlertAPIVersion,
		"capability.monitoring.alert", "metricAlerts", azureAlertProviderID, d.observeAzureAlert)
}

// discoverFrontDoorWAF enumerates FrontDoor WAF policies as capability.security.waf
// (Microsoft.Network/FrontDoorWebApplicationFirewallPolicies). Classic FrontDoor WAF
// policies are subscription-GLOBAL (location "global") — every one is surfaced
// regardless of the requested region. The reverse map is observeFrontDoorWAF.
func (d *Driver) discoverFrontDoorWAF(_ string) ([]provider.Discovered, []string, error) {
	return d.discoverGapBGlobal("Microsoft.Network/FrontDoorWebApplicationFirewallPolicies",
		frontDoorWAFAPIVersion, "capability.security.waf", "wafPolicies",
		frontDoorWAFProviderID, d.observeFrontDoorWAF)
}

// discoverPortalDash enumerates Portal dashboards in the region as
// capability.monitoring.dashboard (Microsoft.Portal/dashboards), reusing the same
// reverse map observe uses.
func (d *Driver) discoverPortalDash(region string) ([]provider.Discovered, []string, error) {
	return d.discoverRegional("Microsoft.Portal/dashboards", portalDashAPIVersion, region,
		"capability.monitoring.dashboard", "dashboards", azureDashProviderID, d.observeAzureDashboard)
}

// discoverWebTest enumerates availability webtests in the region as
// capability.monitoring.uptime (Microsoft.Insights/webtests), reusing the same
// reverse map observe uses.
func (d *Driver) discoverWebTest(region string) ([]provider.Discovered, []string, error) {
	return d.discoverRegional("Microsoft.Insights/webtests", webtestAPIVersion, region,
		"capability.monitoring.uptime", "webtests", azureWebtestProviderID, d.observeAzureWebtest)
}

// discoverScheduledQuery enumerates scheduled query rules in the region as
// capability.monitoring.logmetric (Microsoft.Insights/scheduledQueryRules), reusing
// the same reverse map observe uses.
func (d *Driver) discoverScheduledQuery(region string) ([]provider.Discovered, []string, error) {
	return d.discoverRegional("Microsoft.Insights/scheduledQueryRules", scheduledQueryAPIVersion, region,
		"capability.monitoring.logmetric", "scheduledQueryRules", azureSQProviderID, d.observeAzureScheduledQuery)
}

// discoverEventHubs enumerates Event Hubs in the region as capability.streaming.pipe
// (Microsoft.EventHub namespace + hub): list namespaces at subscription scope, keep
// the in-region ones, list the hubs under each, then reverse-map every hub through
// observeEventHubs (a two-level sweep, the same shape discoverServiceBus uses). The
// ledger identity is the namespace+hub composite.
func (d *Driver) discoverEventHubs(region string) ([]provider.Discovered, []string, error) {
	listURL := fmt.Sprintf("%s/subscriptions/%s/providers/Microsoft.EventHub/namespaces?api-version=%s",
		d.BaseURL, d.Subscription, eventHubsAPIVersion)
	st, resp, err := d.doARM("GET", listURL, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("eventhub namespaces.list: %v", err)
	}
	if st != http.StatusOK {
		return nil, nil, fmt.Errorf("eventhub namespaces.list: HTTP %d", st)
	}
	var namespaces struct {
		Value []azListItem `json:"value"`
	}
	if json.Unmarshal(resp, &namespaces) != nil {
		return nil, nil, &armReadError{Op: "eventhub namespaces.list", Cause: "body", Status: st}
	}
	want := azRegion(region)
	var out []provider.Discovered
	var diags []string
	for _, ns := range namespaces.Value {
		if azRegion(ns.Location) != want {
			continue // lives in another region — not this sweep
		}
		rg := resourceGroupOf(ns.ID)
		if rg == "" {
			diags = append(diags, ns.Name+": resource group unparseable from id")
			continue
		}
		out = append(out, d.ehDiscoverHubs(rg, ns.Name, &diags)...)
	}
	return out, diags, nil
}

// ehDiscoverHubs lists the hubs under one namespace and projects each through
// observeEventHubs. Errors append to diags and yield nothing (never a fabricated
// absence, never a hidden sibling).
func (d *Driver) ehDiscoverHubs(rg, ns string, diags *[]string) []provider.Discovered {
	hubsURL, err := d.armURL(rg, d.ehNamespacePath(ns)+"/eventhubs", eventHubsAPIVersion)
	if err != nil {
		*diags = append(*diags, ns+": "+err.Error())
		return nil
	}
	st, resp, herr := d.doARM("GET", hubsURL, nil)
	if herr != nil || st != http.StatusOK {
		*diags = append(*diags, ns+"/eventhubs: "+azReadWhy(st, resp, herr))
		return nil
	}
	var hubs struct {
		Value []struct {
			Name string `json:"name"`
		} `json:"value"`
	}
	_ = json.Unmarshal(resp, &hubs)
	var out []provider.Discovered
	for _, h := range hubs.Value {
		pid := eventHubsProviderID(d.Subscription, rg, ns, h.Name)
		obs, odiags, oerr := d.observeEventHubs("", pid)
		if oerr != nil {
			*diags = append(*diags, ns+"/"+h.Name+": "+oerr.Error())
			continue
		}
		for _, dg := range odiags {
			*diags = append(*diags, ns+"/"+h.Name+": "+dg)
		}
		out = append(out, provider.Discovered{
			ProviderID:   pid,
			ResourceType: "capability.streaming.pipe",
			Observations: obs,
		})
	}
	return out
}
