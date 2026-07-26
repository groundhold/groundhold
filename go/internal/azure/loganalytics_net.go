// Azure Log Analytics workspace network shell (D76 parity): the ARM half of the Azure
// capability.monitoring.logs driver. A single async PUT
// (Microsoft.OperationalInsights/workspaces) polled to provisioningState=Succeeded,
// tagged for ownership. retention.days is patchable in place (a PATCH of
// properties.retentionInDays), so an updater is wired — never a mutable-without-updater
// lie. Delete is ownership-tag-gated and four-valued (D47, stateful — a workspace HOLDS
// logs). D29/D87 honesty: a lost/garbled create is unknown WITH the deterministic pid.
package azure

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"groundhold/internal/provider"
)

func laProviderID(sub, rg, name string) string {
	return "laworkspace:" + sub + ":" + rg + ":" + name
}

func splitLAProviderID(providerID string) (sub, rg, name string, err error) {
	parts := strings.Split(providerID, ":")
	if len(parts) != 4 || parts[0] != "laworkspace" {
		return "", "", "", fmt.Errorf("providerId %q is not laworkspace:sub:rg:name", providerID)
	}
	if !subOK.MatchString(parts[1]) || !rgOK.MatchString(parts[2]) || !azNameOK.MatchString(parts[3]) {
		return "", "", "", fmt.Errorf("providerId %q has an invalid component", providerID)
	}
	return parts[1], parts[2], parts[3], nil
}

func (d *Driver) laPath(name string) string {
	return "Microsoft.OperationalInsights/workspaces/" + name
}

func (d *Driver) createLogAnalytics(environment, capability string,
	attrs, impl map[string]any, generation int) provider.CreateResult {
	plan, err := BuildLogAnalytics(environment, capability, attrs, impl, generation)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	rg, _ := impl["resource_group"].(string)
	if !rgOK.MatchString(rg) {
		return provider.CreateResult{Status: "failed",
			Reason: "azure log analytics requires implementation.resource_group"}
	}
	if !subOK.MatchString(d.Subscription) {
		return provider.CreateResult{Status: "failed",
			Reason: fmt.Sprintf("azure subscription %q is not a valid GUID", d.Subscription)}
	}
	pid := laProviderID(d.Subscription, rg, plan.Name)
	url, _ := d.armURL(rg, d.laPath(plan.Name), laAPIVersion)
	body, _ := json.Marshal(plan.createBody(d.tags(capability, environment)))
	if r := d.putAndPoll(url, body, pid, "azure log analytics workspace"); r != nil {
		return *r
	}
	return provider.CreateResult{ProviderID: pid, Status: "succeeded"}
}

type laDoc struct {
	Location   string            `json:"location"`
	Tags       map[string]string `json:"tags"`
	Properties struct {
		ProvisioningState string `json:"provisioningState"`
		RetentionInDays   *int   `json:"retentionInDays"`
		Sku               struct {
			Name string `json:"name"`
		} `json:"sku"`
		Features struct {
			ClusterResourceId string `json:"clusterResourceId"`
		} `json:"features"`
	} `json:"properties"`
}

// getLA returns the workspace doc, whether found, and readability. A garbled 200 is
// unreadable (never a confident state).
// getLA reads the resource. D295: a read that yielded nothing returns an
// error NAMING the cause (status + the provider's own code); a 404 stays an
// authoritative absence (found=false, no error), so the four-valued
// semantics are unchanged — only the diagnosis is new.
func (d *Driver) getLA(rg, name string) (doc laDoc, found bool, err error) {
	url, uerr := d.armURL(rg, d.laPath(name), laAPIVersion)
	if uerr != nil {
		return laDoc{}, false, &armReadError{Op: "workspaces.get", Cause: "scope", Detail: uerr.Error()}
	}
	found, err = d.armGetURLInto("workspaces.get", url, &doc)
	return doc, found, err
}

// observeLogAnalytics reverse-maps a live workspace: location.region, retention.days
// (retentionInDays -> a duration), service.managed, and encryption.customerManagedKeys
// (true ONLY when the workspace is linked to a dedicated cluster — the sole way a
// customer key covers Log Analytics; a standalone workspace exposes no key, so CMK is
// simply not emitted rather than faked).
func (d *Driver) observeLogAnalytics(capability, providerID string) ([]provider.Observation, []string, error) {
	sub, rg, name, err := splitLAProviderID(providerID)
	if err != nil {
		return nil, nil, err
	}
	if sub != d.Subscription && d.Subscription != "" {
		return nil, nil, fmt.Errorf("providerId subscription %q is not the driver's", sub)
	}
	doc, found, rerr := d.getLA(rg, name)
	if rerr != nil {
		return nil, nil, rerr
	}
	if !found {
		return nil, []string{"log analytics workspace not found — nothing to observe"}, nil
	}
	obs := []provider.Observation{
		{Path: "service.managed", Value: true, Derivation: "measured"},
	}
	if doc.Location != "" {
		obs = append(obs, provider.Observation{Path: "location.region",
			Value: strings.ToLower(doc.Location), Derivation: "measured"})
	}
	if doc.Properties.RetentionInDays != nil && *doc.Properties.RetentionInDays > 0 {
		obs = append(obs, provider.Observation{Path: "retention.days",
			Value: fmt.Sprintf("%dd", *doc.Properties.RetentionInDays), Derivation: "measured"})
	}
	if strings.TrimSpace(doc.Properties.Features.ClusterResourceId) != "" {
		obs = append(obs, provider.Observation{Path: "encryption.customerManagedKeys",
			Value: true, Derivation: "measured"})
	}
	return obs, nil, nil
}

// updateLogAnalytics patches a workspace IN PLACE for the mutable paths (D46):
// retention.days via a PATCH of properties.retentionInDays. Ownership is re-checked
// (tags) BEFORE any mutation; unreadable -> unknown, vanished -> failed. An ambiguous
// outcome (transport / 5xx) is unknown WITH the providerId; a 4xx is failed.
func (d *Driver) updateLogAnalytics(capability, environment, providerID string,
	attrs, impl map[string]any, changes []string) provider.CreateResult {
	sub, rg, name, err := splitLAProviderID(providerID)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	if sub != d.Subscription && d.Subscription != "" {
		return provider.CreateResult{Status: "failed",
			Reason: fmt.Sprintf("providerId subscription %q is not the driver's", sub)}
	}
	plan, err := BuildLogAnalytics(environment, capability, attrs, impl, 1)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}

	// ownership re-check before any mutation.
	doc, found, rerr := d.getLA(rg, name)
	if rerr != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown",
			Reason: "pre-update read gave no answer — reconcile: " + rerr.Error()}
	}
	if !found {
		return provider.CreateResult{Status: "failed",
			Reason: "log analytics workspace to update no longer exists — reconcile"}
	}
	if doc.Tags["groundhold-capability"] != sanitizeAzTag(capability) ||
		doc.Tags["groundhold-environment"] != sanitizeAzTag(environment) {
		return provider.CreateResult{Status: "failed",
			Reason: "workspace tags do not match — refusing to update a resource that is not ours"}
	}

	url, _ := d.armURL(rg, d.laPath(name), laAPIVersion)
	for _, path := range changes {
		switch path {
		case "retention.days":
			if plan.RetentionDays <= 0 {
				return provider.CreateResult{Status: "failed",
					Reason: "retention.days update requires a retention.days value to set"}
			}
			patch, _ := json.Marshal(map[string]any{
				"properties": map[string]any{"retentionInDays": plan.RetentionDays}})
			if r := d.laPatchOutcome("set retention", providerID, url, patch); r != nil {
				return *r
			}
		default:
			return provider.CreateResult{Status: "failed",
				Reason: fmt.Sprintf("log analytics in-place update does not honor %q — reconcile", path)}
		}
	}
	return provider.CreateResult{ProviderID: providerID, Status: "succeeded"}
}

// laPatchOutcome folds one PATCH call into the four-valued shape: nil = keep going (2xx),
// non-nil = terminal. Ambiguous (transport / 5xx) is unknown WITH the providerId; a 4xx
// is failed.
func (d *Driver) laPatchOutcome(what, providerID, url string, patch []byte) *provider.CreateResult {
	st, resp, err := d.doARM("PATCH", url, patch)
	switch {
	case err != nil:
		return &provider.CreateResult{ProviderID: providerID, Status: "unknown",
			Reason: fmt.Sprintf("%s outcome unknown (may have landed): %v", what, err)}
	case st >= 200 && st < 300:
		return nil
	case st >= 500:
		return &provider.CreateResult{ProviderID: providerID, Status: "unknown",
			Reason: fmt.Sprintf("%s HTTP %d (server error — may have landed) — reconcile", what, st)}
	default:
		return &provider.CreateResult{Status: "failed",
			Reason: fmt.Sprintf("%s HTTP %d: %s", what, st, mutDetailAz(resp))}
	}
}

// deleteLogAnalytics is ownership-tag-gated (D47, stateful — a workspace HOLDS logs, so
// destroying it loses history) and four-valued. A missing workspace is an idempotent
// success; a tag mismatch refuses (never delete a foreign workspace); an ambiguous
// outcome is unknown WITH the pid.
func (d *Driver) deleteLogAnalytics(capability, environment, providerID string) provider.CreateResult {
	_, rg, name, err := splitLAProviderID(providerID)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	doc, found, rerr := d.getLA(rg, name)
	if rerr != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown",
			Reason: "pre-delete read gave no answer — reconcile: " + rerr.Error()}
	}
	if !found {
		return provider.CreateResult{ProviderID: providerID, Status: "succeeded"} // idempotent
	}
	if doc.Tags["groundhold-capability"] != sanitizeAzTag(capability) ||
		doc.Tags["groundhold-environment"] != sanitizeAzTag(environment) {
		return provider.CreateResult{Status: "failed",
			Reason: "workspace tags do not match — refusing to delete a resource that is not ours (its logs are data)"}
	}
	url, _ := d.armURL(rg, d.laPath(name), laAPIVersion)
	if r := d.deleteAndConfirm(url, providerID, "log analytics workspace"); r != nil {
		return *r
	}
	return provider.CreateResult{ProviderID: providerID, Status: "succeeded"}
}

// discoverLogAnalytics enumerates the region's workspaces as
// capability.monitoring.logs, each reverse-mapped by the SAME observeLogAnalytics.
// Per-workspace isolation: one unmappable name never sinks the sweep.
func (d *Driver) discoverLogAnalytics(region string) ([]provider.Discovered, []string, error) {
	listURL := fmt.Sprintf("%s/subscriptions/%s/providers/Microsoft.OperationalInsights/workspaces?api-version=%s",
		d.BaseURL, d.Subscription, laAPIVersion)
	st, resp, err := d.doARM("GET", listURL, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("workspaces.list: %v", err)
	}
	if st != http.StatusOK {
		return nil, nil, fmt.Errorf("workspaces.list: HTTP %d", st)
	}
	var list struct {
		Value []struct {
			ID       string `json:"id"`
			Name     string `json:"name"`
			Location string `json:"location"`
		} `json:"value"`
	}
	if json.Unmarshal(resp, &list) != nil {
		return nil, nil, &armReadError{Op: "workspaces.list", Cause: "body", Status: st}
	}
	want := azRegion(region)
	var out []provider.Discovered
	var diags []string
	for _, w := range list.Value {
		if azRegion(w.Location) != want {
			continue // lives in another region — not this sweep
		}
		rg := resourceGroupOf(w.ID)
		if rg == "" {
			diags = append(diags, w.Name+": resource group unparseable from id")
			continue
		}
		if !azNameOK.MatchString(w.Name) {
			diags = append(diags, w.Name+": name not representable as a providerId")
			continue
		}
		pid := laProviderID(d.Subscription, rg, w.Name)
		obs, odiags, oerr := d.observeLogAnalytics("", pid)
		if oerr != nil {
			diags = append(diags, w.Name+": "+oerr.Error())
			continue
		}
		for _, dg := range odiags {
			diags = append(diags, w.Name+": "+dg)
		}
		out = append(out, provider.Discovered{
			ProviderID:   pid,
			ResourceType: "capability.monitoring.logs",
			Observations: obs,
		})
	}
	return out, diags, nil
}
