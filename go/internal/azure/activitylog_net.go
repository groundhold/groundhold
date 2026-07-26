// Azure Activity Log export network shell (D76 parity): the bearer-signed ARM half of
// the Azure capability.audit.trail driver. The resource is a subscription-scope
// diagnostic setting (Microsoft.Insights/diagnosticSettings) selecting the Activity Log
// and exporting it to a durable ujście. A PUT is create-or-update by name (synchronous,
// not an LRO), so the providerId is knowable BEFORE the response (a lost create is
// unknown, reconcile by the same id, D29).
//
// Ownership honesty: a diagnostic setting is a proxy resource with NO tags (the
// changefeed/azcustomrole discipline), so ownership IS the deterministic content-
// addressed name — groundhold only ever mutates a setting at its own name, and never
// mutates/deletes across a subscription boundary. A subscription-scope setting has no
// resource group, so URLs are built directly (subOK + diagSettingNameOK bound the
// interpolation, the D73 injection boundary), not via armURL.
//
// Endpoints (Microsoft.Insights/diagnosticSettings, subscription scope):
//
//	PUT    /subscriptions/{s}/providers/Microsoft.Insights/diagnosticSettings/{name}
//	GET    /subscriptions/{s}/providers/Microsoft.Insights/diagnosticSettings/{name}
//	DELETE /subscriptions/{s}/providers/Microsoft.Insights/diagnosticSettings/{name}
//	LIST   /subscriptions/{s}/providers/Microsoft.Insights/diagnosticSettings
//
// Azure has NO credentials in this environment — code + golden httptest certified, NOT
// live-validated (D99 honesty stance).
package azure

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"groundhold/internal/provider"
)

func activityLogProviderID(sub, name string) string { return "activitylog:" + sub + ":" + name }

func splitActivityLogProviderID(providerID string) (sub, name string, err error) {
	parts := strings.SplitN(providerID, ":", 3)
	if len(parts) != 3 || parts[0] != "activitylog" {
		return "", "", fmt.Errorf("providerId %q is not activitylog:subscription:settingName", providerID)
	}
	if !subOK.MatchString(parts[1]) {
		return "", "", fmt.Errorf("providerId subscription %q is invalid", parts[1])
	}
	if !diagSettingNameOK.MatchString(parts[2]) {
		return "", "", fmt.Errorf("providerId diagnostic setting name %q is invalid", parts[2])
	}
	return parts[1], parts[2], nil
}

// activityLogURL is the subscription-scoped diagnostic-setting URL. The scope is the
// subscription itself (no resource group), so it is built directly rather than via
// armURL. sub is bounded by subOK and name by diagSettingNameOK before interpolation.
func (d *Driver) activityLogURL(sub, name string) (string, error) {
	if !subOK.MatchString(sub) {
		return "", fmt.Errorf("azure subscription %q is not a valid GUID", sub)
	}
	if !diagSettingNameOK.MatchString(name) {
		return "", fmt.Errorf("diagnostic setting name %q is invalid", name)
	}
	return fmt.Sprintf("%s/subscriptions/%s/providers/Microsoft.Insights/diagnosticSettings/%s?api-version=%s",
		d.BaseURL, sub, name, activityLogAPIVersion), nil
}

// activityLogDoc is the projection of a diagnostic setting the driver reverse-maps.
type activityLogDoc struct {
	Name       string `json:"name"`
	Properties struct {
		WorkspaceID                 string `json:"workspaceId"`
		StorageAccountID            string `json:"storageAccountId"`
		EventHubAuthorizationRuleID string `json:"eventHubAuthorizationRuleId"`
		Logs                        []struct {
			Category string `json:"category"`
			Enabled  bool   `json:"enabled"`
		} `json:"logs"`
	} `json:"properties"`
}

// getActivityLog reads one setting. (found, readable): a 404 is found=false +
// readable=true (authoritatively absent); a transport/HTTP/parse failure is
// readable=false (unknown — never a fabricated absence).
// getActivityLog reads the setting. D297: a failed read names its cause; a 404 stays
// an authoritative absence.
func (d *Driver) getActivityLog(sub, name string) (activityLogDoc, bool, error) {
	var doc activityLogDoc
	url, uerr := d.activityLogURL(sub, name)
	if uerr != nil {
		return doc, false, &armReadError{Op: "diagnosticSettings.get", Cause: "scope", Detail: uerr.Error()}
	}
	found, err := d.armGetURLInto("diagnosticSettings.get", url, &doc)
	return doc, found, err
}

// createActivityLog provisions the Activity Log export diagnostic setting. Four-valued
// and honest per D29: the pid is knowable before the response (deterministic name), so a
// lost/5xx PUT carries it. A PUT is create-or-update by name; the content-addressed name
// is the ownership marker (a setting at our name is ours by construction).
func (d *Driver) createActivityLog(environment, capability string,
	attrs, impl map[string]any, generation int) provider.CreateResult {
	plan, err := BuildActivityLog(d.Subscription, environment, capability, attrs, impl, generation)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	pid := activityLogProviderID(d.Subscription, plan.Name)
	url, err := d.activityLogURL(d.Subscription, plan.Name)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	body, _ := json.Marshal(plan.createBody())
	st, resp, e := d.doARM("PUT", url, body)
	switch {
	case e != nil:
		return provider.CreateResult{ProviderID: pid, Status: "unknown",
			Reason: fmt.Sprintf("create outcome unknown (may have landed): %v", e)}
	case st == http.StatusOK || st == http.StatusCreated:
		return provider.CreateResult{ProviderID: pid, Status: "succeeded"}
	case st >= 500:
		return provider.CreateResult{ProviderID: pid, Status: "unknown",
			Reason: fmt.Sprintf("create HTTP %d (server error — may have landed) — reconcile", st)}
	default:
		return provider.CreateResult{Status: "failed", Reason: fmt.Sprintf("create HTTP %d: %s", st, mutDetailAz(resp))}
	}
}

// observeActivityLog reverse-maps a live diagnostic setting to capability.audit.trail —
// HONESTLY. Only what the setting genuinely reports is measured: delivery.assured (any
// Activity Log category enabled), service.managed, and scope.multiRegion (a subscription
// setting is subscription-global by construction). location.region,
// integrity.logValidation and encryption.customerManagedKeys are OMITTED with
// diagnostics — either a property of the destination operand (residency/CMK) or with no
// Azure equivalent at all (integrity). They are NEVER fabricated.
func (d *Driver) observeActivityLog(capability, providerID string) ([]provider.Observation, []string, error) {
	sub, name, err := splitActivityLogProviderID(providerID)
	if err != nil {
		return nil, nil, err
	}
	if sub != d.Subscription && d.Subscription != "" {
		return nil, nil, fmt.Errorf("providerId subscription %q is not the driver's", sub)
	}
	doc, found, rerr := d.getActivityLog(sub, name)
	if rerr != nil {
		return nil, nil, rerr
	}
	if !found {
		return nil, []string{"diagnostic setting not found — nothing to observe"}, nil
	}
	// delivery.assured is measured from the live category enabled flags: the export is
	// delivering iff at least one Activity Log category is enabled.
	deliver := false
	for _, l := range doc.Properties.Logs {
		if l.Enabled && isActivityLogCategory(l.Category) {
			deliver = true
			break
		}
	}
	obs := []provider.Observation{
		// a subscription diagnostic setting captures the Activity Log across every region
		// (it is subscription-global) — measured structurally, not fabricated.
		{Path: "scope.multiRegion", Value: true, Derivation: "measured"},
		{Path: "delivery.assured", Value: deliver, Derivation: "measured"},
		{Path: "service.managed", Value: true, Derivation: "measured"},
	}
	diags := []string{
		"location.region omitted — a subscription diagnostic setting is global; residency lives in the destination operand (a separate capability), not derivable from the setting",
		"integrity.logValidation omitted — Azure has no CloudTrail log-file-validation equivalent for the Activity Log (unsupported, never fabricated)",
		"encryption.customerManagedKeys omitted — CMK is a property of the destination operand (a separate capability), not the setting",
	}
	return obs, diags, nil
}

// updateActivityLog patches a bound setting in place (D46): the ONLY in-place-mutable
// capability attribute is delivery.assured (a re-PUT flipping the category enabled
// flags). Ownership (the deterministic name) gates the patch; the desired shape is
// re-derived (refuse-before-mutate) from the hash-pinned candidate; four-valued
// throughout. mutable ⇒ this updater is wired (never a mutable-without-updater claim).
func (d *Driver) updateActivityLog(capability, environment, providerID string,
	attrs, impl map[string]any, changes []string) provider.CreateResult {
	sub, name, err := splitActivityLogProviderID(providerID)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	if sub != d.Subscription && d.Subscription != "" {
		return provider.CreateResult{Status: "failed",
			Reason: "providerId subscription is not the driver's — refusing to update across subscriptions"}
	}
	// refuse-before-mutate: re-derive + validate the full desired shape (e.g. an
	// integrity.logValidation=true or a missing destination refuses here).
	plan, err := BuildActivityLog(sub, environment, capability, attrs, impl, 1)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	if plan.Name != name {
		return provider.CreateResult{Status: "failed",
			Reason: fmt.Sprintf("candidate diagnostic setting name %q does not match the bound setting %q — refusing", plan.Name, name)}
	}
	// only delivery.assured is patchable; anything else is gated by ClassifyChange
	// (unsupported/immutable) and must never silently no-op here.
	for _, path := range changes {
		if path != "delivery.assured" {
			return provider.CreateResult{Status: "failed",
				Reason: "no in-place Azure activity-log-export mapping for " + path}
		}
	}
	// ownership re-check before mutating: the setting must still exist at our name.
	if _, found, rerr := d.getActivityLog(sub, name); rerr != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown",
			Reason: "pre-update read gave no answer — reconcile before patching: " + rerr.Error()}
	} else if !found {
		return provider.CreateResult{Status: "failed", Reason: "diagnostic setting no longer exists — cannot update"}
	}
	url, err := d.activityLogURL(sub, name)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	body, _ := json.Marshal(plan.createBody())
	st, resp, e := d.doARM("PUT", url, body)
	switch {
	case e != nil:
		return provider.CreateResult{ProviderID: providerID, Status: "unknown",
			Reason: fmt.Sprintf("patch outcome unknown (may have landed): %v", e)}
	case st == http.StatusOK || st == http.StatusCreated:
		return provider.CreateResult{ProviderID: providerID, Status: "succeeded"}
	case st >= 500:
		return provider.CreateResult{ProviderID: providerID, Status: "unknown",
			Reason: fmt.Sprintf("patch HTTP %d (server error — may have landed) — reconcile", st)}
	default:
		return provider.CreateResult{Status: "failed", Reason: fmt.Sprintf("patch HTTP %d: %s", st, mutDetailAz(resp))}
	}
}

// deleteActivityLog removes a bound setting, refusing across a subscription boundary
// (the only cross-tenant safety a tagless proxy resource affords — the name is
// content-addressed and ours by construction). Deleting the setting ENDS the export; the
// Activity Log itself is always-on and untouched, and the log OBJECTS already delivered
// to the destination (a separate capability) remain — deleting the setting does not
// erase the past record. A transport/5xx is unknown WITH the pid (reconcile).
func (d *Driver) deleteActivityLog(capability, environment, providerID string) provider.CreateResult {
	sub, name, err := splitActivityLogProviderID(providerID)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	if sub != d.Subscription && d.Subscription != "" {
		return provider.CreateResult{Status: "failed",
			Reason: "providerId subscription is not the driver's — refusing to delete across subscriptions"}
	}
	url, err := d.activityLogURL(sub, name)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	st, resp, e := d.doARM("DELETE", url, nil)
	if e != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown", Reason: fmt.Sprintf("delete outcome unknown: %v", e)}
	}
	if st == http.StatusNotFound {
		return provider.CreateResult{ProviderID: providerID, Status: "succeeded"} // idempotent
	}
	if st >= 500 {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown", Reason: fmt.Sprintf("delete HTTP %d (server error) — reconcile", st)}
	}
	if st < 200 || st >= 300 {
		return provider.CreateResult{ProviderID: providerID, Status: "failed", Reason: fmt.Sprintf("delete HTTP %d: %s", st, mutDetailAz(resp))}
	}
	return provider.CreateResult{ProviderID: providerID, Status: "succeeded"}
}

// discoverActivityLog enumerates the subscription's Activity Log export settings as
// capability.audit.trail (the subscription-scope diagnosticSettings list), each
// reverse-mapped by observeActivityLog. Every subscription-scope diagnostic setting
// exports the Activity Log by construction, so all are surfaced (brownfield onboarding
// wants foreign settings too). Settings are subscription-global; region does not filter.
func (d *Driver) discoverActivityLog(region string) ([]provider.Discovered, []string, error) {
	if !subOK.MatchString(d.Subscription) {
		return nil, nil, fmt.Errorf("azure activity-log discovery requires a subscription GUID")
	}
	listURL := fmt.Sprintf("%s/subscriptions/%s/providers/Microsoft.Insights/diagnosticSettings?api-version=%s",
		d.BaseURL, d.Subscription, activityLogAPIVersion)
	st, resp, err := d.doARM("GET", listURL, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("diagnosticSettings.list: %v", err)
	}
	if st != http.StatusOK {
		return nil, nil, fmt.Errorf("diagnosticSettings.list: HTTP %d", st)
	}
	var list struct {
		Value []activityLogDoc `json:"value"`
	}
	if json.Unmarshal(resp, &list) != nil {
		return nil, nil, &armReadError{Op: "diagnosticSettings.list", Cause: "body", Status: st}
	}
	var out []provider.Discovered
	var diags []string
	for _, s := range list.Value {
		if s.Name == "" {
			continue
		}
		if !diagSettingNameOK.MatchString(s.Name) {
			diags = append(diags, s.Name+": name not representable as a providerId")
			continue
		}
		pid := activityLogProviderID(d.Subscription, s.Name)
		obs, odiags, oerr := d.observeActivityLog("", pid)
		if oerr != nil {
			diags = append(diags, s.Name+": "+oerr.Error())
			continue
		}
		for _, dg := range odiags {
			diags = append(diags, s.Name+": "+dg)
		}
		out = append(out, provider.Discovered{
			ProviderID:   pid,
			ResourceType: "capability.audit.trail",
			Observations: obs,
		})
	}
	return out, diags, nil
}
