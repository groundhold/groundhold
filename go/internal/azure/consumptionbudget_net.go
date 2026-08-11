// Azure Consumption Budget network shell (D76 parity): the ARM half of the
// capability.cost.budget driver (Microsoft.Consumption/budgets). A budget is
// create-or-update via a SYNCHRONOUS PUT (no LRO poll) to a deterministic name;
// observe reverse-maps the limit / period / threshold; the deterministic NAME is
// the ownership marker (no tags on the object). A lost PUT is unknown (D29/D87).
package azure

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"groundhold/internal/provider"
)

// consBudgetProviderID encodes scope (sub + optional rg) and name. An empty rg
// segment means subscription scope; a non-empty one means resource-group scope.
func consBudgetProviderID(sub, rg, name string) string {
	return "azconsbudget:" + sub + ":" + rg + ":" + name
}

func splitConsBudgetProviderID(providerID string) (sub, rg, name string, err error) {
	parts := strings.SplitN(providerID, ":", 4)
	if len(parts) != 4 || parts[0] != "azconsbudget" {
		return "", "", "", fmt.Errorf("providerId %q is not azconsbudget:sub:rg:name", providerID)
	}
	if !subOK.MatchString(parts[1]) {
		return "", "", "", fmt.Errorf("providerId %q has an invalid subscription", providerID)
	}
	if parts[2] != "" && !rgOK.MatchString(parts[2]) {
		return "", "", "", fmt.Errorf("providerId %q has an invalid resource group", providerID)
	}
	if !consBudgetNameOK.MatchString(parts[3]) {
		return "", "", "", fmt.Errorf("providerId budget name %q is invalid — refusing to interpolate it into an ARM path", parts[3])
	}
	return parts[1], parts[2], parts[3], nil
}

// consBudgetURL builds the management-plane URL for one budget, bounding sub/rg
// (the D73 injection boundary). rg == "" -> subscription scope.
func (d *Driver) consBudgetURL(rg, name string) (string, error) {
	if !subOK.MatchString(d.Subscription) {
		return "", fmt.Errorf("azure subscription %q is not a valid GUID", d.Subscription)
	}
	scope := "/subscriptions/" + d.Subscription
	if rg != "" {
		if !rgOK.MatchString(rg) {
			return "", fmt.Errorf("resource_group %q is not a valid Azure resource group name", rg)
		}
		scope += "/resourceGroups/" + rg
	}
	if !consBudgetNameOK.MatchString(name) {
		return "", fmt.Errorf("budget name %q is invalid", name)
	}
	return fmt.Sprintf("%s%s/providers/Microsoft.Consumption/budgets/%s?api-version=%s",
		d.BaseURL, scope, name, consBudgetAPIVersion), nil
}

// consBudgetPeriodStart is the first of the CURRENT month (UTC), the startDate an
// Azure Consumption budget requires. It is a temporal fact the vocab does not
// carry, derived deterministically from the coordination clock (d.Now) — never a
// silent default. First-of-month is accepted by Azure for every timeGrain.
func consBudgetPeriodStart(now time.Time) string {
	u := now.UTC()
	return time.Date(u.Year(), u.Month(), 1, 0, 0, 0, 0, time.UTC).Format(time.RFC3339)
}

type consBudgetDoc struct {
	Name       string `json:"name"`
	ID         string `json:"id"`
	Properties struct {
		Category   string  `json:"category"`
		Amount     float64 `json:"amount"`
		TimeGrain  string  `json:"timeGrain"`
		TimePeriod struct {
			StartDate string `json:"startDate"`
			EndDate   string `json:"endDate"`
		} `json:"timePeriod"`
		CurrentSpend struct {
			Amount float64 `json:"amount"`
			Unit   string  `json:"unit"`
		} `json:"currentSpend"`
		ForecastSpend struct {
			Unit string `json:"unit"`
		} `json:"forecastSpend"`
		Notifications map[string]struct {
			Enabled       bool     `json:"enabled"`
			Operator      string   `json:"operator"`
			Threshold     float64  `json:"threshold"`
			ThresholdType string   `json:"thresholdType"`
			ContactEmails []string `json:"contactEmails"`
			ContactGroups []string `json:"contactGroups"`
		} `json:"notifications"`
	} `json:"properties"`
}

func (d *Driver) createConsumptionBudget(environment, capability string,
	attrs, impl map[string]any, generation int) provider.CreateResult {
	plan, err := BuildConsumptionBudget(environment, capability, attrs, impl, generation)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	rURL, err := d.consBudgetURL(plan.ResourceGroup, plan.Name)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	pid := consBudgetProviderID(d.Subscription, plan.ResourceGroup, plan.Name)
	// D804: read before writing at a name anyone can compute. An ARM PUT is an
	// unconditional upsert and a budget carries no tags, so ownership is read from the
	// budget itself — against the contract terms only, never the period window.
	if r := d.refuseForeignByContentOrAdopt(rURL, plan.contractBody(), pid, "consumption budget"); r != nil {
		return *r
	}
	body, _ := json.Marshal(plan.createBody(consBudgetPeriodStart(d.Now())))
	st, resp, e := d.doARM("PUT", rURL, body)
	if e != nil {
		return provider.CreateResult{ProviderID: pid, Status: "unknown",
			Reason: fmt.Sprintf("budget PUT outcome unknown (may have landed): %v", e)}
	}
	if st >= 500 {
		return provider.CreateResult{ProviderID: pid, Status: "unknown",
			Reason: fmt.Sprintf("budget PUT HTTP %d (server error — may have landed) — reconcile", st)}
	}
	if st < 200 || st >= 300 {
		return provider.CreateResult{ProviderID: pid, Status: "failed",
			Reason: fmt.Sprintf("budget PUT HTTP %d: %s", st, mutDetailAz(resp))}
	}
	return provider.CreateResult{ProviderID: pid, Status: "succeeded"}
}

// consBudgetObservations reverse-maps a live budget document into vocabulary
// paths. The billing currency is not on the budget object; it is recovered from
// currentSpend.unit (fallback forecastSpend.unit). If neither is present yet (a
// fresh budget with no recorded spend), budget.limit is emitted with an empty
// currency and a diagnostic explains why — never a fabricated currency.
func consBudgetObservations(doc consBudgetDoc) ([]provider.Observation, []string) {
	obs := []provider.Observation{
		{Path: "service.managed", Value: true, Derivation: "measured"},
	}
	var diags []string

	currency := doc.Properties.CurrentSpend.Unit
	if currency == "" {
		currency = doc.Properties.ForecastSpend.Unit
	}
	if currency != "" {
		obs = append(obs, provider.Observation{Path: "budget.limit",
			Value:      map[string]any{"amount": doc.Properties.Amount, "currency": currency},
			Derivation: "measured"})
	} else {
		diags = append(diags, fmt.Sprintf(
			"budget.limit currency not observable yet (the subscription has no recorded/forecast spend); "+
				"the amount is %v in the billing currency", doc.Properties.Amount))
	}

	if period := budgetPeriodFromTimeGrain(doc.Properties.TimeGrain); period != "" {
		obs = append(obs, provider.Observation{Path: "budget.period", Value: period, Derivation: "measured"})
	} else if doc.Properties.TimeGrain != "" {
		diags = append(diags, fmt.Sprintf("budget.period not mapped: timeGrain %q has no recurring vocab equivalent", doc.Properties.TimeGrain))
	}

	// the first ACTUAL GreaterThan notification carries the alert threshold.
	for _, n := range doc.Properties.Notifications {
		if strings.EqualFold(n.ThresholdType, "Actual") && strings.EqualFold(n.Operator, "GreaterThan") {
			obs = append(obs, provider.Observation{Path: "alert.threshold", Value: n.Threshold, Derivation: "measured"})
			break
		}
	}
	return obs, diags
}

// consBudgetGet reads one budget. found=false + readable=true is an authoritative
// 404; readable=false is transport/HTTP/parse.
// consBudgetGet reads one budget. D295: a failed read names its cause.
func (d *Driver) consBudgetGet(rURL string) (consBudgetDoc, bool, error) {
	var doc consBudgetDoc
	found, err := d.armGetURLInto("budgets.get", rURL, &doc)
	return doc, found, err
}

func (d *Driver) observeConsumptionBudget(capability, providerID string) ([]provider.Observation, []string, error) {
	sub, rg, name, err := splitConsBudgetProviderID(providerID)
	if err != nil {
		return nil, nil, err
	}
	if sub != d.Subscription && d.Subscription != "" {
		return nil, nil, fmt.Errorf("providerId subscription %q is not the driver's", sub)
	}
	rURL, err := d.consBudgetURL(rg, name)
	if err != nil {
		return nil, nil, err
	}
	doc, found, rerr := d.consBudgetGet(rURL)
	if rerr != nil {
		return nil, nil, rerr
	}
	if !found {
		return []provider.Observation{
			// F-LC3 (D802): a BOUND resource the API authoritatively 404s is GONE. An
			// empty return leaves the last good observations standing as the freshest
			// word, so posture reads managed-ok and audit stays satisfied about a
			// resource that does not exist (D513/D518, fixed here last).
			{Path: provider.ResourceAbsentPath, Value: true, Derivation: "measured"},
		}, []string{"consumption budget not found — bound resource is gone (will re-create)"}, nil
	}
	obs, diags := consBudgetObservations(doc)
	return obs, diags, nil
}

func (d *Driver) deleteConsumptionBudget(capability, environment, providerID string) provider.CreateResult {
	sub, rg, name, err := splitConsBudgetProviderID(providerID)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	if sub != d.Subscription && d.Subscription != "" {
		return provider.CreateResult{Status: "failed", Reason: fmt.Sprintf("providerId subscription %q is not the driver's", sub)}
	}
	rURL, err := d.consBudgetURL(rg, name)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	// ownership: the deterministic NAME is the marker (no tags on the object). A
	// name that does not carry our (env, cap) owner token is never deleted.
	if !consBudgetOurs(name, environment, capability) {
		return provider.CreateResult{Status: "failed",
			Reason: "budget name does not carry our ownership marker — refusing to delete a resource that is not ours"}
	}
	_, found, rerr := d.consBudgetGet(rURL)
	if rerr != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown", Reason: "pre-delete read gave no answer — reconcile: " + rerr.Error()}
	}
	if !found {
		return provider.CreateResult{ProviderID: providerID, Status: "succeeded"} // idempotent
	}
	st, resp, e := d.doARM("DELETE", rURL, nil)
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
		return provider.CreateResult{ProviderID: providerID, Status: "failed", Reason: fmt.Sprintf("delete HTTP %d: %s", st, mutDetailAz(resp))}
	}
	return provider.CreateResult{ProviderID: providerID, Status: "succeeded"}
}

// updateConsumptionBudget patches the mutable paths IN PLACE (D46/
// classifyConsumptionBudgetChange). Microsoft.Consumption/budgets is create-or-
// update via a full PUT to the same name, so the update rebuilds the whole desired
// body and PUTs it — preserving the EXISTING startDate (a pre-update GET) so the
// budget window is not silently shifted. Ownership is the deterministic NAME; the
// pre-update GET confirms our marker (ours); unreadable -> unknown, vanished ->
// failed, foreign -> failed. An ambiguous PUT (transport/5xx) is unknown WITH the
// providerId (D29/D87); a 4xx is failed.
func (d *Driver) updateConsumptionBudget(capability, environment, providerID string,
	attrs, impl map[string]any, changes []string) provider.CreateResult {
	sub, rg, name, err := splitConsBudgetProviderID(providerID)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	if sub != d.Subscription && d.Subscription != "" {
		return provider.CreateResult{Status: "failed", Reason: fmt.Sprintf("providerId subscription %q is not the driver's", sub)}
	}
	if !consBudgetOurs(name, environment, capability) {
		return provider.CreateResult{Status: "failed",
			Reason: "budget name does not carry our ownership marker — refusing to patch a resource that is not ours"}
	}
	// only the wired mutable paths may reach the updater (fail closed on anything else).
	for _, path := range changes {
		if kind, _ := classifyConsumptionBudgetChange(path); kind != "mutable" {
			return provider.CreateResult{Status: "failed",
				Reason: fmt.Sprintf("azure consumption budget in-place update does not honor %q — reconcile", path)}
		}
	}
	plan, err := BuildConsumptionBudget(environment, capability, attrs, impl, 1)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	rURL, err := d.consBudgetURL(rg, name)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	doc, found, rerr := d.consBudgetGet(rURL)
	if rerr != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown", Reason: "pre-update read gave no answer — reconcile: " + rerr.Error()}
	}
	if !found {
		return provider.CreateResult{Status: "failed", Reason: "budget to update no longer exists — reconcile"}
	}
	// preserve the live startDate (a full PUT would otherwise reset the window to
	// the current period); fall back to the current period only if it is absent.
	startDate := doc.Properties.TimePeriod.StartDate
	if _, perr := time.Parse(time.RFC3339, startDate); perr != nil {
		startDate = consBudgetPeriodStart(d.Now())
	}
	body, _ := json.Marshal(plan.createBody(startDate))
	st, resp, e := d.doARM("PUT", rURL, body)
	if e != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown", Reason: fmt.Sprintf("patch outcome unknown: %v", e)}
	}
	if st >= 500 {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown", Reason: fmt.Sprintf("patch HTTP %d (server error — may have landed) — reconcile", st)}
	}
	if st < 200 || st >= 300 {
		return provider.CreateResult{Status: "failed", Reason: fmt.Sprintf("patch HTTP %d: %s", st, mutDetailAz(resp))}
	}
	return provider.CreateResult{ProviderID: providerID, Status: "succeeded"}
}

// discoverConsumptionBudget enumerates SUBSCRIPTION-scoped budgets as
// capability.cost.budget. Budgets are not regional, so region is ignored (the
// sweep runs once). Resource-group-scoped budgets are enumerated per-RG, not by
// this subscription-scope list — a documented coverage limitation (the common
// case is subscription scope).
func (d *Driver) discoverConsumptionBudget(region string) ([]provider.Discovered, []string, error) {
	if !subOK.MatchString(d.Subscription) {
		return nil, nil, fmt.Errorf("consumption budgets: discovery requires a subscription GUID")
	}
	listURL := fmt.Sprintf("%s/subscriptions/%s/providers/Microsoft.Consumption/budgets?api-version=%s",
		d.BaseURL, d.Subscription, consBudgetAPIVersion)
	st, resp, err := d.doARM("GET", listURL, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("budgets.list: %v", err)
	}
	if st != http.StatusOK {
		return nil, nil, fmt.Errorf("budgets.list: HTTP %d", st)
	}
	var list struct {
		Value []consBudgetDoc `json:"value"`
	}
	if json.Unmarshal(resp, &list) != nil {
		return nil, nil, &armReadError{Op: "budgets.list", Cause: "body", Status: st}
	}
	var out []provider.Discovered
	var diags []string
	for _, b := range list.Value {
		if !consBudgetNameOK.MatchString(b.Name) {
			diags = append(diags, b.Name+": budget name not representable as a providerId")
			continue
		}
		obs, ds := consBudgetObservations(b)
		diags = append(diags, ds...)
		out = append(out, provider.Discovered{
			// subscription-scope discovery -> empty rg segment in the providerId.
			ProviderID:   consBudgetProviderID(d.Subscription, "", b.Name),
			ResourceType: "capability.cost.budget",
			Observations: provider.WithoutAbsence(obs),
		})
	}
	return out, diags, nil
}
