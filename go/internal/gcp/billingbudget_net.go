// GCP Cloud Billing Budget network shell (D76 parity): the bearer-signed half of
// the GCP capability.cost.budget driver (billingbudgets.googleapis.com/v1). A
// budget is billing-account-scoped, NOT a project resource, so its providerId
// carries the billing account id and the SERVER-ASSIGNED budget id, never a
// project/region. The create is a plain synchronous POST (no LRO).
//
// Honesty per D29/D87: a GCP budget id is server-assigned, so the providerId is
// NOT knowable before the response. Two mitigations keep the handle from being
// lost. (1) Idempotency: create first LISTS the account's budgets and matches our
// deterministic display name (GCP does NOT dedupe on display name, so a blind retry
// would otherwise duplicate the budget) — a match is a recovered success. (2) On an
// ambiguous outcome (transport / 5xx) create RE-LISTS to recover the id; found is a
// success, absent is unknown (reconcile by the display name in the reason). Ownership
// is the deterministic DISPLAY NAME (there are no labels on the object); a foreign
// display name is never mutated.
package gcp

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"groundhold/internal/provider"
)

const billingBudgetsBaseURL = "https://billingbudgets.googleapis.com/v1"
const cloudBillingBaseURL = "https://cloudbilling.googleapis.com/v1"

// These overrides redirect the (billing-account-scoped, non-project) endpoints to a
// test server. They live here rather than on the Driver struct because this driver
// ships entirely in its own files (the shared Driver struct is not edited); the
// httptest tests in this package do not run in parallel, so package-level overrides
// are safe. Empty = real GCP.
var billingBudgetsBaseURLOverride string
var cloudBillingBaseURLOverride string

func (d *Driver) billingBudgetsBase() string {
	if billingBudgetsBaseURLOverride != "" {
		return billingBudgetsBaseURLOverride
	}
	return billingBudgetsBaseURL
}

func (d *Driver) cloudBillingBase() string {
	if cloudBillingBaseURLOverride != "" {
		return cloudBillingBaseURLOverride
	}
	return cloudBillingBaseURL
}

func billingBudgetProviderID(billingAccountID, budgetID string) string {
	return "gcp-billingbudget:" + billingAccountID + ":" + budgetID
}

func splitBillingBudgetProviderID(providerID string) (billingAccountID, budgetID string, err error) {
	parts := strings.SplitN(providerID, ":", 3)
	if len(parts) != 3 || parts[0] != "gcp-billingbudget" {
		return "", "", fmt.Errorf("providerId %q is not gcp-billingbudget:billingAccountId:budgetId", providerID)
	}
	if !billingAccountOK.MatchString(parts[1]) {
		return "", "", fmt.Errorf("providerId billing account %q is invalid", parts[1])
	}
	if !billingBudgetIDOK.MatchString(parts[2]) {
		return "", "", fmt.Errorf("providerId budget id %q is invalid — refusing to interpolate it into an API path", parts[2])
	}
	return parts[1], parts[2], nil
}

// budgetIDFromName extracts the trailing id from a "billingAccounts/{a}/budgets/{id}"
// resource name.
func budgetIDFromName(name string) string {
	return name[strings.LastIndex(name, "/")+1:]
}

func (d *Driver) billingBudgetURL(billingAccountID, budgetID string) string {
	return fmt.Sprintf("%s/billingAccounts/%s/budgets/%s", d.billingBudgetsBase(), billingAccountID, budgetID)
}

type billingBudgetDoc struct {
	Name         string `json:"name"`
	DisplayName  string `json:"displayName"`
	BudgetFilter struct {
		CalendarPeriod string `json:"calendarPeriod"`
	} `json:"budgetFilter"`
	Amount struct {
		SpecifiedAmount struct {
			CurrencyCode string `json:"currencyCode"`
			Units        string `json:"units"`
			Nanos        int    `json:"nanos"`
		} `json:"specifiedAmount"`
	} `json:"amount"`
	ThresholdRules []struct {
		ThresholdPercent float64 `json:"thresholdPercent"`
		SpendBasis       string  `json:"spendBasis"`
	} `json:"thresholdRules"`
}

// billingBudgetGet reads one budget. found=false + readable=true is an
// authoritative "does not exist" (404); readable=false is transport/HTTP/parse.
func (d *Driver) billingBudgetGet(billingAccountID, budgetID string) (billingBudgetDoc, bool, error) {
	const op = "billingBudGet.get"
	st, body, err := d.call("GET", d.billingBudgetURL(billingAccountID, budgetID), nil)
	if err != nil {
		return billingBudgetDoc{}, false, readTransport(op, err)
	}
	if st == http.StatusNotFound {
		return billingBudgetDoc{}, false, nil
	}
	if st != http.StatusOK {
		return billingBudgetDoc{}, false, readHTTP(op, st, gcpErrCode(body))
	}
	var doc billingBudgetDoc
	if json.Unmarshal(body, &doc) != nil {
		return billingBudgetDoc{}, false, readBody(op, st)
	}
	return doc, true, nil
}

// billingBudgetList enumerates the billing account's budgets (paginated). ok=false
// on any transport/HTTP/parse failure.
func (d *Driver) billingBudgetList(billingAccountID string) ([]billingBudgetDoc, error) {
	var all []billingBudgetDoc
	pageToken := ""
	for {
		u := fmt.Sprintf("%s/billingAccounts/%s/budgets", d.billingBudgetsBase(), billingAccountID)
		if pageToken != "" {
			u += "?pageToken=" + url.QueryEscape(pageToken)
		}
		const op = "budgets.list"
		st, body, cerr := d.call("GET", u, nil)
		if cerr != nil {
			return nil, readTransport(op, cerr)
		}
		if st != http.StatusOK {
			return nil, readHTTP(op, st, gcpErrCode(body))
		}
		var page struct {
			Budgets       []billingBudgetDoc `json:"budgets"`
			NextPageToken string             `json:"nextPageToken"`
		}
		if json.Unmarshal(body, &page) != nil {
			return nil, readBody(op, st)
		}
		all = append(all, page.Budgets...)
		if page.NextPageToken == "" {
			return all, nil
		}
		pageToken = page.NextPageToken
	}
}

// findBillingBudgetByDisplayName resolves the server-assigned id of a budget with an
// EXACT display name match (the create idempotency + D29 recovery handle). Returns
// the id, found, and why-not (a non-nil error means the list itself gave no answer).
func (d *Driver) findBillingBudgetByDisplayName(billingAccountID, displayName string) (string, bool, error) {
	list, lerr := d.billingBudgetList(billingAccountID)
	if lerr != nil {
		return "", false, lerr
	}
	for _, b := range list {
		if b.DisplayName == displayName {
			return budgetIDFromName(b.Name), true, nil
		}
	}
	return "", false, nil
}

func (d *Driver) createBillingBudget(capability, environment string,
	attrs, impl map[string]any, generation int) provider.CreateResult {
	plan, err := BuildBillingBudget(d.Project, environment, capability, attrs, impl, generation)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	acct := plan.BillingAccountID

	// idempotency: a budget with our deterministic display name already ours?
	// (GCP does not dedupe on display name — this is the only guard against a
	// duplicate on a retried create.)
	if id, found, lerr := d.findBillingBudgetByDisplayName(acct, plan.DisplayName); lerr == nil && found {
		return provider.CreateResult{ProviderID: billingBudgetProviderID(acct, id), Status: "succeeded"}
	}

	u := fmt.Sprintf("%s/billingAccounts/%s/budgets", d.billingBudgetsBase(), acct)
	st, body, cerr := d.call("POST", u, plan.createBody())
	switch {
	case cerr != nil:
		// lost response — the budget MAY have landed; re-list to recover the id.
		if id, found, lerr := d.findBillingBudgetByDisplayName(acct, plan.DisplayName); lerr == nil && found {
			return provider.CreateResult{ProviderID: billingBudgetProviderID(acct, id), Status: "succeeded"}
		}
		return provider.CreateResult{Status: "unknown",
			Reason: fmt.Sprintf("create outcome unknown (may have landed; reconcile by displayName %q): %v", plan.DisplayName, cerr)}
	case st == http.StatusOK || st == http.StatusCreated:
		var doc billingBudgetDoc
		if json.Unmarshal(body, &doc) != nil || doc.Name == "" {
			// success without a parseable id — recover by display name.
			if id, found, lerr := d.findBillingBudgetByDisplayName(acct, plan.DisplayName); lerr == nil && found {
				return provider.CreateResult{ProviderID: billingBudgetProviderID(acct, id), Status: "succeeded"}
			}
			return provider.CreateResult{Status: "unknown", Reason: "create response carried no budget name — reconcile"}
		}
		return provider.CreateResult{ProviderID: billingBudgetProviderID(acct, budgetIDFromName(doc.Name)), Status: "succeeded"}
	case st >= 500:
		if id, found, lerr := d.findBillingBudgetByDisplayName(acct, plan.DisplayName); lerr == nil && found {
			return provider.CreateResult{ProviderID: billingBudgetProviderID(acct, id), Status: "succeeded"}
		}
		return provider.CreateResult{Status: "unknown",
			Reason: fmt.Sprintf("create HTTP %d (server error — may have landed; reconcile by displayName %q): %s", st, plan.DisplayName, mutDetail(body))}
	default:
		return provider.CreateResult{Status: "failed", Reason: fmt.Sprintf("create HTTP %d: %s", st, mutDetail(body))}
	}
}

// budgetObservations reverse-maps a live budget document into vocabulary paths.
func budgetObservations(doc billingBudgetDoc) ([]provider.Observation, []string) {
	var diags []string
	obs := []provider.Observation{
		{Path: "service.managed", Value: true, Derivation: "measured"},
	}
	sa := doc.Amount.SpecifiedAmount
	if sa.CurrencyCode != "" && sa.Units != "" {
		if units, perr := strconv.ParseInt(sa.Units, 10, 64); perr == nil {
			amount := float64(units) + float64(sa.Nanos)/1e9
			// the {amount, currency} object form is the canonical money value the
			// verifier reverse-parses (no lossy string formatting).
			obs = append(obs, provider.Observation{Path: "budget.limit",
				Value:      map[string]any{"amount": amount, "currency": sa.CurrencyCode},
				Derivation: "measured"})
		}
	}
	if period := budgetPeriodFromCalendar(doc.BudgetFilter.CalendarPeriod); period != "" {
		obs = append(obs, provider.Observation{Path: "budget.period", Value: period, Derivation: "measured"})
	}
	// D798. WHICH rule this reads decides what the alert watches. A threshold rule
	// fires on CURRENT_SPEND or on FORECASTED_SPEND, and those are different promises:
	// one says "you have spent 80% of the budget", the other says "we predict you
	// will". This used to take thresholdRules[0] unconditionally, so a budget whose
	// first rule was a forecast reported a spend alert that does not exist — while the
	// AWS driver filtered ThresholdType=PERCENTAGE and the Azure one thresholdType=
	// Actual, for the SAME attribute. Two clouds drew the distinction; this one did not.
	//
	// An empty basis is a current-spend rule, and that is the API's own statement:
	// "Behavior defaults to CURRENT_SPEND if not set".
	forecastOnly := 0
	spendRule := false
	for _, r := range doc.ThresholdRules {
		if r.SpendBasis != "" && r.SpendBasis != "CURRENT_SPEND" {
			forecastOnly++
			continue
		}
		// API is a FRACTION; the vocab is a PERCENTAGE.
		obs = append(obs, provider.Observation{Path: "alert.threshold",
			Value: r.ThresholdPercent * 100, Derivation: "measured"})
		spendRule = true
		break
	}
	if !spendRule && forecastOnly > 0 {
		diags = append(diags, fmt.Sprintf("alert.threshold not observed: all %d of the "+
			"budget's threshold rules fire on FORECASTED spend, which is a prediction "+
			"rather than a measurement of what has been spent — reporting one as the "+
			"spend threshold would claim an alert this budget does not have", forecastOnly))
	}
	return obs, diags
}

func (d *Driver) observeBillingBudget(capability, providerID string) ([]provider.Observation, []string, error) {
	acct, budgetID, err := splitBillingBudgetProviderID(providerID)
	if err != nil {
		return nil, nil, err
	}
	doc, found, rerr := d.billingBudgetGet(acct, budgetID)
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
		}, []string{"billing budget not found — bound resource is gone (will re-create)"}, nil
	}
	var diags []string
	if doc.BudgetFilter.CalendarPeriod == "" {
		diags = append(diags, "budget.period not observed: the budget uses a custom period, which has no recurring vocab mapping")
	}
	obs, obsDiags := budgetObservations(doc)
	return obs, append(diags, obsDiags...), nil
}

func (d *Driver) deleteBillingBudget(capability, environment, providerID string) provider.CreateResult {
	acct, budgetID, err := splitBillingBudgetProviderID(providerID)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	doc, found, rerr := d.billingBudgetGet(acct, budgetID)
	if rerr != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown", Reason: "pre-delete read gave no answer — reconcile: " + rerr.Error()}
	}
	if !found {
		return provider.CreateResult{ProviderID: providerID, Status: "succeeded"} // idempotent
	}
	if !billingBudgetOurs(doc.DisplayName, environment, capability) {
		return provider.CreateResult{Status: "failed",
			Reason: "budget display name does not carry our ownership marker — refusing to delete a resource that is not ours"}
	}
	st, body, e := d.call("DELETE", d.billingBudgetURL(acct, budgetID), nil)
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
		return provider.CreateResult{Status: "failed", Reason: fmt.Sprintf("delete HTTP %d: %s", st, mutDetail(body))}
	}
	return provider.CreateResult{ProviderID: providerID, Status: "succeeded"}
}

// updateBillingBudget patches the mutable paths IN PLACE (D46/classifyBillingBudget
// Change): budget.limit -> amount.specifiedAmount, alert.threshold -> thresholdRules,
// budget.period -> budgetFilter.calendarPeriod, in ONE budgets.patch with a combined
// updateMask. Ownership is the deterministic DISPLAY NAME — a pre-patch GET confirms
// the budget carries our marker (ours); unreadable -> unknown, vanished -> failed,
// foreign -> failed. Honesty per D29/D87: an ambiguous outcome (transport / 5xx) is
// unknown WITH the providerId; a 4xx is failed.
func (d *Driver) updateBillingBudget(capability, environment, providerID string,
	attrs, impl map[string]any, changes []string) provider.CreateResult {
	acct, budgetID, err := splitBillingBudgetProviderID(providerID)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	plan, err := BuildBillingBudget(d.Project, environment, capability, attrs, impl, 1)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	// ownership re-check: the display name IS the marker (no labels on the object).
	doc, found, rerr := d.billingBudgetGet(acct, budgetID)
	if rerr != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown", Reason: "pre-update read gave no answer — reconcile: " + rerr.Error()}
	}
	if !found {
		return provider.CreateResult{Status: "failed", Reason: "budget to update no longer exists — reconcile"}
	}
	if !billingBudgetOurs(doc.DisplayName, environment, capability) {
		return provider.CreateResult{Status: "failed",
			Reason: "budget display name does not carry our ownership marker — refusing to patch a resource that is not ours"}
	}

	body := map[string]any{}
	var masks []string
	for _, path := range changes {
		switch path {
		case "budget.limit":
			body["amount"] = map[string]any{"specifiedAmount": plan.specifiedAmount()}
			masks = append(masks, "amount.specifiedAmount")
		case "alert.threshold":
			body["thresholdRules"] = []any{plan.thresholdRule()}
			masks = append(masks, "thresholdRules")
		case "budget.period":
			body["budgetFilter"] = map[string]any{"calendarPeriod": plan.CalendarPeriod}
			masks = append(masks, "budgetFilter.calendarPeriod")
		default:
			return provider.CreateResult{Status: "failed",
				Reason: fmt.Sprintf("cloud billing budget in-place update does not honor %q — reconcile", path)}
		}
	}
	if len(masks) == 0 {
		return provider.CreateResult{ProviderID: providerID, Status: "succeeded"} // nothing to do
	}

	u := d.billingBudgetURL(acct, budgetID) + "?updateMask=" + url.QueryEscape(strings.Join(masks, ","))
	st, respBody, perr := d.call("PATCH", u, body)
	if perr != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown", Reason: fmt.Sprintf("patch outcome unknown: %v", perr)}
	}
	if st >= 500 {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown", Reason: fmt.Sprintf("patch HTTP %d (server error — may have landed) — reconcile", st)}
	}
	if st < 200 || st >= 300 {
		return provider.CreateResult{Status: "failed", Reason: fmt.Sprintf("patch HTTP %d: %s", st, mutDetail(respBody))}
	}
	return provider.CreateResult{ProviderID: providerID, Status: "succeeded"}
}

// resolveBillingAccount reads the billing account the pinned PROJECT is linked to
// (cloudbilling.projects.getBillingInfo) — the vantage discovery needs, since a
// budget is billing-account-scoped and List() only carries a project/region.
// D642: the single `bool` collapsed four different answers into one — no project
// pinned, the request could not be made, the API refused, the body was unreadable,
// and "this project has no billing account". Only the LAST of those means there are
// no budgets; the others mean nothing was read, and the caller returned a nil error
// for all five, so `discover` counted an unreachable billing API as a swept service.
// An answered request with no account returns ("", nil) — genuinely zero budgets.
func (d *Driver) resolveBillingAccount() (string, error) {
	if d.Project == "" {
		return "", fmt.Errorf("no project is pinned")
	}
	u := fmt.Sprintf("%s/projects/%s/billingInfo", d.cloudBillingBase(), d.Project)
	st, body, err := d.call("GET", u, nil)
	if err != nil {
		return "", fmt.Errorf("billingInfo.get: %v", err)
	}
	if st != http.StatusOK {
		return "", fmt.Errorf("billingInfo.get: HTTP %d", st)
	}
	var info struct {
		BillingAccountName string `json:"billingAccountName"`
		BillingEnabled     bool   `json:"billingEnabled"`
	}
	if jerr := json.Unmarshal(body, &info); jerr != nil {
		return "", fmt.Errorf("billingInfo.get: HTTP %d but the body did not parse: %v",
			st, jerr)
	}
	acct := strings.TrimPrefix(info.BillingAccountName, "billingAccounts/")
	if acct == "" {
		return "", nil // answered: the project is linked to no billing account
	}
	if !billingAccountOK.MatchString(acct) {
		return "", fmt.Errorf("billingInfo.get: billing account %q is not representable",
			info.BillingAccountName)
	}
	return acct, nil
}

// discoverBillingBudget enumerates the billing account's budgets as
// capability.cost.budget. Budgets are billing-account-scoped (not project/region),
// so the region argument is ignored; the billing account is resolved from the pinned
// project's billing info. Each budget is reverse-mapped by budgetObservations.
func (d *Driver) discoverBillingBudget(region string) ([]provider.Discovered, []string, error) {
	acct, aerr := d.resolveBillingAccount()
	if aerr != nil {
		return nil, nil, fmt.Errorf(
			"billing budgets: could not resolve the project's billing account "+
				"(needs a pinned project with billing enabled and cloudbilling "+
				"access): %v", aerr)
	}
	if acct == "" {
		return nil, []string{"billing budgets: this project is linked to no billing " +
			"account, so it has no budgets"}, nil
	}
	list, lerr := d.billingBudgetList(acct)
	if lerr != nil {
		return nil, nil, lerr
	}
	var out []provider.Discovered
	var diags []string
	for _, b := range list {
		id := budgetIDFromName(b.Name)
		if !billingBudgetIDOK.MatchString(id) {
			diags = append(diags, b.DisplayName+": budget id not representable as a providerId")
			continue
		}
		budgetObs, budgetDiags := budgetObservations(b)
		for _, dg := range budgetDiags {
			diags = append(diags, b.DisplayName+": "+dg)
		}
		out = append(out, provider.Discovered{
			ProviderID:   billingBudgetProviderID(acct, id),
			ResourceType: "capability.cost.budget",
			Observations: budgetObs,
		})
	}
	return out, diags, nil
}
