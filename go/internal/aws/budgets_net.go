// AWS Budgets network shell (D151): the SigV4-signed, JSON-1.1 half of the AWS
// capability.cost.budget driver. AWS Budgets is a GLOBAL service — one endpoint
// (budgets.amazonaws.com), SigV4 signed for service "budgets" in region
// us-east-1, addressed by X-Amz-Target AWSBudgetServiceGateway.<Action>. A
// create is two calls: CreateBudget then CreateNotification.
// Honesty per D29/D87: the budget name is deterministic, so the providerId is
// knowable BEFORE the response (carried on every ambiguous outcome). A partial
// (budget created, notification failed) is unknown WITH the providerId, never a
// silent success. Ownership is the deterministic NAME (there are no tags on the
// object).
package aws

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"groundhold/internal/provider"
	"regexp"
)

// budgetSigningRegion is the SigV4 region for the global Budgets endpoint.
const budgetSigningRegion = "us-east-1"

// budgetsBaseURLOverride redirects the (single, global) Budgets endpoint to a
// test server. It lives here rather than on the Driver struct because this
// driver ships entirely in its own files (the Driver struct is not edited); the
// httptest tests in this package do not run in parallel, so a package-level
// override is safe. Empty = real AWS.
var budgetsBaseURLOverride string

func (d *Driver) budgetBase() string {
	if budgetsBaseURLOverride != "" {
		return budgetsBaseURLOverride
	}
	return "https://budgets.amazonaws.com"
}

func budgetProviderID(account, name string) string {
	return "budgets:" + account + ":" + name
}

func splitBudgetProviderID(providerID string) (account, name string, err error) {
	parts := strings.SplitN(providerID, ":", 3)
	if len(parts) != 3 || parts[0] != "budgets" {
		return "", "", fmt.Errorf("providerId %q is not budgets:account:budgetName", providerID)
	}
	if !account12.MatchString(parts[1]) {
		return "", "", fmt.Errorf("providerId account %q is invalid", parts[1])
	}
	if !budgetNameOK.MatchString(parts[2]) {
		return "", "", fmt.Errorf("providerId budget name %q is invalid", parts[2])
	}
	return parts[1], parts[2], nil
}

// budgetCall signs and sends a JSON-1.1 request (X-Amz-Target). Budgets is
// global: always signed for us-east-1, service "budgets".
func (d *Driver) budgetCall(action, body string) (int, []byte, error) {
	h := map[string]string{
		"Content-Type": "application/x-amz-json-1.1",
		"X-Amz-Target": budgetTarget + "." + action,
	}
	return d.doSigned("POST", d.budgetBase()+"/", "budgets", budgetSigningRegion, h, []byte(body))
}

type budgetDesc struct {
	BudgetName  string `json:"BudgetName"`
	TimeUnit    string `json:"TimeUnit"`
	BudgetType  string `json:"BudgetType"`
	BudgetLimit struct {
		Amount string `json:"Amount"` // the API returns Amount as a STRING
		Unit   string `json:"Unit"`
	} `json:"BudgetLimit"`
}

// describeBudget reads one budget. found=false + readable=true is an
// authoritative "does not exist" (NotFoundException); readable=false is a
// transport/HTTP/parse failure.
func (d *Driver) describeBudget(account, name string) (budgetDesc, bool, error) {
	const op = "DescribeBudget"
	st, resp, err := d.budgetCall("DescribeBudget", jsonBody(map[string]any{
		"AccountId": account, "BudgetName": name}))
	if err != nil {
		return budgetDesc{}, false, readTransport(op, err)
	}
	if strings.Contains(ecsErr(resp), "NotFoundException") {
		return budgetDesc{}, false, nil
	}
	if st != http.StatusOK {
		return budgetDesc{}, false, readHTTP(op, st, ecsErr(resp))
	}
	var out struct {
		Budget budgetDesc `json:"Budget"`
	}
	if json.Unmarshal(resp, &out) != nil {
		return budgetDesc{}, false, readBody(op, st)
	}
	return out.Budget, true, nil
}

// budgetThreshold reads the ACTUAL/PERCENTAGE notification threshold. ok=false
// on any transport/HTTP/parse failure; ok=true + found=false is a readable
// "the budget has no notification".
func (d *Driver) budgetThreshold(account, name string) (threshold float64, found bool, err error) {
	const op = "DescribeNotificationsForBudget"
	st, resp, cerr := d.budgetCall("DescribeNotificationsForBudget", jsonBody(map[string]any{
		"AccountId": account, "BudgetName": name}))
	if cerr != nil {
		return 0, false, readTransport(op, cerr)
	}
	if st != http.StatusOK {
		return 0, false, readHTTP(op, st, ecsErr(resp))
	}
	var out struct {
		Notifications []struct {
			NotificationType string  `json:"NotificationType"`
			Threshold        float64 `json:"Threshold"`
			ThresholdType    string  `json:"ThresholdType"`
		} `json:"Notifications"`
	}
	if json.Unmarshal(resp, &out) != nil {
		return 0, false, readBody(op, st)
	}
	for _, n := range out.Notifications {
		if n.ThresholdType == "PERCENTAGE" {
			return n.Threshold, true, nil
		}
	}
	return 0, false, nil
}

// createBudget: CreateBudget then CreateNotification. Ownership
// is the deterministic name; a DuplicateRecordException on the budget re-checks
// via DescribeBudget (a budget at our name is ours). A partial (budget landed,
// notification failed) is unknown WITH the providerId — never a silent success.
func (d *Driver) createBudget(account, environment, capability string,
	attrs, impl map[string]any, generation int) provider.CreateResult {
	plan, err := BuildBudget(environment, capability, attrs, impl, generation)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	pid := budgetProviderID(account, plan.Name)

	// ---- CreateBudget ----
	st, resp, err := d.budgetCall("CreateBudget", jsonBody(plan.createBudgetBody(account)))
	switch {
	case err != nil:
		return provider.CreateResult{ProviderID: pid, Status: "unknown",
			Reason: fmt.Sprintf("create budget outcome unknown (may have landed): %v", err)}
	case st == http.StatusOK:
		// created — fall through to the notification
	case strings.Contains(ecsErr(resp), "DuplicateRecordException"):
		// a budget at our deterministic name already exists. The name IS the
		// ownership marker, so re-read to confirm it is readable, then continue
		// (the notification create below is idempotent on its own).
		_, found, rerr := d.describeBudget(account, plan.Name)
		if rerr != nil {
			return provider.CreateResult{ProviderID: pid, Status: "unknown",
				Reason: "budget name conflict, existing budget gave no answer — reconcile: " + rerr.Error()}
		}
		if !found {
			return provider.CreateResult{ProviderID: pid, Status: "unknown",
				Reason: "duplicate reported but budget not found on re-read — reconcile"}
		}
		// ours (by name) — fall through to ensure the notification
	case st >= 500:
		return provider.CreateResult{ProviderID: pid, Status: "unknown",
			Reason: fmt.Sprintf("create budget HTTP %d (server error — may have landed): %s", st, mutDetail(resp))}
	default:
		return provider.CreateResult{Status: "failed",
			Reason: fmt.Sprintf("create budget HTTP %d (%s): %s", st, ecsErr(resp), mutDetail(resp))}
	}

	// ---- CreateNotification (the alert sink) ----
	// The budget has landed; from here ANY notification failure is a PARTIAL —
	// unknown WITH the providerId (reconcile), never failed, never a silent
	// success.
	st, resp, err = d.budgetCall("CreateNotification",
		jsonBody(plan.createNotificationBody(account)))
	switch {
	case err != nil:
		return provider.CreateResult{ProviderID: pid, Status: "unknown",
			Reason: fmt.Sprintf("budget created but notification outcome unknown: %v", err)}
	case st == http.StatusOK:
		return provider.CreateResult{ProviderID: pid, Status: "succeeded"}
	case strings.Contains(ecsErr(resp), "DuplicateRecordException"):
		// the notification already exists — ours, idempotent success.
		return provider.CreateResult{ProviderID: pid, Status: "succeeded"}
	default:
		return provider.CreateResult{ProviderID: pid, Status: "unknown",
			Reason: fmt.Sprintf("budget created but notification failed: HTTP %d (%s) — reconcile", st, ecsErr(resp))}
	}
}

// observeBudget reverse-maps a live budget: budget.limit (Amount+Unit),
// budget.period (TimeUnit), service.managed, and the alert.threshold from the
// notification. Unreadable -> error; not-found -> "nothing to observe".
func (d *Driver) observeBudget(capability, providerID string) ([]provider.Observation, []string, error) {
	account, name, err := splitBudgetProviderID(providerID)
	if err != nil {
		return nil, nil, err
	}
	if err := d.sameAccount(account); err != nil {
		return nil, nil, err
	}
	desc, found, rerr := d.describeBudget(account, name)
	if rerr != nil {
		return nil, nil, rerr
	}
	if !found {
		// F-LC3 (D520): a BOUND resource the API authoritatively 404s is GONE.
		// A diagnostic alone leaves the binding a no-op forever (D513).
		return []provider.Observation{
			{Path: provider.ResourceAbsentPath, Value: true, Derivation: "measured"},
		}, []string{"budget not found — bound resource is gone (will re-create)"}, nil
	}
	obs := []provider.Observation{
		// Present: clear the marker (F-LC3), or a stale "gone" survives a re-create.
		{Path: provider.ResourceAbsentPath, Value: false, Derivation: "measured"},
		{Path: "service.managed", Value: true, Derivation: "measured"},
	}
	if desc.BudgetLimit.Amount != "" && desc.BudgetLimit.Unit != "" {
		if amt, perr := strconv.ParseFloat(desc.BudgetLimit.Amount, 64); perr == nil {
			// the object {amount, currency} form is the canonical money value the
			// verifier reverse-parses (no lossy "700.0 EUR" string formatting).
			obs = append(obs, provider.Observation{Path: "budget.limit",
				Value:      map[string]any{"amount": amt, "currency": desc.BudgetLimit.Unit},
				Derivation: "measured"})
		}
	}
	var diags []string
	if period := budgetPeriodFromTimeUnit(desc.TimeUnit); period != "" {
		obs = append(obs, provider.Observation{Path: "budget.period", Value: period, Derivation: "measured"})
	} else if desc.TimeUnit != "" {
		// D1234, the AWS twin of the GCP silence. A TimeUnit this mapping does not know
		// produced NOTHING — no observation and no diagnostic — so a value AWS adds
		// later reads as "the budget has no period" rather than "we could not map it".
		// The vocabulary publishes the opposite convention for this attribute ("no
		// equivalent is named in a diagnostic, never coerced"); Azure honors it and the
		// other two did not.
		diags = append(diags, "budget.period not mapped: TimeUnit "+desc.TimeUnit+
			" has no recurring vocab equivalent")
	}
	if threshold, tFound, terr := d.budgetThreshold(account, name); terr == nil && tFound {
		obs = append(obs, provider.Observation{Path: "alert.threshold", Value: threshold, Derivation: "measured"})
	}
	return obs, diags, nil
}

// deleteBudget: DeleteBudget by name. Ownership is the deterministic name — the
// providerId carries the name groundhold bound, and a foreign budget at a foreign
// name is never addressed here. A missing budget is an idempotent success.
func (d *Driver) deleteBudget(capability, environment, providerID string) provider.CreateResult {
	account, name, err := splitBudgetProviderID(providerID)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	if err := d.sameAccount(account); err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	// OWNERSHIP (D443). A budget carries NO TAGS — AWS offers none on this resource —
	// so the deterministic NAME is the entire ownership marker, and the create path
	// already treats it as one (a DuplicateRecordException is resolved as "ours, by
	// name"). The delete did not check it at all: it split the providerId, read the
	// budget and deleted it. A providerId naming ANY budget in the account therefore
	// destroyed that budget, and a providerId is not a secret — it comes from the
	// ledger, which a hand-authored plan is explicitly allowed to supply (D47/D48).
	//
	// The generation is not known here, so the full name cannot be rebuilt; the
	// capability+environment SLUG can be, and it is what distinguishes our budgets from
	// everyone else's. A name outside our scheme for this capability is refused.
	if !budgetNameLooksOurs(name, capability, environment) {
		return provider.CreateResult{Status: "failed",
			Reason: fmt.Sprintf("budget %q is not named by groundhold for %s/%s — refusing "+
				"to delete a budget this contract does not own (a budget carries no tags, "+
				"so its name is the only ownership evidence there is)",
				name, capability, environment)}
	}
	_, found, rerr := d.describeBudget(account, name)
	if rerr != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown",
			Reason: "pre-delete read gave no answer — reconcile: " + rerr.Error()}
	}
	if !found {
		return provider.CreateResult{ProviderID: providerID, Status: "succeeded"} // idempotent
	}
	st, resp, err := d.budgetCall("DeleteBudget", jsonBody(map[string]any{
		"AccountId": account, "BudgetName": name}))
	if err != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown",
			Reason: fmt.Sprintf("delete outcome unknown: %v", err)}
	}
	if strings.Contains(ecsErr(resp), "NotFoundException") {
		return provider.CreateResult{ProviderID: providerID, Status: "succeeded"} // idempotent
	}
	if st >= 500 {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown",
			Reason: fmt.Sprintf("delete HTTP %d (server error) — reconcile", st)}
	}
	if st != http.StatusOK {
		return provider.CreateResult{Status: "failed",
			Reason: fmt.Sprintf("delete HTTP %d (%s)", st, ecsErr(resp))}
	}
	return provider.CreateResult{ProviderID: providerID, Status: "succeeded"}
}

// updateBudget patches a budget IN PLACE for the mutable paths (D151/D46):
// budget.limit via UpdateBudget (a full NewBudget definition), alert.threshold
// via UpdateNotification (the fixed ACTUAL/GREATER_THAN/PERCENTAGE shape, only the
// threshold value moving). Ownership is the deterministic NAME — a pre-patch
// DescribeBudget confirms a budget at our name exists (ours); unreadable ->
// unknown, vanished -> failed. Honesty per D29/D87: an ambiguous outcome
// (transport / 5xx) is unknown WITH the providerId; a 4xx is failed.
func (d *Driver) updateBudget(capability, environment, providerID string,
	attrs, impl map[string]any, changes []string) provider.CreateResult {
	account, name, err := splitBudgetProviderID(providerID)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	if err := d.sameAccount(account); err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	plan, err := BuildBudget(environment, capability, attrs, impl, 1)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	// the resource identity is the name groundhold bound (carried in the providerId),
	// not a re-derived one — pin the plan to it so the patch bodies address the
	// existing budget regardless of the generation discriminator.
	plan.Name = name
	// ownership re-check: the name IS the marker (no tags on the object). D459 — this
	// comment was here, and the check under it was an EXISTENCE check. An update on a
	// budget outside our naming scheme replaced a stranger's whole budget definition
	// with ours; the delete beside it had carried the name check since D444.
	if !budgetNameLooksOurs(name, capability, environment) {
		return provider.CreateResult{Status: "failed",
			Reason: fmt.Sprintf("budget %q is not named by groundhold for %s/%s — refusing "+
				"to update a budget this contract does not own (a budget carries no tags, "+
				"so its name is the only ownership evidence there is)",
				name, capability, environment)}
	}
	_, found, rerr := d.describeBudget(account, name)
	if rerr != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown",
			Reason: "pre-update read gave no answer — reconcile: " + rerr.Error()}
	}
	if !found {
		return provider.CreateResult{Status: "failed",
			Reason: "budget to update no longer exists — reconcile"}
	}
	for _, path := range changes {
		switch path {
		case "budget.limit", "budget.period":
			// UpdateBudget replaces the whole definition; we re-send the full,
			// deterministic budget — which carries the new limit AND the new TimeUnit
			// (D806), so both are honoured by the same call.
			st, resp, cerr := d.budgetCall("UpdateBudget", jsonBody(map[string]any{
				"AccountId": account,
				"NewBudget": plan.createBudgetBody(account)["Budget"],
			}))
			if r := budgetPatchOutcome("update limit", providerID, st, resp, cerr); r != nil {
				return *r
			}
		case "alert.threshold":
			// UpdateNotification needs the OLD notification to match on; its shape is
			// fixed by createNotificationBody, only the threshold value moves. Read the
			// live threshold to build OldNotification (ambiguous read -> unknown).
			old, tFound, terr := d.budgetThreshold(account, name)
			if terr != nil {
				return provider.CreateResult{ProviderID: providerID, Status: "unknown",
					Reason: "pre-update notification read gave no answer — reconcile: " + terr.Error()}
			}
			if !tFound {
				// no notification to update — create it (idempotent on duplicate).
				st, resp, cerr := d.budgetCall("CreateNotification",
					jsonBody(plan.createNotificationBody(account)))
				if cerr == nil && strings.Contains(ecsErr(resp), "DuplicateRecordException") {
					continue
				}
				if r := budgetPatchOutcome("create notification", providerID, st, resp, cerr); r != nil {
					return *r
				}
				continue
			}
			st, resp, cerr := d.budgetCall("UpdateNotification", jsonBody(map[string]any{
				"AccountId":  account,
				"BudgetName": name,
				"OldNotification": map[string]any{
					"NotificationType":   "ACTUAL",
					"ComparisonOperator": "GREATER_THAN",
					"Threshold":          old,
					"ThresholdType":      "PERCENTAGE",
				},
				"NewNotification": map[string]any{
					"NotificationType":   "ACTUAL",
					"ComparisonOperator": "GREATER_THAN",
					"Threshold":          plan.Threshold,
					"ThresholdType":      "PERCENTAGE",
				},
			}))
			if r := budgetPatchOutcome("update threshold", providerID, st, resp, cerr); r != nil {
				return *r
			}
		default:
			return provider.CreateResult{Status: "failed",
				Reason: fmt.Sprintf("budgets in-place update does not honor %q — reconcile", path)}
		}
	}
	return provider.CreateResult{ProviderID: providerID, Status: "succeeded"}
}

// budgetPatchOutcome folds one Budgets patch call into the four-valued shape:
// nil means "keep going" (HTTP 200), non-nil is the terminal result. Ambiguous
// (transport / 5xx) is unknown WITH the providerId; a 4xx is failed.
func budgetPatchOutcome(what, providerID string, st int, resp []byte, err error) *provider.CreateResult {
	switch {
	case err != nil:
		return &provider.CreateResult{ProviderID: providerID, Status: "unknown",
			Reason: fmt.Sprintf("%s outcome unknown (may have landed): %v", what, err)}
	case st == http.StatusOK:
		return nil
	case st >= 500:
		return &provider.CreateResult{ProviderID: providerID, Status: "unknown",
			Reason: fmt.Sprintf("%s HTTP %d (server error — may have landed) — reconcile", what, st)}
	default:
		return &provider.CreateResult{Status: "failed",
			Reason: fmt.Sprintf("%s HTTP %d (%s)", what, st, ecsErr(resp))}
	}
}

// discoverBudgets enumerates the account's budgets (DescribeBudgets) as
// capability.cost.budget, each reverse-mapped by observeBudget. Budgets is a
// GLOBAL, account-scoped service, so the region argument is ignored; the account
// is resolved once via STS.
func (d *Driver) discoverBudgets(region string) ([]provider.Discovered, []string, error) {
	account, err := d.resolveAccount()
	if err != nil {
		return nil, nil, fmt.Errorf("budgets: %v", err)
	}
	st, body, err := d.budgetCall("DescribeBudgets", jsonBody(map[string]any{"AccountId": account}))
	if err != nil {
		return nil, nil, fmt.Errorf("budgets DescribeBudgets: %v", err)
	}
	if st != http.StatusOK {
		return nil, nil, fmt.Errorf("budgets DescribeBudgets: HTTP %d (%s)", st, ecsErr(body))
	}
	var r struct {
		Budgets []struct {
			BudgetName string `json:"BudgetName"`
		} `json:"Budgets"`
	}
	if json.Unmarshal(body, &r) != nil {
		return nil, nil, readBody("budgets DescribeBudgets", st)
	}
	var out []provider.Discovered
	var diags []string
	for _, b := range r.Budgets {
		if !budgetNameOK.MatchString(b.BudgetName) {
			diags = append(diags, b.BudgetName+": name not representable as a providerId")
			continue
		}
		pid := budgetProviderID(account, b.BudgetName)
		obs, odiags, oerr := d.observeBudget("", pid)
		if oerr != nil {
			diags = append(diags, b.BudgetName+": "+oerr.Error())
			continue
		}
		for _, dg := range odiags {
			diags = append(diags, b.BudgetName+": "+dg)
		}
		out = append(out, provider.Discovered{
			ProviderID:   pid,
			ResourceType: "capability.cost.budget",
			Observations: provider.WithoutAbsence(obs),
		})
	}
	return out, diags, nil
}

// nameLooksOurs is the shared ownership predicate for TAG-LESS resources (D444). AWS
// offers no tags on budgets, IAM policies or log metric filters, so the deterministic
// NAME is the only ownership evidence there is — and the delete path is where that has
// to be checked, because the providerId it is handed comes from the ledger.
//
// The generation is not passed to a delete, so the trailing hash cannot be rebuilt; the
// capability+environment slug can. The predicate is: our prefix, our slug, and a tail of
// the expected shape and length. It cannot say WHICH generation made the resource and
// does not try — it says the resource belongs to this contract's capability rather than
// to somebody else entirely, which is exactly what a tag would have answered.
func nameLooksOurs(name, capability, environment string, bad *regexp.Regexp, tailLen int, hexTail bool) bool {
	slug := capability
	if environment != "" {
		slug += "-" + environment
	}
	slug = strings.Trim(bad.ReplaceAllString(strings.ToLower(slug), "-"), "-")
	prefix := "pv-" + slug + "-"
	if !strings.HasPrefix(name, prefix) {
		return false
	}
	tail := name[len(prefix):]
	if len(tail) != tailLen {
		return false
	}
	for _, c := range tail {
		ok := c >= 'a' && c <= 'z'
		if hexTail {
			ok = (c >= 'a' && c <= 'f') || (c >= '0' && c <= '9')
		}
		if !ok {
			return false
		}
	}
	return true
}

// budgetNameLooksOurs reports whether name is one BudgetName would produce for this
// capability and environment at SOME generation. The generation salts only the trailing
// hash, so the check is: our prefix, our slug, and an 8-letter tail of the right shape.
// It cannot prove which generation made it — it does not need to. It proves the budget
// belongs to this contract's capability rather than to somebody else entirely, which is
// the whole question a tag would have answered.
func budgetNameLooksOurs(name, capability, environment string) bool {
	slug := capability
	if environment != "" {
		slug += "-" + environment
	}
	slug = strings.Trim(budgetBad.ReplaceAllString(strings.ToLower(slug), "-"), "-")
	prefix := "pv-" + slug + "-"
	if len(name) != len(prefix)+8 || !strings.HasPrefix(name, prefix) {
		// a truncated slug (the maxLen branch of BudgetName) still shares the prefix up
		// to the truncation point, so fall back to a prefix-only test for long names.
		return len(slug)+len("pv-")+9 > 100 && strings.HasPrefix(name, "pv-") &&
			strings.HasPrefix(slug, strings.TrimPrefix(name[:len(name)-9], "pv-"))
	}
	for _, c := range name[len(prefix):] {
		if c < 'a' || c > 'z' {
			return false
		}
	}
	return true
}
