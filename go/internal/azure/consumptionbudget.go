// Azure Consumption Budget request building (D76 parity): the Azure half of the
// capability.cost.budget driver — the SAME vocabulary AWS Budgets and GCP Cloud
// Billing Budgets fulfil (one TYPE, many services). A budget
// (Microsoft.Consumption/budgets, ARM) is a cost guardrail scoped to a
// SUBSCRIPTION (default) or a RESOURCE GROUP (impl.resource_group operand);
// STATELESS — it holds no durable data.
//
// What the contract governs: the spend LIMIT (properties.amount), the PERIOD
// (properties.timeGrain) and the alert THRESHOLD (properties.notifications[].
// threshold). The notification sink is an operator OPERAND (D26): contactEmails
// and/or action groups (contactGroups), passed in the impl block — a budget that
// claims to alert but has no sink is refused (parity with AWS Budgets).
//
// Three honest gaps this cloud forces, stated rather than hidden:
//
//   - budget.period=daily is REFUSED — an Azure Consumption budget's timeGrain
//     offers only Monthly/Quarterly/Annually (and their Billing* variants); there
//     is no daily cost budget. Silently widening daily to a month would lie
//     (the same refusal GCP makes; AWS alone honors daily).
//
//   - the budget amount is DIMENSIONLESS in the API — it is denominated in the
//     SUBSCRIPTION's billing currency, which the budget resource cannot set. The
//     billing currency is therefore substrate groundhold does not own (the D99
//     account/subscription trap): it is verified-or-refused, never silently
//     coerced. The operator asserts it via impl.billingCurrency; a mismatch with
//     budget.limit's currency is a refusal (invariant #2 — no currency coercion),
//     not a silent conversion.
//
//   - Consumption budgets carry NO ARM tags (a proxy resource), so ownership is
//     the deterministic budget NAME (the AWS/GCP budget doctrine): a budget at our
//     derived name is ours; a foreign name we never mutate. This is a weaker
//     marker than tags (a hand-created budget colliding with our name would be
//     treated as ours), stated plainly.
package azure

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"groundhold/internal/scalars"
)

// Microsoft.Consumption/budgets stable API version.
const consBudgetAPIVersion = "2023-05-01"

// consBudgetNameOK bounds a budget name before it enters an ARM URL (the D73
// injection boundary) or a providerId. The generator emits a lowercase
// alnum+hyphen subset; the parser accepts the fuller safe set (letters, digits,
// underscore, hyphen) so a hand-adopted name is not rejected. Azure caps a budget
// name at 63 chars.
var consBudgetNameOK = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,62}$`)

// ConsumptionBudgetPlan is the attribute-derived shape a create/update assembles.
type ConsumptionBudgetPlan struct {
	Name          string
	ResourceGroup string // "" => subscription scope; non-empty => RG scope (operand)
	Amount        float64
	Currency      string // ISO code of budget.limit; asserted to equal the billing currency
	TimeGrain     string // Monthly | Quarterly | Annually
	Threshold     float64
	ContactEmails []string
	ActionGroups  []string // action group resource ids (contactGroups)
}

// budgetTimeGrain maps the capability.cost.budget budget.period enum to the Azure
// Consumption timeGrain. The vocab enum is the closed set (daily|monthly|
// quarterly|annually); daily has no Azure cost-budget equivalent (honest refusal)
// and an unknown value is a refusal, never a silent default.
func budgetTimeGrain(period string) (string, error) {
	switch period {
	case "monthly":
		return "Monthly", nil
	case "quarterly":
		return "Quarterly", nil
	case "annually":
		return "Annually", nil
	case "daily":
		return "", fmt.Errorf(
			"budget.period=daily cannot be honored on Azure — a Consumption budget's " +
				"timeGrain offers only Monthly/Quarterly/Annually; there is no daily cost " +
				"budget (refusing rather than silently widening to a month)")
	default:
		return "", fmt.Errorf("budget.period %q is not one of daily|monthly|quarterly|annually", period)
	}
}

// budgetPeriodFromTimeGrain is the reverse map (observe/discover). Billing*
// variants map to the same recurring vocab period; a custom/unknown grain is "".
func budgetPeriodFromTimeGrain(grain string) string {
	switch grain {
	case "Monthly", "BillingMonth":
		return "monthly"
	case "Quarterly", "BillingQuarter":
		return "quarterly"
	case "Annually", "BillingAnnual":
		return "annually"
	default:
		return ""
	}
}

// consBudgetOwnerToken is the generation-INDEPENDENT ownership marker embedded (as
// a suffix) in the budget name. delete/update recompute it from (env, cap) alone.
func consBudgetOwnerToken(environment, capability string) string {
	sum := sha256.Sum256([]byte(environment + "|" + capability))
	return hex.EncodeToString(sum[:])[:8]
}

// ConsumptionBudgetName is the deterministic budget name — BOTH the idempotency
// handle (a PUT to this name is create-or-update) AND the ownership marker (there
// are no tags on the object). The owner token is generation-independent; g>=2
// (D48 replacements) coexist via the -gN salt in the middle. Azure caps the name
// at 63 chars; the slug truncates, never the owner token.
func ConsumptionBudgetName(environment, capability string, generation int) string {
	slug := capability
	if environment != "" {
		slug += "-" + environment
	}
	slug = trimDash(nonAZ.ReplaceAllString(toLowerASCII(slug), "-"))
	suffix := ""
	if generation >= 2 {
		suffix = fmt.Sprintf("-g%d", generation)
	}
	owner := consBudgetOwnerToken(environment, capability)
	const maxLen = 63
	fixed := len("pv-") + len(suffix) + len("-") + len(owner)
	if fixed+len(slug) > maxLen {
		keep := maxLen - fixed
		if keep < 0 {
			keep = 0
		}
		if keep < len(slug) {
			slug = trimDash(slug[:keep])
		}
	}
	return "pv-" + slug + suffix + "-" + owner
}

// consBudgetOurs is the ownership predicate: the name is a groundhold marker AND
// carries the (env, cap) owner token. Generation-independent by design.
func consBudgetOurs(name, environment, capability string) bool {
	return strings.HasPrefix(name, "pv-") &&
		strings.HasSuffix(name, "-"+consBudgetOwnerToken(environment, capability))
}

// BuildConsumptionBudget maps capability.cost.budget attributes + the impl block
// to a plan. Every error is a preflight refusal apply surfaces before any mutation
// — never a silently dropped attribute.
func BuildConsumptionBudget(environment, capability string,
	attrs, impl map[string]any, generation int) (ConsumptionBudgetPlan, error) {
	if generation < 1 {
		generation = 1
	}
	p := ConsumptionBudgetPlan{}
	var haveLimit, havePeriod, haveThreshold bool

	paths := make([]string, 0, len(attrs))
	for k := range attrs {
		paths = append(paths, k)
	}
	sort.Strings(paths)

	for _, path := range paths {
		raw := attrs[path]
		switch path {
		case "budget.limit":
			s, err := scalars.Parse(raw)
			if err != nil || s.Kind != scalars.Money {
				return ConsumptionBudgetPlan{}, fmt.Errorf("budget.limit is not a money value (e.g. \"700 EUR\"): %v", raw)
			}
			mv := s.Value.(scalars.MoneyValue)
			if mv.Amount <= 0 {
				return ConsumptionBudgetPlan{}, fmt.Errorf("budget.limit amount must be positive, got %v", mv.Amount)
			}
			p.Amount = mv.Amount
			p.Currency = mv.Currency
			haveLimit = true
		case "budget.period":
			period, _ := raw.(string)
			tg, err := budgetTimeGrain(period)
			if err != nil {
				return ConsumptionBudgetPlan{}, err
			}
			p.TimeGrain = tg
			havePeriod = true
		case "alert.threshold":
			s, err := scalars.Parse(raw)
			if err != nil || s.Kind != scalars.Number {
				return ConsumptionBudgetPlan{}, fmt.Errorf("alert.threshold is not a number (percent 0-100): %v", raw)
			}
			t := s.Value.(float64)
			if t < 0 || t > 100 {
				return ConsumptionBudgetPlan{}, fmt.Errorf("alert.threshold must be a percent in [0,100], got %v", t)
			}
			// Azure's notification threshold is already a PERCENTAGE (0-100),
			// unlike GCP's fraction — passed through, not converted.
			p.Threshold = t
			haveThreshold = true
		case "service.managed":
			if raw != true {
				return ConsumptionBudgetPlan{}, fmt.Errorf("service.managed=false cannot be honored by Azure Consumption Budgets")
			}
		default:
			return ConsumptionBudgetPlan{}, fmt.Errorf(
				"attribute %s has no Azure Consumption Budget mapping — refusing rather than silently dropping it", path)
		}
	}

	if !haveLimit {
		return ConsumptionBudgetPlan{}, fmt.Errorf("azure consumption budget requires budget.limit (the spend ceiling)")
	}
	if !havePeriod {
		return ConsumptionBudgetPlan{}, fmt.Errorf("azure consumption budget requires budget.period (monthly|quarterly|annually; daily is unsupported on Azure)")
	}
	if !haveThreshold {
		return ConsumptionBudgetPlan{}, fmt.Errorf("azure consumption budget requires alert.threshold (the percent at which the alert fires)")
	}

	// the billing currency is a property of the SUBSCRIPTION substrate groundhold does
	// NOT own (D99 account trap). The budget resource cannot set it — the amount is
	// denominated in it — so it is verified-or-refused: the operator asserts it and
	// a mismatch with budget.limit's currency is a refusal (invariant #2, no coercion).
	billingCurrency, _ := impl["billingCurrency"].(string)
	billingCurrency = strings.TrimSpace(billingCurrency)
	if billingCurrency == "" {
		return ConsumptionBudgetPlan{}, fmt.Errorf(
			"azure consumption budget requires implementation.billingCurrency (the subscription's " +
				"billing currency) — the budget amount is denominated in it and Azure cannot set it; " +
				"it is verified, not mutated")
	}
	if !strings.EqualFold(billingCurrency, p.Currency) {
		return ConsumptionBudgetPlan{}, fmt.Errorf(
			"budget.limit currency %q does not match the subscription's billing currency %q — "+
				"refusing to silently spend in a different currency than the contract declares "+
				"(Azure denominates the budget in the billing currency; there is no conversion)",
			p.Currency, billingCurrency)
	}

	// scope: subscription by default; a resource group operand narrows it (D26).
	if rgRaw, ok := impl["resource_group"]; ok {
		rg, _ := rgRaw.(string)
		rg = strings.TrimSpace(rg)
		if rg != "" {
			if !rgOK.MatchString(rg) {
				return ConsumptionBudgetPlan{}, fmt.Errorf("implementation.resource_group %q is not a valid Azure resource group name", rg)
			}
			p.ResourceGroup = rg
		}
	}

	// notification sink (OPERAND, D26): contactEmails and/or action groups. Azure
	// requires a notification to carry at least one recipient — refuse a SILENT
	// alert that claims to notify (parity with AWS Budgets).
	emails, err := consBudgetStrList(impl["contactEmails"])
	if err != nil {
		return ConsumptionBudgetPlan{}, fmt.Errorf("implementation.contactEmails: %v", err)
	}
	groups, err := consBudgetStrList(impl["actionGroups"])
	if err != nil {
		return ConsumptionBudgetPlan{}, fmt.Errorf("implementation.actionGroups: %v", err)
	}
	for _, e := range emails {
		if strings.ContainsAny(e, " \t\n") || !strings.Contains(e, "@") {
			return ConsumptionBudgetPlan{}, fmt.Errorf("implementation.contactEmails entry %q is not an email address", e)
		}
	}
	for _, g := range groups {
		if strings.ContainsAny(g, " \t\n") || !strings.HasPrefix(g, "/subscriptions/") {
			return ConsumptionBudgetPlan{}, fmt.Errorf("implementation.actionGroups entry %q is not an action group resource id (/subscriptions/...)", g)
		}
	}
	if len(emails) == 0 && len(groups) == 0 {
		return ConsumptionBudgetPlan{}, fmt.Errorf(
			"azure consumption budget requires implementation.contactEmails and/or implementation.actionGroups " +
				"(the alert sink) — refusing to create a SILENT budget that claims to notify")
	}
	p.ContactEmails = emails
	p.ActionGroups = groups

	p.Name = ConsumptionBudgetName(environment, capability, generation)
	if !consBudgetNameOK.MatchString(p.Name) {
		return ConsumptionBudgetPlan{}, fmt.Errorf("derived budget name %q is invalid", p.Name)
	}
	return p, nil
}

// notificationBlock builds the single ACTUAL > threshold% notification. The key is
// a fixed, always-valid identifier (Azure notification keys are constrained).
func (p ConsumptionBudgetPlan) notificationBlock() map[string]any {
	n := map[string]any{
		"enabled":       true,
		"operator":      "GreaterThan",
		"threshold":     p.Threshold,
		"thresholdType": "Actual",
	}
	if len(p.ContactEmails) > 0 {
		n["contactEmails"] = toAnySlice(p.ContactEmails)
	}
	if len(p.ActionGroups) > 0 {
		n["contactGroups"] = toAnySlice(p.ActionGroups)
	}
	return map[string]any{"pv-actual-threshold": n}
}

// createBody is the PUT body. startDate (RFC3339) is a temporal fact the vocab
// does not carry — the create supplies the first of the current period from the
// coordination clock; the update preserves the existing one (a full PUT replace).
// contractBody is createBody WITHOUT the time window — the fields this contract
// describes and nothing else (D804). The ownership pre-read compares against this,
// because timePeriod.startDate is a provisioning fact of the run rather than a term of
// the contract: comparing it would make the driver refuse its OWN budget after every
// period boundary.
func (p ConsumptionBudgetPlan) contractBody() map[string]any {
	return map[string]any{
		"properties": map[string]any{
			"category":      "Cost",
			"amount":        p.Amount,
			"timeGrain":     p.TimeGrain,
			"notifications": p.notificationBlock(),
		},
	}
}

func (p ConsumptionBudgetPlan) createBody(startDate string) map[string]any {
	return map[string]any{
		"properties": map[string]any{
			"category":  "Cost",
			"amount":    p.Amount,
			"timeGrain": p.TimeGrain,
			"timePeriod": map[string]any{
				"startDate": startDate,
			},
			"notifications": p.notificationBlock(),
		},
	}
}

// classifyConsumptionBudgetChange answers, for one attribute, whether Azure can
// honor the transition IN PLACE (D46) — PURE provider knowledge, no network.
// Microsoft.Consumption/budgets is create-or-update via a full PUT to the same
// name, so the limit, the alert threshold AND the recurrence are all patchable in
// place without a new identity — every mutable path here is wired in
// updateConsumptionBudget (invariant: mutable-with-an-updater, never a false claim).
func classifyConsumptionBudgetChange(path string) (string, string) {
	switch path {
	case "budget.limit":
		return "mutable", "" // PUT with the new properties.amount
	case "alert.threshold":
		return "mutable", "" // PUT with the new notifications[].threshold
	case "budget.period":
		return "mutable", "" // PUT with the new properties.timeGrain (daily still refuses at build)
	case "service.managed":
		return "unsupported", "platform/projection property — nothing to patch"
	default:
		return "unsupported", "no Azure Consumption Budget in-place mapping for " + path
	}
}

// consBudgetStrList coerces an impl operand into a []string (accepts []string,
// []any of strings, or a single string). nil/absent -> empty, not an error.
func consBudgetStrList(raw any) ([]string, error) {
	switch v := raw.(type) {
	case nil:
		return nil, nil
	case string:
		if strings.TrimSpace(v) == "" {
			return nil, nil
		}
		return []string{v}, nil
	case []string:
		return v, nil
	case []any:
		out := make([]string, 0, len(v))
		for _, e := range v {
			s, ok := e.(string)
			if !ok {
				return nil, fmt.Errorf("entry %v is not a string", e)
			}
			out = append(out, s)
		}
		return out, nil
	default:
		return nil, fmt.Errorf("expected a list of strings, got %T", raw)
	}
}

func toAnySlice(ss []string) []any {
	out := make([]any, len(ss))
	for i, s := range ss {
		out[i] = s
	}
	return out
}
