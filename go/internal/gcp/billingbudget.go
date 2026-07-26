// GCP Cloud Billing Budget request building (D76 parity): the semantic core of
// the GCP capability.cost.budget driver — the SAME vocabulary AWS Budgets fulfils
// (one TYPE, many services). A budget lives under a BILLING ACCOUNT
// (billingAccounts/{id}/budgets/{budgetId}, billingbudgets.googleapis.com/v1), NOT
// a project — the billing account is an operator OPERAND (impl.billingAccountId).
// STATELESS: a budget holds no durable data.
//
// What the contract governs: the spend LIMIT (amount.specifiedAmount), the PERIOD
// (budgetFilter.calendarPeriod) and the alert THRESHOLD (thresholdRules[].
// thresholdPercent). The notification sink (pubsubTopic /
// monitoringNotificationChannels) is an operator OPERAND (D26) — a separate
// messaging/monitoring capability. Unlike AWS Budgets the sink is OPTIONAL: a GCP
// budget with thresholdRules and no notificationsRule still emails the billing
// account's admins/users by default, so a budget with no explicit sink is still a
// working guardrail (this divergence is stated, not hidden).
//
// Two honest gaps this builder enforces:
//   - budget.period=daily is REFUSED — GCP budgetFilter.calendarPeriod offers only
//     MONTH/QUARTER/YEAR; the only daily shape is a customPeriod with explicit
//     start/end dates, which is a one-off window, not a recurring daily budget.
//     Refusing is honest; silently mapping daily onto a month would lie.
//   - the alert threshold is a PERCENTAGE (0-100) in the vocab but a FRACTION
//     (0.0-1.0) in the API — mapped, never passed through raw.
//
// Ownership: a GCP budget carries NO labels and its id is a SERVER-ASSIGNED uuid,
// so the deterministic DISPLAY NAME is the ownership marker (the AWS Budgets
// doctrine). The marker token is generation-INDEPENDENT so delete/update recompute
// it from (environment, capability) alone — the providerId carries only the opaque
// server id. This is a weaker marker than labels (a hand-created budget whose
// display name collided would be treated as ours), stated plainly rather than hidden.
package gcp

import (
	"fmt"
	"math"
	"regexp"
	"strconv"
	"strings"

	"groundhold/internal/scalars"
)

// billingAccountOK bounds a billing account id before it is interpolated into a
// REST path or a providerId (D73 boundary). Canonical form is three 6-char
// hex-ish groups, e.g. 012345-6789AB-CDEF01.
var billingAccountOK = regexp.MustCompile(`^[0-9A-Fa-f]{6}-[0-9A-Fa-f]{6}-[0-9A-Fa-f]{6}$`)

// billingBudgetIDOK bounds a server-assigned budget id (a uuid) — the safe subset
// that can never rewrite the REST path ('/', '.', ':', '%' excluded).
var billingBudgetIDOK = regexp.MustCompile(`^[0-9A-Za-z_-]{1,60}$`)

// BillingBudgetPlan is the attribute-derived shape a create/update assembles.
type BillingBudgetPlan struct {
	BillingAccountID string
	DisplayName      string
	CalendarPeriod   string  // MONTH | QUARTER | YEAR
	Currency         string  // ISO currency code
	Units            int64   // integer part of the limit
	Nanos            int32   // fractional part, billionths
	ThresholdPercent float64 // FRACTION 0.0-1.0 (vocab percent/100)
	// notification sink (OPERAND, optional): a Pub/Sub topic and/or a set of
	// Cloud Monitoring notification channels the alert publishes to.
	PubSubTopic          string
	NotificationChannels []string
}

// budgetCalendarPeriod maps the capability.cost.budget budget.period enum to the
// GCP budgetFilter.calendarPeriod. The vocab enum is the closed set (daily|monthly|
// quarterly|annually); daily has no GCP recurring equivalent (honest refusal) and
// an unknown value is a refusal, never a silent default.
func budgetCalendarPeriod(period string) (string, error) {
	switch period {
	case "monthly":
		return "MONTH", nil
	case "quarterly":
		return "QUARTER", nil
	case "annually":
		return "YEAR", nil
	case "daily":
		return "", fmt.Errorf(
			"budget.period=daily cannot be honored on GCP — a Cloud Billing budget's " +
				"budgetFilter.calendarPeriod offers only MONTH/QUARTER/YEAR; the only daily " +
				"shape is a one-off customPeriod with explicit start/end dates, not a " +
				"recurring daily budget (refusing rather than silently widening to a month)")
	default:
		return "", fmt.Errorf("budget.period %q is not one of daily|monthly|quarterly|annually", period)
	}
}

// budgetPeriodFromCalendar is the reverse map (observe/discover).
func budgetPeriodFromCalendar(cal string) string {
	switch cal {
	case "MONTH":
		return "monthly"
	case "QUARTER":
		return "quarterly"
	case "YEAR":
		return "annually"
	default:
		return ""
	}
}

// billingBudgetOwnerToken is the generation-INDEPENDENT ownership marker embedded
// (as a suffix) in the display name. delete/update recompute it from (env, cap)
// alone because the providerId carries only the server-assigned budget id.
func billingBudgetOwnerToken(environment, capability string) string {
	return letterHash(environment+"|"+capability, 8)
}

// BillingBudgetDisplayName is the deterministic display name — the ownership marker
// (there are no labels on the object) and the create idempotency handle (create
// lists the billing account's budgets and matches this name; GCP does NOT dedupe on
// displayName, so a blind retry would otherwise create a DUPLICATE). GCP caps a
// display name at 60 chars; the slug truncates, never the owner token.
func BillingBudgetDisplayName(environment, capability string, generation int) string {
	slug := capability
	if environment != "" {
		slug += "-" + environment
	}
	slug = strings.Trim(nameOK.ReplaceAllString(strings.ToLower(slug), "-"), "-")
	suffix := ""
	if generation >= 2 {
		suffix = fmt.Sprintf("-g%d", generation)
	}
	owner := billingBudgetOwnerToken(environment, capability)
	const maxLen = 60
	fixed := len("groundhold-") + len(suffix) + len("-") + len(owner)
	if fixed+len(slug) > maxLen {
		keep := maxLen - fixed
		if keep < 0 {
			keep = 0
		}
		if keep < len(slug) {
			slug = strings.TrimRight(slug[:keep], "-")
		}
	}
	return "groundhold-" + slug + suffix + "-" + owner
}

// billingBudgetOurs is the ownership predicate: the display name is a groundhold
// marker AND carries the (env, cap) owner token. Generation-independent by design.
func billingBudgetOurs(displayName, environment, capability string) bool {
	return strings.HasPrefix(displayName, "groundhold-") &&
		strings.HasSuffix(displayName, "-"+billingBudgetOwnerToken(environment, capability))
}

// moneyToUnitsNanos splits a money amount into the GCP {units(string), nanos(int32)}
// pair. units is the integer part; nanos is the fractional part in billionths.
func moneyToUnitsNanos(amount float64) (int64, int32) {
	units := int64(math.Floor(amount))
	nanos := int32(math.Round((amount - float64(units)) * 1e9))
	// rounding can carry into the next unit (e.g. 0.9999999996 -> 1e9 nanos)
	if nanos >= 1e9 {
		units++
		nanos -= 1e9
	}
	return units, nanos
}

// BuildBillingBudget maps capability.cost.budget attributes + the impl block to a
// plan. Every error is a preflight refusal apply surfaces before any mutation —
// never a silently dropped attribute.
func BuildBillingBudget(project, environment, capability string,
	attrs, impl map[string]any, generation int) (BillingBudgetPlan, error) {
	if generation < 1 {
		generation = 1
	}
	p := BillingBudgetPlan{}
	var haveLimit, havePeriod, haveThreshold bool

	for _, path := range sortedKeysG(attrs) {
		raw := attrs[path]
		switch path {
		case "budget.limit":
			s, err := scalars.Parse(raw)
			if err != nil || s.Kind != scalars.Money {
				return BillingBudgetPlan{}, fmt.Errorf("budget.limit is not a money value (e.g. \"700 EUR\"): %v", raw)
			}
			mv := s.Value.(scalars.MoneyValue)
			if mv.Amount <= 0 {
				return BillingBudgetPlan{}, fmt.Errorf("budget.limit amount must be positive, got %v", mv.Amount)
			}
			p.Units, p.Nanos = moneyToUnitsNanos(mv.Amount)
			p.Currency = mv.Currency
			haveLimit = true
		case "budget.period":
			period, _ := raw.(string)
			cal, err := budgetCalendarPeriod(period)
			if err != nil {
				return BillingBudgetPlan{}, err
			}
			p.CalendarPeriod = cal
			havePeriod = true
		case "alert.threshold":
			s, err := scalars.Parse(raw)
			if err != nil || s.Kind != scalars.Number {
				return BillingBudgetPlan{}, fmt.Errorf("alert.threshold is not a number (percent 0-100): %v", raw)
			}
			t := s.Value.(float64)
			if t < 0 || t > 100 {
				return BillingBudgetPlan{}, fmt.Errorf("alert.threshold must be a percent in [0,100], got %v", t)
			}
			// vocab is a PERCENTAGE; the API wants a FRACTION.
			p.ThresholdPercent = t / 100
			haveThreshold = true
		case "service.managed":
			if raw != true {
				return BillingBudgetPlan{}, fmt.Errorf("service.managed=false cannot be honored by Cloud Billing Budgets")
			}
		default:
			return BillingBudgetPlan{}, fmt.Errorf(
				"attribute %s has no Cloud Billing Budget mapping — refusing rather than silently dropping it", path)
		}
	}

	if !haveLimit {
		return BillingBudgetPlan{}, fmt.Errorf("cloud billing budget requires budget.limit (the spend ceiling)")
	}
	if !havePeriod {
		return BillingBudgetPlan{}, fmt.Errorf("cloud billing budget requires budget.period (monthly|quarterly|annually; daily is unsupported on GCP)")
	}
	if !haveThreshold {
		return BillingBudgetPlan{}, fmt.Errorf("cloud billing budget requires alert.threshold (the percent at which the alert fires)")
	}

	// the billing account owns the budget (D26 operand): a budget is NOT a
	// project resource. Required, and bounded before it enters a REST path.
	acct, _ := impl["billingAccountId"].(string)
	acct = strings.TrimSpace(strings.TrimPrefix(acct, "billingAccounts/"))
	if acct == "" {
		return BillingBudgetPlan{}, fmt.Errorf(
			"cloud billing budget requires implementation.billingAccountId (a budget lives under a " +
				"BILLING ACCOUNT, not a project — it is an operator operand)")
	}
	if !billingAccountOK.MatchString(acct) {
		return BillingBudgetPlan{}, fmt.Errorf(
			"implementation.billingAccountId %q is not a valid billing account id "+
				"(expected NNNNNN-NNNNNN-NNNNNN)", acct)
	}
	p.BillingAccountID = acct

	// notification sink (OPERAND, OPTIONAL): a GCP budget without a
	// notificationsRule still emails the billing account admins/users by
	// default, so — unlike AWS Budgets — the sink is not required.
	if topic, ok := impl["pubsubTopic"].(string); ok {
		topic = strings.TrimSpace(topic)
		if topic != "" {
			if !strings.HasPrefix(topic, "projects/") || strings.ContainsAny(topic, " \t\n") {
				return BillingBudgetPlan{}, fmt.Errorf(
					"implementation.pubsubTopic %q is not a projects/<p>/topics/<t> resource name", topic)
			}
			p.PubSubTopic = topic
		}
	}
	if chans := impl["monitoringNotificationChannels"]; chans != nil {
		list, err := toStringList(chans)
		if err != nil {
			return BillingBudgetPlan{}, fmt.Errorf("implementation.monitoringNotificationChannels: %v", err)
		}
		for _, c := range list {
			if strings.ContainsAny(c, " \t\n") || c == "" {
				return BillingBudgetPlan{}, fmt.Errorf("implementation.monitoringNotificationChannels entry %q is invalid", c)
			}
		}
		p.NotificationChannels = list
	}

	p.DisplayName = BillingBudgetDisplayName(environment, capability, generation)
	return p, nil
}

// specifiedAmount is the shared {currencyCode, units, nanos} body fragment. units
// is a STRING (int64) per the API; nanos is an int.
func (p BillingBudgetPlan) specifiedAmount() map[string]any {
	amt := map[string]any{
		"currencyCode": p.Currency,
		"units":        strconv.FormatInt(p.Units, 10),
	}
	if p.Nanos != 0 {
		amt["nanos"] = p.Nanos
	}
	return amt
}

// thresholdRule is the single ACTUAL-spend threshold rule.
func (p BillingBudgetPlan) thresholdRule() map[string]any {
	return map[string]any{
		"thresholdPercent": p.ThresholdPercent,
		"spendBasis":       "CURRENT_SPEND",
	}
}

// notificationsRule builds the optional sink block; nil when no sink was supplied
// (the budget then alerts the billing account's default recipients).
func (p BillingBudgetPlan) notificationsRule() map[string]any {
	if p.PubSubTopic == "" && len(p.NotificationChannels) == 0 {
		return nil
	}
	rule := map[string]any{"schemaVersion": "1.0"}
	if p.PubSubTopic != "" {
		rule["pubsubTopic"] = p.PubSubTopic
	}
	if len(p.NotificationChannels) > 0 {
		chans := make([]any, len(p.NotificationChannels))
		for i, c := range p.NotificationChannels {
			chans[i] = c
		}
		rule["monitoringNotificationChannels"] = chans
	}
	return rule
}

// createBody is the POST body — a Budget resource sent directly (not wrapped).
func (p BillingBudgetPlan) createBody() map[string]any {
	body := map[string]any{
		"displayName": p.DisplayName,
		"budgetFilter": map[string]any{
			"calendarPeriod": p.CalendarPeriod,
		},
		"amount": map[string]any{
			"specifiedAmount": p.specifiedAmount(),
		},
		"thresholdRules": []any{p.thresholdRule()},
	}
	if rule := p.notificationsRule(); rule != nil {
		body["notificationsRule"] = rule
	}
	return body
}

// classifyBillingBudgetChange answers, for one attribute, whether Cloud Billing
// Budgets can honor the transition IN PLACE (D46) — PURE provider knowledge, no
// network. Every mutable path here is wired in updateBillingBudget (invariant:
// mutable-with-an-updater, never a false claim). The spend limit, the alert
// threshold AND the recurrence are all patchable via budgets.patch with an
// updateMask — GCP honestly supports patching the calendarPeriod in place
// (per-provider truth: AWS treats the period as a replacement, GCP does not).
func classifyBillingBudgetChange(path string) (string, string) {
	switch path {
	case "budget.limit":
		return "mutable", "" // patch amount.specifiedAmount
	case "alert.threshold":
		return "mutable", "" // patch thresholdRules
	case "budget.period":
		return "mutable", "" // patch budgetFilter.calendarPeriod (daily still refuses at build)
	case "service.managed":
		return "unsupported", "platform/projection property — nothing to patch"
	default:
		return "unsupported", "no Cloud Billing Budget in-place mapping for " + path
	}
}
