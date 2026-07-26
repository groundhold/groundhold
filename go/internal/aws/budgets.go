// AWS Budgets request building (D151): the semantic core of the AWS
// capability.cost.budget driver — a cost guardrail as a governed capability
// (the SAME vocabulary GCP/Azure budget alerts fulfil, D76). AWS Budgets is a
// GLOBAL service (one endpoint budgets.amazonaws.com, SigV4 region us-east-1),
// account-scoped and STATELESS (a budget holds no durable data). What the
// contract governs: the spend LIMIT, the PERIOD, and the alert THRESHOLD; the
// notification sink is an operator OPERAND (impl.notificationTopicArn, an SNS
// topic — a separate messaging.topic capability, D26).
//
// Ownership honesty: a budget object carries NO tags the way S3/DynamoDB do
// (the Budgets API has no per-budget resource tagging in this path), so the
// deterministic budget NAME (account+environment+capability+generation) IS the
// ownership marker — a budget at our derived name is ours; a foreign name we
// never touch. This is a weaker marker than tags (a hand-created budget that
// collides with our derived name would be treated as ours), stated plainly
// rather than hidden.
package aws

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"groundhold/internal/scalars"
)

// budgetTarget is the X-Amz-Target service prefix (AWS JSON 1.1).
const budgetTarget = "AWSBudgetServiceGateway"

// budgetNameOK bounds a budget name before it is interpolated into a providerId
// or a request body (D73 boundary). The driver GENERATES a lowercase
// alnum+hyphen subset; the parser accepts the fuller safe set so a hand-adopted
// name is not rejected. AWS budget names go up to 100 chars.
var budgetNameOK = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,99}$`)

// budgetBad collapses everything outside the generated name charset.
var budgetBad = regexp.MustCompile(`[^a-z0-9-]+`)

// BudgetName is the deterministic budget name — BOTH the idempotency handle
// (CreateBudget dedupes on the name within an account) AND the ownership marker
// (there are no tags on the object). Budgets are account-scoped and the account
// rides in the providerId, so the name is NOT account-salted (the dynamodb
// pattern); environment+capability salt the hash so two installs in one account
// never collide, and g>=2 (D48 replacements) coexist via the -gN salt.
func BudgetName(environment, capability string, generation int) string {
	slug := capability
	if environment != "" {
		slug += "-" + environment
	}
	slug = strings.Trim(budgetBad.ReplaceAllString(strings.ToLower(slug), "-"), "-")
	tail := "-" + letterHash(environment+"|"+capability+genSuffix(generation), 8)
	const maxLen = 100
	if len("pv-")+len(slug)+len(tail) > maxLen {
		slug = slug[:maxLen-len("pv-")-len(tail)]
		slug = strings.TrimRight(slug, "-")
	}
	return "pv-" + slug + tail
}

// budgetTimeUnit maps the capability.cost.budget budget.period enum to the AWS
// Budgets TimeUnit. The vocab enum is the closed set (daily|monthly|quarterly|
// annually); an unknown value is a refusal, never a silent default.
func budgetTimeUnit(period string) (string, error) {
	switch period {
	case "daily":
		return "DAILY", nil
	case "monthly":
		return "MONTHLY", nil
	case "quarterly":
		return "QUARTERLY", nil
	case "annually":
		return "ANNUALLY", nil
	default:
		return "", fmt.Errorf("budget.period %q is not one of daily|monthly|quarterly|annually", period)
	}
}

// budgetPeriodFromTimeUnit is the reverse map (observe/discover).
func budgetPeriodFromTimeUnit(timeUnit string) string {
	switch timeUnit {
	case "DAILY":
		return "daily"
	case "MONTHLY":
		return "monthly"
	case "QUARTERLY":
		return "quarterly"
	case "ANNUALLY":
		return "annually"
	default:
		return ""
	}
}

// BudgetPlan is the attribute-derived shape a create assembles: the
// deterministic name, the limit (amount+currency unit), the AWS TimeUnit, the
// alert threshold (a percentage 0-100) and the SNS topic the notification
// targets (the operand).
type BudgetPlan struct {
	Name                 string
	LimitAmount          float64
	LimitUnit            string // ISO currency code (the money value's currency)
	TimeUnit             string // DAILY | MONTHLY | QUARTERLY | ANNUALLY
	Threshold            float64
	NotificationTopicArn string // impl operand — the SNS topic the alert publishes to
}

// BuildBudget maps capability.cost.budget attributes + the impl block to a
// create plan. Every error is a refusal apply surfaces in preflight, before any
// mutation — never a silently dropped attribute.
func BuildBudget(environment, capability string,
	attrs, impl map[string]any, generation int) (BudgetPlan, error) {
	if generation < 1 {
		generation = 1
	}
	p := BudgetPlan{}
	var haveLimit, havePeriod, haveThreshold bool

	for _, path := range sortedKeys(attrs) {
		raw := attrs[path]
		switch path {
		case "budget.limit":
			s, err := scalars.Parse(raw)
			if err != nil || s.Kind != scalars.Money {
				return BudgetPlan{}, fmt.Errorf("budget.limit is not a money value (e.g. \"700 EUR\"): %v", raw)
			}
			mv := s.Value.(scalars.MoneyValue)
			if mv.Amount <= 0 {
				return BudgetPlan{}, fmt.Errorf("budget.limit amount must be positive, got %v", mv.Amount)
			}
			p.LimitAmount = mv.Amount
			p.LimitUnit = mv.Currency
			haveLimit = true
		case "budget.period":
			period, _ := raw.(string)
			tu, err := budgetTimeUnit(period)
			if err != nil {
				return BudgetPlan{}, err
			}
			p.TimeUnit = tu
			havePeriod = true
		case "alert.threshold":
			s, err := scalars.Parse(raw)
			if err != nil || s.Kind != scalars.Number {
				return BudgetPlan{}, fmt.Errorf("alert.threshold is not a number (percent 0-100): %v", raw)
			}
			t := s.Value.(float64)
			if t < 0 || t > 100 {
				return BudgetPlan{}, fmt.Errorf("alert.threshold must be a percent in [0,100], got %v", t)
			}
			p.Threshold = t
			haveThreshold = true
		case "service.managed":
			if raw != true {
				return BudgetPlan{}, fmt.Errorf("service.managed=false cannot be honored by AWS Budgets")
			}
		default:
			return BudgetPlan{}, fmt.Errorf(
				"attribute %s has no AWS Budgets mapping — refusing rather than silently dropping it", path)
		}
	}

	if !haveLimit {
		return BudgetPlan{}, fmt.Errorf("aws budgets requires budget.limit (the spend ceiling)")
	}
	if !havePeriod {
		return BudgetPlan{}, fmt.Errorf("aws budgets requires budget.period (daily|monthly|quarterly|annually)")
	}
	if !haveThreshold {
		return BudgetPlan{}, fmt.Errorf("aws budgets requires alert.threshold (the percent at which the alert fires)")
	}

	// the notification sink is an operator OPERAND (D26): the SNS topic is a
	// separate messaging.topic capability, passed in the impl block. A budget
	// with no alert sink is not the guardrail the contract asked for — refuse.
	topic, _ := impl["notificationTopicArn"].(string)
	if strings.TrimSpace(topic) == "" {
		return BudgetPlan{}, fmt.Errorf(
			"aws budgets requires implementation.notificationTopicArn (the SNS topic the alert " +
				"publishes to) — it is a separate messaging.topic capability, passed in as an operand")
	}
	p.NotificationTopicArn = topic

	p.Name = BudgetName(environment, capability, generation)
	if !budgetNameOK.MatchString(p.Name) {
		return BudgetPlan{}, fmt.Errorf("derived budget name %q is invalid", p.Name)
	}
	return p, nil
}

// createBudgetBody is the CreateBudget request body. BudgetType COST is the
// spend budget (not usage/RI); the limit is a {Amount(string), Unit} pair.
func (p BudgetPlan) createBudgetBody(account string) map[string]any {
	return map[string]any{
		"AccountId": account,
		"Budget": map[string]any{
			"BudgetName": p.Name,
			"BudgetLimit": map[string]any{
				// the Budgets API takes Amount as a STRING; -1 precision gives the
				// minimal exact decimal (700, not 700.0000).
				"Amount": strconv.FormatFloat(p.LimitAmount, 'f', -1, 64),
				"Unit":   p.LimitUnit,
			},
			"TimeUnit":   p.TimeUnit,
			"BudgetType": "COST",
		},
	}
}

// createNotificationBody is the CreateNotificationWithSubscribers request body:
// an ACTUAL > threshold% notification with the SNS topic as the sole subscriber.
func (p BudgetPlan) createNotificationBody(account string) map[string]any {
	return map[string]any{
		"AccountId":  account,
		"BudgetName": p.Name,
		"Notification": map[string]any{
			"NotificationType":   "ACTUAL",
			"ComparisonOperator": "GREATER_THAN",
			"Threshold":          p.Threshold,
			"ThresholdType":      "PERCENTAGE",
		},
		"Subscribers": []any{
			map[string]any{
				"SubscriptionType": "SNS",
				"Address":          p.NotificationTopicArn,
			},
		},
	}
}

// classifyBudgetChange answers, for one attribute, whether AWS Budgets can honor
// the transition IN PLACE (D46) — PURE provider knowledge, no network. The spend
// limit is patchable (UpdateBudget); the alert threshold is patchable
// (UpdateNotification); the period is the budget's fundamental recurrence and is
// treated as immutable (a change is a replacement), never a silent claim of
// mutability.
func classifyBudgetChange(path string) (string, string) {
	switch path {
	case "budget.limit":
		return "mutable", "" // UpdateBudget with the new BudgetLimit
	case "alert.threshold":
		return "mutable", "" // UpdateNotification with the new Threshold
	case "budget.period":
		return "immutable", "the budget period (TimeUnit) is its fundamental recurrence — a change is a replacement"
	case "service.managed":
		return "unsupported", "platform/projection property — nothing to patch"
	default:
		return "unsupported", "no AWS Budgets in-place mapping for " + path
	}
}
