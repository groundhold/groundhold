// EventBridge change-feed request building (D143): the semantic core of the AWS
// capability.observability.changefeed driver. A change feed is an EventBridge rule on
// the DEFAULT event bus that matches AWS control-plane MUTATIONS (delivered through
// CloudTrail) and forwards them to a target a consumer drains — the operator-provided
// feed.target (an existing SQS queue ARN). It is the opt-in path from the polling crawl
// (D141) to real-time posture (D142): declare the capability, groundhold stands up the
// rule + target, and `groundhold react` drains the queue.
//
// The capability is deliberately thin (invariant #4): feed.target (WHERE changes go) is
// the verifiable semantic; the event-pattern grammar and delivery internals are noise.
// v0.1 captures BROADLY (all CloudTrail management events) and leaves filtering to
// `react` — coverage semantics are absent until a real contract governs them.
//
// The rule's region is NOT a vocab attribute — it rides in the feed.target ARN (an
// EventBridge rule delivers to a same-region SQS target), so the driver DERIVES it
// from the target rather than demanding a location.region the capability does not carry
// (symmetric with cloudwatch, whose region is an implementation detail). Ownership is
// the DESCRIPTION marker (symmetric with the EventBridge Scheduler driver): a rule's
// Description is set at birth and read back on the ownership pre-check, avoiding a
// tag-API dance.
package aws

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"
)

// cfRuleNameOK bounds an EventBridge rule name (1-64: [.\-_A-Za-z0-9] per the API).
var cfRuleNameOK = regexp.MustCompile(`^[0-9a-zA-Z_.-]{1,64}$`)
var cfBad = regexp.MustCompile(`[^a-z0-9-]+`)

// defaultChangeFeedPattern captures AWS control-plane activity BROADLY: every API call
// recorded through CloudTrail. Combined with the ENABLED_WITH_ALL_CLOUDTRAIL_MANAGEMENT_EVENTS
// rule state (see putRuleBody), this is the widest infra-mutation net the default event
// bus can cast. v0.1 filters nothing here (the cloud grammars differ sharply — filter in
// `react`); coverage semantics enter the vocab only when an org governs them.
const defaultChangeFeedPattern = `{"detail-type":["AWS API Call via CloudTrail"]}`

// CFRuleName is the deterministic rule name (the idempotency/recovery handle): the pid
// is knowable BEFORE the response (D29). A replacement (generation >= 2) coexists with
// its predecessor via the hash tail.
func CFRuleName(environment, capability string, generation int) string {
	slug := capability
	if environment != "" {
		slug += "-" + environment
	}
	slug = strings.Trim(cfBad.ReplaceAllString(strings.ToLower(slug), "-"), "-")
	hashInput := environment + "|" + capability
	if generation >= 2 {
		hashInput += fmt.Sprintf("|g%d", generation)
	}
	sum := sha256.Sum256([]byte(hashInput))
	tail := "-" + hex.EncodeToString(sum[:])[:8]
	const maxLen = 64
	if len(slug)+len(tail) > maxLen {
		slug = strings.TrimRight(slug[:maxLen-len(tail)], "-")
	}
	name := slug + tail
	if name == "" || !((name[0] >= 'a' && name[0] <= 'z') || (name[0] >= 'A' && name[0] <= 'Z')) {
		name = "r" + strings.TrimLeft(name, "-")
	}
	return name
}

// ChangeFeedPlan is the attribute-derived shape a create assembles.
type ChangeFeedPlan struct {
	RuleName string
	Region   string // DERIVED from the feed.target ARN, not the vocab
	Target   string // feed.target — the existing SQS queue ARN events land in
	TargetID string // deterministic target Id within the rule
	Pattern  string // event pattern (opaque impl, driver-defaulted)
}

// arnField returns the 0-based colon-delimited component of an ARN, or "".
// arn:aws:sqs:<region>:<account>:<name> -> [2]=sqs [3]=region [4]=account [5]=name.
func arnField(arn string, i int) string {
	parts := strings.SplitN(arn, ":", 6)
	if i < 0 || i >= len(parts) {
		return ""
	}
	return parts[i]
}

// BuildChangeFeed maps capability.observability.changefeed attributes + impl to a plan.
// Every error is a preflight refusal, never a silent drop (invariant: no coercion, no
// dropping a semantic attribute the driver cannot honor).
func BuildChangeFeed(environment, capability string,
	attrs, impl map[string]any, generation int) (ChangeFeedPlan, error) {
	if generation < 1 {
		generation = 1
	}
	p := ChangeFeedPlan{RuleName: CFRuleName(environment, capability, generation)}
	for _, path := range sortedKeys(attrs) {
		raw := attrs[path]
		switch path {
		case "feed.target":
			s, ok := raw.(string)
			if !ok {
				return ChangeFeedPlan{}, fmt.Errorf("feed.target must be a string (the delivery destination ARN)")
			}
			p.Target = s
		case "service.managed":
			if raw != true {
				return ChangeFeedPlan{}, fmt.Errorf("service.managed=false cannot be honored by an EventBridge change feed (a rule IS a managed feed)")
			}
		default:
			return ChangeFeedPlan{}, fmt.Errorf(
				"attribute %s has no EventBridge change-feed mapping — refusing rather than silently "+
					"dropping it (event-pattern coverage and delivery internals are opaque impl in v0.1)", path)
		}
	}
	if p.Target == "" {
		return ChangeFeedPlan{}, fmt.Errorf(
			"capability.observability.changefeed requires feed.target (the destination changes land in) — " +
				"a feed with no reachable target captures nothing anyone can use")
	}
	// The AWS change feed delivers to an SQS queue in the SAME region as the rule, so
	// the target ARN both NAMES the destination and PINS the region — refuse a target
	// that is not a region-bearing SQS ARN rather than guessing a region.
	if arnField(p.Target, 0) != "arn" || arnField(p.Target, 2) != "sqs" {
		return ChangeFeedPlan{}, fmt.Errorf(
			"feed.target %q is not an SQS queue ARN (arn:aws:sqs:<region>:<account>:<name>) — the v0.1 AWS "+
				"change feed delivers to SQS; the target's OWN provisioning is a separate capability", p.Target)
	}
	p.Region = arnField(p.Target, 3)
	if !regionOK.MatchString(p.Region) {
		return ChangeFeedPlan{}, fmt.Errorf("feed.target ARN carries no valid region: %q", p.Target)
	}
	if acct := arnField(p.Target, 4); !account12.MatchString(acct) {
		return ChangeFeedPlan{}, fmt.Errorf("feed.target ARN carries no valid account: %q", p.Target)
	}
	// event_pattern is an opaque impl override (the coverage grammar is noise, D4);
	// default to the broad CloudTrail net when the operator does not pin one.
	if ep, ok := impl["event_pattern"].(string); ok && strings.TrimSpace(ep) != "" {
		p.Pattern = ep
	} else {
		p.Pattern = defaultChangeFeedPattern
	}
	// the target Id is deterministic and stable within the rule (a single feed target).
	p.TargetID = p.RuleName
	if !cfRuleNameOK.MatchString(p.RuleName) {
		return ChangeFeedPlan{}, fmt.Errorf("derived rule name %q is invalid", p.RuleName)
	}
	return p, nil
}

// putRuleBody is the PutRule request body. The Description carries the ownership marker;
// State ENABLED_WITH_ALL_CLOUDTRAIL_MANAGEMENT_EVENTS is what makes CloudTrail management
// events (control-plane infra mutations) actually match — a plain ENABLED rule excludes
// them (per the PutRule contract), which would silently capture nothing.
func (p ChangeFeedPlan) putRuleBody(capability, environment string) map[string]any {
	return map[string]any{
		"Name":         p.RuleName,
		"EventPattern": p.Pattern,
		"State":        "ENABLED_WITH_ALL_CLOUDTRAIL_MANAGEMENT_EVENTS",
		"Description":  awsOwnerMarker(capability, environment),
	}
}

// putTargetsBody attaches the feed.target queue as the rule's single target. No Input is
// ever set (a payload may be a secret — D53); EventBridge -> SQS needs no RoleArn (the
// queue's resource policy authorizes events.amazonaws.com, and that policy is the
// TARGET's concern — out of this capability's scope).
func (p ChangeFeedPlan) putTargetsBody() map[string]any {
	return map[string]any{
		"Rule": p.RuleName,
		"Targets": []map[string]any{
			{"Id": p.TargetID, "Arn": p.Target},
		},
	}
}
