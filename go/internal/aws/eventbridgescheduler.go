// EventBridge Scheduler request building (D123): the semantic core of the AWS
// capability.scheduler.cron driver. EventBridge Scheduler is a REST-JSON API
// (scheduler.<region>.amazonaws.com): CreateSchedule is POST /schedules/{Name}. The
// capability is deliberately thin — residency + whether the trigger is armed — so the
// ScheduleExpression (cron), timezone, target and payload are OPAQUE impl (invariant
// #4). The target (Arn + invoker RoleArn) is required to create a working schedule and
// rides in the impl block; no payload/input is ever set (it may be a secret — D53).
// schedule.enabled maps DIRECTLY to the create-time State (ENABLED|DISABLED), unlike
// GCP's post-create pause. Ownership is the DESCRIPTION marker (symmetric with the GCP
// Cloud Scheduler driver) — a schedule's Description is set at birth and read back on
// the ownership pre-check, avoiding the ARN-in-path tag-API dance.
package aws

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"
)

// ebsNameOK bounds a schedule name (1-64: letters, digits, and -_. per the API).
var ebsNameOK = regexp.MustCompile(`^[0-9a-zA-Z_.-]{1,64}$`)
var ebsBad = regexp.MustCompile(`[^a-z0-9-]+`)

// EBSName is the deterministic schedule name (the idempotency/recovery handle).
func EBSName(environment, capability string, generation int) string {
	slug := capability
	if environment != "" {
		slug += "-" + environment
	}
	slug = strings.Trim(ebsBad.ReplaceAllString(strings.ToLower(slug), "-"), "-")
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
		name = "s" + strings.TrimLeft(name, "-")
	}
	return name
}

// EBSPlan is the attribute-derived shape a create assembles.
type EBSPlan struct {
	Name      string
	Region    string
	Enabled   bool
	Schedule  string // cron/rate expression (opaque impl)
	TimeZone  string
	TargetArn string
	RoleArn   string
}

// BuildEventBridgeScheduler maps capability.scheduler.cron attributes + impl to a
// plan. Every error is a preflight refusal, never a silent drop.
func BuildEventBridgeScheduler(environment, capability string,
	attrs, impl map[string]any, generation int) (EBSPlan, error) {
	if generation < 1 {
		generation = 1
	}
	p := EBSPlan{Name: EBSName(environment, capability, generation), Enabled: true}
	for _, path := range sortedKeys(attrs) {
		raw := attrs[path]
		switch path {
		case "location.region":
			p.Region, _ = raw.(string)
		case "schedule.enabled":
			b, ok := raw.(bool)
			if !ok {
				return EBSPlan{}, fmt.Errorf("schedule.enabled must be a bool")
			}
			p.Enabled = b
		case "service.managed":
			if raw != true {
				return EBSPlan{}, fmt.Errorf("service.managed=false cannot be honored by EventBridge Scheduler")
			}
		default:
			return EBSPlan{}, fmt.Errorf(
				"attribute %s has no EventBridge Scheduler mapping — refusing rather than silently "+
					"dropping it (cron, target, payload are opaque impl)", path)
		}
	}
	if !regionOK.MatchString(p.Region) {
		return EBSPlan{}, fmt.Errorf("capability.scheduler.cron requires a valid location.region")
	}
	p.Schedule, _ = impl["schedule"].(string)
	if p.Schedule == "" {
		return EBSPlan{}, fmt.Errorf(
			"EventBridge Scheduler requires implementation.schedule (the cron/rate expression is opaque impl)")
	}
	p.TimeZone, _ = impl["timezone"].(string)
	p.TargetArn, _ = impl["target_arn"].(string)
	p.RoleArn, _ = impl["role_arn"].(string)
	if p.TargetArn == "" || p.RoleArn == "" {
		return EBSPlan{}, fmt.Errorf(
			"EventBridge Scheduler requires implementation.target_arn and implementation.role_arn " +
				"(the target and its invoker role are opaque impl; a payload/input is a secret, never set — D53)")
	}
	if !ebsNameOK.MatchString(p.Name) {
		return EBSPlan{}, fmt.Errorf("derived schedule name %q is invalid", p.Name)
	}
	return p, nil
}

// ebsClientToken is a DETERMINISTIC idempotency token for CreateSchedule, derived
// from the deterministic schedule name (which already folds environment+capability+
// generation). CreateSchedule REQUIRES a non-empty ClientToken in the raw REST-JSON
// path — the SDK auto-fills one, but the raw API rejects an empty one with HTTP 400
// "ClientToken cannot be empty" (live Acme finding, same class as F27). A retry after
// a lost response reuses this token, so AWS collapses the duplicate rather than
// double-creating. UUID-format keeps it inside the token's charset/length budget.
func ebsClientToken(name string) string {
	h := sha256hex([]byte("groundhold-ebsched|" + name))
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:32]
}

// createBody is the CreateSchedule request body. The Description carries the
// ownership marker.
func (p EBSPlan) createBody(capability, environment string) map[string]any {
	state := "ENABLED"
	if !p.Enabled {
		state = "DISABLED"
	}
	body := map[string]any{
		"ClientToken":        ebsClientToken(p.Name),
		"ScheduleExpression": p.Schedule,
		"State":              state,
		"Description":        awsOwnerMarker(capability, environment),
		"FlexibleTimeWindow": map[string]any{"Mode": "OFF"},
		"Target":             map[string]any{"Arn": p.TargetArn, "RoleArn": p.RoleArn},
	}
	if p.TimeZone != "" {
		body["ScheduleExpressionTimezone"] = p.TimeZone
	}
	return body
}

// awsOwnerMarker / awsMarkerOurs are the AWS-side description-marker ownership helpers
// (mirroring the GCP marker for resources tagged via a free-text Description rather
// than a tag set). Parsed, not whole-string equality, so a future marker extension
// cannot lock the driver out of its own resources.
func awsOwnerMarker(capability, environment string) string {
	return "groundhold:capability=" + sanitizeTag(capability) + ";environment=" + sanitizeTag(environment)
}

func awsMarkerOurs(desc, capability, environment string) bool {
	const pfx = "groundhold:"
	i := strings.Index(desc, pfx)
	if i < 0 {
		return false
	}
	var cap, env string
	for _, kv := range strings.Split(desc[i+len(pfx):], ";") {
		k, v, found := strings.Cut(kv, "=")
		if !found {
			continue
		}
		switch k {
		case "capability":
			cap = v
		case "environment":
			env = v
		}
	}
	return cap == sanitizeTag(capability) && env == sanitizeTag(environment)
}
