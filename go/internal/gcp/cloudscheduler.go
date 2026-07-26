// Cloud Scheduler request building (D123): the semantic core of the GCP
// capability.scheduler.cron driver. A Cloud Scheduler JOB has NO labels field, so
// ownership rides in the DESCRIPTION marker (reusing the D82 VPC marker helpers). The
// capability is deliberately thin — residency + whether the trigger is armed — so the
// cron expression, timezone and target are OPAQUE impl (invariant #4). The target is
// required to create a working job; exactly one of implementation.pubsub_topic (a
// topic resource name) or implementation.http_uri is accepted. No payload/header/auth
// is ever set (those are secrets — D53). schedule.enabled=false is applied by a
// jobs.pause AFTER create (a fresh job is ENABLED).
package gcp

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"
)

// shortHash is an 8-hex-char digest (the deterministic name suffix).
func shortHash(input string) string {
	sum := sha256.Sum256([]byte(input))
	return hex.EncodeToString(sum[:])[:8]
}

// genTag salts a generation >= 2 (a D48 replacement) into the hash input.
func genTag(generation int) string {
	if generation >= 2 {
		return fmt.Sprintf("|g%d", generation)
	}
	return ""
}

// schedJobIDOK bounds a Cloud Scheduler job id: starts with a letter, then letters/
// digits/underscores/hyphens (a conservative subset of the 500-char limit).
var schedJobIDOK = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9_-]{1,80}$`)
var schedBad = regexp.MustCompile(`[^a-z0-9-]+`)

// SchedulerJobID is the deterministic job id (the idempotency/recovery handle).
func SchedulerJobID(environment, capability string, generation int) string {
	slug := capability
	if environment != "" {
		slug += "-" + environment
	}
	slug = strings.Trim(schedBad.ReplaceAllString(strings.ToLower(slug), "-"), "-")
	h := shortHash(environment + "|" + capability + genTag(generation))
	name := "pv-" + slug + "-" + h
	if len(name) > 80 {
		name = name[:80]
	}
	return name
}

// SchedulerPlan is the attribute-derived shape a create assembles.
type SchedulerPlan struct {
	JobID       string
	Location    string
	Description string // ownership marker
	Enabled     bool
	Schedule    string // cron (opaque impl)
	TimeZone    string
	PubsubTopic string // one target...
	HTTPURI     string // ...or the other
}

// BuildCloudSchedulerJob maps capability.scheduler.cron attributes + impl to a plan.
// Every error is a preflight refusal, never a silent drop.
func BuildCloudSchedulerJob(project, environment, capability string,
	attrs, impl map[string]any, generation int) (SchedulerPlan, error) {
	if generation < 1 {
		generation = 1
	}
	p := SchedulerPlan{
		JobID:       SchedulerJobID(environment, capability, generation),
		Description: vpcOwnerMarker(capability, environment),
		Enabled:     true,
	}
	for _, path := range sortedKeysG(attrs) {
		raw := attrs[path]
		switch path {
		case "location.region":
			p.Location, _ = raw.(string)
		case "schedule.enabled":
			b, ok := raw.(bool)
			if !ok {
				return SchedulerPlan{}, fmt.Errorf("schedule.enabled must be a bool")
			}
			p.Enabled = b
		case "service.managed":
			if raw != true {
				return SchedulerPlan{}, fmt.Errorf("service.managed=false cannot be honored by Cloud Scheduler")
			}
		default:
			return SchedulerPlan{}, fmt.Errorf(
				"attribute %s has no Cloud Scheduler mapping — refusing rather than silently "+
					"dropping it (cron, target, payload are opaque impl)", path)
		}
	}
	if p.Location == "" {
		return SchedulerPlan{}, fmt.Errorf("capability.scheduler.cron requires location.region (the job location)")
	}
	p.Schedule, _ = impl["schedule"].(string)
	if p.Schedule == "" {
		return SchedulerPlan{}, fmt.Errorf(
			"Cloud Scheduler requires implementation.schedule (the cron expression is opaque impl)")
	}
	p.TimeZone, _ = impl["timezone"].(string)
	if p.TimeZone == "" {
		p.TimeZone = "Etc/UTC"
	}
	p.PubsubTopic, _ = impl["pubsub_topic"].(string)
	p.HTTPURI, _ = impl["http_uri"].(string)
	switch {
	case p.PubsubTopic != "" && p.HTTPURI != "":
		return SchedulerPlan{}, fmt.Errorf(
			"implementation must set exactly one target — pubsub_topic OR http_uri, not both")
	case p.PubsubTopic == "" && p.HTTPURI == "":
		return SchedulerPlan{}, fmt.Errorf(
			"Cloud Scheduler requires a target — implementation.pubsub_topic or implementation.http_uri " +
				"(the target is opaque impl; a payload/auth header is a secret, never set — D53)")
	}
	if !schedJobIDOK.MatchString(p.JobID) {
		return SchedulerPlan{}, fmt.Errorf("derived job id %q is invalid", p.JobID)
	}
	return p, nil
}

// createBody is the jobs.create request body. state is not set here — a fresh job is
// ENABLED; a paused job is a post-create jobs.pause.
func (p SchedulerPlan) createBody(project string) map[string]any {
	body := map[string]any{
		"name":        fmt.Sprintf("projects/%s/locations/%s/jobs/%s", project, p.Location, p.JobID),
		"description": p.Description,
		"schedule":    p.Schedule,
		"timeZone":    p.TimeZone,
	}
	if p.PubsubTopic != "" {
		body["pubsubTarget"] = map[string]any{
			"topicName": p.PubsubTopic,
			"data":      base64.StdEncoding.EncodeToString([]byte("{}")),
		}
	} else {
		body["httpTarget"] = map[string]any{"uri": p.HTTPURI, "httpMethod": "POST"}
	}
	return body
}
