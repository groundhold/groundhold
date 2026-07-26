// GCP Cloud Run Jobs request building (D120): the semantic core of the GCP
// capability.container.job driver — the SAME vocabulary Azure Container Apps Jobs
// fulfils (AWS has no standalone managed-job resource, so the domain is honestly
// two-cloud). A Cloud Run Job is a run-to-completion container (v2 API, the same
// endpoint as the Cloud Run service). Cloud Run Jobs are MANUAL-run; trigger.type=
// schedule is an honest refusal here (scheduling needs a separate Cloud Scheduler
// resource). Env vars, args, resource limits and retry count are opaque impl config.
package gcp

import (
	"fmt"
	"strings"

	"groundhold/internal/scalars"
)

// CloudRunJobPlan is the attribute-derived shape a create assembles.
type CloudRunJobPlan struct {
	Name       string
	Region     string
	Image      string
	TimeoutSec int
}

// jobTimeoutSeconds converts a duration scalar to whole seconds (Cloud Run Jobs use
// a "<n>s" timeout). Below one second is refused.
func jobTimeoutSeconds(raw any) (int, error) {
	sc, err := scalars.Parse(raw)
	if err != nil || sc.Kind != scalars.Duration {
		return 0, fmt.Errorf("not a duration")
	}
	ms, _ := sc.Value.(float64)
	secs := int(ms) / 1000
	if secs < 1 {
		return 0, fmt.Errorf("below 1 second cannot be honored")
	}
	return secs, nil
}

// BuildCloudRunJob maps capability.container.job attributes to a plan. Every error
// is a preflight refusal, never a silent drop.
func BuildCloudRunJob(project, environment, capability string,
	attrs, impl map[string]any, generation int) (CloudRunJobPlan, error) {
	p := CloudRunJobPlan{Name: resourceName(project, environment, capability, generation, 63)}
	for _, path := range sortedKeysG(attrs) {
		raw := attrs[path]
		switch path {
		case "location.region":
			p.Region, _ = raw.(string)
		case "image":
			p.Image, _ = raw.(string)
			p.Image = strings.TrimSpace(p.Image)
			if p.Image == "" {
				return CloudRunJobPlan{}, fmt.Errorf("image must not be empty")
			}
		case "trigger.type":
			switch raw {
			case "manual":
				// Cloud Run Jobs are manual-run (executed on demand) — the native mode
			case "schedule":
				return CloudRunJobPlan{}, fmt.Errorf(
					"trigger.type=schedule cannot be honored by Cloud Run Jobs — a Cloud Run Job is " +
						"manual-run; scheduling requires a SEPARATE Cloud Scheduler resource, out of this " +
						"single resource's scope; refusing rather than dropping the schedule")
			default:
				return CloudRunJobPlan{}, fmt.Errorf("trigger.type %v has no Cloud Run Jobs mapping", raw)
			}
		case "timeout":
			secs, err := jobTimeoutSeconds(raw)
			if err != nil {
				return CloudRunJobPlan{}, fmt.Errorf("timeout: %v", err)
			}
			p.TimeoutSec = secs
		case "service.managed":
			if raw != true {
				return CloudRunJobPlan{}, fmt.Errorf("service.managed=false cannot be honored by Cloud Run Jobs")
			}
		default:
			return CloudRunJobPlan{}, fmt.Errorf(
				"attribute %s has no Cloud Run Jobs mapping — refusing rather than silently dropping it "+
					"(env vars, args, resource limits, retry count are opaque implementation config)", path)
		}
	}
	if p.Region == "" {
		return CloudRunJobPlan{}, fmt.Errorf("container job requires location.region")
	}
	if p.Image == "" {
		return CloudRunJobPlan{}, fmt.Errorf("container job requires image")
	}
	if !gcpName.MatchString(p.Name) {
		return CloudRunJobPlan{}, fmt.Errorf("derived job name %q is invalid", p.Name)
	}
	if !projectOK.MatchString(project) {
		return CloudRunJobPlan{}, fmt.Errorf("project %q is invalid", project)
	}
	return p, nil
}

// createBody is the jobs.create request body. Ownership is labels.
func (p CloudRunJobPlan) createBody(capability, environment string) map[string]any {
	container := map[string]any{"image": p.Image}
	taskTemplate := map[string]any{"containers": []any{container}, "maxRetries": 3}
	if p.TimeoutSec > 0 {
		taskTemplate["timeout"] = fmt.Sprintf("%ds", p.TimeoutSec)
	}
	return map[string]any{
		"labels": map[string]any{
			"groundhold-capability":  sanitizeLabel(capability),
			"groundhold-environment": sanitizeLabel(environment),
		},
		"template": map[string]any{
			"template": taskTemplate,
		},
	}
}
