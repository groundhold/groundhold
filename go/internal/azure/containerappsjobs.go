// Azure Container Apps Jobs request building (D120): the semantic core of the Azure
// capability.container.job driver — the SAME vocabulary GCP Cloud Run Jobs fulfils
// (AWS has no standalone managed-job resource, so the domain is honestly two-cloud).
// A Container Apps Job is a run-to-completion container inside a managed environment
// (a prerequisite substrate). It supports a native Schedule trigger. The cron
// expression, env vars, args and resource limits are opaque impl config.
package azure

import (
	"fmt"
	"sort"
	"strings"

	"groundhold/internal/scalars"
)

const containerAppsJobsAPIVersion = "2023-05-01"

// ContainerAppsJobPlan is the attribute-derived shape a create assembles into ARM bodies.
type ContainerAppsJobPlan struct {
	Name           string
	Region         string
	Image          string
	TriggerType    string // Manual | Schedule
	CronExpression string // impl (opaque), required when Schedule
	TimeoutSec     int
	EnvironmentID  string // impl (a managed-environment prerequisite)
}

// jobTimeoutSecondsAz converts a duration scalar to whole seconds (Container Apps
// Jobs replicaTimeout is seconds). Below one second is refused.
func jobTimeoutSecondsAz(raw any) (int, error) {
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

// BuildContainerAppsJob maps capability.container.job attributes to a plan. Every
// error is a refusal apply surfaces in preflight.
func BuildContainerAppsJob(environment, capability string,
	attrs, impl map[string]any, generation int) (ContainerAppsJobPlan, error) {
	p := ContainerAppsJobPlan{
		Name:        azResourceName("pv-job", environment, capability, generation),
		TriggerType: "Manual",
		TimeoutSec:  1800,
	}
	schedule := false
	paths := make([]string, 0, len(attrs))
	for k := range attrs {
		paths = append(paths, k)
	}
	sort.Strings(paths)
	for _, path := range paths {
		raw := attrs[path]
		switch path {
		case "location.region":
			p.Region, _ = raw.(string)
		case "image":
			p.Image, _ = raw.(string)
			p.Image = strings.TrimSpace(p.Image)
			if p.Image == "" {
				return ContainerAppsJobPlan{}, fmt.Errorf("image must not be empty")
			}
		case "trigger.type":
			switch raw {
			case "manual":
				p.TriggerType = "Manual"
			case "schedule":
				p.TriggerType = "Schedule"
				schedule = true
			default:
				return ContainerAppsJobPlan{}, fmt.Errorf("trigger.type %v has no Container Apps Jobs mapping", raw)
			}
		case "timeout":
			secs, err := jobTimeoutSecondsAz(raw)
			if err != nil {
				return ContainerAppsJobPlan{}, fmt.Errorf("timeout: %v", err)
			}
			p.TimeoutSec = secs
		case "service.managed":
			if raw != true {
				return ContainerAppsJobPlan{}, fmt.Errorf("service.managed=false cannot be honored by Container Apps Jobs")
			}
		default:
			return ContainerAppsJobPlan{}, fmt.Errorf(
				"attribute %s has no Container Apps Jobs mapping — refusing rather than silently dropping it "+
					"(env vars, args, resource limits, retry count are opaque implementation config)", path)
		}
	}
	if p.Region == "" {
		return ContainerAppsJobPlan{}, fmt.Errorf("container job requires location.region")
	}
	if p.Image == "" {
		return ContainerAppsJobPlan{}, fmt.Errorf("container job requires image")
	}
	// a Container Apps Job runs inside a managed environment (a prerequisite substrate).
	p.EnvironmentID, _ = impl["environment_id"].(string)
	if p.EnvironmentID == "" {
		return ContainerAppsJobPlan{}, fmt.Errorf(
			"a Container Apps Job requires implementation.environment_id (a Microsoft.App " +
				"managedEnvironment the job runs in)")
	}
	// a Schedule trigger needs a cron expression (opaque impl config).
	if schedule {
		p.CronExpression, _ = impl["cron_expression"].(string)
		if p.CronExpression == "" {
			return ContainerAppsJobPlan{}, fmt.Errorf(
				"trigger.type=schedule requires implementation.cron_expression (the schedule cadence)")
		}
	}
	if !azNameOK.MatchString(p.Name) {
		return ContainerAppsJobPlan{}, fmt.Errorf("derived job name %q is invalid", p.Name)
	}
	return p, nil
}

// createBody is the jobs PUT body. Ownership is tags.
func (p ContainerAppsJobPlan) createBody(tags map[string]any) map[string]any {
	config := map[string]any{
		"triggerType":       p.TriggerType,
		"replicaTimeout":    p.TimeoutSec,
		"replicaRetryLimit": 3,
	}
	if p.TriggerType == "Manual" {
		config["manualTriggerConfig"] = map[string]any{"replicaCompletionCount": 1, "parallelism": 1}
	} else {
		config["scheduleTriggerConfig"] = map[string]any{
			"cronExpression": p.CronExpression, "replicaCompletionCount": 1, "parallelism": 1,
		}
	}
	return map[string]any{
		"location": p.Region,
		"tags":     tags,
		"properties": map[string]any{
			"environmentId": p.EnvironmentID,
			"configuration": config,
			"template": map[string]any{
				"containers": []any{map[string]any{"name": "job", "image": p.Image}},
			},
		},
	}
}
