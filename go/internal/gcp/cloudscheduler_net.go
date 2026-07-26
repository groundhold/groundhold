// Cloud Scheduler network shell (D123): the httptest-covered half of the GCP
// capability.scheduler.cron driver. jobs.create is SYNCHRONOUS (200 with the job, no
// LRO). The job id is deterministic, so the providerId is knowable BEFORE the response
// (D29). Ownership is the DESCRIPTION marker (jobs have no labels). schedule.enabled=
// false is a jobs.pause AFTER create; observe reads state back (ENABLED/PAUSED).
package gcp

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"groundhold/internal/provider"
)

const cloudSchedulerBaseURL = "https://cloudscheduler.googleapis.com/v1"

func (d *Driver) schedBase() string {
	if d.SchedulerBaseURL != "" {
		return d.SchedulerBaseURL
	}
	return cloudSchedulerBaseURL
}

func schedProviderID(project, location, jobID string) string {
	return "gsched:" + project + ":" + location + ":" + jobID
}

func splitSchedProviderID(providerID string) (project, location, jobID string, err error) {
	parts := strings.Split(providerID, ":")
	if len(parts) != 4 || parts[0] != "gsched" {
		return "", "", "", fmt.Errorf("providerId %q is not gsched:project:location:jobId", providerID)
	}
	if !gcpName.MatchString(parts[1]) {
		return "", "", "", fmt.Errorf("providerId project %q is invalid", parts[1])
	}
	if !gcpName.MatchString(parts[2]) {
		return "", "", "", fmt.Errorf("providerId location %q is invalid", parts[2])
	}
	if !schedJobIDOK.MatchString(parts[3]) {
		return "", "", "", fmt.Errorf("providerId job id %q is invalid", parts[3])
	}
	return parts[1], parts[2], parts[3], nil
}

func (d *Driver) schedJobURL(project, location, jobID string) string {
	return fmt.Sprintf("%s/projects/%s/locations/%s/jobs/%s", d.schedBase(), project, location, jobID)
}

type schedJobDoc struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	State       string `json:"state"`
	Schedule    string `json:"schedule"`
}

func (d *Driver) schedGetJob(project, location, jobID string) (schedJobDoc, bool, error) {
	const op = "schedGetJob.get"
	st, body, err := d.call("GET", d.schedJobURL(project, location, jobID), nil)
	if err != nil {
		return schedJobDoc{}, false, readTransport(op, err)
	}
	if st == http.StatusNotFound {
		return schedJobDoc{}, false, nil
	}
	if st != http.StatusOK {
		return schedJobDoc{}, false, readHTTP(op, st, gcpErrCode(body))
	}
	var doc schedJobDoc
	if json.Unmarshal(body, &doc) != nil {
		return schedJobDoc{}, false, readBody(op, st)
	}
	return doc, true, nil
}

func (d *Driver) createCloudScheduler(capability, environment string,
	attrs, impl map[string]any, generation int) provider.CreateResult {
	plan, err := BuildCloudSchedulerJob(d.Project, environment, capability, attrs, impl, generation)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	pid := schedProviderID(d.Project, plan.Location, plan.JobID)
	url := fmt.Sprintf("%s/projects/%s/locations/%s/jobs?jobId=%s",
		d.schedBase(), d.Project, plan.Location, plan.JobID)
	st, body, err := d.call("POST", url, plan.createBody(d.Project))
	switch {
	case err != nil:
		return provider.CreateResult{ProviderID: pid, Status: "unknown",
			Reason: fmt.Sprintf("jobs.create outcome unknown (may have landed): %v", err)}
	case st == http.StatusConflict:
		doc, found, rerr := d.schedGetJob(d.Project, plan.Location, plan.JobID)
		if rerr != nil {
			return provider.CreateResult{ProviderID: pid, Status: "unknown",
				Reason: "name conflict, existing job gave no answer — reconcile: " + rerr.Error()}
		}
		if !found || !markerOurs(doc.Description, capability, environment) {
			return provider.CreateResult{Status: "failed",
				Reason: "a job with this id exists and is not ours (marker does not match)"}
		}
		// ours — ensure the desired armed state below
	case st >= 500:
		return provider.CreateResult{ProviderID: pid, Status: "unknown",
			Reason: fmt.Sprintf("jobs.create HTTP %d (server error — may have landed): %s", st, mutDetail(body))}
	case st >= 400:
		if r := provider.MutationResult(st, gcpErrCode(body), nil, pid, "jobs.create"); r != nil {
			return *r // D237: 429/403 is a wire fact, not an orphan — unknown+pid
		}
		return provider.CreateResult{Status: "failed",
			Reason: fmt.Sprintf("jobs.create HTTP %d: %s", st, mutDetail(body))}
	default:
		var doc schedJobDoc
		if json.Unmarshal(body, &doc) != nil || doc.Name == "" {
			return provider.CreateResult{ProviderID: pid, Status: "unknown",
				Reason: "jobs.create response carried no job — reconcile"}
		}
	}
	// schedule.enabled=false: a fresh job is ENABLED; pause it. This is a second
	// mutation on the SAME job, so a lost/5xx outcome is unknown-with-pid (D29).
	if !plan.Enabled {
		if unknown, err := d.schedPause(d.Project, plan.Location, plan.JobID); err != nil {
			stt := "failed"
			if unknown {
				stt = "unknown"
			}
			return provider.CreateResult{ProviderID: pid, Status: stt, Reason: err.Error()}
		}
	}
	return provider.CreateResult{ProviderID: pid, Status: "succeeded"}
}

func (d *Driver) schedPause(project, location, jobID string) (unknown bool, err error) {
	url := d.schedJobURL(project, location, jobID) + ":pause"
	st, body, cerr := d.call("POST", url, map[string]any{})
	if cerr != nil {
		return true, fmt.Errorf("pause outcome unknown — reconcile: %v", cerr)
	}
	if st == http.StatusOK {
		return false, nil
	}
	if provider.Classify(st, gcpErrCode(body), nil).Unknown() {
		// D237: 5xx/429/403 on the pause is a wire fact — reconcile, keep the handle.
		return true, fmt.Errorf("pause HTTP %d (%s) — reconcile: %s", st, gcpErrCode(body), mutDetail(body))
	}
	return false, fmt.Errorf("pause HTTP %d: %s", st, mutDetail(body))
}

func (d *Driver) observeCloudScheduler(capability, providerID string) ([]provider.Observation, []string, error) {
	project, location, jobID, err := splitSchedProviderID(providerID)
	if err != nil {
		return nil, nil, err
	}
	if err := d.sameProject(project); err != nil {
		return nil, nil, err
	}
	doc, found, rerr := d.schedGetJob(project, location, jobID)
	if rerr != nil {
		return nil, nil, rerr
	}
	if !found {
		return nil, []string{"job not found — nothing to observe"}, nil
	}
	obs := []provider.Observation{
		{Path: "location.region", Value: location, Derivation: "measured"},
		{Path: "service.managed", Value: true, Derivation: "measured"},
		// ENABLED is armed; PAUSED/DISABLED is not. UPDATE_FAILED is not armed either.
		{Path: "schedule.enabled", Value: doc.State == "ENABLED", Derivation: "measured"},
	}
	return obs, nil, nil
}

func (d *Driver) deleteCloudScheduler(capability, environment, providerID string) provider.CreateResult {
	project, location, jobID, err := splitSchedProviderID(providerID)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	if err := d.sameProject(project); err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	doc, found, rerr := d.schedGetJob(project, location, jobID)
	if rerr != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown", Reason: "pre-delete read gave no answer — reconcile: " + rerr.Error()}
	}
	if !found {
		return provider.CreateResult{ProviderID: providerID, Status: "succeeded"} // idempotent
	}
	if !markerOurs(doc.Description, capability, environment) {
		return provider.CreateResult{Status: "failed",
			Reason: "job marker does not match — refusing to delete a resource that is not ours"}
	}
	st, body, err := d.call("DELETE", d.schedJobURL(project, location, jobID), nil)
	if err != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown",
			Reason: fmt.Sprintf("delete outcome unknown: %v", err)}
	}
	if st == http.StatusNotFound {
		return provider.CreateResult{ProviderID: providerID, Status: "succeeded"}
	}
	if st >= 500 {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown",
			Reason: fmt.Sprintf("delete HTTP %d (server error) — reconcile", st)}
	}
	if st >= 400 {
		if r := provider.MutationResult(st, gcpErrCode(body), nil, providerID, "delete"); r != nil {
			return *r // D237: 429/403 is a wire fact, not authoritative absence — unknown+pid
		}
		return provider.CreateResult{Status: "failed", Reason: fmt.Sprintf("delete HTTP %d: %s", st, mutDetail(body))}
	}
	return provider.CreateResult{ProviderID: providerID, Status: "succeeded"}
}
