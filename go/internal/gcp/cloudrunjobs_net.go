// GCP Cloud Run Jobs network shell (D120): the bearer-signed REST half of the
// capability.container.job driver. Create/delete are async (v2 LRO — the same
// operation machinery as the Cloud Run service). The jobId is deterministic, so the
// providerId is knowable before the create response (D29). Ownership is labels.
package gcp

import (
	"encoding/json"
	"fmt"
	"net/http"

	"groundhold/internal/provider"
)

func cloudRunJobProviderID(project, region, name string) string {
	return "gjob:" + project + ":" + region + ":" + name
}

func splitCloudRunJobProviderID(providerID string) (project, region, name string, err error) {
	parts := splitN4(providerID)
	if len(parts) != 4 || parts[0] != "gjob" {
		return "", "", "", fmt.Errorf("providerId %q is not gjob:project:region:name", providerID)
	}
	if !projectOK.MatchString(parts[1]) {
		return "", "", "", fmt.Errorf("providerId project %q is invalid", parts[1])
	}
	if !redisRegionOK.MatchString(parts[2]) {
		return "", "", "", fmt.Errorf("providerId region %q is invalid", parts[2])
	}
	if !gcpName.MatchString(parts[3]) {
		return "", "", "", fmt.Errorf("providerId job %q is invalid", parts[3])
	}
	return parts[1], parts[2], parts[3], nil
}

// splitN4 splits on ':' into at most 4 parts (project/region/name have no colon).
func splitN4(s string) []string {
	out := make([]string, 0, 4)
	start := 0
	for i := 0; i < len(s) && len(out) < 3; i++ {
		if s[i] == ':' {
			out = append(out, s[start:i])
			start = i + 1
		}
	}
	return append(out, s[start:])
}

func (d *Driver) cloudRunJobURL(project, region, name string) string {
	return fmt.Sprintf("%s/projects/%s/locations/%s/jobs/%s", d.runBase(), project, region, name)
}

type cloudRunJobDoc struct {
	Name     string            `json:"name"`
	Labels   map[string]string `json:"labels"`
	Template struct {
		Template struct {
			Containers []struct {
				Image string `json:"image"`
			} `json:"containers"`
			Timeout string `json:"timeout"`
		} `json:"template"`
	} `json:"template"`
}

func (d *Driver) getCloudRunJob(project, region, name string) (cloudRunJobDoc, bool, error) {
	const op = "cloudRunJob.get"
	st, body, err := d.call("GET", d.cloudRunJobURL(project, region, name), nil)
	if err != nil {
		return cloudRunJobDoc{}, false, readTransport(op, err)
	}
	if st == http.StatusNotFound {
		return cloudRunJobDoc{}, false, nil
	}
	if st != http.StatusOK {
		return cloudRunJobDoc{}, false, readHTTP(op, st, gcpErrCode(body))
	}
	var doc cloudRunJobDoc
	if json.Unmarshal(body, &doc) != nil {
		return cloudRunJobDoc{}, false, readBody(op, st)
	}
	return doc, true, nil
}

func (d *Driver) createCloudRunJob(environment, capability string,
	attrs, impl map[string]any, generation int) provider.CreateResult {
	plan, err := BuildCloudRunJob(d.Project, environment, capability, attrs, impl, generation)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	pid := cloudRunJobProviderID(d.Project, plan.Region, plan.Name)
	url := fmt.Sprintf("%s/projects/%s/locations/%s/jobs?jobId=%s",
		d.runBase(), d.Project, plan.Region, plan.Name)
	st, body, err := d.call("POST", url, plan.createBody(capability, environment))
	switch {
	case err != nil:
		return provider.CreateResult{ProviderID: pid, Status: "unknown",
			Reason: fmt.Sprintf("create outcome unknown (may have landed): %v", err)}
	case st == http.StatusOK:
		// LRO started — poll below
	case st == http.StatusConflict:
		doc, found, rerr := d.getCloudRunJob(d.Project, plan.Region, plan.Name)
		if rerr != nil {
			return provider.CreateResult{ProviderID: pid, Status: "unknown",
				Reason: "name conflict, existing job gave no answer — reconcile: " + rerr.Error()}
		}
		if !found || doc.Labels["groundhold-capability"] != sanitizeLabel(capability) ||
			doc.Labels["groundhold-environment"] != sanitizeLabel(environment) {
			return provider.CreateResult{Status: "failed",
				Reason: "a job with this name exists and is not ours (labels do not match)"}
		}
		return provider.CreateResult{ProviderID: pid, Status: "succeeded"} // ours, present
	case st >= 500:
		return provider.CreateResult{ProviderID: pid, Status: "unknown",
			Reason: fmt.Sprintf("create HTTP %d (server error — may have landed) — reconcile", st)}
	default:
		if r := provider.MutationResult(st, gcpErrCode(body), nil, pid, "create"); r != nil {
			return *r
		}
		return provider.CreateResult{Status: "failed",
			Reason: fmt.Sprintf("create HTTP %d: %s", st, mutDetail(body))}
	}
	var op struct {
		Name string `json:"name"`
	}
	if json.Unmarshal(body, &op) != nil || op.Name == "" {
		return provider.CreateResult{ProviderID: pid, Status: "unknown",
			Reason: "create response carried no operation — reconcile"}
	}
	res := d.pollRunOperation(op.Name)
	if res.Status == "succeeded" || res.ProviderID == "" {
		res.ProviderID = pid
	}
	return res
}

func (d *Driver) observeCloudRunJob(capability, providerID string) ([]provider.Observation, []string, error) {
	project, region, name, err := splitCloudRunJobProviderID(providerID)
	if err != nil {
		return nil, nil, err
	}
	if err := d.sameProject(project); err != nil {
		return nil, nil, err
	}
	doc, found, rerr := d.getCloudRunJob(project, region, name)
	if rerr != nil {
		return nil, nil, rerr
	}
	if !found {
		return nil, []string{"job not found — nothing to observe"}, nil
	}
	obs := []provider.Observation{
		{Path: "location.region", Value: region, Derivation: "measured"},
		{Path: "service.managed", Value: true, Derivation: "measured"},
		// Cloud Run Jobs are manual-run.
		{Path: "trigger.type", Value: "manual", Derivation: "config-intent"},
	}
	if imgs := doc.Template.Template.Containers; len(imgs) > 0 && imgs[0].Image != "" {
		obs = append(obs, provider.Observation{Path: "image", Value: imgs[0].Image, Derivation: "measured"})
	}
	if t := doc.Template.Template.Timeout; t != "" {
		obs = append(obs, provider.Observation{Path: "timeout", Value: t, Derivation: "measured"})
	}
	return obs, nil, nil
}

func (d *Driver) deleteCloudRunJob(capability, environment, providerID string) provider.CreateResult {
	project, region, name, err := splitCloudRunJobProviderID(providerID)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	if err := d.sameProject(project); err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	doc, found, rerr := d.getCloudRunJob(project, region, name)
	if rerr != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown", Reason: "pre-delete read gave no answer — reconcile: " + rerr.Error()}
	}
	if !found {
		return provider.CreateResult{ProviderID: providerID, Status: "succeeded"} // idempotent
	}
	if doc.Labels["groundhold-capability"] != sanitizeLabel(capability) ||
		doc.Labels["groundhold-environment"] != sanitizeLabel(environment) {
		return provider.CreateResult{Status: "failed",
			Reason: "job labels do not match — refusing to delete a resource that is not ours"}
	}
	st, body, e := d.call("DELETE", d.cloudRunJobURL(project, region, name), nil)
	if e != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown", Reason: fmt.Sprintf("delete outcome unknown: %v", e)}
	}
	if st == http.StatusNotFound {
		return provider.CreateResult{ProviderID: providerID, Status: "succeeded"}
	}
	if st >= 500 {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown", Reason: fmt.Sprintf("delete HTTP %d (server error) — reconcile", st)}
	}
	if st != http.StatusOK {
		if r := provider.MutationResult(st, gcpErrCode(body), nil, providerID, "delete"); r != nil {
			return *r
		}
		return provider.CreateResult{ProviderID: providerID, Status: "failed", Reason: fmt.Sprintf("delete HTTP %d: %s", st, mutDetail(body))}
	}
	var op struct {
		Name string `json:"name"`
	}
	if json.Unmarshal(body, &op) != nil || op.Name == "" {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown", Reason: "delete response carried no operation — reconcile"}
	}
	res := d.pollRunOperation(op.Name)
	if res.Status == "succeeded" || res.ProviderID == "" {
		res.ProviderID = providerID
	}
	return res
}
