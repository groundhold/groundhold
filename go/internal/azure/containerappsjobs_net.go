// Azure Container Apps Jobs network shell (D120): the ARM half of the
// capability.container.job driver. A single Microsoft.App/jobs PUT polled to
// provisioningState=Succeeded; the job name is deterministic, so the providerId is
// knowable before the response (D29). Ownership is tags. D29/D87 honesty throughout.
package azure

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"groundhold/internal/provider"
)

func containerAppsJobProviderID(sub, rg, name string) string {
	return "acjob:" + sub + ":" + rg + ":" + name
}

func splitContainerAppsJobProviderID(providerID string) (sub, rg, name string, err error) {
	parts := strings.Split(providerID, ":")
	if len(parts) != 4 || parts[0] != "acjob" {
		return "", "", "", fmt.Errorf("providerId %q is not acjob:sub:rg:name", providerID)
	}
	if !subOK.MatchString(parts[1]) || !rgOK.MatchString(parts[2]) || !azNameOK.MatchString(parts[3]) {
		return "", "", "", fmt.Errorf("providerId %q has an invalid component", providerID)
	}
	return parts[1], parts[2], parts[3], nil
}

func (d *Driver) containerAppsJobPath(name string) string {
	return "Microsoft.App/jobs/" + name
}

func (d *Driver) createContainerAppsJob(environment, capability string,
	attrs, impl map[string]any, generation int) provider.CreateResult {
	plan, err := BuildContainerAppsJob(environment, capability, attrs, impl, generation)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	rg, _ := impl["resource_group"].(string)
	if !rgOK.MatchString(rg) {
		return provider.CreateResult{Status: "failed",
			Reason: "azure container apps job requires implementation.resource_group"}
	}
	if !subOK.MatchString(d.Subscription) {
		return provider.CreateResult{Status: "failed",
			Reason: fmt.Sprintf("azure subscription %q is not a valid GUID", d.Subscription)}
	}
	pid := containerAppsJobProviderID(d.Subscription, rg, plan.Name)
	url, _ := d.armURL(rg, d.containerAppsJobPath(plan.Name), containerAppsJobsAPIVersion)
	body, _ := json.Marshal(plan.createBody(d.tags(capability, environment)))
	if r := d.putAndPoll(url, body, pid, "container apps job"); r != nil {
		return *r
	}
	return provider.CreateResult{ProviderID: pid, Status: "succeeded"}
}

type containerAppsJobDoc struct {
	Location   string            `json:"location"`
	Tags       map[string]string `json:"tags"`
	Properties struct {
		ProvisioningState string `json:"provisioningState"`
		Configuration     struct {
			TriggerType string `json:"triggerType"`
		} `json:"configuration"`
		Template struct {
			Containers []struct {
				Image string `json:"image"`
			} `json:"containers"`
		} `json:"template"`
	} `json:"properties"`
}

func (d *Driver) observeContainerAppsJob(capability, providerID string) ([]provider.Observation, []string, error) {
	sub, rg, name, err := splitContainerAppsJobProviderID(providerID)
	if err != nil {
		return nil, nil, err
	}
	if sub != d.Subscription && d.Subscription != "" {
		return nil, nil, fmt.Errorf("providerId subscription %q is not the driver's", sub)
	}
	url, _ := d.armURL(rg, d.containerAppsJobPath(name), containerAppsJobsAPIVersion)
	st, resp, e := d.doARM("GET", url, nil)
	if e != nil {
		return nil, nil, fmt.Errorf("jobs.get: %v", e)
	}
	if st == http.StatusNotFound {
		return nil, []string{"container apps job not found — nothing to observe"}, nil
	}
	if st != http.StatusOK {
		return nil, nil, fmt.Errorf("jobs.get: HTTP %d", st)
	}
	var doc containerAppsJobDoc
	if json.Unmarshal(resp, &doc) != nil {
		return nil, nil, &armReadError{Op: "jobs.get", Cause: "body", Status: st}
	}
	obs := []provider.Observation{
		{Path: "service.managed", Value: true, Derivation: "measured"},
	}
	if doc.Location != "" {
		obs = append(obs, provider.Observation{Path: "location.region", Value: strings.ToLower(doc.Location), Derivation: "measured"})
	}
	switch doc.Properties.Configuration.TriggerType {
	case "Manual":
		obs = append(obs, provider.Observation{Path: "trigger.type", Value: "manual", Derivation: "measured"})
	case "Schedule":
		obs = append(obs, provider.Observation{Path: "trigger.type", Value: "schedule", Derivation: "measured"})
	}
	if imgs := doc.Properties.Template.Containers; len(imgs) > 0 && imgs[0].Image != "" {
		obs = append(obs, provider.Observation{Path: "image", Value: imgs[0].Image, Derivation: "measured"})
	}
	return obs, nil, nil
}

func (d *Driver) deleteContainerAppsJob(capability, environment, providerID string) provider.CreateResult {
	_, rg, name, err := splitContainerAppsJobProviderID(providerID)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	url, _ := d.armURL(rg, d.containerAppsJobPath(name), containerAppsJobsAPIVersion)
	st, resp, e := d.doARM("GET", url, nil)
	if e != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown", Reason: "pre-delete read gave no answer — reconcile: " + azReadWhy(st, resp, e)}
	}
	if st == http.StatusNotFound {
		return provider.CreateResult{ProviderID: providerID, Status: "succeeded"} // idempotent
	}
	if st != http.StatusOK {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown", Reason: fmt.Sprintf("pre-delete read HTTP %d — reconcile", st)}
	}
	var doc containerAppsJobDoc
	if json.Unmarshal(resp, &doc) != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown", Reason: "pre-delete read answered HTTP 200 with an unparseable body — reconcile"}
	}
	if doc.Tags["groundhold-capability"] != sanitizeAzTag(capability) ||
		doc.Tags["groundhold-environment"] != sanitizeAzTag(environment) {
		return provider.CreateResult{Status: "failed",
			Reason: "job tags do not match — refusing to delete a resource that is not ours"}
	}
	dst, dresp, de := d.doARM("DELETE", url, nil)
	if de != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown", Reason: fmt.Sprintf("delete outcome unknown: %v", de)}
	}
	if dst == http.StatusNotFound {
		return provider.CreateResult{ProviderID: providerID, Status: "succeeded"}
	}
	if dst >= 500 {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown", Reason: fmt.Sprintf("delete HTTP %d (server error) — reconcile", dst)}
	}
	if dst < 200 || dst >= 300 {
		if r := provider.MutationResult(dst, azErrCode(dresp), nil, providerID, "delete"); r != nil {
			return *r
		}
		return provider.CreateResult{ProviderID: providerID, Status: "failed", Reason: fmt.Sprintf("delete HTTP %d: %s", dst, mutDetailAz(dresp))}
	}
	return provider.CreateResult{ProviderID: providerID, Status: "succeeded"}
}
