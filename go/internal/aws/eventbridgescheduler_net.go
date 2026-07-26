// EventBridge Scheduler network shell (D123): the SigV4-signed, REST-JSON half of the
// AWS capability.scheduler.cron driver. CreateSchedule is POST /schedules/{Name};
// GetSchedule is GET; DeleteSchedule is DELETE. The name is deterministic, so the pid
// is knowable BEFORE the response (D29). Ownership is the DESCRIPTION marker (read back
// via GetSchedule). schedule.enabled maps to the create-time State. Create is
// effectively synchronous (a schedule is ENABLED/DISABLED immediately, no async poll).
package aws

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"groundhold/internal/provider"
)

func (d *Driver) ebsBase(region string) string {
	if d.SchedulerBaseURL != "" {
		return d.SchedulerBaseURL
	}
	return "https://scheduler." + region + ".amazonaws.com"
}

func (d *Driver) ebsCall(method, region, path string, body []byte) (int, []byte, error) {
	h := map[string]string{"Content-Type": "application/json"}
	return d.doSigned(method, d.ebsBase(region)+path, "scheduler", region, h, body)
}

func ebsProviderID(region, name string) string { return "ebsched:" + region + ":" + name }

func splitEBSProviderID(providerID string) (region, name string, err error) {
	parts := strings.SplitN(providerID, ":", 3)
	if len(parts) != 3 || parts[0] != "ebsched" {
		return "", "", fmt.Errorf("providerId %q is not ebsched:region:name", providerID)
	}
	if !regionOK.MatchString(parts[1]) {
		return "", "", fmt.Errorf("providerId region %q is invalid", parts[1])
	}
	if !ebsNameOK.MatchString(parts[2]) {
		return "", "", fmt.Errorf("providerId name %q is invalid", parts[2])
	}
	return parts[1], parts[2], nil
}

type ebsScheduleDoc struct {
	Name        string `json:"Name"`
	Arn         string `json:"Arn"`
	State       string `json:"State"`
	Description string `json:"Description"`
}

// getSchedule reads a schedule. found=false + readable=true is authoritative "does not
// exist"; readable=false is transport/HTTP/parse failure.
func (d *Driver) getSchedule(region, name string) (ebsScheduleDoc, bool, error) {
	const op = "GetSchedule"
	st, resp, err := d.ebsCall("GET", region, "/schedules/"+name, nil)
	if err != nil {
		return ebsScheduleDoc{}, false, readTransport(op, err)
	}
	if st == http.StatusNotFound || strings.Contains(ecsErr(resp), "ResourceNotFound") {
		return ebsScheduleDoc{}, false, nil
	}
	if st != http.StatusOK {
		return ebsScheduleDoc{}, false, readHTTP(op, st, ecsErr(resp))
	}
	var doc ebsScheduleDoc
	if json.Unmarshal(resp, &doc) != nil {
		return ebsScheduleDoc{}, false, readBody(op, st)
	}
	return doc, true, nil
}

func (d *Driver) createEventBridgeScheduler(region, environment, capability string,
	attrs, impl map[string]any, generation int) provider.CreateResult {
	plan, err := BuildEventBridgeScheduler(environment, capability, attrs, impl, generation)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	if plan.Region != "" && plan.Region != region {
		region = plan.Region
	}
	pid := ebsProviderID(region, plan.Name)
	body, _ := json.Marshal(plan.createBody(capability, environment))
	st, resp, err := d.ebsCall("POST", region, "/schedules/"+plan.Name, body)
	switch {
	case err != nil:
		return provider.CreateResult{ProviderID: pid, Status: "unknown",
			Reason: fmt.Sprintf("CreateSchedule outcome unknown (may have landed): %v", err)}
	case st >= 200 && st < 300:
		return provider.CreateResult{ProviderID: pid, Status: "succeeded"}
	case strings.Contains(ecsErr(resp), "ConflictException"), strings.Contains(ecsErr(resp), "ResourceExists"):
		doc, found, rerr := d.getSchedule(region, plan.Name)
		if rerr != nil {
			return provider.CreateResult{ProviderID: pid, Status: "unknown",
				Reason: "name conflict, existing schedule gave no answer — reconcile: " + rerr.Error()}
		}
		if !found || !awsMarkerOurs(doc.Description, capability, environment) {
			return provider.CreateResult{Status: "failed",
				Reason: "a schedule with this name exists and is not ours (marker does not match)"}
		}
		return provider.CreateResult{ProviderID: pid, Status: "succeeded"} // ours, present
	case st >= 500:
		return provider.CreateResult{ProviderID: pid, Status: "unknown",
			Reason: fmt.Sprintf("CreateSchedule HTTP %d (server error — may have landed): %s", st, ecsErr(resp))}
	default:
		// D237: throttle/503/live-403 -> unknown WITH the pid (the schedule name is
		// deterministic, keep the handle); only a clean 4xx refusal fails.
		if r := provider.MutationResult(st, ecsErr(resp), nil, pid, "CreateSchedule"); r != nil {
			return *r
		}
		return provider.CreateResult{Status: "failed",
			Reason: fmt.Sprintf("CreateSchedule HTTP %d: %s", st, ecsErr(resp))}
	}
}

func (d *Driver) observeEventBridgeScheduler(capability, providerID string) ([]provider.Observation, []string, error) {
	region, name, err := splitEBSProviderID(providerID)
	if err != nil {
		return nil, nil, err
	}
	doc, found, rerr := d.getSchedule(region, name)
	if rerr != nil {
		return nil, nil, rerr
	}
	if !found {
		return nil, []string{"schedule not found — nothing to observe"}, nil
	}
	obs := []provider.Observation{
		{Path: "location.region", Value: region, Derivation: "measured"},
		{Path: "service.managed", Value: true, Derivation: "measured"},
		{Path: "schedule.enabled", Value: doc.State == "ENABLED", Derivation: "measured"},
	}
	return obs, nil, nil
}

func (d *Driver) deleteEventBridgeScheduler(capability, environment, providerID string) provider.CreateResult {
	// the region is read from the provider ID, which carries the authoritative location.
	region, name, err := splitEBSProviderID(providerID)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	doc, found, rerr := d.getSchedule(region, name)
	if rerr != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown", Reason: "pre-delete read gave no answer — reconcile: " + rerr.Error()}
	}
	if !found {
		return provider.CreateResult{ProviderID: providerID, Status: "succeeded"} // idempotent
	}
	if !awsMarkerOurs(doc.Description, capability, environment) {
		return provider.CreateResult{Status: "failed",
			Reason: "schedule marker does not match — refusing to delete a resource that is not ours"}
	}
	st, resp, err := d.ebsCall("DELETE", region, "/schedules/"+name, nil)
	if err != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown",
			Reason: fmt.Sprintf("delete outcome unknown: %v", err)}
	}
	if st == http.StatusNotFound || strings.Contains(ecsErr(resp), "ResourceNotFound") {
		return provider.CreateResult{ProviderID: providerID, Status: "succeeded"}
	}
	if st >= 500 {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown",
			Reason: fmt.Sprintf("delete HTTP %d (server error) — reconcile", st)}
	}
	if st < 200 || st >= 300 {
		// D237: throttle/503/live-403 -> unknown WITH the pid, never failed.
		if r := provider.MutationResult(st, ecsErr(resp), nil, providerID, "delete"); r != nil {
			return *r
		}
		return provider.CreateResult{Status: "failed", Reason: fmt.Sprintf("delete HTTP %d: %s", st, ecsErr(resp))}
	}
	return provider.CreateResult{ProviderID: providerID, Status: "succeeded"}
}
