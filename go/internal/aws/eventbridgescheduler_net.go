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
	Name               string `json:"Name"`
	Arn                string `json:"Arn"`
	State              string `json:"State"`
	Description        string `json:"Description"`
	ScheduleExpression string `json:"ScheduleExpression"` // D1004: the cron/rate expression, for drift
}

// ebsScheduleOperand is the reserved observation path the DECLARED schedule expression and
// the OBSERVED one compare on (D1004). The expression is opaque impl (invariant #4), so it
// is an operand, not a vocab attribute — but a change to it must be SEEN, or the contract
// can stand a schedule up and never keep it (a key-destroying timer silently drifting off
// its declared cadence is a term nobody guards; field: acme).
const ebsScheduleOperand = provider.OperandPrefix + "schedule"

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
		// F-LC3 (D520): a BOUND resource the API authoritatively 404s is GONE.
		// A diagnostic alone leaves the binding a no-op forever (D513).
		return []provider.Observation{
			{Path: provider.ResourceAbsentPath, Value: true, Derivation: "measured"},
		}, []string{"schedule not found — bound resource is gone (will re-create)"}, nil
	}
	obs := []provider.Observation{
		// Present: clear the marker (F-LC3), or a stale "gone" survives a re-create.
		{Path: provider.ResourceAbsentPath, Value: false, Derivation: "measured"},
		{Path: "location.region", Value: region, Derivation: "measured"},
		{Path: "service.managed", Value: true, Derivation: "measured"},
		{Path: "schedule.enabled", Value: doc.State == "ENABLED", Derivation: "measured"},
		// D1004: the cron/rate expression, so a change to it is a detected drift, not silence.
		{Path: ebsScheduleOperand, Value: doc.ScheduleExpression, Derivation: "measured"},
	}
	return obs, nil, nil
}

// updateEventBridgeScheduler patches a LIVE schedule in place via UpdateSchedule (PUT
// /schedules/{Name}) — the schedule identity survives, unlike a replacement (D1004).
// EventBridge Scheduler's UpdateSchedule requires the FULL definition, so it re-sends the
// create body. Ownership (the Description marker) is re-checked BEFORE any mutation.
func (d *Driver) updateEventBridgeScheduler(capability, environment, providerID string,
	attrs, impl map[string]any, changes []string) provider.CreateResult {
	region, name, err := splitEBSProviderID(providerID)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	doc, found, rerr := d.getSchedule(region, name)
	if rerr != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown", Reason: "pre-update read gave no answer — reconcile: " + rerr.Error()}
	}
	if !found {
		return provider.CreateResult{Status: "failed", Reason: "schedule no longer exists — re-observe and re-plan"}
	}
	if !awsMarkerOurs(doc.Description, capability, environment) {
		return provider.CreateResult{Status: "failed",
			Reason: "schedule marker does not match — refusing to patch a resource that is not ours"}
	}
	plan, berr := BuildEventBridgeScheduler(environment, capability, attrs, impl, 1)
	if berr != nil {
		return provider.CreateResult{Status: "failed", Reason: berr.Error()}
	}
	plan.Name = name
	body, _ := json.Marshal(plan.createBody(capability, environment))
	st, resp, e := d.ebsCall("PUT", region, "/schedules/"+name, body)
	switch {
	case e != nil:
		return provider.CreateResult{ProviderID: providerID, Status: "unknown", Reason: fmt.Sprintf("UpdateSchedule outcome unknown: %v", e)}
	case st == http.StatusOK:
		return provider.CreateResult{ProviderID: providerID, Status: "succeeded"}
	case st >= 500:
		return provider.CreateResult{ProviderID: providerID, Status: "unknown", Reason: fmt.Sprintf("UpdateSchedule HTTP %d (server error) — reconcile", st)}
	default:
		if r := provider.MutationResult(st, ecsErr(resp), nil, providerID, "UpdateSchedule"); r != nil {
			return *r
		}
		return provider.CreateResult{ProviderID: providerID, Status: "failed", Reason: fmt.Sprintf("UpdateSchedule HTTP %d: %s", st, ecsErr(resp))}
	}
}

// classifyEBSChange (D1004): the schedule expression and enabled state patch in place via
// UpdateSchedule; the region is fixed at creation (a replacement).
func classifyEBSChange(path string) (string, string) {
	switch path {
	case ebsScheduleOperand:
		return "mutable", "the schedule expression patches in place via UpdateSchedule (no replacement)"
	case "schedule.enabled":
		return "mutable", "the schedule's enabled state patches in place via UpdateSchedule"
	case "location.region":
		return "immutable", "a schedule's region is fixed at creation — a change is a replacement"
	default:
		return "immutable", "not an in-place-patchable schedule attribute — a change is a replacement"
	}
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
	// D899: EventBridge Scheduler's DeleteSchedule REQUIRES a clientToken query
	// parameter — without it AWS rejects the call ("ClientToken cannot be empty",
	// HTTP 400) and the schedule is never deleted (it lingers and keeps firing). The
	// token is deterministic (derived from the schedule name, as the CreateSchedule
	// token is) so a retried delete is idempotent rather than a new request.
	st, resp, err := d.ebsCall("DELETE", region, "/schedules/"+name+"?clientToken="+ebsClientToken(name), nil)
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
