// AWS Backup Plan network shell (D153): the SigV4-signed, REST-JSON half of the AWS
// capability.backup.plan driver. It shares the vault's API host, so it REUSES the
// vault shell's d.backupBase/d.backupCall and d.bkvTags (GET /tags/{arn}) rather than
// duplicating them. The endpoints:
//
//	CreateBackupPlan       PUT    /backup/plans/                        (yields the BackupPlanId)
//	CreateBackupSelection  PUT    /backup/plans/{planId}/selections/    (a plan with no selection backs up nothing)
//	GetBackupPlan          GET    /backup/plans/{planId}/               (returns BackupPlanArn — we OBSERVE the ARN, never build it)
//	ListBackupSelections   GET    /backup/plans/{planId}/selections/
//	DeleteBackupSelection  DELETE /backup/plans/{planId}/selections/{selectionId}
//	DeleteBackupPlan       DELETE /backup/plans/{planId}
//	ListBackupPlans        GET    /backup/plans/
//
// The BackupPlanId is SERVER-assigned, so the providerId (backupplan:<region>:<planId>)
// is only knowable AFTER the create response (D29): a lost CreateBackupPlan response is
// unknown WITHOUT a pid (the CreatorRequestId idempotates the retry; discover finds the
// orphan by its tags). Once the plan exists, a failed CreateBackupSelection is unknown
// WITH the pid (plan without selection — reconcile). Ownership is tags read via the
// ARN returned by GetBackupPlan; a foreign plan is refused, never mutated.
package aws

import (
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strings"

	"groundhold/internal/provider"
)

var backupPlanIdOK = regexp.MustCompile(`^[a-zA-Z0-9._-]{1,64}$`)

func backupPlanProviderID(region, planID string) string {
	return "backupplan:" + region + ":" + planID
}

func splitBackupPlanProviderID(providerID string) (region, planID string, err error) {
	parts := strings.Split(providerID, ":")
	if len(parts) != 3 || parts[0] != "backupplan" {
		return "", "", fmt.Errorf("providerId %q is not backupplan:region:planId", providerID)
	}
	if !regionOK.MatchString(parts[1]) {
		return "", "", fmt.Errorf("providerId region %q is invalid", parts[1])
	}
	if !backupPlanIdOK.MatchString(parts[2]) {
		return "", "", fmt.Errorf("providerId plan id %q is invalid", parts[2])
	}
	return parts[1], parts[2], nil
}

type bkpRule struct {
	ScheduleExpression    string `json:"ScheduleExpression"`
	TargetBackupVaultName string `json:"TargetBackupVaultName"`
	Lifecycle             struct {
		DeleteAfterDays int `json:"DeleteAfterDays"`
	} `json:"Lifecycle"`
	CopyActions []struct {
		DestinationBackupVaultArn string `json:"DestinationBackupVaultArn"`
	} `json:"CopyActions"`
}

type bkpGet struct {
	BackupPlanArn string `json:"BackupPlanArn"`
	BackupPlanId  string `json:"BackupPlanId"`
	BackupPlan    struct {
		BackupPlanName string    `json:"BackupPlanName"`
		Rules          []bkpRule `json:"Rules"`
	} `json:"BackupPlan"`
}

// getBackupPlan reads a plan. found=false + readable=true is authoritative "does not
// exist"; readable=false is transport/HTTP/parse failure.
func (d *Driver) getBackupPlan(region, planID string) (bkpGet, bool, error) {
	const op = "GetBackupPlan"
	st, resp, err := d.backupCall("GET", region, "/backup/plans/"+planID+"/", nil)
	if err != nil {
		return bkpGet{}, false, readTransport(op, err)
	}
	if st == http.StatusNotFound || strings.Contains(ecsErr(resp), "ResourceNotFound") {
		return bkpGet{}, false, nil
	}
	if st != http.StatusOK {
		return bkpGet{}, false, readHTTP(op, st, ecsErr(resp))
	}
	var doc bkpGet
	if json.Unmarshal(resp, &doc) != nil {
		return bkpGet{}, false, readBody(op, st)
	}
	return doc, true, nil
}

// listBackupSelectionIDs enumerates a plan's selection ids (readable=false on failure).
func (d *Driver) listBackupSelectionIDs(region, planID string) ([]string, error) {
	const op = "ListBackupSelections"
	st, resp, cerr := d.backupCall("GET", region, "/backup/plans/"+planID+"/selections/", nil)
	if cerr != nil {
		return nil, readTransport(op, cerr)
	}
	if st != http.StatusOK {
		return nil, readHTTP(op, st, ecsErr(resp))
	}
	var r struct {
		BackupSelectionsList []struct {
			SelectionId string `json:"SelectionId"`
		} `json:"BackupSelectionsList"`
	}
	if json.Unmarshal(resp, &r) != nil {
		return nil, readBody(op, st)
	}
	var out []string
	for _, s := range r.BackupSelectionsList {
		if s.SelectionId != "" {
			out = append(out, s.SelectionId)
		}
	}
	return out, nil
}

func (d *Driver) createBackupPlan(region, environment, capability string,
	attrs, impl map[string]any, generation int) provider.CreateResult {
	plan, err := BuildBackupPlan(environment, capability, attrs, impl, generation)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	if plan.Region != "" {
		region = plan.Region
	}

	// ---- CreateBackupPlan (yields the server-assigned pid) ----
	body, _ := json.Marshal(plan.createPlanBody(capability, environment))
	st, resp, err := d.backupCall("PUT", region, "/backup/plans/", body)
	switch {
	case err != nil:
		// no pid yet — the CreatorRequestId makes a retry safe; discover reconciles by tags.
		return provider.CreateResult{Status: "unknown",
			Reason: fmt.Sprintf("CreateBackupPlan outcome unknown (may have landed; retry idempotates via CreatorRequestId, or discover by tags): %v", err)}
	case st >= 500:
		return provider.CreateResult{Status: "unknown",
			Reason: fmt.Sprintf("CreateBackupPlan HTTP %d (server error — may have landed): %s", st, ecsErr(resp))}
	case st < 200 || st >= 300:
		// D237: throttle/503/live-403 -> unknown (the BackupPlanId is server-assigned,
		// no pid yet; retry idempotates via CreatorRequestId); only a clean 4xx fails.
		if r := provider.MutationResult(st, ecsErr(resp), nil, "", "CreateBackupPlan"); r != nil {
			return *r
		}
		return provider.CreateResult{Status: "failed",
			Reason: fmt.Sprintf("CreateBackupPlan HTTP %d: %s", st, ecsErr(resp))}
	}
	var created struct {
		BackupPlanId string `json:"BackupPlanId"`
	}
	if json.Unmarshal(resp, &created) != nil || created.BackupPlanId == "" {
		// created but the id did not parse — we cannot form the handle; honest unknown.
		return provider.CreateResult{Status: "unknown",
			Reason: "CreateBackupPlan succeeded but its response carried no readable " +
				"BackupPlanId — reconcile by tags"}
	}
	pid := backupPlanProviderID(region, created.BackupPlanId)

	// ---- CreateBackupSelection (a plan with no selection backs up nothing) ----
	selBody, _ := json.Marshal(plan.createSelectionBody())
	st, resp, err = d.backupCall("PUT", region, "/backup/plans/"+created.BackupPlanId+"/selections/", selBody)
	switch {
	case err != nil:
		return provider.CreateResult{ProviderID: pid, Status: "unknown",
			Reason: fmt.Sprintf("plan created; CreateBackupSelection outcome unknown (plan may back up nothing) — reconcile: %v", err)}
	case st >= 500:
		return provider.CreateResult{ProviderID: pid, Status: "unknown",
			Reason: fmt.Sprintf("plan created; CreateBackupSelection HTTP %d (server error) — reconcile", st)}
	case st < 200 || st >= 300:
		return provider.CreateResult{ProviderID: pid, Status: "unknown",
			Reason: fmt.Sprintf("plan created but CreateBackupSelection failed (plan backs up nothing): HTTP %d (%s) — reconcile", st, ecsErr(resp))}
	}
	return provider.CreateResult{ProviderID: pid, Status: "succeeded"}
}

func (d *Driver) observeBackupPlan(capability, providerID string) ([]provider.Observation, []string, error) {
	region, planID, err := splitBackupPlanProviderID(providerID)
	if err != nil {
		return nil, nil, err
	}
	doc, found, rerr := d.getBackupPlan(region, planID)
	if rerr != nil {
		return nil, nil, rerr
	}
	if !found {
		return nil, []string{"backup plan not found — nothing to observe"}, nil
	}
	obs := []provider.Observation{
		{Path: "location.region", Value: region, Derivation: "measured"},
		{Path: "service.managed", Value: true, Derivation: "measured"},
	}
	var diags []string
	if len(doc.BackupPlan.Rules) == 0 {
		return obs, []string{"backup plan has no rules — cadence/retention unobservable"}, nil
	}
	if len(doc.BackupPlan.Rules) > 1 {
		diags = append(diags, "backup plan has multiple rules — observing the first (cadence/retention from rule[0])")
	}
	rule := doc.BackupPlan.Rules[0]
	if freq, ok := cronToFrequency(rule.ScheduleExpression); ok {
		obs = append(obs, provider.Observation{Path: "schedule.frequency", Value: freq, Derivation: "measured"})
	} else if rule.ScheduleExpression != "" {
		diags = append(diags, "schedule "+rule.ScheduleExpression+" is a bespoke cron with no canonical cadence — schedule.frequency omitted (RPO not derivable)")
	}
	if rule.Lifecycle.DeleteAfterDays > 0 {
		obs = append(obs, provider.Observation{Path: "retention.duration",
			Value: fmt.Sprintf("%dh", rule.Lifecycle.DeleteAfterDays*24), Derivation: "measured"})
	}
	crossRegion := false
	for _, ca := range rule.CopyActions {
		destRegion, aerr := regionFromBackupArn(ca.DestinationBackupVaultArn)
		if aerr != nil {
			diags = append(diags, "copy destination "+ca.DestinationBackupVaultArn+": "+aerr.Error())
			continue
		}
		if destRegion != region {
			crossRegion = true
			obs = append(obs, provider.Observation{Path: "copy.destinationRegion", Value: destRegion, Derivation: "measured"})
		}
	}
	obs = append(obs, provider.Observation{Path: "copy.crossRegion", Value: crossRegion, Derivation: "measured"})
	return obs, diags, nil
}

func (d *Driver) updateBackupPlan(capability, environment, providerID string,
	attrs, impl map[string]any, changes []string) provider.CreateResult {
	region, planID, err := splitBackupPlanProviderID(providerID)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	// refuse-before-mutate: re-derive + validate the full desired shape (e.g.
	// copy.crossRegion=true with no copyDestinationVaultArn refuses here).
	plan, err := BuildBackupPlan(environment, capability, attrs, impl, 1)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	// ownership re-check before mutating: read the ARN from GetBackupPlan (we OBSERVE
	// the ARN, never build it), then read its tags.
	doc, found, rerr := d.getBackupPlan(region, planID)
	if rerr != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown",
			Reason: "pre-update ownership read gave no answer — reconcile before patching: " + rerr.Error()}
	}
	if !found {
		return provider.CreateResult{Status: "failed", Reason: "backup plan no longer exists — cannot update"}
	}
	tags, terr := d.bkvTags(region, doc.BackupPlanArn)
	if terr != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown",
			Reason: "ownership tags gave no answer — reconcile before patching: " + terr.Error()}
	}
	if !groundholdTagsMatch(tags, capability, environment) {
		return provider.CreateResult{Status: "failed",
			Reason: "backup plan tags do not match — refusing to patch a resource that is not ours"}
	}
	// UpdateBackupPlan replaces the rule set — every mutable semantic path
	// (schedule.frequency / retention.duration / copy.crossRegion / copy.destinationRegion)
	// lives in the rule, so one POST covers whatever `changes` selected.
	body, _ := json.Marshal(plan.updatePlanBody())
	st, resp, err := d.backupCall("POST", region, "/backup/plans/"+planID, body)
	switch {
	case err != nil:
		return provider.CreateResult{ProviderID: providerID, Status: "unknown",
			Reason: fmt.Sprintf("UpdateBackupPlan outcome unknown (may have landed): %v", err)}
	case st >= 500:
		return provider.CreateResult{ProviderID: providerID, Status: "unknown",
			Reason: fmt.Sprintf("UpdateBackupPlan HTTP %d (server error — may have landed)", st)}
	case st < 200 || st >= 300:
		return provider.CreateResult{Status: "failed",
			Reason: fmt.Sprintf("UpdateBackupPlan HTTP %d: %s", st, ecsErr(resp))}
	}
	return provider.CreateResult{ProviderID: providerID, Status: "succeeded"}
}

func (d *Driver) deleteBackupPlan(capability, environment, providerID string) provider.CreateResult {
	region, planID, err := splitBackupPlanProviderID(providerID)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	doc, found, rerr := d.getBackupPlan(region, planID)
	if rerr != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown", Reason: "pre-delete read gave no answer — reconcile: " + rerr.Error()}
	}
	if !found {
		return provider.CreateResult{ProviderID: providerID, Status: "succeeded"} // idempotent
	}
	tags, terr := d.bkvTags(region, doc.BackupPlanArn)
	if terr != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown", Reason: "ownership tags gave no answer — reconcile: " + terr.Error()}
	}
	if !groundholdTagsMatch(tags, capability, environment) {
		return provider.CreateResult{Status: "failed",
			Reason: "backup plan tags do not match — refusing to delete a resource that is not ours"}
	}
	// A plan with selections cannot be deleted — remove selections first.
	selIDs, serr := d.listBackupSelectionIDs(region, planID)
	if serr != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown", Reason: "reconcile: " + serr.Error()}
	}
	for _, sid := range selIDs {
		st, resp, derr := d.backupCall("DELETE", region, "/backup/plans/"+planID+"/selections/"+sid, nil)
		if derr != nil {
			return provider.CreateResult{ProviderID: providerID, Status: "unknown",
				Reason: fmt.Sprintf("DeleteBackupSelection %s outcome unknown: %v", sid, derr)}
		}
		if st == http.StatusNotFound || strings.Contains(ecsErr(resp), "ResourceNotFound") {
			continue // already gone
		}
		if st >= 500 {
			return provider.CreateResult{ProviderID: providerID, Status: "unknown",
				Reason: fmt.Sprintf("DeleteBackupSelection %s HTTP %d (server error) — reconcile", sid, st)}
		}
		if st < 200 || st >= 300 {
			// D237: throttle/503/live-403 -> unknown WITH the pid, never failed.
			if r := provider.MutationResult(st, ecsErr(resp), nil, providerID,
				"DeleteBackupSelection "+sid); r != nil {
				return *r
			}
			return provider.CreateResult{Status: "failed",
				Reason: fmt.Sprintf("DeleteBackupSelection %s HTTP %d: %s", sid, st, ecsErr(resp))}
		}
	}
	// Now delete the plan itself. Note: recovery points already written stay in the
	// vault (they age out under the vault's retention/lock) — a plan is a schedule,
	// not a store (stateful: false), so there is no recovery-point safety gate here.
	st, resp, err := d.backupCall("DELETE", region, "/backup/plans/"+planID, nil)
	if err != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown", Reason: fmt.Sprintf("DeleteBackupPlan outcome unknown: %v", err)}
	}
	if st == http.StatusNotFound || strings.Contains(ecsErr(resp), "ResourceNotFound") {
		return provider.CreateResult{ProviderID: providerID, Status: "succeeded"}
	}
	if st >= 500 {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown", Reason: fmt.Sprintf("DeleteBackupPlan HTTP %d (server error) — reconcile", st)}
	}
	if st < 200 || st >= 300 {
		// D237: throttle/503/live-403 -> unknown WITH the pid, never failed.
		if r := provider.MutationResult(st, ecsErr(resp), nil, providerID, "DeleteBackupPlan"); r != nil {
			return *r
		}
		return provider.CreateResult{Status: "failed", Reason: fmt.Sprintf("DeleteBackupPlan HTTP %d: %s", st, ecsErr(resp))}
	}
	return provider.CreateResult{ProviderID: providerID, Status: "succeeded"}
}

// classifyBackupPlanChange (D46): can a transition be honored IN PLACE? PURE provider
// knowledge, no network. UpdateBackupPlan replaces the rule set, so the cadence,
// retention and cross-region copy are mutable; region is a replacement; the selection
// is an operand (not a vocab path, so it never reaches here).
func classifyBackupPlanChange(path string, desired any, impl map[string]any) (string, string) {
	switch path {
	case "schedule.frequency":
		return "mutable", "in-place via UpdateBackupPlan (the rule's ScheduleExpression is replaced)"
	case "retention.duration":
		return "mutable", "in-place via UpdateBackupPlan (the rule's Lifecycle.DeleteAfterDays is replaced)"
	case "copy.crossRegion":
		if desired == true {
			if arn, _ := impl["copyDestinationVaultArn"].(string); arn == "" {
				return "unsupported", "enabling copy.crossRegion needs implementation.copyDestinationVaultArn (the destination vault ARN)"
			}
		}
		return "mutable", "in-place via UpdateBackupPlan (adding/removing the rule's cross-region CopyAction)"
	case "copy.destinationRegion":
		return "mutable", "in-place via UpdateBackupPlan (the CopyAction destination is replaced)"
	case "location.region":
		return "immutable", "a plan's region is fixed at creation — a region change is a new plan (existing recovery points stay in the vault)"
	case "service.managed":
		return "unsupported", "platform/projection property — nothing to patch"
	default:
		return "unsupported", "no Backup plan in-place mapping for " + path
	}
}

// discoverBackupPlans enumerates AWS Backup plans in the region as
// capability.backup.plan: GET /backup/plans/ returns plan ids; observeBackupPlan
// reverse-maps each. A plan whose id is not representable as backupplan:region:planId
// becomes a diagnostic, never a fabricated record.
func (d *Driver) discoverBackupPlans(region string) ([]provider.Discovered, []string, error) {
	st, body, err := d.backupCall("GET", region, "/backup/plans/", nil)
	if err != nil {
		return nil, nil, fmt.Errorf("backup ListBackupPlans: %v", err)
	}
	if st != http.StatusOK {
		return nil, nil, fmt.Errorf("backup ListBackupPlans: HTTP %d: %s", st, ecsErr(body))
	}
	var r struct {
		BackupPlansList []struct {
			BackupPlanId string `json:"BackupPlanId"`
		} `json:"BackupPlansList"`
	}
	if json.Unmarshal(body, &r) != nil {
		return nil, nil, readBody("backup ListBackupPlans", st)
	}
	var out []provider.Discovered
	var diags []string
	for _, pl := range r.BackupPlansList {
		if pl.BackupPlanId == "" {
			continue
		}
		pid := backupPlanProviderID(region, pl.BackupPlanId)
		obs, odiags, oerr := d.observeBackupPlan("", pid)
		if oerr != nil {
			diags = append(diags, pl.BackupPlanId+": "+oerr.Error())
			continue
		}
		for _, dg := range odiags {
			diags = append(diags, pl.BackupPlanId+": "+dg)
		}
		out = append(out, provider.Discovered{
			ProviderID:   pid,
			ResourceType: "capability.backup.plan",
			Observations: obs,
		})
	}
	return out, diags, nil
}
