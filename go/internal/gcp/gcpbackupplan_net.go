// GCP Backup and DR backup-plan network shell (D76 fala 4): the httptest-covered half
// of the GCP capability.backup.plan driver. It shares the vault's API host, so it
// REUSES the vault shell's d.backupDRBase() and d.pollBackupDROperation() rather than
// duplicating them. The endpoints:
//
//	backupPlans.create  POST   /projects/{p}/locations/{loc}/backupPlans?backupPlanId={id}  (LRO)
//	backupPlans.get     GET    /projects/{p}/locations/{loc}/backupPlans/{id}
//	backupPlans.patch   PATCH  /projects/{p}/locations/{loc}/backupPlans/{id}?updateMask=backupRules (LRO)
//	backupPlans.delete  DELETE /projects/{p}/locations/{loc}/backupPlans/{id}                (LRO)
//	backupPlans.list    GET    /projects/{p}/locations/{loc}/backupPlans
//
// The plan id is DETERMINISTIC (a slug+hash), so the providerId
// (gbkplan:project:location:planId) is knowable BEFORE the create response (D29).
// Ownership is LABELS; a foreign plan is refused, never mutated. Unlike the vault,
// delete has NO data-loss friction: a plan is a schedule (stateful:false) — deleting it
// stops future backups, it never removes recovery points already written (they age out
// under the vault's retention/lock).
package gcp

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"groundhold/internal/provider"
)

func gbpProviderID(project, location, planID string) string {
	return "gbkplan:" + project + ":" + location + ":" + planID
}

func splitGbpProviderID(providerID string) (project, location, planID string, err error) {
	parts := strings.Split(providerID, ":")
	if len(parts) != 4 || parts[0] != "gbkplan" {
		return "", "", "", fmt.Errorf("providerId %q is not gbkplan:project:location:planId", providerID)
	}
	for i, p := range parts[1:] {
		if !gcpName.MatchString(p) {
			return "", "", "", fmt.Errorf("providerId component %d (%q) is not a valid GCP identifier", i+1, p)
		}
	}
	return parts[1], parts[2], parts[3], nil
}

func (d *Driver) gbpPlanURL(project, location, planID string) string {
	return fmt.Sprintf("%s/projects/%s/locations/%s/backupPlans/%s", d.backupDRBase(), project, location, planID)
}

// gbpRule is the observed shape of a backupRules[] element (only the semantic paths).
type gbpRule struct {
	BackupRetentionDays int `json:"backupRetentionDays"`
	StandardSchedule    struct {
		RecurrenceType  string `json:"recurrenceType"`
		HourlyFrequency int    `json:"hourlyFrequency"`
	} `json:"standardSchedule"`
}

type gbpDoc struct {
	Labels      map[string]string `json:"labels"`
	BackupRules []gbpRule         `json:"backupRules"`
}

func (doc gbpDoc) ours(capability, environment string) bool {
	return doc.Labels["groundhold-capability"] == sanitizeLabel(capability) &&
		doc.Labels["groundhold-environment"] == sanitizeLabel(environment)
}

// gbpGet reads a plan. found=false + readable=true is authoritative "does not exist";
// readable=false is transport/HTTP/parse failure.
func (d *Driver) gbpGet(project, location, planID string) (gbpDoc, bool, error) {
	const op = "gbpGet.get"
	st, body, err := d.call("GET", d.gbpPlanURL(project, location, planID), nil)
	if err != nil {
		return gbpDoc{}, false, readTransport(op, err)
	}
	if st == http.StatusNotFound {
		return gbpDoc{}, false, nil
	}
	if st != http.StatusOK {
		return gbpDoc{}, false, readHTTP(op, st, gcpErrCode(body))
	}
	var doc gbpDoc
	if json.Unmarshal(body, &doc) != nil {
		return gbpDoc{}, false, readBody(op, st)
	}
	return doc, true, nil
}

func (d *Driver) createBackupPlanGCP(capability, environment string,
	attrs, impl map[string]any, generation int) provider.CreateResult {
	plan, err := BuildBackupPlanGCP(d.Project, environment, capability, attrs, impl, generation)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	pid := gbpProviderID(d.Project, plan.Location, plan.PlanID)
	url := fmt.Sprintf("%s/projects/%s/locations/%s/backupPlans?backupPlanId=%s",
		d.backupDRBase(), d.Project, plan.Location, plan.PlanID)
	st, body, err := d.call("POST", url, plan.createBody())
	switch {
	case err != nil:
		return provider.CreateResult{ProviderID: pid, Status: "unknown",
			Reason: fmt.Sprintf("backupPlans.create outcome unknown (may have landed): %v", err)}
	case st == http.StatusConflict:
		doc, found, rerr := d.gbpGet(d.Project, plan.Location, plan.PlanID)
		if rerr != nil {
			return provider.CreateResult{ProviderID: pid, Status: "unknown", Reason: "name conflict, existing plan gave no answer — reconcile: " + rerr.Error()}
		}
		if !found || !doc.ours(capability, environment) {
			return provider.CreateResult{Status: "failed", Reason: "a backup plan with this id exists and is not ours (labels do not match)"}
		}
		return provider.CreateResult{ProviderID: pid, Status: "succeeded"}
	case st >= 500:
		return provider.CreateResult{ProviderID: pid, Status: "unknown",
			Reason: fmt.Sprintf("backupPlans.create HTTP %d (server error — may have landed): %s", st, mutDetail(body))}
	case st >= 400:
		return provider.CreateResult{Status: "failed",
			Reason: fmt.Sprintf("backupPlans.create HTTP %d: %s", st, mutDetail(body))}
	}
	var op struct {
		Name string `json:"name"`
	}
	if json.Unmarshal(body, &op) != nil || op.Name == "" {
		return provider.CreateResult{ProviderID: pid, Status: "unknown", Reason: "create response carried no operation — reconcile"}
	}
	res := d.pollBackupDROperation(op.Name)
	res.ProviderID = pid
	return res
}

func (d *Driver) observeBackupPlanGCP(capability, providerID string) ([]provider.Observation, []string, error) {
	project, location, planID, err := splitGbpProviderID(providerID)
	if err != nil {
		return nil, nil, err
	}
	if err := d.sameProject(project); err != nil {
		return nil, nil, err
	}
	doc, found, rerr := d.gbpGet(project, location, planID)
	if rerr != nil {
		return nil, nil, rerr
	}
	if !found {
		// F-LC3 (D519): a BOUND resource the API authoritatively 404s is GONE.
		// A diagnostic alone leaves the binding a no-op forever (D513).
		return []provider.Observation{
			{Path: provider.ResourceAbsentPath, Value: true, Derivation: "measured"},
		}, []string{"backup plan not found — bound resource is gone (will re-create)"}, nil
	}
	obs := []provider.Observation{
		// Present: clear the marker (F-LC3), or a stale "gone" survives a re-create.
		{Path: provider.ResourceAbsentPath, Value: false, Derivation: "measured"},
		{Path: "location.region", Value: location, Derivation: "measured"},
		{Path: "service.managed", Value: true, Derivation: "measured"},
		// A backupdr backup plan has no cross-region copy — the posture is always false,
		// and that is a MEASURED fact, not an omission (contrast AWS Backup CopyActions).
		{Path: "copy.crossRegion", Value: false, Derivation: "measured"},
	}
	var diags []string
	if len(doc.BackupRules) == 0 {
		return obs, []string{"backup plan has no rules — cadence/retention unobservable"}, nil
	}
	if len(doc.BackupRules) > 1 {
		diags = append(diags, "backup plan has multiple rules — observing the first (cadence/retention from rule[0])")
	}
	rule := doc.BackupRules[0]
	if freq, ok := gbpScheduleToFrequency(rule.StandardSchedule.RecurrenceType, rule.StandardSchedule.HourlyFrequency); ok {
		obs = append(obs, provider.Observation{Path: "schedule.frequency", Value: freq, Derivation: "measured"})
	} else if rule.StandardSchedule.RecurrenceType != "" {
		diags = append(diags, "recurrence "+rule.StandardSchedule.RecurrenceType+
			" has no fixed-duration cadence — schedule.frequency omitted (RPO not derivable)")
	}
	if rule.BackupRetentionDays > 0 {
		obs = append(obs, provider.Observation{Path: "retention.duration",
			Value: fmt.Sprintf("%dh", rule.BackupRetentionDays*24), Derivation: "measured"})
	}
	return obs, diags, nil
}

func (d *Driver) updateBackupPlanGCP(capability, environment, providerID string,
	attrs, impl map[string]any, changes []string) provider.CreateResult {
	project, location, planID, err := splitGbpProviderID(providerID)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	if err := d.sameProject(project); err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	// refuse-before-mutate: re-derive + validate the full desired shape (e.g.
	// copy.crossRegion=true refuses here, honestly, before any patch).
	plan, err := BuildBackupPlanGCP(project, environment, capability, attrs, impl, 1)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	// ownership re-check before mutating: read the labels.
	doc, found, rerr := d.gbpGet(project, location, planID)
	if rerr != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown", Reason: "pre-update ownership read gave no answer — reconcile: " + rerr.Error()}
	}
	if !found {
		return provider.CreateResult{Status: "failed", Reason: "backup plan no longer exists — cannot update"}
	}
	if !doc.ours(capability, environment) {
		return provider.CreateResult{Status: "failed",
			Reason: "backup plan labels do not match — refusing to patch a resource that is not ours"}
	}
	// patch the rule set — every mutable semantic path (schedule.frequency /
	// retention.duration) lives in backupRules, so one masked patch covers `changes`.
	url := d.gbpPlanURL(project, location, planID) + "?updateMask=backupRules"
	st, body, err := d.call("PATCH", url, plan.patchBody())
	switch {
	case err != nil:
		return provider.CreateResult{ProviderID: providerID, Status: "unknown",
			Reason: fmt.Sprintf("backupPlans.patch outcome unknown (may have landed): %v", err)}
	case st >= 500:
		return provider.CreateResult{ProviderID: providerID, Status: "unknown",
			Reason: fmt.Sprintf("backupPlans.patch HTTP %d (server error — may have landed)", st)}
	case st >= 400:
		return provider.CreateResult{Status: "failed",
			Reason: fmt.Sprintf("backupPlans.patch HTTP %d: %s", st, mutDetail(body))}
	}
	var op struct {
		Name string `json:"name"`
	}
	if json.Unmarshal(body, &op) != nil || op.Name == "" {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown", Reason: "patch response carried no operation — reconcile"}
	}
	res := d.pollBackupDROperation(op.Name)
	res.ProviderID = providerID // identity survives an update
	return res
}

// classifyBackupPlanGCPChange (D46): can a transition be honored IN PLACE? PURE
// provider knowledge, no network. backupPlans.patch replaces backupRules, so cadence
// and retention are mutable; location is a replacement; cross-region copy is not a
// backupdr plan capability at all (honest unsupported, never a silent claim).
func classifyBackupPlanGCPChange(path string, desired any) (string, string) {
	switch path {
	case "schedule.frequency":
		return "mutable", "in-place via backupPlans.patch (the rule's standardSchedule recurrence is replaced)"
	case "retention.duration":
		return "mutable", "in-place via backupPlans.patch (the rule's backupRetentionDays is replaced)"
	case "copy.crossRegion":
		if desired == true {
			return "unsupported", "GCP Backup and DR backup plans have no cross-region copy — the backupdr schema has no destination-region copy field (unlike AWS Backup CopyActions)"
		}
		return "unsupported", "GCP Backup and DR backup plans have no cross-region copy — nothing to patch (the posture is always false)"
	case "copy.destinationRegion":
		return "unsupported", "GCP Backup and DR backup plans have no cross-region copy destination to patch"
	case "location.region":
		return "immutable", "a plan's location is fixed at creation — a location change is a new plan (existing recovery points stay in the vault)"
	case "service.managed":
		return "unsupported", "platform/projection property — nothing to patch"
	default:
		return "unsupported", "no Backup and DR plan in-place mapping for " + path
	}
}

func (d *Driver) deleteBackupPlanGCP(capability, environment, providerID string) provider.CreateResult {
	project, location, planID, err := splitGbpProviderID(providerID)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	if err := d.sameProject(project); err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	doc, found, rerr := d.gbpGet(project, location, planID)
	if rerr != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown", Reason: "pre-delete read gave no answer — reconcile: " + rerr.Error()}
	}
	if !found {
		return provider.CreateResult{ProviderID: providerID, Status: "succeeded"} // idempotent
	}
	if !doc.ours(capability, environment) {
		return provider.CreateResult{Status: "failed",
			Reason: "backup plan labels do not match — refusing to delete a resource that is not ours"}
	}
	// A plan is a schedule (stateful:false): deleting it stops future backups but never
	// removes recovery points already written (they age out under the vault). No
	// data-loss safety gate here (contrast the vault's holds-backups refusal).
	st, body, err := d.call("DELETE", d.gbpPlanURL(project, location, planID), nil)
	if err != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown", Reason: fmt.Sprintf("delete outcome unknown: %v", err)}
	}
	if st == http.StatusNotFound {
		return provider.CreateResult{ProviderID: providerID, Status: "succeeded"}
	}
	if st >= 500 {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown", Reason: fmt.Sprintf("delete HTTP %d (server error) — reconcile", st)}
	}
	if st >= 400 {
		return provider.CreateResult{Status: "failed", Reason: fmt.Sprintf("delete HTTP %d: %s", st, mutDetail(body))}
	}
	var op struct {
		Name string `json:"name"`
	}
	if json.Unmarshal(body, &op) != nil || op.Name == "" {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown", Reason: "delete response carried no operation — reconcile"}
	}
	res := d.pollBackupDROperation(op.Name)
	res.ProviderID = providerID
	return res
}

// discoverBackupPlansGCP enumerates Backup and DR backup plans as
// capability.backup.plan, reusing observeBackupPlanGCP. A given region is swept
// directly; an empty region enumerates the project's locations first (reusing the
// vault's backupDRDiscoverLocations). A per-location list failure is a diagnostic — it
// never hides the plans another location returned. Plans are regional, so region
// filters on the swept location.
func (d *Driver) discoverBackupPlansGCP(region string) ([]provider.Discovered, []string, error) {
	return d.sweepEachLocation(region, d.backupDRDiscoverLocations,
		func(loc string) ([]provider.Discovered, []string, error) {
			var out []provider.Discovered
			var diags []string
			status, body, err := d.call("GET", fmt.Sprintf(
				"%s/projects/%s/locations/%s/backupPlans", d.backupDRBase(), d.Project, loc), nil)
			if err != nil {
				// D642: the LIST failed — this location was not read.
				return nil, nil, fmt.Errorf("%s", "backupPlans.list "+loc+": "+err.Error())
			}
			if status != http.StatusOK {
				// D642: the LIST failed — this location was not read.
				return nil, nil, fmt.Errorf("%s", fmt.Sprintf("backupPlans.list %s: HTTP %d", loc, status))
			}
			var resp struct {
				BackupPlans []struct {
					Name string `json:"name"`
				} `json:"backupPlans"`
			}
			if err := json.Unmarshal(body, &resp); err != nil {
				// D642: the LIST failed — this location was not read.
				return nil, nil, fmt.Errorf("%s", loc+": "+readBody("backupPlans.list", status).Error())
			}
			for _, pl := range resp.BackupPlans {
				planID := leafName(pl.Name)
				if planID == "" {
					continue
				}
				pid := gbpProviderID(d.Project, loc, planID)
				obs, odiags, oerr := d.observeBackupPlanGCP("", pid)
				if oerr != nil {
					diags = append(diags, planID+": "+oerr.Error())
					continue
				}
				for _, dg := range odiags {
					diags = append(diags, planID+": "+dg)
				}
				out = append(out, provider.Discovered{
					ProviderID:   pid,
					ResourceType: "capability.backup.plan",
					Observations: provider.WithoutAbsence(obs),
				})
			}
			return out, diags, nil
		})
}
