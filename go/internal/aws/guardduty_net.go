// AWS GuardDuty network shell (D154): the SigV4-signed, REST-JSON half of the AWS
// capability.security.threatdetection driver. GuardDuty speaks REST-JSON at
// guardduty.<region>.amazonaws.com (SigV4 service "guardduty"); the detector is a
// SINGLETON per account per region, addressed under /detector.
//
// Honesty per D29/D87, four-valued throughout:
//   - CREATE pre-reads (ListDetectors). A detector that is OURS (ownership tags)
//     converges; a FOREIGN detector HONEST-REFUSES (one detector per account per
//     region — groundhold can never stand up a second, so it never pretends to).
//   - the detector id is AWS-assigned, so a fresh create's pid is knowable only from
//     the response; a transport/5xx before the id lands is unknown (reconcile via
//     ListDetectors — a singleton, so recovery is unambiguous), never a silent
//     success.
//   - once a detector STANDS, any later config ambiguity (Features / frequency) is
//     unknown WITH the pid (a partial posture to reconcile), never a bare "failed"
//     that hides a standing detector.
//
// DELETE is ownership-tag-gated and idempotent on already-gone. Ownership is the
// tags applied at CreateDetector birth (groundhold-capability / groundhold-environment).
package aws

import (
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strings"

	"groundhold/internal/provider"
)

const guardDutyDetectorPath = "/detector"

// guardDutyDetectorOK bounds a detector id before it is interpolated into a pid or a
// request path (D73 boundary). GuardDuty detector ids are 32-char lowercase hex.
var guardDutyDetectorOK = regexp.MustCompile(`^[0-9a-f]{32}$`)

// guarddutyBaseURLOverride redirects the (regional) GuardDuty endpoint to a test
// server. It lives here rather than on the Driver struct because this driver ships
// entirely in its own files (the Driver struct is not edited); the httptest tests in
// this package do not run in parallel, so a package-level override is safe. Empty =
// real AWS.
var guarddutyBaseURLOverride string

func (d *Driver) guarddutyBase(region string) string {
	if guarddutyBaseURLOverride != "" {
		return guarddutyBaseURLOverride
	}
	return "https://guardduty." + region + ".amazonaws.com"
}

// guarddutyDo is the REST-JSON caller for GuardDuty (SigV4 service "guardduty").
func (d *Driver) guarddutyDo(method, region, path string, body []byte) (int, []byte, error) {
	return d.doSigned(method, d.guarddutyBase(region)+path, "guardduty", region,
		map[string]string{"Content-Type": "application/json"}, body)
}

// guarddutyErr pulls a human string out of a GuardDuty JSON error body.
func guarddutyErr(body []byte) string {
	var e struct {
		Message string `json:"message"`
		Msg     string `json:"Message"`
	}
	_ = json.Unmarshal(body, &e)
	if e.Message != "" {
		return e.Message
	}
	if e.Msg != "" {
		return e.Msg
	}
	return mutDetail(body)
}

func guarddutyIsNotFound(status int, body []byte) bool {
	return status == http.StatusNotFound || strings.Contains(guarddutyErr(body), "NotFound")
}

// guardDutyProviderID pins the identity: guardduty:<region>:<detectorId>.
func guardDutyProviderID(region, detectorID string) string {
	return "guardduty:" + region + ":" + detectorID
}

func splitGuardDutyProviderID(providerID string) (region, detectorID string, err error) {
	parts := strings.SplitN(providerID, ":", 3)
	if len(parts) != 3 || parts[0] != "guardduty" {
		return "", "", fmt.Errorf("providerId %q is not guardduty:region:detectorId", providerID)
	}
	region, detectorID = parts[1], parts[2]
	if !regionOK.MatchString(region) {
		return "", "", fmt.Errorf("providerId region %q is invalid", region)
	}
	if !guardDutyDetectorOK.MatchString(detectorID) {
		return "", "", fmt.Errorf("providerId detectorId %q is invalid", detectorID)
	}
	return region, detectorID, nil
}

// guardDutyDetector is the projection of GetDetector the driver reads. Status drives
// detection.enabled; the Features list drives protection.kubernetes/malware; Tags
// drive the ownership gate for every mutation.
type guardDutyDetector struct {
	Status   string `json:"Status"` // ENABLED | DISABLED
	Features []struct {
		Name   string `json:"Name"`
		Status string `json:"Status"` // ENABLED | DISABLED
	} `json:"Features"`
	FindingPublishingFrequency string            `json:"FindingPublishingFrequency"`
	Tags                       map[string]string `json:"Tags"`
}

// featureEnabled reports whether a named GuardDuty feature is ENABLED.
func (det guardDutyDetector) featureEnabled(name string) bool {
	for _, f := range det.Features {
		if f.Name == name {
			return f.Status == "ENABLED"
		}
	}
	return false
}

// getDetector resolves the detector our id names. (found, readable): a 404 / NotFound
// is found=false+readable (an absent detector, not an error); a transport error or
// any other non-200 is readable=false (unknown — never a fabricated absence).
func (d *Driver) getDetector(region, detectorID string) (guardDutyDetector, bool, error) {
	const op = "GetDetector"
	st, resp, err := d.guarddutyDo("GET", region, guardDutyDetectorPath+"/"+detectorID, nil)
	if err != nil {
		return guardDutyDetector{}, false, readTransport(op, err)
	}
	if guarddutyIsNotFound(st, resp) {
		return guardDutyDetector{}, false, nil
	}
	if st != http.StatusOK {
		return guardDutyDetector{}, false, readHTTP(op, st, ecsErr(resp))
	}
	var det guardDutyDetector
	if json.Unmarshal(resp, &det) != nil {
		return guardDutyDetector{}, false, readBody(op, st)
	}
	return det, true, nil
}

// listDetectorIDs lists the region's detector ids (a singleton — 0 or 1).
// readable=false on any transport/HTTP/parse failure (never a fabricated empty set).
func (d *Driver) listDetectorIDs(region string) ([]string, error) {
	const op = "ListDetectors"
	st, resp, err := d.guarddutyDo("GET", region, guardDutyDetectorPath, nil)
	if err != nil {
		return nil, readTransport(op, err)
	}
	if st != http.StatusOK {
		return nil, readHTTP(op, st, awsErrCodeOf(resp))
	}
	var out struct {
		DetectorIds []string `json:"DetectorIds"`
	}
	if json.Unmarshal(resp, &out) != nil {
		return nil, readBody(op, st)
	}
	return out.DetectorIds, nil
}

// createGuardDuty provisions the region's threat-detection posture, four-valued +
// ownership tags. The detector is a SINGLETON: create pre-reads (ListDetectors) and
//   - converges OURS (ensure the Features/frequency posture via UpdateDetector),
//   - HONEST-REFUSES a FOREIGN detector (one per account+region — never a second),
//   - else CreateDetector (Enable + Features + tags + frequency).
//
// A fresh detector's id is AWS-assigned, so a transport/5xx before it lands is
// unknown (reconcile via ListDetectors), never a silent success.
func (d *Driver) createGuardDuty(region, environment, capability string,
	attrs, impl map[string]any, generation int) provider.CreateResult {
	plan, err := BuildGuardDuty(environment, capability, attrs, impl, generation)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}

	// ---- singleton pre-read: is there already a detector in this region? ----
	ids, lerr := d.listDetectorIDs(region)
	if lerr != nil {
		return provider.CreateResult{Status: "unknown",
			Reason: "pre-create ListDetectors gave no answer — reconcile before provisioning: " + lerr.Error()}
	}
	if len(ids) > 0 {
		existing := ids[0]
		pid := guardDutyProviderID(region, existing)
		det, found, rerr := d.getDetector(region, existing)
		if rerr != nil {
			return provider.CreateResult{ProviderID: pid, Status: "unknown",
				Reason: "a detector exists but is gave no answer — reconcile before provisioning: " + rerr.Error()}
		}
		if !found {
			return provider.CreateResult{ProviderID: pid, Status: "unknown",
				Reason: "a detector was listed but vanished on read — reconcile"}
		}
		if !groundholdTagsMatch(det.Tags, capability, environment) {
			// HONEST-REFUSE: the account already has a GuardDuty detector in this region
			// that groundhold does not own, and only ONE detector may exist per account per
			// region — so groundhold can neither create a second nor silently adopt this one.
			return provider.CreateResult{Status: "failed",
				Reason: "the account already has a GuardDuty detector in " + region + " that is not groundhold-managed " +
					"(one detector per account per region) — refusing to adopt it; adopt it explicitly or remove it"}
		}
		// ours already — converge the posture (idempotent repair of a partial).
		return d.ensureGuardDutyConfig(region, pid, plan)
	}

	// ---- CreateDetector (Enable + Features + frequency + ownership tags) ----
	body := jsonBody(map[string]any{
		"Enable":                     plan.Enabled,
		"Features":                   plan.desiredFeatures(),
		"FindingPublishingFrequency": plan.FindingFrequency,
		"Tags": map[string]string{
			"groundhold-capability":  sanitizeTag(capability),
			"groundhold-environment": sanitizeTag(environment),
		},
	})
	st, resp, err := d.guarddutyDo("POST", region, guardDutyDetectorPath, []byte(body))
	switch {
	case err != nil:
		return provider.CreateResult{Status: "unknown",
			Reason: fmt.Sprintf("CreateDetector outcome unknown (may have landed) — reconcile via ListDetectors: %v", err)}
	case st == http.StatusOK || st == http.StatusCreated:
		// created — recover the AWS-assigned id below
	case strings.Contains(guarddutyErr(resp), "already exists") || strings.Contains(guarddutyErr(resp), "detector already"):
		return provider.CreateResult{Status: "unknown",
			Reason: "CreateDetector says a detector now exists — reconcile ownership via ListDetectors"}
	case st >= 500:
		return provider.CreateResult{Status: "unknown",
			Reason: fmt.Sprintf("CreateDetector HTTP %d (server error — may have landed) — reconcile via ListDetectors: %s", st, guarddutyErr(resp))}
	default:
		return provider.CreateResult{Status: "failed",
			Reason: fmt.Sprintf("CreateDetector HTTP %d: %s", st, guarddutyErr(resp))}
	}
	var out struct {
		DetectorID string `json:"DetectorId"`
	}
	if json.Unmarshal(resp, &out) != nil || out.DetectorID == "" {
		return provider.CreateResult{Status: "unknown",
			Reason: "CreateDetector returned no detector id — reconcile via ListDetectors"}
	}
	return provider.CreateResult{ProviderID: guardDutyProviderID(region, out.DetectorID), Status: "succeeded"}
}

// ensureGuardDutyConfig converges an EXISTING detector's posture (Enable + Features +
// frequency) via UpdateDetector. The detector ALREADY stands, so EVERY failure here
// is unknown WITH the pid (a partial posture to reconcile), NEVER a bare "failed"
// that hides the standing detector (D29/D87). Shared by the create-converge and the
// in-place update paths.
func (d *Driver) ensureGuardDutyConfig(region, pid string, plan GuardDutyPlan) provider.CreateResult {
	_, detectorID, err := splitGuardDutyProviderID(pid)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	body := jsonBody(map[string]any{
		"Enable":                     plan.Enabled,
		"Features":                   plan.desiredFeatures(),
		"FindingPublishingFrequency": plan.FindingFrequency,
	})
	st, resp, err := d.guarddutyDo("POST", region, guardDutyDetectorPath+"/"+detectorID, []byte(body))
	switch {
	case err != nil:
		return provider.CreateResult{ProviderID: pid, Status: "unknown",
			Reason: fmt.Sprintf("detector exists but UpdateDetector outcome unknown (may have landed) — reconcile: %v", err)}
	case st == http.StatusOK:
		return provider.CreateResult{ProviderID: pid, Status: "succeeded"}
	default:
		// the detector STANDS; a config failure is a partial posture, not a clean
		// failure — unknown WITH the pid so the reconcile repairs it, never a bare
		// "failed" that hides a standing detector.
		return provider.CreateResult{ProviderID: pid, Status: "unknown",
			Reason: fmt.Sprintf("detector exists but its posture could not be set (UpdateDetector HTTP %d: %s) — reconcile", st, guarddutyErr(resp))}
	}
}

// observeGuardDuty reverse-maps a live detector to capability.security.threatdetection:
// detection.enabled (Status==ENABLED), protection.kubernetes/malware (the feature
// states), location.region, service.managed. An unreadable detector is unknown (an
// error); a not-found detector is nothing-to-observe.
func (d *Driver) observeGuardDuty(capability, providerID string) ([]provider.Observation, []string, error) {
	region, detectorID, err := splitGuardDutyProviderID(providerID)
	if err != nil {
		return nil, nil, err
	}
	det, found, rerr := d.getDetector(region, detectorID)
	if rerr != nil {
		return nil, nil, rerr
	}
	if !found {
		return nil, []string{"detector not found — nothing to observe"}, nil
	}
	obs := []provider.Observation{
		{Path: "location.region", Value: region, Derivation: "measured"},
		{Path: "detection.enabled", Value: det.Status == "ENABLED", Derivation: "measured"},
		{Path: "protection.kubernetes", Value: det.featureEnabled(gdFeatureEKSAuditLogs), Derivation: "measured"},
		{Path: "protection.malware", Value: det.featureEnabled(gdFeatureEBSMalware), Derivation: "measured"},
		{Path: "service.managed", Value: true, Derivation: "measured"},
	}
	return obs, nil, nil
}

// updateGuardDuty patches a bound detector's posture IN PLACE (D46): detection.enabled
// and the protection.* surface all flow through a single UpdateDetector. Ownership
// tags gate the patch; the desired shape is re-derived (refuse-before-mutate) from the
// hash-pinned candidate attrs+impl; four-valued throughout (an ambiguous outcome is
// unknown WITH the providerId, never a silent success).
func (d *Driver) updateGuardDuty(capability, environment, providerID string,
	attrs, impl map[string]any, changes []string) provider.CreateResult {
	region, detectorID, err := splitGuardDutyProviderID(providerID)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	// gate the change-set: every path must be one this service patches in place.
	for _, path := range changes {
		if kind, reason := classifyGuardDutyChange(path); kind != "mutable" {
			return provider.CreateResult{Status: "failed",
				Reason: fmt.Sprintf("guardduty cannot honor an in-place change to %q: %s", path, reason)}
		}
	}
	// refuse-before-mutate: re-derive + validate the full desired posture.
	plan, err := BuildGuardDuty(environment, capability, attrs, impl, 1)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	// ownership re-check before mutating (refuse a foreign detector).
	det, found, rerr := d.getDetector(region, detectorID)
	if rerr != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown",
			Reason: "pre-update ownership read gave no answer — reconcile before patching: " + rerr.Error()}
	}
	if !found {
		return provider.CreateResult{Status: "failed", Reason: "detector no longer exists — cannot update"}
	}
	if !groundholdTagsMatch(det.Tags, capability, environment) {
		return provider.CreateResult{Status: "failed",
			Reason: "detector tags do not match — refusing to patch a resource that is not ours"}
	}
	// one UpdateDetector carries the whole desired posture (Enable + Features).
	return d.ensureGuardDutyConfig(region, providerID, plan)
}

// deleteGuardDuty removes a detector groundhold created, ownership-gated. Deleting the
// detector is a POSTURE change (threat detection off), not the loss of a store —
// GuardDuty findings live in the service, not in the detector object (stateless).
// Idempotent on already-gone (404); a transport/5xx is unknown WITH the pid
// (reconcile), never a claimed success.
func (d *Driver) deleteGuardDuty(capability, environment, providerID string) provider.CreateResult {
	region, detectorID, err := splitGuardDutyProviderID(providerID)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	det, found, rerr := d.getDetector(region, detectorID)
	if rerr != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown", Reason: "pre-delete read gave no answer — reconcile: " + rerr.Error()}
	}
	if !found {
		return provider.CreateResult{ProviderID: providerID, Status: "succeeded"} // idempotent — already gone
	}
	// ownership guard: refuse a foreign detector.
	if !groundholdTagsMatch(det.Tags, capability, environment) {
		return provider.CreateResult{Status: "failed",
			Reason: "detector tags do not match — refusing to delete a resource that is not ours"}
	}
	st, body, err := d.guarddutyDo("DELETE", region, guardDutyDetectorPath+"/"+detectorID, nil)
	switch {
	case err != nil:
		return provider.CreateResult{ProviderID: providerID, Status: "unknown", Reason: fmt.Sprintf("DeleteDetector outcome unknown: %v", err)}
	case st == http.StatusOK || st == http.StatusNoContent || guarddutyIsNotFound(st, body):
		return provider.CreateResult{ProviderID: providerID, Status: "succeeded"}
	case st >= 500:
		return provider.CreateResult{ProviderID: providerID, Status: "unknown", Reason: fmt.Sprintf("DeleteDetector HTTP %d (server error) — reconcile", st)}
	default:
		return provider.CreateResult{Status: "failed", Reason: fmt.Sprintf("DeleteDetector HTTP %d: %s", st, guarddutyErr(body))}
	}
}

// discoverGuardDuty enumerates the region's detector (a singleton) as
// capability.security.threatdetection — so `discover --provider aws` surfaces the
// threat-detection posture for adoption. Reuses observeGuardDuty (two-step:
// ListDetectors -> per-detector reverse map).
func (d *Driver) discoverGuardDuty(region string) ([]provider.Discovered, []string, error) {
	ids, lerr := d.listDetectorIDs(region)
	if lerr != nil {
		return nil, nil, lerr
	}
	var found []provider.Discovered
	var diags []string
	for _, id := range ids {
		if !guardDutyDetectorOK.MatchString(id) {
			diags = append(diags, id+": detector id not representable as a providerId")
			continue
		}
		pid := guardDutyProviderID(region, id)
		obs, od, oerr := d.observeGuardDuty("", pid)
		if oerr != nil {
			diags = append(diags, id+": "+oerr.Error())
			continue
		}
		diags = append(diags, od...)
		found = append(found, provider.Discovered{
			ProviderID: pid, ResourceType: "capability.security.threatdetection", Observations: obs})
	}
	return found, diags, nil
}
