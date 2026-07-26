// GCP Cloud Logging log bucket network shell (D76 parity slice): the bearer-signed
// REST half of the capability.monitoring.logs driver. buckets.create/patch/delete
// are SYNCHRONOUS (no LRO). The bucket is content-addressed by (project, location,
// id); a 409 continues only if the existing bucket is OURS (description marker).
// retention.days and CMEK are patchable in place (the mutable ⇒ updater invariant).
// A LOCKED bucket refuses delete — a compliance hold is never auto-lifted (D47).
package gcp

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"groundhold/internal/provider"
)

// gcpLogBucketProviderID: service-prefixed with the location (log buckets are
// per-location, and buckets.list wildcards location, so the location must survive
// in the handle). Format: gcp-logbucket:<project>:<location>:<bucket>.
func gcpLogBucketProviderID(project, location, bucket string) string {
	return "gcp-logbucket:" + project + ":" + location + ":" + bucket
}

// splitLogBucketProviderID validates every component before path interpolation (D73).
func splitLogBucketProviderID(providerID string) (project, location, bucket string, err error) {
	parts := strings.Split(providerID, ":")
	if len(parts) != 4 || parts[0] != "gcp-logbucket" {
		return "", "", "", fmt.Errorf(
			"providerId %q is not gcp-logbucket:project:location:bucket", providerID)
	}
	if !projectOK.MatchString(parts[1]) {
		return "", "", "", fmt.Errorf("providerId project %q is invalid", parts[1])
	}
	if !logBucketLocationOK.MatchString(parts[2]) {
		return "", "", "", fmt.Errorf("providerId location %q is invalid", parts[2])
	}
	if !logBucketIDOK.MatchString(parts[3]) {
		return "", "", "", fmt.Errorf("providerId bucket %q is invalid", parts[3])
	}
	return parts[1], parts[2], parts[3], nil
}

func (d *Driver) logBucketParentURL(project, location string) string {
	return fmt.Sprintf("%s/projects/%s/locations/%s/buckets",
		d.loggingBase(), project, location)
}

func (d *Driver) logBucketURL(project, location, bucket string) string {
	return fmt.Sprintf("%s/projects/%s/locations/%s/buckets/%s",
		d.loggingBase(), project, location, bucket)
}

type logBucketDoc struct {
	Name          string `json:"name"`
	Description   string `json:"description"`
	RetentionDays int    `json:"retentionDays"`
	Locked        bool   `json:"locked"`
	CmekSettings  struct {
		KmsKeyName string `json:"kmsKeyName"`
	} `json:"cmekSettings"`
	LifecycleState string `json:"lifecycleState"`
}

// getLogBucket is three-valued: (doc, found, readable). Unreadable is never
// "not found" — a transport error or a non-404 error stays inconclusive.
func (d *Driver) getLogBucket(project, location, bucket string) (logBucketDoc, bool, error) {
	const op = "logBucket.get"
	st, body, err := d.call("GET", d.logBucketURL(project, location, bucket), nil)
	if err != nil {
		return logBucketDoc{}, false, readTransport(op, err)
	}
	if st == http.StatusNotFound {
		return logBucketDoc{}, false, nil
	}
	if st != http.StatusOK {
		return logBucketDoc{}, false, readHTTP(op, st, gcpErrCode(body))
	}
	var doc logBucketDoc
	if json.Unmarshal(body, &doc) != nil {
		return logBucketDoc{}, false, readBody(op, st)
	}
	return doc, true, nil
}

// createLogBucket: build -> POST buckets.create?bucketId= (synchronous). The
// deterministic id makes the providerId knowable BEFORE the response, so a
// lost/garbled outcome (D29) still carries the handle to reconcile (never orphaned).
func (d *Driver) createLogBucket(capability, environment string,
	attrs, impl map[string]any, generation int) provider.CreateResult {
	plan, err := BuildLogBucket(d.Project, environment, capability, attrs, impl, generation)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	pid := gcpLogBucketProviderID(d.Project, plan.Location, plan.BucketID)
	url := d.logBucketParentURL(d.Project, plan.Location) + "?bucketId=" + plan.BucketID
	st, body, e := d.call("POST", url, plan.createBody())
	switch {
	case e != nil:
		return provider.CreateResult{ProviderID: pid, Status: "unknown",
			Reason: fmt.Sprintf("create outcome unknown (may have landed): %v", e)}
	case st == http.StatusOK || st == http.StatusCreated:
		return provider.CreateResult{ProviderID: pid, Status: "succeeded"}
	case st == http.StatusConflict:
		doc, found, rerr := d.getLogBucket(d.Project, plan.Location, plan.BucketID)
		if rerr != nil {
			return provider.CreateResult{ProviderID: pid, Status: "unknown",
				Reason: "name conflict, existing bucket gave no answer — reconcile: " + rerr.Error()}
		}
		if !found || doc.Description != plan.Description {
			return provider.CreateResult{Status: "failed",
				Reason: "a log bucket with this id exists and is not ours " +
					"(description marker does not match) — adopt is an explicit action, " +
					"not a conflict handler"}
		}
		return provider.CreateResult{ProviderID: pid, Status: "succeeded"}
	case st >= 500:
		return provider.CreateResult{ProviderID: pid, Status: "unknown",
			Reason: fmt.Sprintf("create HTTP %d (server error — may have landed) — reconcile", st)}
	default:
		return provider.CreateResult{Status: "failed",
			Reason: fmt.Sprintf("create HTTP %d: %s", st, mutDetail(body))}
	}
}

// observeLogBucket reverse-maps a live log bucket. location.region is authoritative
// from the providerId (already validated); retention.days maps back from the integer
// retentionDays; customerManagedKeys is TRUE iff a CMEK key is set (the Google-
// managed default carries no id and does NOT satisfy the constraint — emit nothing).
func (d *Driver) observeLogBucket(capability, providerID string) ([]provider.Observation, []string, error) {
	project, location, bucket, err := splitLogBucketProviderID(providerID)
	if err != nil {
		return nil, nil, err
	}
	if err := d.sameProject(project); err != nil {
		return nil, nil, err
	}
	doc, found, rerr := d.getLogBucket(project, location, bucket)
	if rerr != nil {
		return nil, nil, rerr
	}
	if !found {
		return nil, []string{"log bucket not found — nothing to observe"}, nil
	}
	obs := []provider.Observation{
		{Path: "location.region", Value: location, Derivation: "measured"},
		{Path: "service.managed", Value: true, Derivation: "measured"},
	}
	if doc.RetentionDays > 0 {
		obs = append(obs, provider.Observation{Path: "retention.days",
			Value: fmt.Sprintf("%dd", doc.RetentionDays), Derivation: "measured"})
	}
	if doc.CmekSettings.KmsKeyName != "" {
		obs = append(obs, provider.Observation{Path: "encryption.customerManagedKeys",
			Value: true, Derivation: "measured"})
	}
	return obs, nil, nil
}

// updateLogBucket patches mutable attributes in place (the mutable ⇒ updater
// invariant): retention.days (updateMask=retentionDays) and CMEK
// (updateMask=cmekSettings.kmsKeyName). Ownership (description marker) is re-checked
// first; classifyLogBucketChange already gated the change set, so a non-patchable
// path here is a bug — refused, never silently applied.
func (d *Driver) updateLogBucket(capability, environment, providerID string,
	attrs, impl map[string]any, changes []string) provider.CreateResult {
	project, location, bucket, err := splitLogBucketProviderID(providerID)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	if err := d.sameProject(project); err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	doc, found, rerr := d.getLogBucket(project, location, bucket)
	if rerr != nil {
		return provider.CreateResult{Status: "unknown",
			Reason: "pre-update read gave no answer — reconcile: " + rerr.Error()}
	}
	if !found {
		return provider.CreateResult{Status: "unknown",
			Reason: "log bucket not found — the update's target vanished; re-observe before concluding"}
	}
	if doc.Description != logBucketDescription(capability, environment) {
		return provider.CreateResult{Status: "failed",
			Reason: "log bucket description marker does not match — refusing to patch a resource that is not ours"}
	}

	patch := map[string]any{}
	var masks []string
	for _, path := range changes {
		switch path {
		case "retention.days":
			days, derr := logBucketRetentionDays(attrs[path])
			if derr != nil {
				return provider.CreateResult{Status: "failed", Reason: derr.Error()}
			}
			patch["retentionDays"] = days
			masks = append(masks, "retentionDays")
		case "encryption.customerManagedKeys":
			want, _ := attrs[path].(bool)
			key := ""
			if want {
				key, _ = impl["kms_key_name"].(string)
				if key == "" {
					return provider.CreateResult{Status: "failed",
						Reason: "encryption.customerManagedKeys=true requires implementation.kms_key_name"}
				}
			}
			// empty kmsKeyName reverts to the Google-managed default (CMEK off).
			patch["cmekSettings"] = map[string]any{"kmsKeyName": key}
			masks = append(masks, "cmekSettings.kmsKeyName")
		default:
			return provider.CreateResult{Status: "failed",
				Reason: fmt.Sprintf("path %s is not patchable in place on a log bucket (ClassifyChange should have refused it)", path)}
		}
	}
	if len(masks) == 0 {
		return provider.CreateResult{Status: "failed",
			Reason: "update carried no patchable paths"}
	}
	url := d.logBucketURL(project, location, bucket) + "?updateMask=" + strings.Join(masks, ",")
	st, body, e := d.call("PATCH", url, patch)
	if e != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown",
			Reason: fmt.Sprintf("patch outcome unknown: %v", e)}
	}
	if st >= 500 {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown",
			Reason: fmt.Sprintf("patch HTTP %d (server error) — reconcile", st)}
	}
	if st >= 400 {
		return provider.CreateResult{Status: "failed",
			Reason: fmt.Sprintf("patch HTTP %d: %s", st, mutDetail(body))}
	}
	return provider.CreateResult{ProviderID: providerID, Status: "succeeded"} // identity survives an update
}

// deleteLogBucket: ownership pre-read (description marker) + a LOCKED-bucket guard,
// then DELETE (synchronous). 404 is idempotent success; a locked bucket refuses
// (a compliance hold, never auto-lifted); D29 keeps the handle on a lost/5xx outcome.
func (d *Driver) deleteLogBucket(capability, environment, providerID string) provider.CreateResult {
	project, location, bucket, err := splitLogBucketProviderID(providerID)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	if err := d.sameProject(project); err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	doc, found, rerr := d.getLogBucket(project, location, bucket)
	if rerr != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown",
			Reason: "pre-delete read gave no answer — reconcile: " + rerr.Error()}
	}
	if !found {
		return provider.CreateResult{ProviderID: providerID, Status: "succeeded"} // idempotent
	}
	if doc.Description != logBucketDescription(capability, environment) {
		return provider.CreateResult{Status: "failed",
			Reason: "log bucket description marker does not match — refusing to delete a resource that is not ours"}
	}
	if doc.Locked {
		return provider.CreateResult{Status: "failed",
			Reason: "log bucket is LOCKED — deletion is blocked by a compliance hold, never auto-lifted"}
	}
	st, body, e := d.call("DELETE", d.logBucketURL(project, location, bucket), nil)
	if e != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown",
			Reason: fmt.Sprintf("delete outcome unknown: %v", e)}
	}
	if st == http.StatusNotFound {
		return provider.CreateResult{ProviderID: providerID, Status: "succeeded"}
	}
	if st >= 500 {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown",
			Reason: fmt.Sprintf("delete HTTP %d (server error) — reconcile", st)}
	}
	if st < 200 || st >= 300 {
		return provider.CreateResult{ProviderID: providerID, Status: "failed",
			Reason: fmt.Sprintf("delete HTTP %d: %s", st, mutDetail(body))}
	}
	return provider.CreateResult{ProviderID: providerID, Status: "succeeded"}
}

// logBucketLocationName parses (location, id) out of a log bucket resource name
// (projects/p/locations/<loc>/buckets/<id>).
func logBucketLocationName(resourceName string) (loc, id string, ok bool) {
	li := strings.Index(resourceName, "/locations/")
	bi := strings.Index(resourceName, "/buckets/")
	if li < 0 || bi < 0 || bi < li {
		return "", "", false
	}
	loc = resourceName[li+len("/locations/") : bi]
	id = resourceName[bi+len("/buckets/"):]
	if loc == "" || id == "" {
		return "", "", false
	}
	return loc, id, true
}

// discoverLogBuckets enumerates Cloud Logging buckets as capability.monitoring.logs,
// reusing observeLogBucket's reverse map. The aggregated list (locations/-) spans
// every location; region, when given, filters on the bucket's own location parsed
// from its resource name. System buckets (_Default/_Required) whose id does not pass
// the path-safety gate are skipped with a diagnostic, never a fabricated handle.
func (d *Driver) discoverLogBuckets(region string) ([]provider.Discovered, []string, error) {
	loc := region
	if loc == "" {
		loc = "-"
	}
	status, body, err := d.call("GET", d.logBucketParentURL(d.Project, loc), nil)
	if err != nil {
		return nil, nil, fmt.Errorf("buckets.list: %v", err)
	}
	if status != http.StatusOK {
		return nil, nil, fmt.Errorf("buckets.list: HTTP %d", status)
	}
	var resp struct {
		Buckets []struct {
			Name string `json:"name"`
		} `json:"buckets"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, nil, readBody("buckets.list", status)
	}
	var out []provider.Discovered
	var diags []string
	for _, b := range resp.Buckets {
		bloc, id, ok := logBucketLocationName(b.Name)
		if !ok {
			continue
		}
		if region != "" && bloc != region {
			continue // another location — not this sweep
		}
		if !logBucketIDOK.MatchString(id) || !logBucketLocationOK.MatchString(bloc) {
			diags = append(diags, id+": not a path-safe log bucket handle — skipped")
			continue
		}
		pid := gcpLogBucketProviderID(d.Project, bloc, id)
		obs, odiags, oerr := d.observeLogBucket("", pid)
		if oerr != nil {
			diags = append(diags, id+": "+oerr.Error())
			continue
		}
		for _, dg := range odiags {
			diags = append(diags, id+": "+dg)
		}
		out = append(out, provider.Discovered{
			ProviderID:   pid,
			ResourceType: "capability.monitoring.logs",
			Observations: obs,
		})
	}
	return out, diags, nil
}
