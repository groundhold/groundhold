// AWS CloudTrail network shell (audit-trail slice): the SigV4-signed, JSON-1.1 half of
// the AWS capability.audit.trail driver. CloudTrail is a REGION-scoped JSON service
// (endpoint cloudtrail.<region>.amazonaws.com, X-Amz-Target
// com.amazonaws.cloudtrail.v20131101.CloudTrail_20131101.<Action>). A create is a
// COMPOSITE (D26): CreateTrail then StartLogging — a configured-but-stopped trail is a
// silent audit gap, never a success. Honesty per D29/D87: the trail name is
// deterministic, so the providerId is knowable BEFORE the response and rides on every
// ambiguous outcome; once the trail lands, ANY later failure (StartLogging padł) is
// unknown WITH the providerId (a standing-but-not-logging trail to reconcile), never a
// bare "failed" that hides it and never a silent half-provision. Ownership is tags
// applied at CreateTrail birth and read via ListTags; a foreign trail (tags do not
// match) is refused before any mutation. No live AWS validation in this env — code +
// golden httptest certified.
package aws

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"groundhold/internal/adoptcheck"
	"groundhold/internal/provider"
)

// cloudTrailTarget is the X-Amz-Target service prefix (AWS JSON 1.1) for the
// CloudTrail_20131101 API.
const cloudTrailTarget = "com.amazonaws.cloudtrail.v20131101.CloudTrail_20131101"

// cloudTrailBaseURLOverride redirects the (per-region) CloudTrail endpoint to a test
// server. It lives here rather than on the Driver struct because this driver ships
// entirely in its own files (the Driver struct is not edited); the httptest tests in
// this package do not run in parallel, so a package-level override is safe. Empty = real AWS.
var cloudTrailBaseURLOverride string

func (d *Driver) cloudTrailBase(region string) string {
	if cloudTrailBaseURLOverride != "" {
		return cloudTrailBaseURLOverride
	}
	return "https://cloudtrail." + region + ".amazonaws.com"
}

// cloudTrailCall signs and sends a JSON-1.1 request (X-Amz-Target), region-scoped.
func (d *Driver) cloudTrailCall(region, action string, body map[string]any) (int, []byte, error) {
	h := map[string]string{
		"Content-Type": "application/x-amz-json-1.1",
		"X-Amz-Target": cloudTrailTarget + "." + action,
	}
	return d.doSigned("POST", d.cloudTrailBase(region)+"/", "cloudtrail", region, h, []byte(jsonBody(body)))
}

func cloudTrailProviderID(region, name string) string {
	return "cloudtrail:" + region + ":" + name
}

func splitCloudTrailProviderID(providerID string) (region, name string, err error) {
	parts := strings.SplitN(providerID, ":", 3)
	if len(parts) != 3 || parts[0] != "cloudtrail" {
		return "", "", fmt.Errorf("providerId %q is not cloudtrail:region:trailName", providerID)
	}
	if !regionOK.MatchString(parts[1]) {
		return "", "", fmt.Errorf("providerId region %q is invalid", parts[1])
	}
	if !cloudTrailNameOK.MatchString(parts[2]) {
		return "", "", fmt.Errorf("providerId trail name %q is invalid", parts[2])
	}
	return parts[1], parts[2], nil
}

// cloudTrailDesc is the projection of GetTrail the driver reverse-maps.
type cloudTrailDesc struct {
	Name                       string `json:"Name"`
	TrailARN                   string `json:"TrailARN"`
	HomeRegion                 string `json:"HomeRegion"`
	S3BucketName               string `json:"S3BucketName"`
	IsMultiRegionTrail         bool   `json:"IsMultiRegionTrail"`
	LogFileValidationEnabled   bool   `json:"LogFileValidationEnabled"`
	KmsKeyId                   string `json:"KmsKeyId"`
	IncludeGlobalServiceEvents bool   `json:"IncludeGlobalServiceEvents"`
	SnsTopicARN                string `json:"SnsTopicARN"`
	CloudWatchLogsLogGroupArn  string `json:"CloudWatchLogsLogGroupArn"`
}

// getTrail reads one trail (GetTrail -> {Trail:{…}}). (found, readable): a
// TrailNotFound is found=false + readable=true (authoritatively absent); a
// transport/HTTP/parse failure is readable=false (unknown — never a fabricated absence).
func (d *Driver) getTrail(region, name string) (cloudTrailDesc, bool, error) {
	const op = "GetTrail"
	st, resp, err := d.cloudTrailCall(region, "GetTrail", map[string]any{"Name": name})
	if err != nil {
		return cloudTrailDesc{}, false, readTransport(op, err)
	}
	if strings.Contains(ecsErr(resp), "TrailNotFound") || strings.Contains(ecsErr(resp), "NotFound") {
		return cloudTrailDesc{}, false, nil
	}
	if st != http.StatusOK {
		return cloudTrailDesc{}, false, readHTTP(op, st, ecsErr(resp))
	}
	var out struct {
		Trail cloudTrailDesc `json:"Trail"`
	}
	if json.Unmarshal(resp, &out) != nil {
		return cloudTrailDesc{}, false, readBody(op, st)
	}
	return out.Trail, true, nil
}

// trailDelivery is what GetTrailStatus says about a trail ACTUALLY delivering (D725).
//
// The vocabulary promises `delivery.assured` means "the trail is actually LOGGING
// (delivering events), not merely configured", and this read used `IsLogging` alone.
// AWS defines that as "Whether the CloudTrail trail is currently logging AWS API
// calls" — i.e. StartLogging was called. A trail whose destination bucket policy denies
// `s3:PutObject` keeps `IsLogging: true` forever and writes nothing.
//
// `LatestDeliveryError` is the field that knows: "Displays any Amazon S3 error that
// CloudTrail encountered when attempting to deliver log files to the designated
// bucket … This error occurs only when there is a problem with the destination S3
// bucket." `LatestDeliveryAttemptSucceeded` looks like the right field and AWS marks it
// "This field is no longer in use" — checked, not assumed.
type trailDelivery struct {
	IsLogging     bool
	DeliveryError string
	Delivered     bool // a log file has actually reached the bucket at least once
}

func (d *Driver) trailIsLogging(region, name string) (status trailDelivery, err error) {
	const op = "GetTrailStatus"
	st, resp, cerr := d.cloudTrailCall(region, "GetTrailStatus", map[string]any{"Name": name})
	if cerr != nil {
		return trailDelivery{}, readTransport(op, cerr)
	}
	if st != http.StatusOK {
		return trailDelivery{}, readHTTP(op, st, awsErrCodeOf(resp))
	}
	var out struct {
		IsLogging           bool    `json:"IsLogging"`
		LatestDeliveryError string  `json:"LatestDeliveryError"`
		LatestDeliveryTime  float64 `json:"LatestDeliveryTime"`
	}
	if json.Unmarshal(resp, &out) != nil {
		return trailDelivery{}, readBody(op, st)
	}
	return trailDelivery{IsLogging: out.IsLogging, DeliveryError: out.LatestDeliveryError,
		Delivered: out.LatestDeliveryTime > 0}, nil
}

// trailTags reads a trail's ownership tags (ListTags with the trail ARN). ok=false on
// any transport/HTTP/parse failure.
func (d *Driver) trailTags(region, arn string) (map[string]string, error) {
	const op = "ListTags"
	st, resp, err := d.cloudTrailCall(region, "ListTags", map[string]any{"ResourceIdList": []any{arn}})
	if err != nil || st != http.StatusOK {
		if err != nil {
			return nil, readTransport(op, err)
		}
		return nil, readHTTP(op, st, ecsErr(resp))
	}
	var out struct {
		ResourceTagList []struct {
			ResourceId string `json:"ResourceId"`
			TagsList   []struct {
				Key   string `json:"Key"`
				Value string `json:"Value"`
			} `json:"TagsList"`
		} `json:"ResourceTagList"`
	}
	if json.Unmarshal(resp, &out) != nil {
		return nil, readBody(op, st)
	}
	m := map[string]string{}
	for _, rt := range out.ResourceTagList {
		for _, t := range rt.TagsList {
			m[t.Key] = t.Value
		}
	}
	return m, nil
}

// createCloudTrail provisions the composite (D26): CreateTrail then StartLogging.
// Four-valued: once the trail lands, ANY later ambiguity (StartLogging failed) is
// unknown WITH the providerId (a standing-but-not-logging trail to reconcile), never a
// silent success and never a bare "failed". A name conflict re-reads ownership: ours
// (tags match) repairs the partial (idempotent StartLogging); foreign is refused.
// cloudtrailAdoptControls: CloudTrail sets the KMS key, log-file validation and
// multi-region scope INLINE in the create body, so on a 409-adopt they never applied
// (D1062). All three are re-assertable in place via UpdateTrail (classifyCloudTrail:
// mutable, updateCloudTrail wires them), so a missing one is unknown+bound and converge
// patches it. delivery.assured (StartLogging) is re-asserted on the adopt path already.
var cloudtrailAdoptControls = []adoptcheck.Control{
	{Path: "encryption.customerManagedKeys", Direction: adoptcheck.SecureTrue, UpdateWired: true},
	{Path: "integrity.logValidation", Direction: adoptcheck.SecureTrue, UpdateWired: true},
	{Path: "scope.multiRegion", Direction: adoptcheck.SecureTrue, UpdateWired: true},
}

func (d *Driver) createCloudTrail(region, environment, capability string,
	attrs, impl map[string]any, generation int) provider.CreateResult {
	plan, err := BuildCloudTrail(environment, capability, attrs, impl, generation)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	if plan.Region != "" {
		region = plan.Region
	}
	pid := cloudTrailProviderID(region, plan.Name)

	// ownership pre-read: refuse to touch a foreign trail already at our name.
	// Not-found continues to a fresh create; ours-already repairs a partial.
	if existing, found, rerr := d.getTrail(region, plan.Name); found || rerr != nil {
		if rerr != nil {
			return provider.CreateResult{ProviderID: pid, Status: "unknown",
				Reason: "pre-create ownership read gave no answer — reconcile before provisioning: " + rerr.Error()}
		}
		tags, terr := d.trailTags(region, existing.TrailARN)
		if terr != nil {
			return provider.CreateResult{ProviderID: pid, Status: "unknown",
				Reason: "a trail with this name exists but its tags are gave no answer — reconcile: " + terr.Error()}
		}
		if !groundholdTagsMatch(tags, capability, environment) {
			return provider.CreateResult{Status: "failed",
				Reason: "a trail with this name exists and is not ours (tags do not match) — refusing to adopt it"}
		}
		// ours already — ensure it is logging (repair a partial composite).
		res := d.ensureTrailLogging(region, pid, plan)
		if res.Status != "succeeded" {
			return res
		}
		// D1062: an ADOPTED trail (409, ours) never received the create body's inline
		// controls — the KMS key, log-file validation and multi-region scope. Logging is
		// re-asserted above, but these are not; re-check them against this driver's OWN
		// measured observations. All three are re-assertable in place via UpdateTrail
		// (classifyCloudTrailChange: mutable), so a missing one is unknown+bound and
		// converge patches it — never a false succeeded that hides an unencrypted or
		// unvalidated audit trail.
		obs, _, oerr := d.observeCloudTrail(capability, pid)
		if oerr != nil {
			return provider.CreateResult{ProviderID: pid, Status: "unknown",
				Reason: "adopted trail re-observe gave no answer — reconcile: " + oerr.Error()}
		}
		switch v := adoptcheck.Compare(attrs, obs, cloudtrailAdoptControls); v.Status {
		case "failed":
			return provider.CreateResult{Status: "failed", Reason: v.Reason}
		case "unknown":
			return provider.CreateResult{ProviderID: pid, Status: "unknown", Reason: v.Reason}
		}
		return res
	}

	// CreateTrail. The pid is knowable before the response (deterministic), so
	// transport/5xx/AlreadyExists ambiguity carries it.
	st, resp, err := d.cloudTrailCall(region, "CreateTrail", plan.createTrailBody(capability, environment))
	switch {
	case err != nil:
		return provider.CreateResult{ProviderID: pid, Status: "unknown",
			Reason: fmt.Sprintf("CreateTrail outcome unknown (may have landed): %v", err)}
	case st == http.StatusOK:
		// created — fall through to StartLogging
	case strings.Contains(ecsErr(resp), "TrailAlreadyExists"):
		return provider.CreateResult{ProviderID: pid, Status: "unknown",
			Reason: "CreateTrail says the trail now exists — reconcile ownership"}
	case st >= 500:
		return provider.CreateResult{ProviderID: pid, Status: "unknown",
			Reason: fmt.Sprintf("CreateTrail HTTP %d (server error — may have landed): %s", st, ecsErr(resp))}
	default:
		return provider.CreateResult{Status: "failed",
			Reason: fmt.Sprintf("CreateTrail HTTP %d: %s", st, ecsErr(resp))}
	}
	return d.ensureTrailLogging(region, pid, plan)
}

// ensureTrailLogging brings a standing trail to its desired logging posture:
// StartLogging when delivery.assured, StopLogging otherwise. The trail ALREADY exists,
// so EVERY failure here is unknown WITH the pid (a partial composite to reconcile),
// NEVER a bare "failed" that hides the standing trail.
func (d *Driver) ensureTrailLogging(region, pid string, plan CloudTrailPlan) provider.CreateResult {
	action := "StartLogging"
	if !plan.DeliveryAssured {
		action = "StopLogging"
	}
	st, resp, err := d.cloudTrailCall(region, action, map[string]any{"Name": plan.Name})
	switch {
	case err != nil:
		return provider.CreateResult{ProviderID: pid, Status: "unknown",
			Reason: fmt.Sprintf("trail exists but %s outcome unknown — reconcile: %v", action, err)}
	case st == http.StatusOK:
		return provider.CreateResult{ProviderID: pid, Status: "succeeded"}
	default:
		return provider.CreateResult{ProviderID: pid, Status: "unknown",
			Reason: fmt.Sprintf("trail exists but %s failed (HTTP %d: %s) — the trail is standing but its "+
				"logging posture is wrong; reconcile", action, st, ecsErr(resp))}
	}
}

// observeCloudTrail reverse-maps a live trail to capability.audit.trail. Every value
// is measured. An unreadable GetTrail is unknown (an error); a not-found trail is
// "nothing to observe". delivery.assured comes from GetTrailStatus — an unreadable
// status OMITS the attribute with a diagnostic (never a fabricated "not logging").
func (d *Driver) observeCloudTrail(capability, providerID string) ([]provider.Observation, []string, error) {
	region, name, err := splitCloudTrailProviderID(providerID)
	if err != nil {
		return nil, nil, err
	}
	desc, found, rerr := d.getTrail(region, name)
	if rerr != nil {
		return nil, nil, rerr
	}
	if !found {
		// F-LC3 (D520): a BOUND resource the API authoritatively 404s is GONE.
		// A diagnostic alone leaves the binding a no-op forever (D513).
		return []provider.Observation{
			{Path: provider.ResourceAbsentPath, Value: true, Derivation: "measured"},
		}, []string{"trail not found — bound resource is gone (will re-create)"}, nil
	}
	obs := []provider.Observation{
		// Present: clear the marker (F-LC3), or a stale "gone" survives a re-create.
		{Path: provider.ResourceAbsentPath, Value: false, Derivation: "measured"},
		{Path: "location.region", Value: region, Derivation: "measured"},
		{Path: "scope.multiRegion", Value: desc.IsMultiRegionTrail, Derivation: "measured"},
		{Path: "integrity.logValidation", Value: desc.LogFileValidationEnabled, Derivation: "measured"},
		{Path: "encryption.customerManagedKeys", Value: desc.KmsKeyId != "", Derivation: "measured"},
		{Path: "service.managed", Value: true, Derivation: "measured"},
	}
	var diags []string
	if dv, lerr := d.trailIsLogging(region, name); lerr == nil {
		switch {
		case !dv.IsLogging:
			obs = append(obs, provider.Observation{Path: "delivery.assured", Value: false, Derivation: "measured"})
		case dv.DeliveryError != "":
			// AWS is telling us the bucket is refusing the log files. The trail is on
			// and the audit record is NOT being written — the whole point of the
			// attribute (D725).
			obs = append(obs, provider.Observation{Path: "delivery.assured", Value: false, Derivation: "measured"})
			diags = append(diags, "delivery.assured=false: CloudTrail cannot write to the "+
				"destination bucket ("+dv.DeliveryError+")")
		case dv.Delivered:
			obs = append(obs, provider.Observation{Path: "delivery.assured", Value: true, Derivation: "measured"})
		default:
			// Logging is on, nothing has failed, and nothing has been delivered yet.
			// Claiming assured delivery on a trail that has never delivered is the
			// smaller version of the same lie: withhold and say so (D29).
			diags = append(diags, "delivery.assured not observed: the trail is logging and "+
				"no delivery error is reported, but no log file has reached the bucket yet")
		}
	} else {
		diags = append(diags, "delivery.assured not derivable ("+lerr.Error()+") — omitted rather than fabricated")
	}
	return obs, diags, nil
}

// updateCloudTrail patches a bound trail in place (D46): the UpdateTrail-mutable paths
// (scope.multiRegion / integrity.logValidation / encryption.customerManagedKeys) via a
// single UpdateTrail call, and delivery.assured via StartLogging/StopLogging. Ownership
// tags gate the patch; the desired shape is re-derived (refuse-before-mutate) from the
// hash-pinned candidate attrs+impl; four-valued throughout (an ambiguous outcome is
// unknown WITH the providerId, never a silent success).
func (d *Driver) updateCloudTrail(capability, environment, providerID string,
	attrs, impl map[string]any, changes []string) provider.CreateResult {
	region, name, err := splitCloudTrailProviderID(providerID)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	// refuse-before-mutate: re-derive + validate the full desired shape (e.g.
	// encryption.customerManagedKeys=true with no kmsKeyArn refuses here).
	plan, err := BuildCloudTrail(environment, capability, attrs, impl, 1)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	if plan.Name != name {
		return provider.CreateResult{Status: "failed",
			Reason: fmt.Sprintf("candidate trail name %q does not match the bound trail %q — refusing", plan.Name, name)}
	}
	// ownership re-check before mutating (refuse a foreign trail at our name).
	existing, found, rerr := d.getTrail(region, name)
	if rerr != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown",
			Reason: "pre-update ownership read gave no answer — reconcile before patching: " + rerr.Error()}
	}
	if !found {
		return provider.CreateResult{Status: "failed", Reason: "trail no longer exists — cannot update"}
	}
	tags, terr := d.trailTags(region, existing.TrailARN)
	if terr != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown",
			Reason: "ownership tags gave no answer — reconcile before patching: " + terr.Error()}
	}
	if !groundholdTagsMatch(tags, capability, environment) {
		return provider.CreateResult{Status: "failed",
			Reason: "trail tags do not match — refusing to patch a resource that is not ours"}
	}

	// partition the changes: config paths fold into one UpdateTrail; delivery.assured
	// is a separate StartLogging/StopLogging call.
	needUpdate := false
	needLogging := false
	for _, path := range changes {
		switch path {
		case "scope.multiRegion", "integrity.logValidation", "encryption.customerManagedKeys":
			needUpdate = true
		case "delivery.assured":
			needLogging = true
		default:
			// ClassifyChange gates this (unsupported/immutable); refuse rather than no-op.
			return provider.CreateResult{Status: "failed",
				Reason: "no in-place CloudTrail mapping for " + path}
		}
	}

	if needUpdate {
		st, resp, e := d.cloudTrailCall(region, "UpdateTrail", plan.updateTrailBody())
		switch {
		case e != nil:
			return provider.CreateResult{ProviderID: providerID, Status: "unknown",
				Reason: fmt.Sprintf("UpdateTrail outcome unknown (may have landed): %v", e)}
		case st == http.StatusOK:
			// patched
		case st >= 500:
			return provider.CreateResult{ProviderID: providerID, Status: "unknown",
				Reason: fmt.Sprintf("UpdateTrail HTTP %d (server error — may have landed)", st)}
		default:
			return provider.CreateResult{Status: "failed",
				Reason: fmt.Sprintf("UpdateTrail HTTP %d: %s", st, ecsErr(resp))}
		}
	}
	if needLogging {
		if res := d.ensureTrailLogging(region, providerID, plan); res.Status != "succeeded" {
			return res
		}
	}
	return provider.CreateResult{ProviderID: providerID, Status: "succeeded"}
}

// deleteCloudTrail removes a bound trail (DeleteTrail), ownership-tag-gated. The trail
// CONFIG is deleted; the delivered log objects live in the operator's S3 bucket (a
// separate capability.storage.object) and are untouched — DeleteTrail is not a delete
// of the audit data. Pre-read GetTrail (idempotent success on a gone trail); refuse a
// foreign trail; a transport/5xx is unknown WITH the pid (reconcile), never a claimed
// success.
func (d *Driver) deleteCloudTrail(capability, environment, providerID string) provider.CreateResult {
	region, name, err := splitCloudTrailProviderID(providerID)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	existing, found, rerr := d.getTrail(region, name)
	if rerr != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown", Reason: "pre-delete read gave no answer — reconcile: " + rerr.Error()}
	}
	if !found {
		return provider.CreateResult{ProviderID: providerID, Status: "succeeded"} // idempotent — already gone
	}
	tags, terr := d.trailTags(region, existing.TrailARN)
	if terr != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown", Reason: "ownership tags gave no answer — reconcile: " + terr.Error()}
	}
	if !groundholdTagsMatch(tags, capability, environment) {
		return provider.CreateResult{Status: "failed",
			Reason: "trail tags do not match — refusing to delete a resource that is not ours"}
	}
	st, resp, err := d.cloudTrailCall(region, "DeleteTrail", map[string]any{"Name": name})
	if err != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown", Reason: fmt.Sprintf("delete outcome unknown: %v", err)}
	}
	if strings.Contains(ecsErr(resp), "TrailNotFound") || strings.Contains(ecsErr(resp), "NotFound") {
		return provider.CreateResult{ProviderID: providerID, Status: "succeeded"} // idempotent
	}
	if st >= 500 {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown", Reason: fmt.Sprintf("delete HTTP %d (server error) — reconcile", st)}
	}
	if st != http.StatusOK {
		return provider.CreateResult{Status: "failed", Reason: fmt.Sprintf("delete HTTP %d: %s", st, ecsErr(resp))}
	}
	return provider.CreateResult{ProviderID: providerID, Status: "succeeded"}
}

// discoverCloudTrail enumerates the region's trails as capability.audit.trail
// (ListTrails), each reverse-mapped by observeCloudTrail. Only trails whose HomeRegion
// is this region are surfaced — a multi-region trail appears as a read-only SHADOW in
// every other region, so filtering on HomeRegion avoids enumerating it N times.
func (d *Driver) discoverCloudTrail(region string) ([]provider.Discovered, []string, error) {
	st, body, err := d.cloudTrailCall(region, "ListTrails", map[string]any{})
	if err != nil {
		return nil, nil, fmt.Errorf("cloudtrail ListTrails: %v", err)
	}
	if st != http.StatusOK {
		return nil, nil, fmt.Errorf("cloudtrail ListTrails: HTTP %d: %s", st, ecsErr(body))
	}
	var r struct {
		Trails []struct {
			Name       string `json:"Name"`
			TrailARN   string `json:"TrailARN"`
			HomeRegion string `json:"HomeRegion"`
		} `json:"Trails"`
	}
	if json.Unmarshal(body, &r) != nil {
		return nil, nil, readBody("ListTrails", st)
	}
	var out []provider.Discovered
	var diags []string
	for _, t := range r.Trails {
		if t.HomeRegion != "" && t.HomeRegion != region {
			continue // a shadow of a trail homed elsewhere — enumerated in its home region
		}
		if !cloudTrailNameOK.MatchString(t.Name) {
			diags = append(diags, t.Name+": name not representable as a providerId")
			continue
		}
		pid := cloudTrailProviderID(region, t.Name)
		obs, odiags, oerr := d.observeCloudTrail("", pid)
		if oerr != nil {
			diags = append(diags, t.Name+": "+oerr.Error())
			continue
		}
		for _, dg := range odiags {
			diags = append(diags, t.Name+": "+dg)
		}
		out = append(out, provider.Discovered{
			ProviderID:   pid,
			ResourceType: "capability.audit.trail",
			Observations: provider.WithoutAbsence(obs),
		})
	}
	return out, diags, nil
}
