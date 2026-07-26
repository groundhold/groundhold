// GCS network shell + security (D77): the thin, httptest-covered half of the
// third service. Bucket insert is SYNCHRONOUS (no LRO). Public read is two
// gates — publicAccessPrevention relaxed AND an allUsers objectViewer binding
// — with the same IAM honesty as Cloud Run (version-3 read-modify-write,
// append-only, confirm, DRS surfaced by name, never "succeeded" for a partial
// grant). Reuses the shared appendMember/hasMember/isDomainRestricted/
// sameProject security helpers so the reviewed logic is not duplicated.
package gcp

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"groundhold/internal/provider"
)

func (d *Driver) gcsBase() string {
	if d.GcsBaseURL != "" {
		return d.GcsBaseURL
	}
	return gcsBaseURL
}

// gcsProviderID is service-prefixed; buckets are global, so no region — the
// project rides along only for the cross-project guard.
func gcsProviderID(project, name string) string {
	return "gcs:" + project + ":" + name
}

// splitGcsProviderID validates every component before path interpolation (D73).
func splitGcsProviderID(providerID string) (project, name string, err error) {
	parts := strings.Split(providerID, ":")
	if len(parts) != 3 || parts[0] != "gcs" {
		return "", "", fmt.Errorf("providerId %q is not gcs:project:name", providerID)
	}
	if !gcpName.MatchString(parts[1]) {
		return "", "", fmt.Errorf("providerId project %q is not a valid identifier", parts[1])
	}
	// bucket names allow '.' and '_' (unlike gcpName); bound the dangerous set.
	if !bucketNameOK.MatchString(parts[2]) {
		return "", "", fmt.Errorf("providerId bucket %q is not a valid bucket name", parts[2])
	}
	return parts[1], parts[2], nil
}

func (d *Driver) bucketURL(name string) string {
	return d.gcsBase() + "/b/" + name
}

// normalizePAP folds GCS's legacy/empty publicAccessPrevention values into the
// current vocabulary: "unspecified" (a pre-rename synonym) and "" both mean
// "inherited". Without this an old bucket would spuriously fail the 409 compare.
func normalizePAP(s string) string {
	if s == "" || s == "unspecified" {
		return "inherited"
	}
	return s
}

// ourProjectNumber resolves and caches the pinned project's NUMBER via CRM.
func (d *Driver) ourProjectNumber() (string, error) {
	if d.ProjNumber != "" {
		return d.ProjNumber, nil
	}
	status, body, err := d.call("GET", d.crmBase()+"/projects/"+d.Project, nil)
	if err != nil {
		return "", fmt.Errorf("resolve project number: %v", err)
	}
	if status != http.StatusOK {
		return "", fmt.Errorf("resolve project number: HTTP %d", status)
	}
	var p struct {
		ProjectNumber string `json:"projectNumber"`
	}
	if json.Unmarshal(body, &p) != nil || p.ProjectNumber == "" {
		return "", fmt.Errorf("resolve project number: CRM returned none")
	}
	d.ProjNumber = p.ProjectNumber
	return p.ProjectNumber, nil
}

// sameBucketProject refuses a bucket whose live projectNumber differs from ours
// (D82). GCS names are a GLOBAL namespace, so a deterministic-name collision can
// be a bucket in another project. Labels are NOT proof cross-project — the
// bucket's owner sets them, so an attacker can pre-create our exact name in
// THEIR project with our labels and location; only the live projectNumber, which
// they cannot forge, is authoritative.
func (d *Driver) sameBucketProject(doc bucketDoc) error {
	ours, err := d.ourProjectNumber()
	if err != nil {
		return fmt.Errorf("cannot verify bucket ownership: %v", err)
	}
	if doc.ProjectNumber == "" {
		return fmt.Errorf("bucket carries no projectNumber — cannot prove it is ours")
	}
	if doc.ProjectNumber != ours {
		return fmt.Errorf("bucket belongs to project number %s, not ours (%s) — "+
			"refusing a cross-project global-namespace collision", doc.ProjectNumber, ours)
	}
	return nil
}

// createGCS: build -> POST (synchronous) -> (if public) grant allUsers viewer.
func (d *Driver) createGCS(capability, environment string,
	attrs, impl map[string]any, generation int) provider.CreateResult {
	req, err := BuildGCSCreateRequest(d.Project, environment, capability,
		attrs, impl, generation)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	name := BucketName(d.Project, environment, capability, generation)
	// The bucket name is deterministic, so the providerId is knowable BEFORE the
	// insert response — a lost/garbled create outcome (D29) must carry it so
	// reconcile/retire can target a bucket that may have landed (handle never lost).
	pid := gcsProviderID(d.Project, name)
	public, _ := attrs["network.publicExposure"].(bool)
	wantPrevention := "enforced"
	if public {
		wantPrevention = "inherited"
	}
	wantLocation, _ := attrs["location.region"].(string)
	replEnabled, _ := attrs["replication.enabled"].(bool)
	wantDest, _ := attrs["replication.destinationRegion"].(string)
	req.URL = d.gcsBase() + "/b?project=" + d.Project // rebuild for test base

	status, body, err := d.call(req.Method, req.URL, req.Body)
	if err != nil {
		return provider.CreateResult{ProviderID: pid, Status: "unknown",
			Reason: fmt.Sprintf("create outcome unknown: %v", err)}
	}
	switch {
	case status == http.StatusConflict:
		// the bucket exists — continue ONLY if ours AND its live config matches
		// (GCS update is not wired). Bucket names are a GLOBAL namespace, so a
		// collision can be a bucket in another project; labels are forgeable
		// cross-project, so the authoritative ownership proof is the live
		// projectNumber (D82), checked before any config comparison.
		ours, doc, found, rerr := d.gcsGetBucket(name, capability, environment)
		if rerr != nil {
			return provider.CreateResult{Status: "unknown",
				Reason: "name conflict, existing bucket gave no answer — reconcile: " + rerr.Error()}
		}
		if !found {
			return provider.CreateResult{Status: "unknown",
				Reason: "name conflict, but the conflicting bucket was gone on the follow-up read — reconcile"}
		}
		if !ours {
			return provider.CreateResult{Status: "failed",
				Reason: "a bucket with this name exists but is not ours " +
					"(labels do not match)"}
		}
		if err := d.sameBucketProject(doc); err != nil {
			return provider.CreateResult{Status: "failed", Reason: err.Error()}
		}
		switch {
		case replEnabled && !sameDualRegion(doc.CustomPlacementConfig.DataLocations, wantLocation, wantDest):
			// a dual-region bucket's Location is the continent code (US/EU/ASIA), so
			// the region pair — not doc.Location — is the thing to compare.
			return provider.CreateResult{Status: "failed", Reason: fmt.Sprintf(
				"existing bucket dual-region placement %v does not match desired pair "+
					"[%s %s] and gcs update is not wired — reconcile",
				doc.CustomPlacementConfig.DataLocations, wantLocation, wantDest)}
		case !replEnabled && wantLocation != "" && !strings.EqualFold(doc.Location, wantLocation):
			return provider.CreateResult{Status: "failed", Reason: fmt.Sprintf(
				"existing bucket location %q does not match desired %q and gcs "+
					"update is not wired — reconcile", doc.Location, wantLocation)}
		case normalizePAP(doc.IAMConfiguration.PublicAccessPrevention) != wantPrevention:
			return provider.CreateResult{Status: "failed", Reason: fmt.Sprintf(
				"existing bucket public-access-prevention %q does not match "+
					"desired %q and gcs update is not wired",
				doc.IAMConfiguration.PublicAccessPrevention, wantPrevention)}
		}
	case status >= 400:
		res := mutationResult("create", status, body)
		if res.Status == "unknown" {
			res.ProviderID = pid // 5xx may have landed — keep the deterministic handle
		}
		return res
	default:
		var b struct {
			Name string `json:"name"`
		}
		if json.Unmarshal(body, &b) != nil || b.Name == "" {
			return provider.CreateResult{ProviderID: pid, Status: "unknown",
				Reason: "create response carried no bucket — reconcile"}
		}
	}

	// retention.locked (WORM): lock the SAME bucket's retention policy one-way,
	// AFTER the insert set it (from retention.minimum). Create-time and
	// irreversible, like GCS itself treats it — the builder already refused a
	// lock without a floor.
	if locked, _ := attrs["retention.locked"].(bool); locked {
		if unknown, err := d.lockGcsRetention(name); err != nil {
			st := "failed"
			if unknown {
				st = "unknown"
			}
			return provider.CreateResult{ProviderID: pid, Status: st, Reason: err.Error()}
		}
	}
	if public {
		if unknown, err := d.setBucketPublic(name); err != nil {
			st := "failed"
			if unknown {
				st = "unknown"
			}
			return provider.CreateResult{ProviderID: pid, Status: st, Reason: err.Error()}
		}
	}
	return provider.CreateResult{ProviderID: pid, Status: "succeeded"}
}

// gcsGetBucket returns ownership, the live bucket document, whether the bucket
// exists, and why a read failed — a failed read is never "not ours". A 404 is an
// authoritative absence (found=false, nil error).
func (d *Driver) gcsGetBucket(name, capability, environment string) (ours bool, doc bucketDoc, found bool, err error) {
	const op = "buckets.get"
	status, body, cerr := d.call("GET", d.bucketURL(name), nil)
	if cerr != nil {
		return false, bucketDoc{}, false, readTransport(op, cerr)
	}
	if status == http.StatusNotFound {
		return false, bucketDoc{}, false, nil
	}
	if status != http.StatusOK {
		return false, bucketDoc{}, false, readHTTP(op, status, gcpErrCode(body))
	}
	if json.Unmarshal(body, &doc) != nil {
		return false, bucketDoc{}, false, readBody(op, status)
	}
	ours = doc.Labels["groundhold-capability"] == sanitizeLabel(capability) &&
		doc.Labels["groundhold-environment"] == sanitizeLabel(environment)
	return ours, doc, true, nil
}

type bucketDoc struct {
	Labels         map[string]string `json:"labels"`
	Location       string            `json:"location"`
	Metageneration string            `json:"metageneration"`
	ProjectNumber  string            `json:"projectNumber"`
	Versioning     struct {
		Enabled bool `json:"enabled"`
	} `json:"versioning"`
	RetentionPolicy struct {
		RetentionPeriod string `json:"retentionPeriod"`
		IsLocked        bool   `json:"isLocked"`
	} `json:"retentionPolicy"`
	Lifecycle struct {
		Rule []struct {
			Action struct {
				Type string `json:"type"`
			} `json:"action"`
			Condition struct {
				Age *int `json:"age"`
			} `json:"condition"`
		} `json:"rule"`
	} `json:"lifecycle"`
	Encryption struct {
		DefaultKmsKeyName string `json:"defaultKmsKeyName"`
	} `json:"encryption"`
	IAMConfiguration struct {
		PublicAccessPrevention   string `json:"publicAccessPrevention"`
		UniformBucketLevelAccess struct {
			Enabled bool `json:"enabled"`
		} `json:"uniformBucketLevelAccess"`
	} `json:"iamConfiguration"`
	CustomPlacementConfig struct {
		DataLocations []string `json:"dataLocations"`
	} `json:"customPlacementConfig"`
	Rpo string `json:"rpo"`
}

// sameDualRegion reports whether the live customPlacementConfig dataLocations are
// exactly the desired {primary, destination} pair, order-independent: GCS treats
// the two regions as PEERS (there is no primary/secondary in a dual-region), so a
// match must not depend on their order.
func sameDualRegion(dataLocations []string, primary, dest string) bool {
	if len(dataLocations) != 2 || primary == "" || dest == "" {
		return false
	}
	a, b := strings.ToLower(dataLocations[0]), strings.ToLower(dataLocations[1])
	p, d := strings.ToLower(primary), strings.ToLower(dest)
	return (a == p && b == d) || (a == d && b == p)
}

// lockGcsRetention issues the ONE-WAY buckets.lockRetentionPolicy on a bucket
// that already carries a retentionPolicy (set at create from retention.minimum).
// It reads the live metageneration for the required ifMetagenerationMatch CAS,
// is idempotent (an already-locked bucket is converged, not an error), and
// confirms isLocked from the response — a 200 that did not lock is never a
// silent success. unknown routes a lost/5xx outcome to reconcile (D29).
func (d *Driver) lockGcsRetention(name string) (unknown bool, err error) {
	status, body, err := d.call("GET", d.bucketURL(name), nil)
	if err != nil {
		return true, fmt.Errorf("retention lock: pre-lock read outcome unknown — reconcile: %v", err)
	}
	if status != http.StatusOK {
		return false, fmt.Errorf("retention lock: pre-lock read HTTP %d", status)
	}
	var b bucketDoc
	if json.Unmarshal(body, &b) != nil {
		return false, fmt.Errorf("retention lock: pre-lock read unparseable")
	}
	if b.RetentionPolicy.RetentionPeriod == "" || b.RetentionPolicy.RetentionPeriod == "0" {
		return false, fmt.Errorf("retention lock: bucket has no retention policy to lock")
	}
	if b.RetentionPolicy.IsLocked {
		return false, nil // already locked — converged
	}
	if b.Metageneration == "" {
		return false, fmt.Errorf("retention lock: no metageneration — refusing a CAS-less lock")
	}
	url := d.bucketURL(name) + "/lockRetentionPolicy?ifMetagenerationMatch=" + b.Metageneration
	status, rb, cerr := d.call("POST", url, nil)
	if cerr != nil {
		return true, fmt.Errorf("retention lock: lockRetentionPolicy outcome unknown — reconcile: %v", cerr)
	}
	if status >= 500 {
		return true, fmt.Errorf("retention lock: lockRetentionPolicy HTTP %d (server error) — reconcile: %s", status, mutDetail(rb))
	}
	if status != http.StatusOK {
		return false, fmt.Errorf("retention lock: lockRetentionPolicy HTTP %d: %s", status, mutDetail(rb))
	}
	var after bucketDoc
	if json.Unmarshal(rb, &after) != nil || !after.RetentionPolicy.IsLocked {
		return true, fmt.Errorf("retention lock: lockRetentionPolicy returned 200 but " +
			"isLocked was not confirmed — reconcile")
	}
	return false, nil
}

func (d *Driver) setBucketPublic(name string) (unknown bool, err error) {
	bindings, etag, err := d.getGcsPolicyForWrite(name)
	if err != nil {
		return false, fmt.Errorf("public exposure: %v", err)
	}
	bindings = appendMember(bindings, "roles/storage.objectViewer", "allUsers")
	status, body, cerr := d.call("PUT", d.bucketURL(name)+"/iam",
		map[string]any{"version": iamPolicyVersion, "bindings": bindings, "etag": etag})
	if cerr != nil {
		return true, fmt.Errorf("public exposure: setIamPolicy outcome "+
			"unknown — reconcile via getIamPolicy: %v", cerr)
	}
	if status != http.StatusOK {
		if isDomainRestricted(body) {
			return false, fmt.Errorf("public exposure blocked by domain-"+
				"restricted-sharing (an org-policy decision, not a missing "+
				"permission): %s", mutDetail(body))
		}
		if status >= 500 {
			// a 5xx does NOT prove the grant did not land (D29) — the binding
			// may be live; unknown routes to reconcile, never a false failed.
			return true, fmt.Errorf("public exposure: setIamPolicy HTTP %d "+
				"(server error — the grant may have landed, reconcile): %s",
				status, mutDetail(body))
		}
		if provider.Classify(status, gcpErrCode(body), nil).Unknown() {
			// D237: a throttle (429) or live 403 does not prove the grant failed —
			// unknown routes to reconcile, never a false failed.
			return true, fmt.Errorf("public exposure: setIamPolicy HTTP %d "+
				"(transient/denied — the grant may have landed, reconcile): %s",
				status, mutDetail(body))
		}
		return false, fmt.Errorf("public exposure: setIamPolicy HTTP %d: %s",
			status, mutDetail(body))
	}
	pub, cerr := d.confirmBucketPublic(name)
	switch {
	case pub:
		return false, nil
	case cerr != nil:
		// setIamPolicy returned 200 — a failed confirm read is not proof the
		// grant did not take. Unknown, not failed (D29).
		return true, fmt.Errorf("public exposure: setIamPolicy returned 200 but "+
			"the binding could not be confirmed (%v) — reconcile", cerr)
	default:
		return false, fmt.Errorf("public exposure: allUsers objectViewer " +
			"binding did not take (org policy or a conditional binding may interfere)")
	}
}

func (d *Driver) getGcsPolicyForWrite(name string) ([]map[string]any, string, error) {
	status, body, err := d.call("GET",
		d.bucketURL(name)+"/iam?optionsRequestedPolicyVersion=3", nil)
	if err != nil {
		return nil, "", fmt.Errorf("getIamPolicy: %v", err)
	}
	if status != http.StatusOK {
		return nil, "", fmt.Errorf("getIamPolicy HTTP %d: %s", status, mutDetail(body))
	}
	var policy struct {
		Bindings []map[string]any `json:"bindings"`
		Etag     string           `json:"etag"`
	}
	if err := json.Unmarshal(body, &policy); err != nil {
		return nil, "", fmt.Errorf("getIamPolicy: unparseable policy")
	}
	if policy.Etag == "" {
		return nil, "", fmt.Errorf("getIamPolicy: no etag — refusing a " +
			"CAS-less write that would overwrite the whole policy")
	}
	return policy.Bindings, policy.Etag, nil
}

func (d *Driver) readGcsPolicy(name string) ([]map[string]any, error) {
	const op = "buckets.getIamPolicy"
	status, body, cerr := d.call("GET",
		d.bucketURL(name)+"/iam?optionsRequestedPolicyVersion=3", nil)
	if cerr != nil {
		return nil, readTransport(op, cerr)
	}
	if status != http.StatusOK {
		return nil, readHTTP(op, status, gcpErrCode(body))
	}
	var policy struct {
		Bindings []map[string]any `json:"bindings"`
	}
	if json.Unmarshal(body, &policy) != nil {
		return nil, readBody(op, status)
	}
	return policy.Bindings, nil
}

// confirmBucketPublic is THREE-valued: (public, why-not). A read that gave no
// answer is not "not public" — see confirmPublic in cloudrun_net.go.
func (d *Driver) confirmBucketPublic(name string) (public bool, err error) {
	bindings, perr := d.readGcsPolicy(name)
	if perr != nil {
		return false, perr
	}
	for _, b := range bindings {
		if b["role"] == "roles/storage.objectViewer" && hasMember(b, "allUsers") {
			return true, nil
		}
	}
	return false, nil
}

// deleteGCS: ownership + retention-lock pre-read, then DELETE. 404 is
// idempotent success; a locked retention policy or a non-empty bucket refuses.
func (d *Driver) deleteGCS(capability, environment, providerID string) provider.CreateResult {
	project, name, err := splitGcsProviderID(providerID)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	if err := d.sameProject(project); err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	status, body, err := d.call("GET", d.bucketURL(name), nil)
	if err != nil {
		return provider.CreateResult{Status: "unknown",
			Reason: fmt.Sprintf("pre-delete read failed: %v", err)}
	}
	if status == http.StatusNotFound {
		return provider.CreateResult{ProviderID: providerID, Status: "succeeded"}
	}
	if status != http.StatusOK {
		return provider.CreateResult{Status: "failed",
			Reason: fmt.Sprintf("pre-delete read: HTTP %d", status)}
	}
	var b bucketDoc
	if err := json.Unmarshal(body, &b); err != nil {
		// a truncated/garbled read could leave labels populated but IsLocked at
		// its zero value — refusing on ambiguity beats deleting a locked bucket.
		return provider.CreateResult{Status: "unknown",
			Reason: "pre-delete read unparseable — refusing an ambiguous delete"}
	}
	if b.Labels["groundhold-capability"] != sanitizeLabel(capability) ||
		b.Labels["groundhold-environment"] != sanitizeLabel(environment) {
		return provider.CreateResult{Status: "failed",
			Reason: "bucket labels do not match — refusing to delete a " +
				"resource that is not ours"}
	}
	if err := d.sameBucketProject(b); err != nil {
		// labels are forgeable cross-project (D82) — never delete on labels alone
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	if b.RetentionPolicy.IsLocked {
		return provider.CreateResult{Status: "failed",
			Reason: "bucket retention policy is LOCKED — deletion is blocked " +
				"by a compliance hold, never auto-lifted"}
	}
	// ifMetagenerationMatch closes the TOCTOU between this ownership/retention
	// pre-read and the delete: a concurrent relabel or retention-lock lands as a
	// 412 conflict, never a blind delete of a resource that just changed hands.
	if b.Metageneration == "" {
		// buckets.get always returns a metageneration; its absence means an
		// anomalous read — refuse rather than issue a blind (CAS-less) delete
		// that a concurrent relabel/lock could turn into a wrong deletion.
		return provider.CreateResult{Status: "unknown",
			Reason: "pre-delete read carried no metageneration — refusing a " +
				"delete without a concurrency precondition"}
	}
	delURL := d.bucketURL(name) + "?ifMetagenerationMatch=" + b.Metageneration
	status, respBody, err := d.call("DELETE", delURL, nil)
	if err != nil {
		// a lost delete response (D29) — the delete may have landed; keep the
		// handle so reconcile/retire can conclude it, never drop it.
		return provider.CreateResult{ProviderID: providerID, Status: "unknown",
			Reason: fmt.Sprintf("delete outcome unknown: %v", err)}
	}
	if status == http.StatusConflict {
		return provider.CreateResult{Status: "failed",
			Reason: "bucket is not empty — objects are data; delete them " +
				"explicitly first (retirement is data loss)"}
	}
	if status == http.StatusPreconditionFailed {
		return provider.CreateResult{Status: "failed",
			Reason: "bucket changed between the pre-delete read and the delete " +
				"(metageneration conflict) — re-observe and re-seal"}
	}
	if status >= 400 {
		// a 5xx does NOT prove the delete did not land (D29) — mutationResult
		// maps it to unknown; carry the handle for reconciliation.
		res := mutationResult("delete", status, respBody)
		if res.Status == "unknown" {
			res.ProviderID = providerID
		}
		return res
	}
	return provider.CreateResult{ProviderID: providerID, Status: "succeeded"}
}

// observeGCS reverse-maps a live bucket. publicExposure is TRUE only when
// prevention is NOT enforced AND an allUsers read binding exists; an
// unreadable IAM policy emits a diagnostic and nothing.
func (d *Driver) observeGCS(capability, providerID string) ([]provider.Observation, []string, error) {
	project, name, err := splitGcsProviderID(providerID)
	if err != nil {
		return nil, nil, err
	}
	if err := d.sameProject(project); err != nil {
		return nil, nil, err
	}
	status, body, err := d.call("GET", d.bucketURL(name), nil)
	if err != nil {
		return nil, nil, err
	}
	if status != http.StatusOK {
		return nil, nil, fmt.Errorf("buckets.get: HTTP %d", status)
	}
	var b bucketDoc
	if err := json.Unmarshal(body, &b); err != nil {
		return nil, nil, fmt.Errorf("buckets.get: unparseable bucket document")
	}
	// NOTE: no projectNumber check here — observe is read-only and runs with NO
	// pinned project (the project rides in the providerId, which sameProject
	// already guards). Resolving OUR number needs a pinned project; the D82
	// squat defense lives on create (409-continue) and delete, which have one.

	var obs []provider.Observation
	var diags []string
	// location + cross-region replication. A configurable dual-region bucket
	// carries TWO dataLocations (peers of one bucket); GCS returns them in the
	// order supplied at insert, so dataLocations[0] is the primary (location.region)
	// and [1] the DR destination. A regional/multi-region bucket has none, so
	// location.region is the bucket's own Location and there is no CHOSEN
	// replication destination (multi-region redundancy is a durability class, not a
	// region you point at — the honest difference from S3 CRR).
	if dl := b.CustomPlacementConfig.DataLocations; len(dl) == 2 {
		obs = append(obs,
			provider.Observation{Path: "location.region",
				Value: strings.ToLower(dl[0]), Derivation: "measured"},
			provider.Observation{Path: "replication.enabled",
				Value: true, Derivation: "measured"},
			// replication.destinationRegion is the SUBSTANCE of DR residency and is
			// MEASURED from the placement config, never declared on faith — the same
			// honesty as S3's GetBucketLocation on the replica, but this is a GCS
			// dual-region PEER, not an arbitrary CRR destination.
			provider.Observation{Path: "replication.destinationRegion",
				Value: strings.ToLower(dl[1]), Derivation: "measured"})
		if b.Rpo != "ASYNC_TURBO" {
			diags = append(diags, "replication turbo (rpo=ASYNC_TURBO) is off: this "+
				"dual-region replicates on the default ~12h RPO, not the 15-min turbo RPO")
		}
	} else {
		if b.Location != "" {
			obs = append(obs, provider.Observation{Path: "location.region",
				Value: strings.ToLower(b.Location), Derivation: "measured"})
		}
		obs = append(obs, provider.Observation{Path: "replication.enabled",
			Value: false, Derivation: "measured"})
	}
	obs = append(obs, provider.Observation{Path: "encryption.atRest",
		Value: true, Derivation: "config-intent"}) // GCS always encrypts
	obs = append(obs, provider.Observation{Path: "service.managed",
		Value: true, Derivation: "measured"})
	obs = append(obs, provider.Observation{Path: "versioning.enabled",
		Value: b.Versioning.Enabled, Derivation: "measured"})
	if secs := b.RetentionPolicy.RetentionPeriod; secs != "" && secs != "0" {
		// GCS reports retentionPeriod as whole seconds; a retention contract
		// can only verify from recorded reality if observe emits the path.
		obs = append(obs, provider.Observation{Path: "retention.minimum",
			Value: secs + "s", Derivation: "measured"})
		// retention.locked is meaningful only WITH a retention policy — emit its
		// measured isLocked (WORM on or off). Absent a policy, the path is absent.
		obs = append(obs, provider.Observation{Path: "retention.locked",
			Value: b.RetentionPolicy.IsLocked, Derivation: "measured"})
	}
	// retention.maximum reverse-maps a lifecycle Delete-by-age rule (whole days).
	for _, r := range b.Lifecycle.Rule {
		if r.Action.Type == "Delete" && r.Condition.Age != nil {
			obs = append(obs, provider.Observation{Path: "retention.maximum",
				Value: fmt.Sprintf("%dd", *r.Condition.Age), Derivation: "measured"})
			break
		}
	}
	// customerManagedKeys: a CMEK is present iff the bucket carries a default
	// KMS key. Absent means the Google-managed default, which does NOT satisfy
	// the constraint — emit nothing rather than a false.
	if b.Encryption.DefaultKmsKeyName != "" {
		obs = append(obs, provider.Observation{Path: "encryption.customerManagedKeys",
			Value: true, Derivation: "measured"})
	}

	// publicExposure has TWO honest gates.
	//   1. prevention=enforced is definitively private regardless of IAM.
	//   2. otherwise IAM is the full access story ONLY under uniform bucket-
	//      level access; without UBLA, object/default ACLs can expose data that
	//      the bucket IAM policy never mentions, so a measured "false" would be
	//      a lie. Adopted buckets (D52) and the 409-continue path can be
	//      fine-grained, so this is not hypothetical.
	// buckets.get returns the bucket's OWN PAP, not an org-policy that ENFORCES it
	// above the bucket. D238 closes the resulting false positive: when the bucket
	// PAP is "inherited" and a stale allUsers binding would otherwise read as
	// public, query the effective org policy and downgrade to private ONLY on
	// positive enforcement evidence — an unreadable org policy keeps the
	// conservative public verdict (never-fabricate: a false negative is the
	// dangerous direction).
	prevention := b.IAMConfiguration.PublicAccessPrevention
	switch {
	case prevention == "enforced":
		obs = append(obs, provider.Observation{Path: "network.publicExposure",
			Value: false, Derivation: "measured"})
	case !b.IAMConfiguration.UniformBucketLevelAccess.Enabled:
		diags = append(diags, "network.publicExposure not observed: uniform "+
			"bucket-level access is off, so object ACLs (invisible to the IAM "+
			"policy) may expose data — reconcile")
	default:
		iamPublic, perr := d.readBucketPublic(name)
		switch {
		case perr != nil:
			// D238 rescue: even with the bucket IAM policy unreadable, a positively
			// enforced org PAP is definitive private — an honesty gain over emitting
			// nothing. Absent positive evidence, keep the honest no-observation.
			if enforced, _ := d.effectivePAPEnforced(project); enforced {
				obs = append(obs, provider.Observation{Path: "network.publicExposure",
					Value: false, Derivation: "measured"})
			} else {
				diags = append(diags, "network.publicExposure not observed: "+perr.Error())
			}
		case iamPublic:
			// D238: a stale allUsers binding may be overridden by an org-enforced
			// PAP above this bucket. Query lazily (only now that IAM looks public).
			if enforced, opErr := d.effectivePAPEnforced(project); enforced {
				obs = append(obs, provider.Observation{Path: "network.publicExposure",
					Value: false, Derivation: "measured"})
				diags = append(diags, "network.publicExposure: an allUsers/allAuthenticatedUsers "+
					"read binding exists but effective org-policy PAP is enforced — the binding is "+
					"currently masked and would expose the bucket if the org policy is lifted; remove it")
			} else {
				if opErr != nil {
					diags = append(diags, "network.publicExposure: effective org-policy "+
						"PAP gave no answer ("+opErr.Error()+") — reporting the allUsers "+
						"binding as public conservatively (an org constraint may in fact block it)")
				}
				obs = append(obs, provider.Observation{Path: "network.publicExposure",
					Value: true, Derivation: "measured"})
			}
		default:
			obs = append(obs, provider.Observation{Path: "network.publicExposure",
				Value: false, Derivation: "measured"})
		}
	}
	return obs, diags, nil
}

func (d *Driver) readBucketPublic(name string) (public bool, err error) {
	bindings, perr := d.readGcsPolicy(name)
	if perr != nil {
		return false, perr
	}
	for _, b := range bindings {
		role, _ := b["role"].(string)
		if (role == "roles/storage.objectViewer" || role == "roles/storage.legacyObjectReader") &&
			(hasMember(b, "allUsers") || hasMember(b, "allAuthenticatedUsers")) {
			return true, nil
		}
	}
	return false, nil
}

// updateGCS patches a bucket's mutable attributes in place (D77 update slice,
// symmetric with the S3 update). Only versioning.enabled is a clean patch in this
// slice; the compiler's ClassifyChange (classifyGCSChange) already gated the change
// set, so a non-versioning path here is a bug — refused, never silently applied. The
// live metageneration rides as ifMetagenerationMatch so a concurrent change surfaces
// as a 412 conflict, not a lost update. Ownership (labels) is re-checked first.
func (d *Driver) updateGCS(capability, environment, providerID string,
	attrs map[string]any, changes []string) provider.CreateResult {
	project, name, err := splitGcsProviderID(providerID)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	if err := d.sameProject(project); err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	ours, doc, found, rerr := d.gcsGetBucket(name, capability, environment)
	if rerr != nil {
		return provider.CreateResult{Status: "unknown", Reason: "pre-update read gave no answer — reconcile: " + rerr.Error()}
	}
	if !found {
		return provider.CreateResult{Status: "failed", Reason: "bucket no longer exists — cannot update"}
	}
	if !ours {
		return provider.CreateResult{Status: "failed",
			Reason: "bucket labels do not match — refusing to patch a resource that is not ours"}
	}
	if err := d.sameBucketProject(doc); err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	if doc.Metageneration == "" {
		return provider.CreateResult{Status: "unknown",
			Reason: "pre-update read carried no metageneration — refusing a patch without a concurrency precondition"}
	}
	patch := map[string]any{}
	for _, path := range changes {
		switch path {
		case "versioning.enabled":
			enabled, _ := attrs[path].(bool)
			patch["versioning"] = map[string]any{"enabled": enabled}
		default:
			return provider.CreateResult{Status: "failed",
				Reason: fmt.Sprintf("path %s is not patchable in place on GCS (ClassifyChange should have refused it)", path)}
		}
	}
	url := d.bucketURL(name) + "?ifMetagenerationMatch=" + doc.Metageneration
	status, body, err := d.call("PATCH", url, patch)
	if err != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown",
			Reason: fmt.Sprintf("patch outcome unknown: %v", err)}
	}
	if status == http.StatusPreconditionFailed {
		return provider.CreateResult{Status: "failed",
			Reason: "bucket changed between the pre-update read and the patch (metageneration conflict) — re-observe and re-seal"}
	}
	if status >= 400 {
		res := mutationResult("patch", status, body)
		if res.Status == "unknown" {
			res.ProviderID = providerID
		}
		return res
	}
	return provider.CreateResult{ProviderID: providerID, Status: "succeeded"}
}
