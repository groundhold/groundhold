// GCS request building (D77): the semantic core of the THIRD GCP service,
// same pure/golden pattern as Cloud SQL (D43) and Cloud Run (D76). Maps
// capability.storage.object attributes to a Cloud Storage JSON API v1 bucket
// insert. storage.object is STATEFUL (objects ARE the data), so retirement is
// gated by delete_stateful and replacement by allow_replace_stateful exactly
// like a database — the vocabulary's `stateful: true` drives it, no per-driver
// special-casing. Bucket names, storage tiers and lifecycle syntax are
// implementation noise; the vocabulary carries capability semantics only.
package gcp

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	"groundhold/internal/scalars"
)

const gcsBaseURL = "https://storage.googleapis.com/storage/v1"

// BucketName is the deterministic bucket name (<=63, the GCS limit) — the
// idempotency mechanism, as InstanceName/ServiceName for the other services.
func BucketName(project, environment, capability string, generation int) string {
	return resourceName(project, environment, capability, generation, 63)
}

// gcsRegionToken bounds a GCS region name before it is upper-cased into the
// dual-region placement config.
var gcsRegionToken = regexp.MustCompile(`^[a-z]+-[a-z]+[0-9]+$`)

// gcsContinent maps a region to the location code of the geographical area a
// GCS configurable dual-region resides in (US/EU/ASIA — the only continents that
// support configurable dual-regions). It refuses anything else rather than build
// an invalid bucket.
func gcsContinent(region string) (string, error) {
	if !gcsRegionToken.MatchString(region) {
		return "", fmt.Errorf("not a valid GCS region")
	}
	switch {
	case strings.HasPrefix(region, "us-"):
		return "US", nil
	case strings.HasPrefix(region, "europe-"):
		return "EU", nil
	case strings.HasPrefix(region, "asia-"):
		return "ASIA", nil
	default:
		return "", fmt.Errorf(
			"GCS configurable dual-regions are only supported within US, EU and ASIA")
	}
}

// BuildGCSCreateRequest maps semantic attributes to a bucket insert. Every
// error is a refusal apply surfaces in preflight, before any mutation.
func BuildGCSCreateRequest(project, environment, capability string,
	attrs, impl map[string]any, generation int) (Request, error) {

	if generation < 1 {
		generation = 1
	}
	body := map[string]any{
		"name": BucketName(project, environment, capability, generation),
		"labels": map[string]any{
			"groundhold-capability":  sanitizeLabel(capability),
			"groundhold-environment": sanitizeLabel(environment),
		},
		// uniform bucket-level access is the secure baseline: no per-object
		// ACLs, IAM is the single source of truth for access. publicAccess-
		// Prevention is ALWAYS set explicitly (enforced = private baseline) so
		// the wire request never depends on GCS's account default — the network
		// shell reads it back on an idempotent retry and a silent "inherited"
		// default would make our own bucket look like drift.
		"iamConfiguration": map[string]any{
			"uniformBucketLevelAccess": map[string]any{"enabled": true},
			"publicAccessPrevention":   "enforced",
		},
	}
	iamCfg := body["iamConfiguration"].(map[string]any)

	// Cross-region replication flags: assembled AFTER the loop because a GCS
	// dual-region needs both regions AND their shared continent at once.
	replEnabled := false
	destRegion := ""

	paths := make([]string, 0, len(attrs))
	for p := range attrs {
		paths = append(paths, p)
	}
	sort.Strings(paths)

	for _, path := range paths {
		raw := attrs[path]
		switch path {
		case "location.region":
			body["location"], _ = raw.(string)
		case "durability.class":
			// GCS location TYPE follows the location value (a region is
			// regional; "EU"/"US"/"ASIA" is multi-regional; a dual is
			// dual-region). single-zone has no GCS equivalent.
			if raw == "single-zone" {
				return Request{}, fmt.Errorf(
					"durability.class single-zone cannot be honored by GCS " +
						"(regional is the minimum redundancy)")
			}
		case "versioning.enabled":
			en, _ := raw.(bool)
			body["versioning"] = map[string]any{"enabled": en}
		case "retention.minimum":
			sc, err := scalars.Parse(raw)
			if err != nil || sc.Kind != scalars.Duration {
				return Request{}, fmt.Errorf("retention.minimum is not a duration")
			}
			// round UP: retention.minimum is a floor, so truncating
			// 90500ms -> 90s would provision BELOW the declared minimum.
			secs := (int64(sc.Value.(float64)) + 999) / 1000
			body["retentionPolicy"] = map[string]any{
				"retentionPeriod": fmt.Sprintf("%d", secs)}
		case "retention.locked":
			// WORM presupposes a floor to lock: locked without retention.minimum
			// is meaningless — refuse rather than lock nothing. The lock itself is
			// a one-way buckets.lockRetentionPolicy call the shell issues AFTER the
			// insert (this create field just sets retentionPolicy via minimum).
			if raw == true {
				if _, has := attrs["retention.minimum"]; !has {
					return Request{}, fmt.Errorf(
						"retention.locked=true presupposes retention.minimum " +
							"(you cannot lock nothing) — declare the retention floor")
				}
			}
		case "retention.maximum":
			sc, err := scalars.Parse(raw)
			if err != nil || sc.Kind != scalars.Duration {
				return Request{}, fmt.Errorf("retention.maximum is not a duration")
			}
			// a CEILING: objects must not outlive it, so round DOWN to whole days
			// (GCS lifecycle age is integer days) — deleting at or before the limit.
			days := int64(sc.Value.(float64)) / 86400000
			if days < 1 {
				return Request{}, fmt.Errorf(
					"retention.maximum below 1 day cannot be honored by a GCS " +
						"lifecycle rule (age condition is whole days)")
			}
			body["lifecycle"] = map[string]any{"rule": []any{
				map[string]any{
					"action":    map[string]any{"type": "Delete"},
					"condition": map[string]any{"age": days},
				},
			}}
		case "replication.enabled":
			// GCS honors cross-region replication as a configurable DUAL-REGION
			// bucket with turbo replication (rpo=ASYNC_TURBO). This is NOT S3-style
			// CRR to an arbitrary region: the two regions are PEERS of one bucket,
			// assembled after the loop (needs both regions + their continent).
			replEnabled, _ = raw.(bool)
		case "replication.destinationRegion":
			// the SECOND region of the dual-region pair. Unlike S3 (where the region
			// lives on a separate replica bucket named by an impl ARN and is only
			// OBSERVED), GCS builds the pair directly from this value AND re-measures
			// it on observe — the declared value is used to build but NEVER trusted
			// for verification (residency measured, not theatre).
			destRegion, _ = raw.(string)
		case "network.publicExposure":
			exposed, _ := raw.(bool)
			if exposed {
				// allow public paths; the actual anonymous-read IAM grant is
				// a network-shell concern (like Cloud Run's allUsers invoker)
				iamCfg["publicAccessPrevention"] = "inherited"
			} else {
				// block every public path at the bucket level
				iamCfg["publicAccessPrevention"] = "enforced"
			}
		case "encryption.atRest":
			if raw != true {
				return Request{}, fmt.Errorf(
					"encryption.atRest=false cannot be honored by GCS " +
						"(objects are always encrypted at rest)")
			}
		case "encryption.customerManagedKeys":
			// CMEK: only true is actionable — false is the provider default. A
			// true value sets the bucket's default KMS key at create; the key
			// id is implementation detail (D26).
			if raw == true {
				key, _ := impl["kms_key_name"].(string)
				if key == "" {
					return Request{}, fmt.Errorf(
						"encryption.customerManagedKeys requires " +
							"implementation.kms_key_name (a Cloud KMS key resource) — " +
							"the provider default key does not satisfy it")
				}
				body["encryption"] = map[string]any{"defaultKmsKeyName": key}
			}
		case "service.managed":
			if raw != true {
				return Request{}, fmt.Errorf(
					"service.managed=false cannot be honored by GCS")
			}
		default:
			return Request{}, fmt.Errorf(
				"attribute %s has no GCS mapping — refusing rather than "+
					"silently dropping it", path)
		}
	}
	// Cross-region replication (parity with aws/s3.go). GCS realizes it as a
	// configurable dual-region bucket + turbo replication — a chosen PAIR of
	// peer regions, NOT arbitrary CRR to any region. The pair is fixed at
	// creation (customPlacementConfig is insert-only), so a later change is a
	// replacement, not a patch (classifyGCSChange).
	if destRegion != "" && !replEnabled {
		return Request{}, fmt.Errorf(
			"replication.destinationRegion presupposes replication.enabled=true " +
				"(a destination region without replication is meaningless)")
	}
	if replEnabled {
		primary, _ := body["location"].(string)
		if primary == "" {
			return Request{}, fmt.Errorf(
				"replication.enabled requires location.region (the primary region of the dual-region pair)")
		}
		if destRegion == "" {
			return Request{}, fmt.Errorf(
				"replication.enabled requires replication.destinationRegion — GCS " +
					"replicates across a chosen dual-region PAIR (it has no S3-style " +
					"cross-region replication to an arbitrary region); name the second region")
		}
		if strings.EqualFold(primary, destRegion) {
			return Request{}, fmt.Errorf(
				"replication.destinationRegion %q must differ from location.region %q — "+
					"a dual-region pairs two DISTINCT regions", destRegion, primary)
		}
		contP, err := gcsContinent(primary)
		if err != nil {
			return Request{}, fmt.Errorf("location.region %q: %v", primary, err)
		}
		contD, err := gcsContinent(destRegion)
		if err != nil {
			return Request{}, fmt.Errorf("replication.destinationRegion %q: %v", destRegion, err)
		}
		if contP != contD {
			return Request{}, fmt.Errorf(
				"a GCS configurable dual-region pairs two regions of the SAME continent "+
					"(location.region %q is %s, replication.destinationRegion %q is %s) — "+
					"GCS cannot replicate across continents this way", primary, contP, destRegion, contD)
		}
		// location becomes the continent code; the pair rides in
		// customPlacementConfig; rpo=ASYNC_TURBO is turbo replication (the 15-min
		// RPO — the honest strong-DR analogue of S3 continuous CRR, and the
		// strongest cross-region guarantee GCS offers here).
		body["location"] = contP
		body["customPlacementConfig"] = map[string]any{
			"dataLocations": []any{strings.ToUpper(primary), strings.ToUpper(destRegion)},
		}
		body["rpo"] = "ASYNC_TURBO"
	}
	if body["location"] == nil || body["location"] == "" {
		return Request{}, fmt.Errorf(
			"gcs requires location.region (the bucket location)")
	}
	url := fmt.Sprintf("%s/b?project=%s", gcsBaseURL, project)
	return Request{Method: "POST", URL: url, Body: body}, nil
}
