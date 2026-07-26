// GCP Cloud Logging log bucket request building (D76 parity slice): the semantic
// core of the capability.monitoring.logs driver — the SAME vocabulary AWS
// CloudWatch Logs (cwlogs) fulfils. A log bucket is the durable CONTAINER logs
// live in: capability.monitoring.logs is STATEFUL (the bucket HOLDS log history,
// so retirement is data loss — D47 friction on delete, driven by the vocabulary's
// `stateful: true`, never a per-driver special-case).
//
// Cloud Logging buckets carry NO labels (unlike GCS/Cloud SQL), so ownership is
// marked two ways, both like the sibling logmetric driver: a deterministic bucket
// id AND a description marker. retention.days is a DURATION mapped to the bucket's
// integer retentionDays (rounded UP — a retention floor must never be under-
// delivered). CMEK sets cmekSettings.kmsKeyName from an implementation operand.
package gcp

import (
	"fmt"
	"regexp"

	"groundhold/internal/scalars"
)

// logBucketIDOK bounds a Cloud Logging bucket id: it may contain letters, digits,
// '_', '-' and '.', must start with an alnum, and is capped at 100 chars (the
// service limit). This is a SECURITY boundary — the id is interpolated into a REST
// path, so '/', ':', '%' and a leading '_' (the reserved _Default/_Required system
// buckets) are kept out (D73). A pinned operand or a discovered id runs this gate.
var logBucketIDOK = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]{0,99}$`)

// logBucketLocationOK bounds a log bucket location — a region ("us-central1"), a
// multi-region ("eu"/"us"/"global"). Lowercase alnum + hyphen, bounded before it
// interpolates into the REST path.
var logBucketLocationOK = regexp.MustCompile(`^[a-z][a-z0-9-]{0,62}$`)

// LogBucketPlan is the attribute-derived shape a create/patch assembles.
type LogBucketPlan struct {
	Location      string
	BucketID      string
	RetentionDays int
	CMEK          bool
	KMSKeyName    string
	Description   string
}

// LogBucketName is the deterministic bucket id (the idempotency mechanism, as
// InstanceName/BucketName for the other services). maxLen 100 = the Cloud Logging
// bucket-id limit.
func LogBucketName(project, environment, capability string, generation int) string {
	return resourceName(project, environment, capability, generation, 100)
}

func logBucketDescription(capability, environment string) string {
	return "groundhold-managed " + capability + " (" + environment + ")"
}

// BuildLogBucket maps capability.monitoring.logs attributes + impl operands to a
// plan. Every error is a preflight refusal apply surfaces before any mutation —
// never a silent drop of a semantic attribute.
func BuildLogBucket(project, environment, capability string,
	attrs, impl map[string]any, generation int) (LogBucketPlan, error) {

	if generation < 1 {
		generation = 1
	}
	p := LogBucketPlan{Description: logBucketDescription(capability, environment)}

	// operand (D26): the bucket id — a pinned implementation.log_bucket_id (for an
	// AWS-style dictated bucket) or the deterministic name. Validated either way.
	if pinned, _ := impl["log_bucket_id"].(string); pinned != "" {
		if !logBucketIDOK.MatchString(pinned) {
			return LogBucketPlan{}, fmt.Errorf(
				"implementation.log_bucket_id %q is not a valid log bucket id", pinned)
		}
		p.BucketID = pinned
	} else {
		p.BucketID = LogBucketName(project, environment, capability, generation)
	}

	for _, path := range sortedKeysG(attrs) {
		raw := attrs[path]
		switch path {
		case "location.region":
			loc, _ := raw.(string)
			if !logBucketLocationOK.MatchString(loc) {
				return LogBucketPlan{}, fmt.Errorf(
					"location.region %q is not a valid log bucket location", loc)
			}
			p.Location = loc
		case "retention.days":
			days, err := logBucketRetentionDays(raw)
			if err != nil {
				return LogBucketPlan{}, err
			}
			p.RetentionDays = days
		case "encryption.customerManagedKeys":
			// CMEK: only true is actionable — false is the provider (Google-managed
			// key) default, which carries no key id. A true value sets the bucket's
			// cmekSettings.kmsKeyName; the key id is an implementation operand (D26).
			if raw == true {
				key, _ := impl["kms_key_name"].(string)
				if key == "" {
					return LogBucketPlan{}, fmt.Errorf(
						"encryption.customerManagedKeys requires " +
							"implementation.kms_key_name (a Cloud KMS key resource) — " +
							"the Google-managed default key does not satisfy it")
				}
				p.CMEK = true
				p.KMSKeyName = key
			}
		case "service.managed":
			if raw != true {
				return LogBucketPlan{}, fmt.Errorf(
					"service.managed=false cannot be honored by Cloud Logging")
			}
		default:
			return LogBucketPlan{}, fmt.Errorf(
				"attribute %s has no log-bucket mapping — refusing rather than "+
					"silently dropping it", path)
		}
	}
	if p.Location == "" {
		return LogBucketPlan{}, fmt.Errorf(
			"log bucket requires location.region (the bucket location)")
	}
	if !projectOK.MatchString(project) {
		return LogBucketPlan{}, fmt.Errorf("project %q is invalid", project)
	}
	return p, nil
}

// logBucketRetentionDays converts a retention.days DURATION to the integer
// retentionDays the API takes. It rounds UP to whole days: retention.days is a
// retention FLOOR (a compliance guarantee), so truncating 90.5d -> 90 would keep
// logs BELOW the declared minimum. A value under one day cannot be honored (the
// field is whole days). No type coercion: a non-duration is refused.
func logBucketRetentionDays(raw any) (int, error) {
	sc, err := scalars.Parse(raw)
	if err != nil || sc.Kind != scalars.Duration {
		return 0, fmt.Errorf("retention.days is not a duration")
	}
	ms := int64(sc.Value.(float64))
	days := (ms + 86400000 - 1) / 86400000 // ceil
	if days < 1 {
		return 0, fmt.Errorf(
			"retention.days below one day cannot be honored by a log bucket " +
				"(retentionDays is whole days)")
	}
	return int(days), nil
}

// createBody assembles the LogBucket resource for buckets.create. Ownership is the
// description marker (log buckets carry no labels); retentionDays and (when CMEK
// is requested) cmekSettings.kmsKeyName carry the semantic attributes.
func (p LogBucketPlan) createBody() map[string]any {
	body := map[string]any{"description": p.Description}
	if p.RetentionDays > 0 {
		body["retentionDays"] = p.RetentionDays
	}
	if p.CMEK {
		body["cmekSettings"] = map[string]any{"kmsKeyName": p.KMSKeyName}
	}
	return body
}

// classifyLogBucketChange: which log-bucket transitions can be honored in place?
// retention.days is a clean buckets.patch (updateMask=retentionDays); CMEK is a
// buckets.patch (updateMask=cmekSettings.kmsKeyName). A location change is a
// replacement (the location is fixed in the resource name); platform/projection
// properties have nothing to patch. This is PURE provider knowledge — wired into
// the shared ClassifyChange dispatch (update.go).
func classifyLogBucketChange(path string) (string, string) {
	switch path {
	case "retention.days", "encryption.customerManagedKeys":
		return "mutable", ""
	case "location.region":
		return "immutable", "a log bucket's location is fixed at creation — a change is a replacement"
	case "service.managed":
		return "unsupported", "platform/projection property — nothing to patch"
	default:
		return "unsupported", "no log-bucket in-place mapping for " + path
	}
}
