// BigQuery dataset request building (D122): the semantic core of the GCP
// capability.warehouse.analytics driver. The unit is a DATASET (no server to
// provision) — a project-scoped container of tables, so there is no global-namespace
// squat concern (unlike GCS, D82) and ownership is LABELS. Dataset insert is
// SYNCHRONOUS (no LRO). Two honest gaps this builder enforces: network.publicExposure
// is REFUSED (a dataset has no network boundary — it is reached through the global
// bigquery.googleapis.com endpoint, gated by IAM, so there is nothing to toggle), and
// encryption.customerManagedKeys=true requires an impl-provided key name (the key id
// is implementation detail, never a capability path). Table schemas, query config and
// compute sizing are opaque impl (invariant #4).
package gcp

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"
)

// bqDatasetIDOK bounds a dataset id: letters, digits, underscores (BigQuery forbids
// hyphens in dataset ids, so resourceName's hyphen form cannot be reused). BigQuery's
// own limit is 1024; 300 comfortably covers our pv_<slug>_<hash8> ids and stays under
// RE2's 1000 repeat cap.
var bqDatasetIDOK = regexp.MustCompile(`^[A-Za-z0-9_]{1,300}$`)
var bqNonID = regexp.MustCompile(`[^a-z0-9_]+`)

// BQDatasetID is the deterministic dataset id (the idempotency/recovery handle):
// pv_<slug>_<hash8>, underscores only. generation >= 2 salts a replacement (D48).
func BQDatasetID(project, environment, capability string, generation int) string {
	slug := capability
	if environment != "" {
		slug += "_" + environment
	}
	slug = bqNonID.ReplaceAllString(strings.ToLower(slug), "_")
	slug = strings.Trim(slug, "_")
	hashInput := project + "|" + environment + "|" + capability
	if generation >= 2 {
		hashInput += fmt.Sprintf("|g%d", generation)
	}
	sum := sha256.Sum256([]byte(hashInput))
	tail := "_" + hex.EncodeToString(sum[:])[:8]
	maxSlug := 200 - len("pv_") - len(tail) // stay comfortably under 1024
	if len(slug) > maxSlug {
		slug = slug[:maxSlug]
	}
	return "pv_" + slug + tail
}

// BigQueryDatasetPlan is the attribute-derived shape a create assembles.
type BigQueryDatasetPlan struct {
	DatasetID  string
	Location   string
	Labels     map[string]string
	KmsKeyName string // customer-managed key (impl detail), empty = provider default
}

// BuildBigQueryDataset maps capability.warehouse.analytics attributes + impl to a
// datasets.insert body. Every error is a preflight refusal, never a silent drop.
func BuildBigQueryDataset(project, environment, capability string,
	attrs, impl map[string]any, generation int) (BigQueryDatasetPlan, error) {
	if generation < 1 {
		generation = 1
	}
	p := BigQueryDatasetPlan{
		DatasetID: BQDatasetID(project, environment, capability, generation),
		Labels: map[string]string{
			"groundhold-capability":  sanitizeLabel(capability),
			"groundhold-environment": sanitizeLabel(environment),
		},
	}
	cmk := false
	for _, path := range sortedKeysG(attrs) {
		raw := attrs[path]
		switch path {
		case "location.region":
			p.Location, _ = raw.(string)
		case "network.publicExposure":
			if raw == true {
				return BigQueryDatasetPlan{}, fmt.Errorf(
					"network.publicExposure cannot be honored on BigQuery — a dataset has no " +
						"network boundary (it is reached through the global bigquery.googleapis.com " +
						"endpoint and gated by IAM, not a public/private network mode); refused rather " +
						"than faked as an allUsers IAM grant, which answers a different question")
			}
		case "encryption.atRest":
			if raw == false {
				return BigQueryDatasetPlan{}, fmt.Errorf(
					"encryption.atRest=false cannot be honored — BigQuery always encrypts at rest")
			}
		case "encryption.customerManagedKeys":
			cmk = (raw == true)
		case "service.managed":
			if raw != true {
				return BigQueryDatasetPlan{}, fmt.Errorf("service.managed=false cannot be honored by BigQuery")
			}
		default:
			return BigQueryDatasetPlan{}, fmt.Errorf(
				"attribute %s has no BigQuery dataset mapping — refusing rather than silently "+
					"dropping it (schemas, query config, slot sizing are opaque impl)", path)
		}
	}
	if p.Location == "" {
		return BigQueryDatasetPlan{}, fmt.Errorf(
			"capability.warehouse.analytics requires location.region (the dataset location)")
	}
	if cmk {
		key, _ := impl["kms_key_name"].(string)
		if key == "" {
			return BigQueryDatasetPlan{}, fmt.Errorf(
				"encryption.customerManagedKeys=true requires implementation.kms_key_name " +
					"(the customer key id is implementation detail, never a capability path)")
		}
		p.KmsKeyName = key
	}
	if !bqDatasetIDOK.MatchString(p.DatasetID) {
		return BigQueryDatasetPlan{}, fmt.Errorf("derived dataset id %q is invalid", p.DatasetID)
	}
	return p, nil
}

// insertBody is the datasets.insert request body.
func (p BigQueryDatasetPlan) insertBody(project string) map[string]any {
	body := map[string]any{
		"datasetReference": map[string]any{"datasetId": p.DatasetID, "projectId": project},
		"location":         p.Location,
		"labels":           p.Labels,
	}
	if p.KmsKeyName != "" {
		body["defaultEncryptionConfiguration"] = map[string]any{"kmsKeyName": p.KmsKeyName}
	}
	return body
}
