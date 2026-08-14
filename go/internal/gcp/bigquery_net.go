// BigQuery network shell (D122): the httptest-covered half of the GCP
// capability.warehouse.analytics driver. datasets.insert is SYNCHRONOUS (200 with the
// dataset, no LRO). The dataset id is deterministic, so the providerId is knowable
// BEFORE the response — a lost/garbled create outcome (D29) always carries it.
// Ownership is LABELS (a dataset is project-scoped, so no D82 cross-project squat
// concern). Delete does NOT set deleteContents: a non-empty dataset refuses rather
// than silently dropping tables (retirement is data loss, surfaced honestly).
package gcp

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"groundhold/internal/provider"
)

const bigQueryBaseURL = "https://bigquery.googleapis.com/bigquery/v2"

func (d *Driver) bqBase() string {
	if d.BQBaseURL != "" {
		return d.BQBaseURL
	}
	return bigQueryBaseURL
}

func bqProviderID(project, datasetID string) string {
	return "bqds:" + project + ":" + datasetID
}

func splitBQProviderID(providerID string) (project, datasetID string, err error) {
	parts := strings.Split(providerID, ":")
	if len(parts) != 3 || parts[0] != "bqds" {
		return "", "", fmt.Errorf("providerId %q is not bqds:project:datasetId", providerID)
	}
	if !gcpName.MatchString(parts[1]) {
		return "", "", fmt.Errorf("providerId project %q is not a valid identifier", parts[1])
	}
	if !bqDatasetIDOK.MatchString(parts[2]) {
		return "", "", fmt.Errorf("providerId dataset %q is not a valid dataset id", parts[2])
	}
	return parts[1], parts[2], nil
}

func (d *Driver) bqDatasetURL(project, datasetID string) string {
	return fmt.Sprintf("%s/projects/%s/datasets/%s", d.bqBase(), project, datasetID)
}

type bqDatasetDoc struct {
	DatasetReference struct {
		DatasetID string `json:"datasetId"`
		ProjectID string `json:"projectId"`
	} `json:"datasetReference"`
	Location                       string            `json:"location"`
	Labels                         map[string]string `json:"labels"`
	DefaultEncryptionConfiguration *struct {
		KmsKeyName string `json:"kmsKeyName"`
	} `json:"defaultEncryptionConfiguration"`
}

func (doc bqDatasetDoc) ours(capability, environment string) bool {
	return doc.Labels["groundhold-capability"] == sanitizeLabel(capability) &&
		doc.Labels["groundhold-environment"] == sanitizeLabel(environment)
}

// bqGetDataset reads a dataset. found=false + readable=true is an authoritative
// "does not exist"; readable=false is a transport/HTTP/parse failure.
func (d *Driver) bqGetDataset(project, datasetID string) (bqDatasetDoc, bool, error) {
	const op = "bqGetDataset.get"
	st, body, err := d.call("GET", d.bqDatasetURL(project, datasetID), nil)
	if err != nil {
		return bqDatasetDoc{}, false, readTransport(op, err)
	}
	if st == http.StatusNotFound {
		return bqDatasetDoc{}, false, nil
	}
	if st != http.StatusOK {
		return bqDatasetDoc{}, false, readHTTP(op, st, gcpErrCode(body))
	}
	var doc bqDatasetDoc
	if json.Unmarshal(body, &doc) != nil {
		return bqDatasetDoc{}, false, readBody(op, st)
	}
	return doc, true, nil
}

func (d *Driver) createBigQuery(capability, environment string,
	attrs, impl map[string]any, generation int) provider.CreateResult {
	plan, err := BuildBigQueryDataset(d.Project, environment, capability, attrs, impl, generation)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	pid := bqProviderID(d.Project, plan.DatasetID)
	url := fmt.Sprintf("%s/projects/%s/datasets", d.bqBase(), d.Project)
	st, body, err := d.call("POST", url, plan.insertBody(d.Project))
	switch {
	case err != nil:
		return provider.CreateResult{ProviderID: pid, Status: "unknown",
			Reason: fmt.Sprintf("datasets.insert outcome unknown (may have landed): %v", err)}
	case st == http.StatusConflict:
		// exists — continue ONLY if ours (project-scoped, so labels are authoritative).
		doc, found, rerr := d.bqGetDataset(d.Project, plan.DatasetID)
		if rerr != nil {
			return provider.CreateResult{ProviderID: pid, Status: "unknown",
				Reason: "name conflict, existing dataset gave no answer — reconcile: " + rerr.Error()}
		}
		if !found || !doc.ours(capability, environment) {
			return provider.CreateResult{Status: "failed",
				Reason: "a dataset with this id exists and is not ours (labels do not match)"}
		}
		if plan.Location != "" && !strings.EqualFold(doc.Location, plan.Location) {
			return provider.CreateResult{Status: "failed", Reason: fmt.Sprintf(
				"existing dataset location %q does not match desired %q and update is not wired",
				doc.Location, plan.Location)}
		}
		return provider.CreateResult{ProviderID: pid, Status: "succeeded"} // ours, present
	case st >= 500:
		return provider.CreateResult{ProviderID: pid, Status: "unknown",
			Reason: fmt.Sprintf("datasets.insert HTTP %d (server error — may have landed): %s", st, mutDetail(body))}
	case st >= 400:
		if r := provider.MutationResult(st, gcpErrCode(body), nil, pid, "datasets.insert"); r != nil {
			return *r
		}
		return provider.CreateResult{Status: "failed",
			Reason: fmt.Sprintf("datasets.insert HTTP %d: %s", st, mutDetail(body))}
	default:
		var doc bqDatasetDoc
		if json.Unmarshal(body, &doc) != nil || doc.DatasetReference.DatasetID == "" {
			return provider.CreateResult{ProviderID: pid, Status: "unknown",
				Reason: "datasets.insert response carried no dataset — reconcile"}
		}
		return provider.CreateResult{ProviderID: pid, Status: "succeeded"}
	}
}

func (d *Driver) observeBigQuery(capability, providerID string) ([]provider.Observation, []string, error) {
	project, datasetID, err := splitBQProviderID(providerID)
	if err != nil {
		return nil, nil, err
	}
	if err := d.sameProject(project); err != nil {
		return nil, nil, err
	}
	doc, found, rerr := d.bqGetDataset(project, datasetID)
	if rerr != nil {
		return nil, nil, rerr
	}
	if !found {
		// F-LC3 (D519): a BOUND resource the API authoritatively 404s is GONE.
		// A diagnostic alone leaves the binding a no-op forever (D513).
		return []provider.Observation{
			{Path: provider.ResourceAbsentPath, Value: true, Derivation: "measured"},
		}, []string{"dataset not found — bound resource is gone (will re-create)"}, nil
	}
	obs := []provider.Observation{
		// Present: clear the marker (F-LC3), or a stale "gone" survives a re-create.
		{Path: provider.ResourceAbsentPath, Value: false, Derivation: "measured"},
		{Path: "encryption.atRest", Value: true, Derivation: "platform-invariant"}, // BigQuery always encrypts
		{Path: "service.managed", Value: true, Derivation: "measured"},
	}
	var diags []string
	if doc.Location != "" {
		obs = append(obs, provider.Observation{Path: "location.region",
			Value: strings.ToLower(doc.Location), Derivation: "measured"})
		// D1043: a BigQuery dataset's location is "US"/"EU" (a multi-region) BY DEFAULT —
		// diagnose it so a residency constraint is not silently satisfied over data that
		// spans several regions (D799, propagated from Firestore).
		if d := residencyMultiRegionDiag(doc.Location, "dataset"); d != "" {
			diags = append(diags, d)
		}
	}
	// a customer key is present iff the dataset carries a default KMS key; the
	// Google-managed default does NOT satisfy the constraint. D1003: that is a
	// MEASURED FALSE, never an absence — emit the boolean unconditionally so a hard
	// customerManagedKeys constraint has a value to contradict, not a vacuous pass.
	obs = append(obs, provider.Observation{Path: "encryption.customerManagedKeys",
		Value: doc.DefaultEncryptionConfiguration != nil && doc.DefaultEncryptionConfiguration.KmsKeyName != "", Derivation: "measured"})
	// network.publicExposure is deliberately NOT observed: a BigQuery dataset has no
	// network exposure mode (the honest gap the builder refuses on create).
	diags = append(diags, "network.publicExposure not observed: BigQuery datasets have no network boundary (IAM-gated global endpoint)")
	return obs, diags, nil
}

func (d *Driver) deleteBigQuery(capability, environment, providerID string) provider.CreateResult {
	project, datasetID, err := splitBQProviderID(providerID)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	if err := d.sameProject(project); err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	doc, found, rerr := d.bqGetDataset(project, datasetID)
	if rerr != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown", Reason: "pre-delete read gave no answer — reconcile: " + rerr.Error()}
	}
	if !found {
		return provider.CreateResult{ProviderID: providerID, Status: "succeeded"} // idempotent
	}
	if !doc.ours(capability, environment) {
		return provider.CreateResult{Status: "failed",
			Reason: "dataset labels do not match — refusing to delete a resource that is not ours"}
	}
	// deleteContents is deliberately NOT set: a non-empty dataset refuses (400)
	// rather than silently dropping its tables — retirement is data loss, honest.
	st, body, err := d.call("DELETE", d.bqDatasetURL(project, datasetID), nil)
	if err != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown",
			Reason: fmt.Sprintf("delete outcome unknown: %v", err)}
	}
	if st == http.StatusNotFound {
		return provider.CreateResult{ProviderID: providerID, Status: "succeeded"} // idempotent
	}
	if st >= 500 {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown",
			Reason: fmt.Sprintf("delete HTTP %d (server error) — reconcile", st)}
	}
	if st == http.StatusBadRequest && strings.Contains(string(body), "not empty") {
		return provider.CreateResult{Status: "failed",
			Reason: "dataset still contains tables — tables are data; delete them explicitly first (retirement is data loss)"}
	}
	if st >= 400 {
		if r := provider.MutationResult(st, gcpErrCode(body), nil, providerID, "delete"); r != nil {
			return *r
		}
		return provider.CreateResult{Status: "failed", Reason: fmt.Sprintf("delete HTTP %d: %s", st, mutDetail(body))}
	}
	return provider.CreateResult{ProviderID: providerID, Status: "succeeded"}
}
