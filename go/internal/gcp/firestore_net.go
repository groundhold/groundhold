// GCP Firestore network shell (D112): the bearer-signed REST half of the
// capability.database.nosql driver. Create/delete are async (LRO). The Firestore
// Database resource has NO labels, so ownership is CONTENT-ADDRESSED: a resource
// is ours iff its databaseId equals our deterministic derivation of
// project|environment|capability at some generation. The databaseId is
// deterministic, so the providerId is knowable before the create response (D29).
// D29/D87 honesty throughout.
package gcp

import (
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"

	"groundhold/internal/provider"
)

func (d *Driver) firestoreBase() string {
	if d.FirestoreBaseURL != "" {
		return d.FirestoreBaseURL
	}
	return firestoreBaseURL
}

func firestoreProviderID(project, dbID string) string {
	return "firestore:" + project + ":" + dbID
}

func splitFirestoreProviderID(providerID string) (project, dbID string, err error) {
	parts := strings.Split(providerID, ":")
	if len(parts) != 3 || parts[0] != "firestore" {
		return "", "", fmt.Errorf("providerId %q is not firestore:project:databaseId", providerID)
	}
	if !projectOK.MatchString(parts[1]) {
		return "", "", fmt.Errorf("providerId project %q is invalid", parts[1])
	}
	if !firestoreIDOK.MatchString(parts[2]) {
		return "", "", fmt.Errorf("providerId database id %q is invalid", parts[2])
	}
	return parts[1], parts[2], nil
}

// firestoreOwned is the content-addressed ownership check: dbID is ours iff it
// equals our deterministic derivation at some generation (1..9 covers the
// original plus replacements). No labels exist to compare, so the name IS the tag.
func firestoreOwned(project, environment, capability, dbID string) bool {
	for g := 1; g <= 9; g++ {
		if dbID == FirestoreDatabaseID(project, environment, capability, g) {
			return true
		}
	}
	return false
}

func (d *Driver) firestoreDBURL(project, dbID string) string {
	return fmt.Sprintf("%s/projects/%s/databases/%s", d.firestoreBase(), project, dbID)
}

type firestoreDoc struct {
	Name                          string `json:"name"`
	LocationID                    string `json:"locationId"`
	Type                          string `json:"type"`
	PointInTimeRecoveryEnablement string `json:"pointInTimeRecoveryEnablement"`
	DeleteProtectionState         string `json:"deleteProtectionState"`
	CmekConfig                    struct {
		KmsKeyName string `json:"kmsKeyName"`
	} `json:"cmekConfig"`
}

func (d *Driver) getFirestore(project, dbID string) (firestoreDoc, bool, error) {
	const op = "firestore.get"
	st, body, err := d.call("GET", d.firestoreDBURL(project, dbID), nil)
	if err != nil {
		return firestoreDoc{}, false, readTransport(op, err)
	}
	if st == http.StatusNotFound {
		return firestoreDoc{}, false, nil
	}
	if st != http.StatusOK {
		return firestoreDoc{}, false, readHTTP(op, st, gcpErrCode(body))
	}
	var doc firestoreDoc
	if json.Unmarshal(body, &doc) != nil {
		return firestoreDoc{}, false, readBody(op, st)
	}
	return doc, true, nil
}

func (d *Driver) createFirestore(environment, capability string,
	attrs, impl map[string]any, generation int) provider.CreateResult {
	plan, err := BuildFirestoreCreate(d.Project, environment, capability, attrs, impl, generation)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	pid := firestoreProviderID(d.Project, plan.DatabaseID)
	url := fmt.Sprintf("%s/projects/%s/databases?databaseId=%s",
		d.firestoreBase(), d.Project, plan.DatabaseID)
	st, body, err := d.call("POST", url, plan.createBody())
	switch {
	case err != nil:
		return provider.CreateResult{ProviderID: pid, Status: "unknown",
			Reason: fmt.Sprintf("create outcome unknown (may have landed): %v", err)}
	case st == http.StatusOK:
		// LRO started — poll below
	case st == http.StatusConflict:
		// content-addressed: an existing db with our id is ours (only our scheme
		// produces this hash) — idempotent success.
		_, found, rerr := d.getFirestore(d.Project, plan.DatabaseID)
		if rerr == nil && found {
			return provider.CreateResult{ProviderID: pid, Status: "succeeded"}
		}
		if rerr != nil {
			return provider.CreateResult{ProviderID: pid, Status: "unknown",
				Reason: "name conflict, existing database gave no answer — reconcile: " + rerr.Error()}
		}
		return provider.CreateResult{ProviderID: pid, Status: "unknown",
			Reason: "name conflict, but the conflicting database was gone on the follow-up read — reconcile"}
	case st >= 500:
		return provider.CreateResult{ProviderID: pid, Status: "unknown",
			Reason: fmt.Sprintf("create HTTP %d (server error — may have landed) — reconcile", st)}
	default:
		if r := provider.MutationResult(st, gcpErrCode(body), nil, pid, "create"); r != nil {
			return *r
		}
		return provider.CreateResult{Status: "failed",
			Reason: fmt.Sprintf("create HTTP %d: %s", st, mutDetail(body))}
	}
	var op struct {
		Name string `json:"name"`
	}
	if json.Unmarshal(body, &op) != nil || op.Name == "" {
		return provider.CreateResult{ProviderID: pid, Status: "unknown",
			Reason: "create response carried no operation — reconcile"}
	}
	res := d.pollFirestoreOperation(op.Name)
	if res.Status == "succeeded" || res.ProviderID == "" {
		res.ProviderID = pid
	}
	return res
}

func (d *Driver) pollFirestoreOperation(opName string) provider.CreateResult {
	deadline := d.Now().Add(d.PollTimeout)
	for {
		st, body, err := d.call("GET", d.firestoreBase()+"/"+opName, nil)
		if err == nil && st == http.StatusOK {
			var op struct {
				Done  bool `json:"done"`
				Error *struct {
					Message string `json:"message"`
				} `json:"error"`
			}
			if json.Unmarshal(body, &op) == nil && op.Done {
				if op.Error != nil {
					return provider.CreateResult{Status: "failed", OperationID: opName,
						Reason: fmt.Sprintf("operation failed: %s", op.Error.Message)}
				}
				return provider.CreateResult{Status: "succeeded", OperationID: opName}
			}
		}
		if d.Now().After(deadline) {
			return provider.CreateResult{Status: "unknown", OperationID: opName,
				Reason: "firestore operation still running at poll timeout — reconcile"}
		}
		time.Sleep(d.PollInterval)
	}
}

// gcpRegionID matches a real GCP region (europe-west1, us-central1). A Firestore
// location that does NOT match is a multi-region grouping (nam5, eur3) — D799.
var gcpRegionID = regexp.MustCompile(`^[a-z]+-[a-z]+[0-9]+$`)

// residencyMultiRegionDiag returns the D799/D1043 residency-honesty diagnostic when
// `loc` is a GCP MULTI-REGION (US, EU, ASIA, nam5, eur3 …) rather than a single region.
// A region-name comparison against a multi-region is not comparing what it appears to,
// so a residency constraint (especially an exclusion like `not-in [asia-southeast1]`)
// can read SATISFIED while the bytes physically reside across several regions. Empty
// when `loc` is a single region or empty. `what` names the resource in the message.
// D1043: D799 landed only on Firestore; the same shape sits on every location.region
// emitted from a field that can be a multi-region (BigQuery/GCS Location, image storage).
func residencyMultiRegionDiag(loc, what string) string {
	if loc == "" || gcpRegionID.MatchString(strings.ToLower(loc)) {
		return ""
	}
	return "location.region is " + loc + ", a MULTI-REGION rather than a region: the " +
		what + "'s data is resident in more than one region, and a residency constraint " +
		"comparing region names is not comparing what it appears to"
}

// firestoreAvailability answers from the location the database is actually in, rather
// than from the type of the service (D799).
func firestoreAvailability(locationID string) string {
	if locationID != "" && !gcpRegionID.MatchString(locationID) {
		return "multi-regional"
	}
	return "regional"
}

func (d *Driver) observeFirestore(capability, providerID string) ([]provider.Observation, []string, error) {
	project, dbID, err := splitFirestoreProviderID(providerID)
	if err != nil {
		return nil, nil, err
	}
	if err := d.sameProject(project); err != nil {
		return nil, nil, err
	}
	doc, found, rerr := d.getFirestore(project, dbID)
	if rerr != nil {
		return nil, nil, rerr
	}
	if !found {
		// F-LC3 (D519): a BOUND resource the API authoritatively 404s is GONE.
		// A diagnostic alone leaves the binding a no-op forever (D513).
		return []provider.Observation{
			{Path: provider.ResourceAbsentPath, Value: true, Derivation: "measured"},
		}, []string{"database not found — bound resource is gone (will re-create)"}, nil
	}
	var diags []string
	obs := []provider.Observation{
		// Present: clear the marker (F-LC3), or a stale "gone" survives a re-create.
		{Path: provider.ResourceAbsentPath, Value: false, Derivation: "measured"},
		{Path: "service.managed", Value: true, Derivation: "measured"},
		{Path: "availability.class", Value: firestoreAvailability(doc.LocationID), Derivation: "measured"},
		{Path: "backup.pointInTimeRecovery",
			Value: doc.PointInTimeRecoveryEnablement == "POINT_IN_TIME_RECOVERY_ENABLED", Derivation: "measured"},
		{Path: "deletion.protection",
			Value: doc.DeleteProtectionState == "DELETE_PROTECTION_ENABLED", Derivation: "measured"},
	}
	if doc.LocationID != "" {
		obs = append(obs, provider.Observation{Path: "location.region", Value: doc.LocationID, Derivation: "measured"})
		if !gcpRegionID.MatchString(doc.LocationID) {
			// D799: a Firestore database can be created in a MULTI-REGION (nam5, eur3),
			// and the driver reported that identifier as if it were a region while
			// calling "regional" a platform invariant. Both were wrong, and the pair of
			// them let a residency constraint compare against a name that stands for
			// several regions at once.
			diags = append(diags, "location.region is "+doc.LocationID+", which is a "+
				"MULTI-REGION rather than a region: the database's data is resident in "+
				"more than one region, and a residency constraint comparing region names "+
				"is not comparing what it appears to")
		}
	}
	// D1003: no customer key is a MEASURED FALSE (Google-managed default), never
	// an absence — emit the boolean unconditionally so a hard customerManagedKeys
	// constraint has a value to contradict instead of passing vacuously.
	obs = append(obs, provider.Observation{Path: "encryption.customerManagedKeys", Value: doc.CmekConfig.KmsKeyName != "", Derivation: "measured"})
	return obs, diags, nil
}

func (d *Driver) deleteFirestore(capability, environment, providerID string) provider.CreateResult {
	project, dbID, err := splitFirestoreProviderID(providerID)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	if err := d.sameProject(project); err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	// content-addressed ownership: the databaseId must be one WE could have minted.
	if !firestoreOwned(project, environment, capability, dbID) {
		return provider.CreateResult{Status: "failed",
			Reason: "database id is not one of ours (content-addressed ownership) — refusing to delete a resource that is not ours"}
	}
	doc, found, rerr := d.getFirestore(project, dbID)
	if rerr != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown", Reason: "pre-delete read gave no answer — reconcile: " + rerr.Error()}
	}
	if !found {
		return provider.CreateResult{ProviderID: providerID, Status: "succeeded"} // idempotent
	}
	// deletion protection blocks a destroy — surfaced, never forced.
	if doc.DeleteProtectionState == "DELETE_PROTECTION_ENABLED" {
		return provider.CreateResult{Status: "failed",
			Reason: "the database has delete protection enabled — retirement is blocked until it is " +
				"disabled; never forced (the protection is the capability)"}
	}
	st, body, e := d.call("DELETE", d.firestoreDBURL(project, dbID), nil)
	if e != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown", Reason: fmt.Sprintf("delete outcome unknown: %v", e)}
	}
	if st == http.StatusNotFound {
		return provider.CreateResult{ProviderID: providerID, Status: "succeeded"}
	}
	if st >= 500 {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown", Reason: fmt.Sprintf("delete HTTP %d (server error) — reconcile", st)}
	}
	if st != http.StatusOK {
		if r := provider.MutationResult(st, gcpErrCode(body), nil, providerID, "delete"); r != nil {
			return *r
		}
		return provider.CreateResult{ProviderID: providerID, Status: "failed", Reason: fmt.Sprintf("delete HTTP %d: %s", st, mutDetail(body))}
	}
	var op struct {
		Name string `json:"name"`
	}
	if json.Unmarshal(body, &op) != nil || op.Name == "" {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown", Reason: "delete response carried no operation — reconcile"}
	}
	res := d.pollFirestoreOperation(op.Name)
	if res.Status == "succeeded" || res.ProviderID == "" {
		res.ProviderID = providerID
	}
	return res
}
