// GCP Firestore request building (D112): the semantic core of the GCP
// capability.database.nosql driver — the SAME vocabulary AWS DynamoDB and Azure
// Cosmos DB fulfil. Firestore now supports MULTIPLE NAMED databases per project,
// so a database is a first-class creatable resource (Firestore Admin API). Async
// create/delete via LRO. The Firestore Database resource carries NO labels, so
// ownership is CONTENT-ADDRESSED: the deterministic databaseId (a hash of
// project|environment|capability) is itself the proof a resource is ours.
// availability.class=multi-regional (nam5/eur3) is refused in v0.
package gcp

import (
	"fmt"
	"regexp"
)

const firestoreBaseURL = "https://firestore.googleapis.com/v1"

// firestoreIDOK bounds a Firestore database id: 4-63 chars, lowercase letters,
// digits and hyphens, starting with a letter (the Firestore Admin constraint).
var firestoreIDOK = regexp.MustCompile(`^[a-z][a-z0-9-]{2,61}[a-z0-9]$`)

// FirestoreDatabaseID is the deterministic database id (the content-addressed
// ownership handle): a slug + hash, bounded to the Firestore id charset.
func FirestoreDatabaseID(project, environment, capability string, generation int) string {
	// reuse the shared resource-name helper (lowercase slug + hash8), 63 cap.
	return resourceName(project, environment, capability, generation, 63)
}

// FirestorePlan is the attribute-derived shape a create assembles.
type FirestorePlan struct {
	DatabaseID         string
	Location           string
	PITR               bool
	DeletionProtection bool
	KmsKey             string // CMEK, from impl; "" = google-managed
}

// BuildFirestoreCreate maps capability.database.nosql attributes + impl to a plan.
// Every error is a preflight refusal, never a silent drop.
func BuildFirestoreCreate(project, environment, capability string,
	attrs, impl map[string]any, generation int) (FirestorePlan, error) {
	p := FirestorePlan{DatabaseID: FirestoreDatabaseID(project, environment, capability, generation)}
	for _, path := range sortedKeysG(attrs) {
		raw := attrs[path]
		switch path {
		case "location.region":
			p.Location, _ = raw.(string)
		case "availability.class":
			switch raw {
			case "regional":
				// a regional location (e.g. europe-west1)
			case "multi-regional":
				return FirestorePlan{}, fmt.Errorf(
					"availability.class=multi-regional cannot be honored in v0 — a Firestore " +
						"multi-region location (nam5/eur3) is a heavier setup; refusing rather than faking it")
			default:
				return FirestorePlan{}, fmt.Errorf("availability.class %v has no Firestore mapping", raw)
			}
		case "backup.pointInTimeRecovery":
			p.PITR, _ = raw.(bool)
		case "deletion.protection":
			p.DeletionProtection, _ = raw.(bool)
		case "encryption.customerManagedKeys":
			if raw == true {
				p.KmsKey, _ = impl["kms_key_name"].(string)
				if p.KmsKey == "" {
					return FirestorePlan{}, fmt.Errorf(
						"encryption.customerManagedKeys requires implementation.kms_key_name")
				}
			}
		case "service.managed":
			if raw != true {
				return FirestorePlan{}, fmt.Errorf("service.managed=false cannot be honored by Firestore")
			}
		default:
			return FirestorePlan{}, fmt.Errorf(
				"attribute %s has no Firestore mapping — refusing rather than silently dropping it "+
					"(collections, indexes, security rules are implementation modelling)", path)
		}
	}
	if p.Location == "" {
		return FirestorePlan{}, fmt.Errorf("nosql database requires location.region")
	}
	if !firestoreIDOK.MatchString(p.DatabaseID) {
		return FirestorePlan{}, fmt.Errorf("derived database id %q is invalid", p.DatabaseID)
	}
	if !projectOK.MatchString(project) {
		return FirestorePlan{}, fmt.Errorf("project %q is invalid", project)
	}
	return p, nil
}

// createBody is the databases.create request body. Ownership is content-addressed
// (the databaseId), so there is no label field to set.
func (p FirestorePlan) createBody() map[string]any {
	pitr := "POINT_IN_TIME_RECOVERY_DISABLED"
	if p.PITR {
		pitr = "POINT_IN_TIME_RECOVERY_ENABLED"
	}
	delProt := "DELETE_PROTECTION_DISABLED"
	if p.DeletionProtection {
		delProt = "DELETE_PROTECTION_ENABLED"
	}
	body := map[string]any{
		"type":                          "FIRESTORE_NATIVE",
		"locationId":                    p.Location,
		"concurrencyMode":               "PESSIMISTIC",
		"pointInTimeRecoveryEnablement": pitr,
		"deleteProtectionState":         delProt,
	}
	if p.KmsKey != "" {
		body["cmekConfig"] = map[string]any{"kmsKeyName": p.KmsKey}
	}
	return body
}
