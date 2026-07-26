// Azure Blob request building (D99): the semantic core of the Azure storage.object
// driver — the SAME vocabulary S3 and GCS fulfil. Azure puts the semantics on the
// PARENT (the storage account), so the binding is a CONSTITUTIVE COMPOSITE: a
// storage account + its blobServices/default settings + one container, one binding
// (the container is the leaf; the account is the substrate we create/tag/retire,
// never someone else's). All management-plane ARM — never data-plane / shared-key.
package azure

import (
	"fmt"
	"sort"

	"groundhold/internal/scalars"
)

const storageAPIVersion = "2023-05-01"

// storageAccountIDOK (defined in changefeed.go) bounds a destination storage-
// account resource id (the replication operand) before it is interpolated into an
// ARM URL / policy body (the D73 injection boundary). It is a full resource id so
// observe can GET it to MEASURE the destination region — a bare name has none.

// BlobPlan is the attribute-derived shape a create assembles into ARM bodies.
type BlobPlan struct {
	Account                  string
	Container                string
	Region                   string
	Environment              string
	Capability               string
	SKU                      string // Standard_LRS | Standard_ZRS | Standard_GZRS
	Versioning               bool
	Public                   bool
	RetentionMinDays         int64  // immutability policy; 0 = none
	RetentionLocked          bool   // lock the immutability policy (WORM, one-way)
	RetentionMaxDays         int64  // lifecycle expiration; 0 = none
	KmsKeyVaultURI           string // CMEK, from impl; "" = provider-managed
	KmsIdentity              string // user-assigned identity resource id, from impl
	Replication              bool   // object replication policy (directional, source->dest account)
	ReplicationDestAccountID string // operand: destination storage-account resource id
	ReplicationDestContainer string // operand: destination container blobs replicate into
}

func blobContainerName(environment, capability string, generation int) string {
	// container names: 3-63, lowercase alnum + hyphen.
	return azResourceName("pv-obj", environment, capability, generation)
}

// BuildBlob maps capability.storage.object attributes to a Blob plan. Every error
// is a refusal apply surfaces in preflight.
func BuildBlob(environment, capability string,
	attrs, impl map[string]any, generation int) (BlobPlan, error) {
	if generation < 1 {
		generation = 1
	}
	p := BlobPlan{
		Environment: environment, Capability: capability,
		Account:   azStorageName(environment, capability, generation),
		Container: blobContainerName(environment, capability, generation),
		SKU:       "Standard_LRS", // regional baseline unless durability says otherwise
	}

	paths := make([]string, 0, len(attrs))
	for k := range attrs {
		paths = append(paths, k)
	}
	sort.Strings(paths)

	for _, path := range paths {
		raw := attrs[path]
		switch path {
		case "location.region":
			p.Region, _ = raw.(string)
		case "durability.class":
			switch raw {
			case "single-zone":
				p.SKU = "Standard_LRS"
			case "regional":
				p.SKU = "Standard_ZRS"
			case "multi-regional":
				p.SKU = "Standard_GZRS" // replicates to Azure's paired region (provider-chosen)
			default:
				return BlobPlan{}, fmt.Errorf("durability.class %v has no Azure SKU mapping", raw)
			}
		case "versioning.enabled":
			p.Versioning, _ = raw.(bool)
		case "network.publicExposure":
			p.Public, _ = raw.(bool)
		case "encryption.atRest":
			if raw != true {
				return BlobPlan{}, fmt.Errorf(
					"encryption.atRest=false cannot be honored by Azure Storage (SSE is always on)")
			}
		case "encryption.customerManagedKeys":
			if raw == true {
				p.KmsKeyVaultURI, _ = impl["key_vault_key_uri"].(string)
				p.KmsIdentity, _ = impl["user_assigned_identity"].(string)
				if p.KmsKeyVaultURI == "" || p.KmsIdentity == "" {
					return BlobPlan{}, fmt.Errorf(
						"encryption.customerManagedKeys requires implementation.key_vault_key_uri " +
							"AND implementation.user_assigned_identity — a system-assigned identity " +
							"is a create->grant->update chicken-and-egg that breaks same-call honesty")
				}
			}
		case "retention.minimum":
			d, err := durationDays(raw)
			if err != nil {
				return BlobPlan{}, fmt.Errorf("retention.minimum: %v", err)
			}
			p.RetentionMinDays = d
		case "retention.locked":
			p.RetentionLocked, _ = raw.(bool)
		case "retention.maximum":
			d, err := durationDays(raw)
			if err != nil {
				return BlobPlan{}, fmt.Errorf("retention.maximum: %v", err)
			}
			p.RetentionMaxDays = d
		case "replication.enabled":
			p.Replication, _ = raw.(bool)
		case "replication.destinationRegion":
			// The SUBSTANCE of DR residency, but OBSERVED not built (parity with
			// S3): the region lives on the destination ACCOUNT, not in the object
			// replication policy body. Accept the desired value so a contract can
			// assert it, but emit no request — observe MEASURES it from the
			// destination account's location and never trusts a declared value.
		case "service.managed":
			if raw != true {
				return BlobPlan{}, fmt.Errorf("service.managed=false cannot be honored by Azure Blob")
			}
		default:
			return BlobPlan{}, fmt.Errorf(
				"attribute %s has no Azure Blob mapping — refusing rather than silently dropping it", path)
		}
	}
	if p.Region == "" {
		return BlobPlan{}, fmt.Errorf("azure blob requires location.region")
	}
	if p.RetentionLocked && p.RetentionMinDays == 0 {
		return BlobPlan{}, fmt.Errorf(
			"retention.locked (WORM) requires retention.minimum — you cannot lock nothing")
	}
	if p.Replication {
		// Object replication PRESUPPOSES blob versioning on the source (Azure only
		// replicates versioned blobs), plus change feed (enabled by the shell when
		// replication is asked). Honest-refuse rather than half-apply — the same
		// pattern as S3 CRR presupposing versioning.
		if !p.Versioning {
			return BlobPlan{}, fmt.Errorf(
				"replication.enabled (Azure object replication) presupposes " +
					"versioning.enabled=true on the source account — object replication " +
					"only replicates versioned blobs; refusing rather than half-applying it")
		}
		// operands (D26): the destination is a SEPARATE capability.storage.object in
		// another region. This driver points at it (account resource id + container),
		// never creates it. The destination must ALSO have versioning + change feed
		// enabled — a property of that separate capability, not assertable here.
		p.ReplicationDestAccountID, _ = impl["replication_destination_account_id"].(string)
		p.ReplicationDestContainer, _ = impl["replication_destination_container"].(string)
		if p.ReplicationDestAccountID == "" || p.ReplicationDestContainer == "" {
			return BlobPlan{}, fmt.Errorf(
				"replication.enabled requires implementation.replication_destination_account_id " +
					"(the destination storage account, a separate capability.storage.object in " +
					"another region) AND implementation.replication_destination_container (the " +
					"container blobs replicate into) — refusing rather than half-applying it")
		}
		if !storageAccountIDOK.MatchString(p.ReplicationDestAccountID) {
			return BlobPlan{}, fmt.Errorf(
				"implementation.replication_destination_account_id %q is not a valid "+
					"Microsoft.Storage account resource id", p.ReplicationDestAccountID)
		}
		if !azNameOK.MatchString(p.ReplicationDestContainer) {
			return BlobPlan{}, fmt.Errorf(
				"implementation.replication_destination_container %q is not a valid container name",
				p.ReplicationDestContainer)
		}
	}
	if !storageNameOK.MatchString(p.Account) {
		return BlobPlan{}, fmt.Errorf("derived storage account name %q is invalid", p.Account)
	}
	return p, nil
}

// durationDays parses a duration to whole days (Azure retention/lifecycle are
// day-granular). Sub-day is refused, never rounded to zero.
func durationDays(raw any) (int64, error) {
	sc, err := scalars.Parse(raw)
	if err != nil || sc.Kind != scalars.Duration {
		return 0, fmt.Errorf("not a duration")
	}
	days := int64(sc.Value.(float64)) / 86400000
	if days < 1 {
		return 0, fmt.Errorf("below 1 day cannot be honored (Azure retention is whole days)")
	}
	return days, nil
}
