// Azure Cosmos DB request building (D112): the semantic core of the Azure
// capability.database.nosql driver — the SAME vocabulary AWS DynamoDB and GCP
// Firestore fulfil. A Cosmos DB account (Microsoft.DocumentDB/databaseAccounts) is
// the managed NoSQL resource; the account name is GLOBALLY unique. The honest gap
// this cloud forces: deletion.protection is REFUSED — Cosmos has no account-level
// deletion-protection property (deletion is guarded by a SEPARATE
// Microsoft.Authorization management lock, out of this single resource's scope),
// where DynamoDB and Firestore expose it as a flag. availability.class=
// multi-regional (multi-region writes) is refused in v0.
package azure

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"sort"
)

const cosmosAPIVersion = "2024-05-15"

// cosmosNameOK bounds a Cosmos account name: 3-44 lowercase alphanumerics + hyphen,
// globally unique.
var cosmosNameOK = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{1,42}[a-z0-9]$`)

// CosmosPlan is the attribute-derived shape a create assembles into the ARM body.
type CosmosPlan struct {
	Account        string
	Region         string
	PITR           bool   // continuous backup
	KmsKeyVaultURI string // CMEK, from impl; "" = provider-managed

	// ZoneRedundant is what `availability.class: regional` MEANS in this vocabulary:
	// "replicated across zones in one region". The create used to send false for it
	// unconditionally while accepting the declaration, so the tool built a
	// single-zone account and reported zone resilience (D753).
	ZoneRedundant bool
}

// cosmosAccountName is a deterministic, globally-unique account name (pure hash;
// the account is the constitutive resource, its name is never author-visible).
func cosmosAccountName(environment, capability string, generation int) string {
	hashInput := environment + "|" + capability
	if generation >= 2 {
		hashInput += fmt.Sprintf("|g%d", generation)
	}
	sum := sha256.Sum256([]byte(hashInput))
	return "pv-" + hex.EncodeToString(sum[:])[:20] // "pv-" + 20 hex = 23 chars
}

// BuildCosmos maps capability.database.nosql attributes to a Cosmos plan. Every
// error is a refusal apply surfaces in preflight.
func BuildCosmos(environment, capability string,
	attrs, impl map[string]any, generation int) (CosmosPlan, error) {
	if generation < 1 {
		generation = 1
	}
	p := CosmosPlan{Account: cosmosAccountName(environment, capability, generation)}

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
		case "availability.class":
			switch raw {
			case "regional":
				// D753: NOT merely "a single write region", which is what this branch
				// used to say. The vocabulary defines regional as replicated ACROSS
				// ZONES in one region, and a Cosmos account carries that per location.
				p.ZoneRedundant = true
			case "multi-regional":
				return CosmosPlan{}, fmt.Errorf(
					"availability.class=multi-regional cannot be honored in v0 — Cosmos multi-region " +
						"writes are a heavier setup; refusing rather than faking it")
			default:
				return CosmosPlan{}, fmt.Errorf("availability.class %v has no Cosmos mapping", raw)
			}
		case "backup.pointInTimeRecovery":
			p.PITR, _ = raw.(bool)
		case "deletion.protection":
			if raw == true {
				return CosmosPlan{}, fmt.Errorf(
					"deletion.protection=true cannot be honored on Azure Cosmos DB — Cosmos has no " +
						"account-level deletion-protection property (it is a SEPARATE management lock, " +
						"out of this resource's scope); refusing rather than pretending to set it")
			}
		case "encryption.customerManagedKeys":
			if raw == true {
				p.KmsKeyVaultURI, _ = impl["key_vault_key_uri"].(string)
				if p.KmsKeyVaultURI == "" {
					return CosmosPlan{}, fmt.Errorf(
						"encryption.customerManagedKeys requires implementation.key_vault_key_uri")
				}
			}
		case "service.managed":
			if raw != true {
				return CosmosPlan{}, fmt.Errorf("service.managed=false cannot be honored by Cosmos DB")
			}
		default:
			return CosmosPlan{}, fmt.Errorf(
				"attribute %s has no Cosmos mapping — refusing rather than silently dropping it "+
					"(throughput/RU, containers, indexing policy are implementation modelling)", path)
		}
	}
	if p.Region == "" {
		return CosmosPlan{}, fmt.Errorf("nosql database requires location.region")
	}
	if !cosmosNameOK.MatchString(p.Account) {
		return CosmosPlan{}, fmt.Errorf("derived account name %q is invalid", p.Account)
	}
	return p, nil
}

// createBody is the databaseAccounts PUT body. Ownership is tags.
func (p CosmosPlan) createBody(tags map[string]any) map[string]any {
	// D934: Periodic is not a bare type — Azure rejects {"type":"Periodic"} with
	// "PeriodicModeProperties must be specified when BackupPolicyType is Periodic",
	// so the default (non-PITR) account was uncreatable. Carry the mode's defaults
	// (4-hour interval, 8-hour retention) explicitly; the Continuous branch already
	// carried its own continuousModeProperties.
	backup := map[string]any{"type": "Periodic",
		"periodicModeProperties": map[string]any{
			"backupIntervalInMinutes":        240,
			"backupRetentionIntervalInHours": 8,
		}}
	if p.PITR {
		backup = map[string]any{"type": "Continuous",
			"continuousModeProperties": map[string]any{"tier": "Continuous7Days"}}
	}
	props := map[string]any{
		"databaseAccountOfferType": "Standard",
		"locations": []any{
			map[string]any{"locationName": p.Region, "failoverPriority": 0,
				"isZoneRedundant": p.ZoneRedundant},
		},
		"backupPolicy":        backup,
		"publicNetworkAccess": "Disabled",
	}
	if p.KmsKeyVaultURI != "" {
		props["keyVaultKeyUri"] = p.KmsKeyVaultURI
	}
	return map[string]any{
		"location":   p.Region,
		"kind":       "GlobalDocumentDB",
		"tags":       tags,
		"properties": props,
	}
}
