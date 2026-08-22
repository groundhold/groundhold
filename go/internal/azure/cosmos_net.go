// Azure Cosmos DB network shell (D112): the ARM half of the capability.database.nosql
// driver. A single databaseAccounts PUT polled to provisioningState=Succeeded; the
// account name is deterministic, so the providerId is knowable before the response
// (D29). Ownership is tags. observe reverse-maps region / continuous-backup (PITR)
// / CMK. deletion.protection is refused at build (Cosmos has no flag). D29/D87.
package azure

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"groundhold/internal/provider"
)

func cosmosProviderID(sub, rg, account string) string {
	return "cosmos:" + sub + ":" + rg + ":" + account
}

func splitCosmosProviderID(providerID string) (sub, rg, account string, err error) {
	parts := strings.Split(providerID, ":")
	if len(parts) != 4 || parts[0] != "cosmos" {
		return "", "", "", fmt.Errorf("providerId %q is not cosmos:sub:rg:account", providerID)
	}
	if !subOK.MatchString(parts[1]) || !rgOK.MatchString(parts[2]) || !cosmosNameOK.MatchString(parts[3]) {
		return "", "", "", fmt.Errorf("providerId %q has an invalid component", providerID)
	}
	return parts[1], parts[2], parts[3], nil
}

func (d *Driver) cosmosPath(account string) string {
	return "Microsoft.DocumentDB/databaseAccounts/" + account
}

func (d *Driver) createCosmos(environment, capability string,
	attrs, impl map[string]any, generation int) provider.CreateResult {
	plan, err := BuildCosmos(environment, capability, attrs, impl, generation)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	rg, _ := impl["resource_group"].(string)
	if !rgOK.MatchString(rg) {
		return provider.CreateResult{Status: "failed",
			Reason: "azure cosmos requires implementation.resource_group"}
	}
	if !subOK.MatchString(d.Subscription) {
		return provider.CreateResult{Status: "failed",
			Reason: fmt.Sprintf("azure subscription %q is not a valid GUID", d.Subscription)}
	}
	pid := cosmosProviderID(d.Subscription, rg, plan.Account)
	acctURL, _ := d.armURL(rg, d.cosmosPath(plan.Account), cosmosAPIVersion)
	body, _ := json.Marshal(plan.createBody(d.tags(capability, environment)))
	if r := d.putAndPoll(acctURL, body, pid, "cosmos account"); r != nil {
		return *r
	}
	return provider.CreateResult{ProviderID: pid, Status: "succeeded"}
}

type cosmosDoc struct {
	Location   string            `json:"location"`
	Tags       map[string]string `json:"tags"`
	Properties struct {
		ProvisioningState string `json:"provisioningState"`
		KeyVaultKeyUri    string `json:"keyVaultKeyUri"`
		BackupPolicy      struct {
			Type string `json:"type"`
		} `json:"backupPolicy"`
		Locations []struct {
			LocationName string `json:"locationName"`
			// isZoneRedundant is the field that decides whether this account survives
			// a zone failure — the whole meaning of availability.class (D753).
			IsZoneRedundant bool `json:"isZoneRedundant"`
		} `json:"locations"`
	} `json:"properties"`
}

func (d *Driver) observeCosmos(capability, providerID string) ([]provider.Observation, []string, error) {
	sub, rg, account, err := splitCosmosProviderID(providerID)
	if err != nil {
		return nil, nil, err
	}
	if sub != d.Subscription && d.Subscription != "" {
		return nil, nil, fmt.Errorf("providerId subscription %q is not the driver's", sub)
	}
	acctURL, _ := d.armURL(rg, d.cosmosPath(account), cosmosAPIVersion)
	st, resp, e := d.doARM("GET", acctURL, nil)
	if e != nil {
		return nil, nil, fmt.Errorf("databaseAccounts.get: %v", e)
	}
	if st == http.StatusNotFound {
		// F-LC3 (D518): a BOUND resource the API authoritatively 404s is GONE.
		// A diagnostic alone leaves the binding a no-op forever (D513).
		return []provider.Observation{
			{Path: provider.ResourceAbsentPath, Value: true, Derivation: "measured"},
		}, []string{"cosmos account not found — bound resource is gone (will re-create)"}, nil
	}
	if st != http.StatusOK {
		return nil, nil, fmt.Errorf("databaseAccounts.get: HTTP %d", st)
	}
	var doc cosmosDoc
	if json.Unmarshal(resp, &doc) != nil {
		return nil, nil, &armReadError{Op: "databaseAccounts.get", Cause: "body", Status: st}
	}
	region := doc.Location
	if region == "" && len(doc.Properties.Locations) > 0 {
		region = doc.Properties.Locations[0].LocationName
	}
	// Present: clear the marker, or a stale "gone" survives a re-create.
	obs := []provider.Observation{
		{Path: provider.ResourceAbsentPath, Value: false, Derivation: "measured"},
		{Path: "service.managed", Value: true, Derivation: "measured"},
		{Path: "backup.pointInTimeRecovery", Value: doc.Properties.BackupPolicy.Type == "Continuous", Derivation: "measured"},
	}
	var diags []string
	switch {
	case len(doc.Properties.Locations) > 1:
		// D1045: a Cosmos account replicates data to EVERY configured location, not just
		// the write region. Emitting only Locations[0] as location.region let a single-
		// region residency constraint read satisfied while the data also sits in the other
		// regions. Withhold + diagnose (the availability.class D753 discipline) so a hard
		// residency constraint blocks as unknown rather than passing over multi-region data.
		names := make([]string, len(doc.Properties.Locations))
		for i, l := range doc.Properties.Locations {
			names[i] = l.LocationName
		}
		diags = append(diags, "location.region not observed: this Cosmos account replicates "+
			"to "+strings.Join(names, ", ")+" — a single-region residency constraint cannot be "+
			"confirmed on a multi-region account")
	case region != "":
		obs = append(obs, provider.Observation{Path: "location.region", Value: strings.ToLower(region), Derivation: "measured"})
	}
	// D753. This emitted the constant "regional" with derivation config-intent, while
	// the create sent `isZoneRedundant: false` — so the tool built a single-zone account
	// and reported the class the vocabulary defines as "replicated across zones in one
	// region". A contract asking to survive a zone failure read satisfied against an
	// account that does not.
	//
	// The enum for this capability is [regional, multi-regional]: there is no value for
	// a non-zone-redundant account, so an account that is not zone-redundant gets NO
	// observation and a diagnostic saying why. Withholding blocks a hard constraint,
	// which is the safe direction; naming a class it does not have does not.
	switch {
	case len(doc.Properties.Locations) == 0:
		diags = append(diags, "availability.class not observed: the account reports no "+
			"locations, so its zone redundancy cannot be read")
	case doc.Properties.Locations[0].IsZoneRedundant:
		obs = append(obs, provider.Observation{Path: "availability.class",
			Value: "regional", Derivation: "measured"})
	default:
		diags = append(diags, "availability.class not observed: the account's write "+
			"region is NOT zone-redundant (isZoneRedundant=false), so it does not "+
			"survive a zone failure — which is what regional means here")
	}
	obs = append(obs, provider.Observation{Path: "encryption.customerManagedKeys", Value: doc.Properties.KeyVaultKeyUri != "", Derivation: "measured"})
	return obs, diags, nil
}

func (d *Driver) deleteCosmos(capability, environment, providerID string) provider.CreateResult {
	_, rg, account, err := splitCosmosProviderID(providerID)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	acctURL, _ := d.armURL(rg, d.cosmosPath(account), cosmosAPIVersion)
	st, resp, e := d.doARM("GET", acctURL, nil)
	if e != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown", Reason: "pre-delete read gave no answer — reconcile: " + azReadWhy(st, resp, e)}
	}
	if st == http.StatusNotFound {
		return provider.CreateResult{ProviderID: providerID, Status: "succeeded"} // idempotent
	}
	if st != http.StatusOK {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown", Reason: fmt.Sprintf("pre-delete read HTTP %d — reconcile", st)}
	}
	var doc cosmosDoc
	if json.Unmarshal(resp, &doc) != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown", Reason: "pre-delete read answered HTTP 200 with an unparseable body — reconcile"}
	}
	if doc.Tags["groundhold-capability"] != sanitizeAzTag(capability) ||
		doc.Tags["groundhold-environment"] != sanitizeAzTag(environment) {
		return provider.CreateResult{Status: "failed",
			Reason: "cosmos account tags do not match — refusing to delete a resource that is not ours"}
	}
	// D984: route the delete through deleteAndConfirm (D971) — Cosmos DELETE returns
	// 202 Accepted (async), so concluding succeeded here tombstoned an account still
	// live; the helper polls to a confirmed 404, unknown on timeout.
	return *d.deleteAndConfirm(acctURL, providerID, "cosmos account")
}

// classifyCosmosChange decides whether a drift on a Cosmos DB account is reconciled in place or
// replaced. Before D1216 cosmos had NO ClassifyChange, so every drift fell to the driver default
// of "immutable" = replacement — and replacing a Cosmos account destroys every database in it.
// That verdict was being applied to backup.pointInTimeRecovery (the Periodic/Continuous backup
// mode), which Azure migrates in place. D1216: it is `mutable`, with the one-way direction fenced
// off in the update (the D1202 locked-retention shape) — enabling PITR is a migration, DISabling
// it is refused because Azure cannot revert Continuous to Periodic.
func classifyCosmosChange(path string) (string, string) {
	switch path {
	case "backup.pointInTimeRecovery":
		return "mutable", "backup.pointInTimeRecovery is migrated in place: the account's backup " +
			"mode Periodic->Continuous (an online, ONE-WAY migration). Enabling PITR is the migration; " +
			"disabling it is refused (Azure cannot revert Continuous to Periodic)"
	default:
		return "immutable", fmt.Sprintf(
			"Cosmos DB has no in-place update path for %q — reconciling a drift is a replacement", path)
	}
}

// updateCosmos migrates backup.pointInTimeRecovery on in place (D1216): a PATCH of the account's
// backupPolicy to Continuous, then a poll to the applied state (the migration is async — the
// account reports migrationState=InProgress and backupPolicy.type stays Periodic until it
// completes, so reporting succeeded on accept would claim PITR is on while the backup is still
// migrating). The direction is the design: Periodic->Continuous is a supported ONE-WAY migration,
// so enabling is `mutable`; Continuous->Periodic is REFUSED at apply because Azure does not
// support it (acting would mean replacing the account and destroying its data). Ownership by tags.
func (d *Driver) updateCosmos(capability, environment, providerID string,
	attrs map[string]any, changes []string) provider.CreateResult {
	sub, rg, account, err := splitCosmosProviderID(providerID)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	if sub != d.Subscription && d.Subscription != "" {
		return provider.CreateResult{Status: "failed",
			Reason: fmt.Sprintf("providerId subscription %q is not the driver's", sub)}
	}
	acctURL, _ := d.armURL(rg, d.cosmosPath(account), cosmosAPIVersion)
	st, resp, e := d.doARM("GET", acctURL, nil)
	if e != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown",
			Reason: "pre-update read gave no answer — reconcile: " + azReadWhy(st, resp, e)}
	}
	if st == http.StatusNotFound {
		return provider.CreateResult{Status: "failed", Reason: "cosmos account no longer exists — cannot update"}
	}
	if st != http.StatusOK {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown",
			Reason: fmt.Sprintf("pre-update read HTTP %d — reconcile", st)}
	}
	var doc cosmosDoc
	if json.Unmarshal(resp, &doc) != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown",
			Reason: "pre-update read answered HTTP 200 with an unparseable body — reconcile"}
	}
	if doc.Tags["groundhold-capability"] != sanitizeAzTag(capability) ||
		doc.Tags["groundhold-environment"] != sanitizeAzTag(environment) {
		return provider.CreateResult{Status: "failed",
			Reason: "cosmos account tags do not match — refusing to patch a resource that is not ours"}
	}

	for _, path := range changes {
		switch path {
		case "backup.pointInTimeRecovery":
			pitr, ok := attrs["backup.pointInTimeRecovery"].(bool)
			if !ok {
				return provider.CreateResult{Status: "failed", Reason: "backup.pointInTimeRecovery must be a bool"}
			}
			isContinuous := doc.Properties.BackupPolicy.Type == "Continuous"
			switch {
			case pitr && isContinuous, !pitr && !isContinuous:
				continue // already at the requested backup mode — nothing to migrate
			case !pitr && isContinuous:
				return provider.CreateResult{Status: "failed",
					Reason: "backup.pointInTimeRecovery=false cannot be honored in place: Azure Cosmos " +
						"DB backup migration is ONE-WAY (Continuous cannot be reverted to Periodic). " +
						"Refusing rather than replacing the account and destroying its data"}
			}
			// Periodic -> Continuous: the supported one-way migration (an account PATCH).
			body, _ := json.Marshal(map[string]any{"properties": map[string]any{
				"backupPolicy": map[string]any{"type": "Continuous",
					"continuousModeProperties": map[string]any{"tier": "Continuous7Days"}}}})
			if r := d.patchSetting(acctURL, body, providerID, "cosmos backup migration"); r != nil {
				return *r
			}
			// Poll to the APPLIED state: the migration is async (backupPolicy.type stays Periodic
			// with migrationState=InProgress until it completes), so PITR is not on until the
			// account reports Continuous.
			deadline := d.Now().Add(d.PollTimeout)
			for {
				gst, gresp, ge := d.doARM("GET", acctURL, nil)
				if ge == nil && gst == http.StatusOK {
					var cur cosmosDoc
					if json.Unmarshal(gresp, &cur) == nil && cur.Properties.BackupPolicy.Type == "Continuous" {
						break
					}
				}
				if d.Now().After(deadline) {
					return provider.CreateResult{ProviderID: providerID, Status: "unknown",
						Reason: "backup migration still in progress at poll timeout — reconcile via databaseAccounts.get"}
				}
				time.Sleep(d.PollInterval)
			}
		default:
			return provider.CreateResult{Status: "failed",
				Reason: "no cosmos in-place mapping for " + path}
		}
	}
	return provider.CreateResult{ProviderID: providerID, Status: "succeeded"}
}
