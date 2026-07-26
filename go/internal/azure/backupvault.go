package azure

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// backupvault.go is the Azure driver for capability.backup.vault (D244), the
// third cloud of the domain — a Microsoft.DataProtection/backupVaults resource,
// the parent of the DataProtection backup policies the existing backuppolicy
// driver already speaks. It completes the AWS (Backup vault) + GCP (Backup and DR
// vault) twin to full 3-cloud parity.
//
// The honest per-cloud story, stated not smoothed: Azure is the MOST capable of
// the three for this domain.
//   - retention.lockMode: Azure honors BOTH governance and compliance
//     (immutabilitySettings.state = Unlocked vs Locked) — unlike GCP, which
//     refuses governance (its enforced retention is immutable by construction).
//   - encryption.customerManagedKeys: a real vault-level capability on Azure
//     (securitySettings.encryptionSettings + a system-assigned identity that
//     reads the key) — unlike GCP, which refuses it (Google-managed only).
//   - retention.minimum is OPTIONAL (a vault may exist without a soft-delete
//     retention lock), like AWS and unlike GCP which requires it.
//
// The backup POLICIES, schedules and instances that populate the vault are a
// separate concern (opaque impl, invariant #4); this capability is the vault and
// its retention/immutability guarantee. storageSettings (redundancy + datastore)
// is a required Azure operand, not a capability attribute — an honest default,
// overridable via implementation.storage_redundancy.

// BackupVaultPlan is the attribute-derived shape a create assembles.
type BackupVaultPlan struct {
	Name              string
	ResourceGroup     string
	Region            string
	RetentionDays     int    // 0 = no soft-delete retention lock
	LockState         string // Disabled | Unlocked (governance) | Locked (compliance)
	LockMode          string // governance | compliance | "" (for diagnostics)
	CMK               bool
	KeyVaultKeyURI    string
	StorageRedundancy string // default LocallyRedundant
}

// BackupVaultName derives a deterministic, regex-valid vault name (2-50 chars,
// alphanumeric + dash, alphanumeric start) from environment/capability/generation.
func BackupVaultName(environment, capability string, generation int) string {
	in := environment + "|" + capability
	if generation >= 2 {
		in += fmt.Sprintf("|g%d", generation)
	}
	sum := sha256.Sum256([]byte(in))
	return "pv-bv-" + hex.EncodeToString(sum[:])[:16] // 6 + 16 = 22 chars
}

func backupVaultProviderID(sub, rg, vault string) string {
	return "backupvault:" + sub + ":" + rg + ":" + vault
}

func splitBackupVaultProviderID(providerID string) (sub, rg, vault string, err error) {
	parts := strings.SplitN(providerID, ":", 4)
	if len(parts) != 4 || parts[0] != "backupvault" {
		return "", "", "", fmt.Errorf("providerId %q is not backupvault:sub:rg:vault", providerID)
	}
	if !subOK.MatchString(parts[1]) {
		return "", "", "", fmt.Errorf("providerId %q has an invalid subscription", providerID)
	}
	if !rgOK.MatchString(parts[2]) {
		return "", "", "", fmt.Errorf("providerId %q has an invalid resource group", providerID)
	}
	if !backupVaultNameOK.MatchString(parts[3]) {
		return "", "", "", fmt.Errorf("providerId %q has an invalid vault name", providerID)
	}
	return parts[1], parts[2], parts[3], nil
}

// BuildBackupVault maps capability.backup.vault attributes + impl to a plan. Every
// error is a preflight refusal, never a silent drop.
func BuildBackupVault(environment, capability string,
	attrs, impl map[string]any, generation int) (BackupVaultPlan, error) {
	p := BackupVaultPlan{
		Name:              BackupVaultName(environment, capability, generation),
		LockState:         "Disabled",
		StorageRedundancy: "LocallyRedundant",
	}
	keys := make([]string, 0, len(attrs))
	for k := range attrs {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	cmk := false
	for _, path := range keys {
		raw := attrs[path]
		switch path {
		case "location.region":
			p.Region, _ = raw.(string)
		case "retention.minimum":
			days, err := backupPolicyDurationToDays(raw)
			if err != nil {
				return BackupVaultPlan{}, fmt.Errorf("retention.minimum: %v", err)
			}
			p.RetentionDays = days
		case "retention.lockMode":
			s, _ := raw.(string)
			switch s {
			case "governance":
				// immutability ON but admin-reversible — Azure's governance analog
				// (GCP has no such mode and refuses it; Azure honors it).
				p.LockMode, p.LockState = s, "Unlocked"
			case "compliance":
				p.LockMode, p.LockState = s, "Locked" // irreversible WORM
			default:
				return BackupVaultPlan{}, fmt.Errorf("retention.lockMode %q is not a recognized value", s)
			}
		case "encryption.customerManagedKeys":
			cmk = (raw == true)
		case "service.managed":
			if raw != true {
				return BackupVaultPlan{}, fmt.Errorf("service.managed=false cannot be honored by Azure Backup")
			}
		default:
			return BackupVaultPlan{}, fmt.Errorf(
				"attribute %s has no Azure backup-vault mapping — refusing rather than silently dropping it "+
					"(backup policies, schedules and instances are opaque impl)", path)
		}
	}
	if p.Region == "" {
		return BackupVaultPlan{}, fmt.Errorf("capability.backup.vault requires location.region")
	}
	rg, _ := impl["resource_group"].(string)
	if rg == "" {
		return BackupVaultPlan{}, fmt.Errorf("azure backup vault requires implementation.resource_group")
	}
	p.ResourceGroup = rg
	if p.LockMode != "" && p.RetentionDays == 0 {
		return BackupVaultPlan{}, fmt.Errorf(
			"retention.lockMode requires retention.minimum — a lock enforces a minimum retention, so there must be one to enforce")
	}
	if cmk {
		uri, _ := impl["key_vault_key_uri"].(string)
		if uri == "" {
			return BackupVaultPlan{}, fmt.Errorf(
				"encryption.customerManagedKeys=true requires implementation.key_vault_key_uri " +
					"(the Key Vault key uri is implementation detail, never a capability path)")
		}
		p.CMK, p.KeyVaultKeyURI = true, uri
	}
	if r, ok := impl["storage_redundancy"].(string); ok && r != "" {
		p.StorageRedundancy = r
	}
	if !backupVaultNameOK.MatchString(p.Name) {
		return BackupVaultPlan{}, fmt.Errorf("derived vault name %q is invalid", p.Name)
	}
	return p, nil
}

// backupVaultCreateBody builds the ARM PUT body for the vault.
func (d *Driver) backupVaultCreateBody(p BackupVaultPlan, capability, environment string) []byte {
	security := map[string]any{
		"immutabilitySettings": map[string]any{"state": p.LockState},
	}
	if p.RetentionDays > 0 {
		security["softDeleteSettings"] = map[string]any{
			"state":                   "On",
			"retentionDurationInDays": p.RetentionDays,
		}
	}
	body := map[string]any{
		"location": p.Region,
		"tags":     d.tags(capability, environment),
		"properties": map[string]any{
			"storageSettings": []any{map[string]any{
				"type": p.StorageRedundancy, "datastoreType": "VaultStore",
			}},
			"securitySettings": security,
		},
	}
	if p.CMK {
		// a system-assigned identity reads the customer key
		body["identity"] = map[string]any{"type": "SystemAssigned"}
		security["encryptionSettings"] = map[string]any{
			"state":              "Enabled",
			"keyVaultProperties": map[string]any{"keyUri": p.KeyVaultKeyURI},
			"kekIdentity":        map[string]any{"identityType": "SystemAssigned"},
		}
	}
	raw, _ := json.Marshal(body)
	return raw
}
