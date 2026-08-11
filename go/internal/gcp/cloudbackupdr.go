// Backup and DR request building (D127): the semantic core of the GCP
// capability.backup.vault driver. A backup vault (backupdr.googleapis.com/v1) enforces
// a MINIMUM retention that is immutable by construction — it can be increased, never
// decreased or removed — so it is compliance-only. Two honest gaps this builder
// enforces: retention.lockMode=governance is REFUSED (there is no admin-changeable mode),
// and encryption.customerManagedKeys=true is REFUSED (a Backup and DR backup vault uses
// Google-managed encryption; CMEK is not a vault-level capability in v0). Ownership is
// LABELS. The backup plans/schedules that populate the vault are opaque impl (invariant #4).
package gcp

import (
	"fmt"
	"time"
)

// BackupDRVaultPlan is the attribute-derived shape a create assembles.
type BackupDRVaultPlan struct {
	VaultID          string
	Location         string
	RetentionSeconds string // e.g. "7776000s"
	Labels           map[string]string
}

// BuildBackupDRVault maps capability.backup.vault attributes + impl to a plan. Every
// error is a preflight refusal, never a silent drop.
func BuildBackupDRVault(project, environment, capability string,
	attrs, impl map[string]any, generation int) (BackupDRVaultPlan, error) {
	if generation < 1 {
		generation = 1
	}
	p := BackupDRVaultPlan{
		VaultID: resourceName(project, environment, capability, generation, 63),
		Labels: map[string]string{
			"groundhold-capability":  sanitizeLabel(capability),
			"groundhold-environment": sanitizeLabel(environment),
		},
	}
	for _, path := range sortedKeysG(attrs) {
		raw := attrs[path]
		switch path {
		case "location.region":
			p.Location, _ = raw.(string)
		case "retention.minimum":
			secs, err := durationToSeconds(raw)
			if err != nil {
				return BackupDRVaultPlan{}, fmt.Errorf("retention.minimum: %v", err)
			}
			p.RetentionSeconds = secs
		case "retention.lockMode":
			s, _ := raw.(string)
			switch s {
			case "compliance":
				// D752: promising WORM is the false claim this entry removes. This
				// driver cannot lock a vault — it never sends effectiveTime, the one
				// field that locks one — so a vault it creates is deletable WITH ITS
				// DATA by any principal that may call backupVaults.delete(force=true).
				// Refuse loudly rather than build a governance vault and report it as
				// compliance, which is what happened before.
				return BackupDRVaultPlan{}, fmt.Errorf(
					"retention.lockMode=compliance cannot be honored on GCP by this driver — " +
						"it creates a vault with no lock time (effectiveTime), so the vault's " +
						"settings stay patchable and backupVaults.delete(force=true) removes it with its " +
						"data. Declare retention.lockMode=governance for what this builds, or " +
						"lock the vault out of band and ADOPT it: observe reads effectiveTime " +
						"and will report compliance once the lock is in force")
				// the only mode GCP offers — the enforced retention is immutable
			case "governance":
				// D752: this used to be the refusal, on the belief that GCP had no
				// admin-changeable mode. It has one, and it is the ONLY one this
				// driver builds: createBody sets no effectiveTime, so the vault it
				// creates is patchable and its data deletable. governance is now the
				// honest declaration for what actually gets built.
			default:
				return BackupDRVaultPlan{}, fmt.Errorf("retention.lockMode %q is not a recognized value", s)
			}
		case "encryption.customerManagedKeys":
			if raw == true {
				return BackupDRVaultPlan{}, fmt.Errorf(
					"encryption.customerManagedKeys=true cannot be honored on GCP — a Backup and DR " +
						"backup vault uses Google-managed encryption; CMEK is not a vault-level capability in v0")
			}
		case "service.managed":
			if raw != true {
				return BackupDRVaultPlan{}, fmt.Errorf("service.managed=false cannot be honored by Backup and DR")
			}
		default:
			return BackupDRVaultPlan{}, fmt.Errorf(
				"attribute %s has no Backup and DR vault mapping — refusing rather than silently "+
					"dropping it (backup plans, schedules and selections are opaque impl)", path)
		}
	}
	if p.Location == "" {
		return BackupDRVaultPlan{}, fmt.Errorf("capability.backup.vault requires location.region (the vault location)")
	}
	if p.RetentionSeconds == "" {
		return BackupDRVaultPlan{}, fmt.Errorf(
			"capability.backup.vault requires retention.minimum on GCP (a Backup and DR vault mandates a " +
				"minimum enforced retention at create)")
	}
	if !gcpName.MatchString(p.VaultID) {
		return BackupDRVaultPlan{}, fmt.Errorf("derived vault id %q is invalid", p.VaultID)
	}
	return p, nil
}

// durationToSeconds parses a duration scalar (e.g. "2160h") to a "<n>s" string.
func durationToSeconds(raw any) (string, error) {
	s, ok := raw.(string)
	if !ok {
		return "", fmt.Errorf("must be a duration string")
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return "", fmt.Errorf("not a valid duration: %q", s)
	}
	secs := int64(d.Seconds())
	if secs < 1 {
		return "", fmt.Errorf("must be at least one second")
	}
	return fmt.Sprintf("%ds", secs), nil
}

func (p BackupDRVaultPlan) createBody() map[string]any {
	return map[string]any{
		"backupMinimumEnforcedRetentionDuration": p.RetentionSeconds,
		"labels":                                 p.Labels,
	}
}
