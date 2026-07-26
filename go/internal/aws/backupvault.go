// AWS Backup Vault request building (D127): the semantic core of the AWS
// capability.backup.vault driver. A vault is a REST-JSON resource
// (backup.<region>.amazonaws.com). The retention guarantee is enforced by a Backup
// Vault Lock: retention.minimum -> MinRetentionDays, and retention.lockMode picks
// whether the lock is changeable (governance -> ChangeableForDays set) or IMMUTABLE
// (compliance -> ChangeableForDays omitted, WORM). The KMS key id is impl detail
// (D53-adjacent: a key reference, never key material). Backup plans/schedules that
// populate the vault are opaque impl (invariant #4). Ownership is tags applied at birth.
package aws

import (
	"fmt"
	"regexp"
	"strings"
	"time"
)

var backupVaultNameOK = regexp.MustCompile(`^[a-zA-Z0-9_-]{2,50}$`)
var bkvBad = regexp.MustCompile(`[^a-zA-Z0-9-]+`)

// BackupVaultName is the deterministic vault name (the idempotency/recovery handle).
func BackupVaultName(environment, capability string, generation int) string {
	slug := capability
	if environment != "" {
		slug += "-" + environment
	}
	slug = strings.Trim(bkvBad.ReplaceAllString(slug, "-"), "-")
	tail := "-" + letterHash(environment+"|"+capability+genSuffix(generation), 8)
	const maxLen = 50
	if len(slug)+len(tail) > maxLen {
		slug = strings.TrimRight(slug[:maxLen-len(tail)], "-")
	}
	name := "pv-" + slug + tail
	if len(name) > maxLen {
		name = name[:maxLen]
	}
	return name
}

// BackupVaultPlan is the attribute-derived shape a create assembles.
type BackupVaultPlan struct {
	Name              string
	Region            string
	MinRetentionDays  int    // 0 = no vault lock
	LockMode          string // governance | compliance | ""
	ChangeableForDays int    // governance grace window (>=1) when governance
	KmsKeyArn         string
}

// BuildBackupVault maps capability.backup.vault attributes + impl to a plan. Every
// error is a preflight refusal, never a silent drop.
func BuildBackupVault(environment, capability string,
	attrs, impl map[string]any, generation int) (BackupVaultPlan, error) {
	p := BackupVaultPlan{Name: BackupVaultName(environment, capability, generation)}
	cmk := false
	for _, path := range sortedKeys(attrs) {
		raw := attrs[path]
		switch path {
		case "location.region":
			p.Region, _ = raw.(string)
		case "retention.minimum":
			days, err := durationToDays(raw)
			if err != nil {
				return BackupVaultPlan{}, fmt.Errorf("retention.minimum: %v", err)
			}
			p.MinRetentionDays = days
		case "retention.lockMode":
			s, _ := raw.(string)
			switch s {
			case "governance", "compliance":
				p.LockMode = s
			default:
				return BackupVaultPlan{}, fmt.Errorf("retention.lockMode %q is not a recognized value", s)
			}
		case "encryption.customerManagedKeys":
			cmk = (raw == true)
		case "availability.class":
			return BackupVaultPlan{}, errAvailabilityClassNotPlacement("a backup vault")
		case "service.managed":
			if raw != true {
				return BackupVaultPlan{}, fmt.Errorf("service.managed=false cannot be honored by AWS Backup")
			}
		default:
			return BackupVaultPlan{}, fmt.Errorf(
				"attribute %s has no Backup vault mapping — refusing rather than silently dropping it "+
					"(backup plans, schedules and selections are opaque impl)", path)
		}
	}
	if !regionOK.MatchString(p.Region) {
		return BackupVaultPlan{}, fmt.Errorf("capability.backup.vault requires a valid location.region")
	}
	if p.LockMode != "" && p.MinRetentionDays == 0 {
		return BackupVaultPlan{}, fmt.Errorf(
			"retention.lockMode requires retention.minimum — a lock enforces a minimum retention, so there must be one to enforce")
	}
	if p.LockMode == "governance" {
		p.ChangeableForDays = 3 // a governance grace window (admin-changeable until it elapses)
	}
	if cmk {
		key, _ := impl["kms_key_arn"].(string)
		if key == "" {
			return BackupVaultPlan{}, fmt.Errorf(
				"encryption.customerManagedKeys=true requires implementation.kms_key_arn " +
					"(the customer key arn is implementation detail, never a capability path)")
		}
		p.KmsKeyArn = key
	}
	if !backupVaultNameOK.MatchString(p.Name) {
		return BackupVaultPlan{}, fmt.Errorf("derived vault name %q is invalid", p.Name)
	}
	return p, nil
}

// durationToDays parses a duration scalar (e.g. "720h") to whole days (>=1).
func durationToDays(raw any) (int, error) {
	s, ok := raw.(string)
	if !ok {
		return 0, fmt.Errorf("must be a duration string")
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return 0, fmt.Errorf("not a valid duration: %q", s)
	}
	days := int(d.Hours() / 24)
	if days < 1 {
		return 0, fmt.Errorf("must be at least one day")
	}
	return days, nil
}

func (p BackupVaultPlan) createBody(capability, environment string) map[string]any {
	body := map[string]any{
		"BackupVaultTags": map[string]string{
			"groundhold-capability":  sanitizeTag(capability),
			"groundhold-environment": sanitizeTag(environment),
		},
	}
	if p.KmsKeyArn != "" {
		body["EncryptionKeyArn"] = p.KmsKeyArn
	}
	return body
}

// lockBody is the PutBackupVaultLockConfiguration body (nil when no lock is asked).
func (p BackupVaultPlan) lockBody() map[string]any {
	if p.MinRetentionDays == 0 {
		return nil
	}
	body := map[string]any{"MinRetentionDays": p.MinRetentionDays}
	if p.LockMode == "governance" {
		body["ChangeableForDays"] = p.ChangeableForDays // omitted => compliance (immutable)
	}
	return body
}
