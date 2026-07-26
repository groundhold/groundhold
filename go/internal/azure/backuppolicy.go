// Azure Backup policy request building (D76 fala 4, cross-cloud parity): the Azure
// half of capability.backup.plan — the DR-policy layer AWS fulfils with a Backup
// plan+selection (internal/aws/backupplan.go) and GCP with a Backup-and-DR plan.
//
// WHY Microsoft.DataProtection/backupVaults/backupPolicies (Backup Center / Azure
// Data Protection) and NOT the older Microsoft.RecoveryServices/vaults/backupPolicies:
// the DataProtection plane is the modern, workload-UNIFORM Backup Center model — one
// declarative policyRules array (a ScheduleBasedTrigger carrying the cadence + a
// Retention rule carrying the lifecycle) that reads the same across disks, blobs and
// databases. RecoveryServices is the legacy per-workload plane (separate AzureIaasVM
// vs AzureFileShare vs AzureWorkload schemas, imperative sub-clients, no cross-
// workload policy shape) — it would force a workload-specific driver per datasource
// and could not reverse-map cleanly. DataProtection's policyRules map DIRECTLY onto
// the vocab: schedule.frequency -> the trigger's repeatingTimeIntervals (RPO), and
// retention.duration -> the retention rule's deleteAfter lifecycle. STATELESS: a
// policy is a schedule, not a store (the recovery points live in the vault).
//
// A policy is a CHILD of an EXISTING backupVault (implementation.backupVaultName +
// resource_group operands — a SEPARATE capability.backup.vault). The vault is the
// substrate groundhold does not create here (the D99 substrate trap): location.region is
// a property of the VAULT, so it is VERIFIED against the live vault at create, never
// mutated. And a DataProtection backupPolicy is a PROXY child resource that carries
// NO ARM tags — so ownership is the deterministic policy NAME (the consumption-budget
// doctrine), never a tag.
package azure

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"groundhold/internal/scalars"
)

// Microsoft.DataProtection stable API version.
const dataProtectionAPIVersion = "2023-05-01"

// backupVaultNameOK / backupPolicyNameOK bound the vault and policy names before
// they are interpolated into an ARM path (the D73 injection boundary) or a
// providerId. Azure caps a DataProtection vault name at 50 and a policy name at 150.
var (
	backupVaultNameOK  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9-]{1,49}$`)
	backupPolicyNameOK = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9-]{0,149}$`)
)

// backupPolicyCadences is the closed cadence table: a schedule.frequency duration
// maps to a canonical ISO8601 recurrence interval, and an interval reverse-maps to
// the duration string. The interval maps DIRECTLY to the semantic cadence (an
// advantage over AWS's cron table — no lossy translation), so the round-trip is
// exact: observe recovers schedule.frequency from the interval it measures. The set
// mirrors DataProtection's supported disk cadences (hourly 4/6/8/12, daily, weekly).
// A cadence not in this table is honestly NOT reverse-mappable; an operator who needs
// a bespoke recurrence supplies implementation.scheduleInterval (an operand), and
// observe then omits schedule.frequency rather than fabricate an RPO.
var backupPolicyCadences = []struct {
	freqStr  string
	interval string
}{
	{"4h", "PT4H"},   // every 4 hours
	{"6h", "PT6H"},   // every 6 hours
	{"8h", "PT8H"},   // every 8 hours
	{"12h", "PT12H"}, // twice daily
	{"24h", "P1D"},   // daily
	{"168h", "P1W"},  // weekly
}

func frequencyToInterval(freqStr string) (string, bool) {
	for _, c := range backupPolicyCadences {
		if c.freqStr == freqStr {
			return c.interval, true
		}
	}
	return "", false
}

func intervalToFrequency(interval string) (string, bool) {
	for _, c := range backupPolicyCadences {
		if c.interval == interval {
			return c.freqStr, true
		}
	}
	return "", false
}

// backupPolicyDurationToHours parses a duration scalar to whole hours (>=1).
func backupPolicyDurationToHours(raw any) (int, error) {
	sc, err := scalars.Parse(raw)
	if err != nil || sc.Kind != scalars.Duration {
		return 0, fmt.Errorf("must be a duration string")
	}
	ms := sc.Value.(float64)
	if ms < 3600000 {
		return 0, fmt.Errorf("must be at least one hour")
	}
	if float64(int64(ms))/3600000 != float64(int64(ms)/3600000) {
		return 0, fmt.Errorf("must be a whole number of hours (the backup cadence table is hour-granular)")
	}
	return int(int64(ms) / 3600000), nil
}

// backupPolicyDurationToDays parses a duration scalar to whole days (>=1) — the
// granularity of a DataProtection deleteAfter lifecycle.
func backupPolicyDurationToDays(raw any) (int, error) {
	hours, err := backupPolicyDurationToHours(raw)
	if err != nil {
		return 0, err
	}
	if hours%24 != 0 {
		return 0, fmt.Errorf("retention must be a whole number of days (the lifecycle is day-granular)")
	}
	return hours / 24, nil
}

// retentionISOToHours reverse-maps a DataProtection deleteAfter duration ("P30D",
// "P4W") back to whole hours; ok=false when it is not a plain day/week ISO duration.
func retentionISOToHours(iso string) (int, bool) {
	if len(iso) < 3 || iso[0] != 'P' {
		return 0, false
	}
	body := iso[1:]
	unit := body[len(body)-1]
	num, err := strconv.Atoi(body[:len(body)-1])
	if err != nil || num < 1 {
		return 0, false
	}
	switch unit {
	case 'D':
		return num * 24, true
	case 'W':
		return num * 24 * 7, true
	default:
		return 0, false
	}
}

// backupPolicyOwnerToken is the generation-INDEPENDENT ownership marker embedded (as
// a suffix) in the policy name. update/delete recompute it from (env, cap) alone.
func backupPolicyOwnerToken(environment, capability string) string {
	sum := sha256.Sum256([]byte("backuppolicy|" + environment + "|" + capability))
	return hex.EncodeToString(sum[:])[:8]
}

// BackupPolicyName is the deterministic policy name — BOTH the idempotency handle (a
// PUT to this name is create-or-update) AND the ownership marker (a DataProtection
// policy carries no tags). The owner token is generation-independent; g>=2 (D48
// replacements) coexist via the -gN salt.
func BackupPolicyName(environment, capability string, generation int) string {
	slug := capability
	if environment != "" {
		slug += "-" + environment
	}
	slug = trimDash(nonAZ.ReplaceAllString(toLowerASCII(slug), "-"))
	suffix := ""
	if generation >= 2 {
		suffix = fmt.Sprintf("-g%d", generation)
	}
	owner := backupPolicyOwnerToken(environment, capability)
	const maxLen = 150
	fixed := len("pv-") + len(suffix) + len("-") + len(owner)
	if fixed+len(slug) > maxLen {
		keep := maxLen - fixed
		if keep < 0 {
			keep = 0
		}
		if keep < len(slug) {
			slug = trimDash(slug[:keep])
		}
	}
	return "pv-" + slug + suffix + "-" + owner
}

// backupPolicyOurs is the ownership predicate: the name is a groundhold marker AND
// carries the (env, cap) owner token. Generation-independent by design.
func backupPolicyOurs(name, environment, capability string) bool {
	return strings.HasPrefix(name, "pv-") &&
		strings.HasSuffix(name, "-"+backupPolicyOwnerToken(environment, capability))
}

// BackupPolicyPlan is the attribute+operand-derived shape a create/update assembles.
type BackupPolicyPlan struct {
	Name           string
	VaultName      string // operand — the EXISTING backup vault (capability.backup.vault)
	ResourceGroup  string // operand
	Region         string // location.region — verified against the live vault, never set
	FreqStr        string // normalized cadence ("24h") — the RPO semantics
	Interval       string // the ISO8601 recurrence actually programmed
	RetentionDays  int
	RetentionISO   string // "P30D" — the deleteAfter lifecycle
	DatasourceType string // operand — e.g. "Microsoft.Compute/disks"
	DataStoreType  string // operand — VaultStore (default) | OperationalStore | ArchiveStore
	BackupType     string // operand — Incremental (default) | Full
}

// BuildBackupPolicy maps capability.backup.plan attributes + impl operands to a
// DataProtection backup policy. Every error is a preflight refusal apply surfaces
// before any mutation — never a silently dropped attribute.
//
// The honest gap this cloud forces (stated, not hidden): copy.crossRegion /
// copy.destinationRegion are REFUSED. Azure Backup's cross-region DR is a VAULT
// redundancy setting (GeoRedundant storage + the cross-region-restore feature on the
// backupVault), NOT anything a backupPolicy can express — a policyRule has no copy
// action (contrast AWS Backup, where the Rule carries a cross-region CopyAction). So
// the policy driver refuses rather than pretend; the multi-region posture belongs on
// capability.backup.vault.
func BuildBackupPolicy(environment, capability string,
	attrs, impl map[string]any, generation int) (BackupPolicyPlan, error) {
	if generation < 1 {
		generation = 1
	}
	p := BackupPolicyPlan{Name: BackupPolicyName(environment, capability, generation)}
	var haveFreq, haveRetention bool

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
		case "schedule.frequency":
			hours, err := backupPolicyDurationToHours(raw)
			if err != nil {
				return BackupPolicyPlan{}, fmt.Errorf("schedule.frequency: %v", err)
			}
			p.FreqStr = strconv.Itoa(hours) + "h"
			haveFreq = true
		case "retention.duration":
			days, err := backupPolicyDurationToDays(raw)
			if err != nil {
				return BackupPolicyPlan{}, fmt.Errorf("retention.duration: %v", err)
			}
			p.RetentionDays = days
			p.RetentionISO = fmt.Sprintf("P%dD", days)
			haveRetention = true
		case "copy.crossRegion":
			if raw == true {
				return BackupPolicyPlan{}, fmt.Errorf(
					"copy.crossRegion=true cannot be honored by a DataProtection backupPolicy — " +
						"Azure Backup cross-region DR is a VAULT redundancy setting (GeoRedundant storage " +
						"+ the cross-region-restore feature on the backupVault), not a policy rule; a " +
						"policyRule has no copy action (unlike AWS Backup). It belongs on capability.backup.vault")
			}
		case "copy.destinationRegion":
			return BackupPolicyPlan{}, fmt.Errorf(
				"copy.destinationRegion cannot be honored by a DataProtection backupPolicy — the cross-region " +
					"copy destination is a property of the backupVault's geo-redundancy, not the policy; refusing " +
					"rather than silently dropping a residency-load-bearing attribute")
		case "service.managed":
			if raw != true {
				return BackupPolicyPlan{}, fmt.Errorf("service.managed=false cannot be honored by Azure Backup")
			}
		default:
			return BackupPolicyPlan{}, fmt.Errorf(
				"attribute %s has no Azure Backup policy mapping — refusing rather than silently dropping it "+
					"(the target vault, datasource type and store are operands; cross-region copy is a vault concern)", path)
		}
	}

	if strings.TrimSpace(p.Region) == "" {
		return BackupPolicyPlan{}, fmt.Errorf("capability.backup.plan requires location.region (the vault's region)")
	}
	if !haveFreq {
		return BackupPolicyPlan{}, fmt.Errorf("capability.backup.plan requires schedule.frequency (it determines the RPO)")
	}
	if !haveRetention {
		return BackupPolicyPlan{}, fmt.Errorf("capability.backup.plan requires retention.duration")
	}

	// --- schedule: derive the ISO8601 recurrence interval, or take the operand override ---
	if s, ok := impl["scheduleInterval"].(string); ok && s != "" {
		if !strings.HasPrefix(s, "P") {
			return BackupPolicyPlan{}, fmt.Errorf(
				"implementation.scheduleInterval %q must be an ISO8601 duration (e.g. PT6H, P1D, P1W)", s)
		}
		p.Interval = s
	} else {
		interval, ok := frequencyToInterval(p.FreqStr)
		if !ok {
			return BackupPolicyPlan{}, fmt.Errorf(
				"schedule.frequency %s has no canonical Azure cadence mapping — supported: 4h, 6h, 8h, 12h, 24h, 168h "+
					"(or supply an explicit implementation.scheduleInterval ISO8601 recurrence)", p.FreqStr)
		}
		p.Interval = interval
	}

	// --- required operands: the existing vault + its resource group + the datasource ---
	p.VaultName, _ = impl["backupVaultName"].(string)
	if !backupVaultNameOK.MatchString(p.VaultName) {
		return BackupPolicyPlan{}, fmt.Errorf(
			"capability.backup.plan requires implementation.backupVaultName (the existing DataProtection backup " +
				"vault this policy lives under — a separate capability.backup.vault)")
	}
	p.ResourceGroup, _ = impl["resource_group"].(string)
	if !rgOK.MatchString(p.ResourceGroup) {
		return BackupPolicyPlan{}, fmt.Errorf(
			"capability.backup.plan requires implementation.resource_group (the vault's resource group)")
	}
	p.DatasourceType, _ = impl["datasourceType"].(string)
	p.DatasourceType = strings.TrimSpace(p.DatasourceType)
	if p.DatasourceType == "" || !strings.Contains(p.DatasourceType, "/") {
		return BackupPolicyPlan{}, fmt.Errorf(
			"capability.backup.plan requires implementation.datasourceType (the workload the policy protects, " +
				"e.g. \"Microsoft.Compute/disks\" or \"Microsoft.Storage/storageAccounts/blobServices\")")
	}

	// --- optional operands with honest defaults ---
	p.DataStoreType, _ = impl["dataStoreType"].(string)
	if p.DataStoreType == "" {
		p.DataStoreType = "VaultStore" // the durable tier; the general default
	}
	switch p.DataStoreType {
	case "VaultStore", "OperationalStore", "ArchiveStore":
	default:
		return BackupPolicyPlan{}, fmt.Errorf(
			"implementation.dataStoreType %q is not one of VaultStore|OperationalStore|ArchiveStore", p.DataStoreType)
	}
	p.BackupType, _ = impl["backupType"].(string)
	if p.BackupType == "" {
		p.BackupType = "Incremental"
	}

	if !backupPolicyNameOK.MatchString(p.Name) {
		return BackupPolicyPlan{}, fmt.Errorf("derived backup policy name %q is invalid", p.Name)
	}
	return p, nil
}

// createBody is the DataProtection backupPolicies PUT body. startISO is the
// recurrence anchor (a time-of-day fact the vocab does not carry — supplied by the
// net layer from the coordination clock). The backup rule's taggingCriteria tag
// ("Default") is what binds it to the retention rule of the same name.
func (p BackupPolicyPlan) createBody(startISO string) map[string]any {
	backupRule := map[string]any{
		"name":       "BackupSchedule",
		"objectType": "AzureBackupRule",
		"backupParameters": map[string]any{
			"objectType": "AzureBackupParams",
			"backupType": p.BackupType,
		},
		"dataStore": map[string]any{
			"dataStoreType": p.DataStoreType,
			"objectType":    "DataStoreInfoBase",
		},
		"trigger": map[string]any{
			"objectType": "ScheduleBasedTriggerContext",
			"schedule": map[string]any{
				"timeZone":               "UTC",
				"repeatingTimeIntervals": []any{"R/" + startISO + "/" + p.Interval},
			},
			"taggingCriteria": []any{map[string]any{
				"tagInfo":         map[string]any{"tagName": "Default"},
				"taggingPriority": 99,
				"isDefault":       true,
			}},
		},
	}
	retentionRule := map[string]any{
		"name":       "Default",
		"objectType": "AzureRetentionRule",
		"isDefault":  true,
		"lifecycles": []any{map[string]any{
			"deleteAfter": map[string]any{
				"objectType": "AbsoluteDeleteOption",
				"duration":   p.RetentionISO,
			},
			"sourceDataStore": map[string]any{
				"dataStoreType": p.DataStoreType,
				"objectType":    "DataStoreInfoBase",
			},
			"targetDataStoreCopySettings": []any{},
		}},
	}
	return map[string]any{
		"properties": map[string]any{
			"objectType":      "BackupPolicy",
			"datasourceTypes": []any{p.DatasourceType},
			"policyRules":     []any{backupRule, retentionRule},
		},
	}
}

// classifyBackupPolicyChange (D46): can a transition be honored IN PLACE? PURE
// provider knowledge, no network. A DataProtection backupPolicy is create-or-update
// via a full PUT to the same name, so the cadence and the retention lifecycle are
// mutable in place; the region is vault-bound (a replacement); cross-region copy is
// not expressible at all (unsupported, a vault concern).
func classifyBackupPolicyChange(path string) (string, string) {
	switch path {
	case "schedule.frequency":
		return "mutable", "in-place via a full PUT (the trigger's repeatingTimeIntervals is replaced)"
	case "retention.duration":
		return "mutable", "in-place via a full PUT (the retention rule's deleteAfter is replaced)"
	case "location.region":
		return "immutable", "a policy's region is the vault's — bound at creation; a region change is a new vault+policy"
	case "copy.crossRegion", "copy.destinationRegion":
		return "unsupported", "cross-region copy is a backupVault geo-redundancy setting, never a backupPolicy rule"
	case "service.managed":
		return "unsupported", "platform/projection property — nothing to patch"
	default:
		return "unsupported", "no Azure Backup policy in-place mapping for " + path
	}
}
