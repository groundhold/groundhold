// GCP Backup and DR backup-plan request building (D76 fala 4, parity twin of the
// AWS aws/backupplan.go): the semantic core of the GCP capability.backup.plan driver
// — the DR-POLICY layer that sits ABOVE capability.backup.vault (the vault, D127,
// speaks the SAME backupdr.googleapis.com/v1 host, so this reuses the vault shell's
// backupDRBase/pollBackupDROperation LRO helpers). A backup plan (backupdr
// projects/{p}/locations/{loc}/backupPlans) carries the CADENCE (schedule.frequency ->
// a StandardSchedule recurrence, the RPO determinant) and the plan-level RETENTION
// (retention.duration -> backupRules[].backupRetentionDays). The exact backup window,
// timezone, the target backupVault (a separate capability.backup.vault) and the
// resourceType are operands (D26), never capability paths. stateful:false — deleting a
// plan stops future backups, it never deletes recovery points already in the vault.
//
// HONEST GAP vs AWS Backup: a backupdr backup plan has NO cross-region copy. AWS
// Backup expresses a DR copy with a Rule CopyAction to a destination vault in another
// region; the backupdr BackupPlan/BackupRule schema has no such field (a rule copies
// within its own region only). So copy.crossRegion=true and copy.destinationRegion are
// REFUSED here with an honest reason — we never fabricate a residency posture the API
// cannot deliver.
package gcp

import (
	"fmt"
	"strconv"
	"time"
)

// gbpFrequencyToSchedule maps a normalized whole-hour cadence to a StandardSchedule
// recurrence. HOURLY covers 1..23h (via hourlyFrequency), 24h is DAILY, 168h (7d) is
// WEEKLY. A cadence with no exact recurrence (e.g. 48h — backupdr has no "every N
// days") is refused. observe reverse-maps ONLY these three shapes, so the round-trip
// is exact: a plan whose recurrence is MONTHLY/YEARLY has no fixed-duration cadence and
// observe omits schedule.frequency rather than fabricate an RPO.
func gbpFrequencyToSchedule(hours int) (recurrence string, hourlyFreq int, ok bool) {
	switch {
	case hours >= 1 && hours <= 23:
		return "HOURLY", hours, true
	case hours == 24:
		return "DAILY", 0, true
	case hours == 168:
		return "WEEKLY", 0, true
	default:
		return "", 0, false
	}
}

// gbpScheduleToFrequency reverse-maps a StandardSchedule recurrence back to the
// canonical cadence string. MONTHLY/YEARLY (and any unrecognized recurrence) are NOT a
// fixed duration — false, so observe honestly omits schedule.frequency.
func gbpScheduleToFrequency(recurrence string, hourlyFreq int) (string, bool) {
	switch recurrence {
	case "HOURLY":
		if hourlyFreq >= 1 && hourlyFreq <= 23 {
			return strconv.Itoa(hourlyFreq) + "h", true
		}
		return "", false
	case "DAILY":
		return "24h", true
	case "WEEKLY":
		return "168h", true
	default:
		return "", false
	}
}

// gbpDurationToHours parses a schedule.frequency duration to whole hours (>=1). The
// cadence table is hour-granular, so a sub-hour or non-whole-hour cadence is refused.
func gbpDurationToHours(raw any) (int, error) {
	s, ok := raw.(string)
	if !ok {
		return 0, fmt.Errorf("must be a duration string")
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return 0, fmt.Errorf("not a valid duration: %q", s)
	}
	h := int(d.Hours())
	if h < 1 {
		return 0, fmt.Errorf("must be at least one hour")
	}
	if d.Minutes() != float64(h*60) {
		return 0, fmt.Errorf("must be a whole number of hours (the cadence table is hour-granular): %q", s)
	}
	return h, nil
}

// gbpDurationToDays parses a retention.duration to whole days (backupRetentionDays is
// day-granular, range 1..36159). A sub-day or non-whole-day retention is refused.
func gbpDurationToDays(raw any) (int, error) {
	s, ok := raw.(string)
	if !ok {
		return 0, fmt.Errorf("must be a duration string")
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return 0, fmt.Errorf("not a valid duration: %q", s)
	}
	hours := int(d.Hours())
	if hours < 24 {
		return 0, fmt.Errorf("must be at least one day")
	}
	if d.Minutes() != float64(hours*60) || hours%24 != 0 {
		return 0, fmt.Errorf("must be a whole number of days (backupRetentionDays is day-granular): %q", s)
	}
	days := hours / 24
	if days > 36159 {
		return 0, fmt.Errorf("backupRetentionDays exceeds the backupdr maximum (36159): %q", s)
	}
	return days, nil
}

// BackupPlanGCPPlan is the attribute+operand-derived shape a create assembles.
type BackupPlanGCPPlan struct {
	PlanID        string
	Location      string
	FreqStr       string // normalized cadence ("24h") — the RPO semantics
	Recurrence    string // HOURLY / DAILY / WEEKLY actually programmed
	HourlyFreq    int    // set only for HOURLY
	RetentionDays int
	// operands
	TimeZone     string
	WindowStart  int
	WindowEnd    int
	BackupVault  string // the vault the plan writes recovery points to (a separate capability.backup.vault)
	ResourceType string // backupdr requires a target resourceType (e.g. compute.googleapis.com/Instance)
	Labels       map[string]string
}

// BuildBackupPlanGCP maps capability.backup.plan attributes + impl operands to a plan.
// Every error is a preflight refusal (D26 / refuse-before-mutate), never a silent drop.
func BuildBackupPlanGCP(project, environment, capability string,
	attrs, impl map[string]any, generation int) (BackupPlanGCPPlan, error) {
	if generation < 1 {
		generation = 1
	}
	p := BackupPlanGCPPlan{
		PlanID:      resourceName(project, environment, capability, generation, 62),
		TimeZone:    "Etc/UTC",
		WindowStart: 0,
		WindowEnd:   24,
		Labels: map[string]string{
			"groundhold-capability":  sanitizeLabel(capability),
			"groundhold-environment": sanitizeLabel(environment),
		},
	}
	var haveFreq, haveRetention bool
	for _, path := range sortedKeysG(attrs) {
		raw := attrs[path]
		switch path {
		case "location.region":
			p.Location, _ = raw.(string)
		case "schedule.frequency":
			hours, err := gbpDurationToHours(raw)
			if err != nil {
				return BackupPlanGCPPlan{}, fmt.Errorf("schedule.frequency: %v", err)
			}
			rec, hf, ok := gbpFrequencyToSchedule(hours)
			if !ok {
				return BackupPlanGCPPlan{}, fmt.Errorf(
					"schedule.frequency %dh has no backupdr recurrence mapping — supported cadences: "+
						"1h..23h (HOURLY), 24h (DAILY), 168h (WEEKLY); backupdr has no every-N-days schedule", hours)
			}
			p.FreqStr = strconv.Itoa(hours) + "h"
			p.Recurrence = rec
			p.HourlyFreq = hf
			haveFreq = true
		case "retention.duration":
			days, err := gbpDurationToDays(raw)
			if err != nil {
				return BackupPlanGCPPlan{}, fmt.Errorf("retention.duration: %v", err)
			}
			p.RetentionDays = days
			haveRetention = true
		case "copy.crossRegion":
			if raw == true {
				return BackupPlanGCPPlan{}, fmt.Errorf(
					"copy.crossRegion=true cannot be honored on GCP — a Backup and DR backup plan has NO " +
						"cross-region copy (the backupdr BackupPlan/BackupRule schema has no destination-region " +
						"copy field; a rule copies within its own region only). AWS Backup expresses this with a " +
						"Rule CopyAction; backupdr does not. Refusing rather than fabricating a residency posture")
			}
		case "copy.destinationRegion":
			return BackupPlanGCPPlan{}, fmt.Errorf(
				"copy.destinationRegion has no GCP Backup and DR mapping — the plan has no cross-region copy; " +
					"refusing rather than silently dropping the residency intent")
		case "service.managed":
			if raw != true {
				return BackupPlanGCPPlan{}, fmt.Errorf("service.managed=false cannot be honored by Backup and DR")
			}
		default:
			return BackupPlanGCPPlan{}, fmt.Errorf(
				"attribute %s has no Backup and DR plan mapping — refusing rather than silently dropping it "+
					"(the backup window, timezone, target vault and resourceType are operands; cross-region "+
					"copy is not a backupdr plan capability)", path)
		}
	}

	if p.Location == "" {
		return BackupPlanGCPPlan{}, fmt.Errorf("capability.backup.plan requires location.region (the plan location)")
	}
	if !haveFreq {
		return BackupPlanGCPPlan{}, fmt.Errorf("capability.backup.plan requires schedule.frequency (it determines the RPO)")
	}
	if !haveRetention {
		return BackupPlanGCPPlan{}, fmt.Errorf("capability.backup.plan requires retention.duration")
	}

	// --- required operands: target vault + resourceType ---
	p.BackupVault, _ = impl["backupVault"].(string)
	if p.BackupVault == "" {
		return BackupPlanGCPPlan{}, fmt.Errorf(
			"capability.backup.plan requires implementation.backupVault (the Backup and DR backup vault the " +
				"plan writes to — a separate capability.backup.vault; e.g. projects/<p>/locations/<loc>/backupVaults/<v>)")
	}
	p.ResourceType, _ = impl["resourceType"].(string)
	if p.ResourceType == "" {
		return BackupPlanGCPPlan{}, fmt.Errorf(
			"capability.backup.plan requires implementation.resourceType (the resource kind backupdr protects, " +
				"e.g. compute.googleapis.com/Instance or sqladmin.googleapis.com/Instance — a plan is scoped to one type)")
	}

	// --- optional operands: timezone + backup window ---
	if tz, ok := impl["timeZone"].(string); ok && tz != "" {
		p.TimeZone = tz
	}
	if v, ok := implIntG(impl, "backupWindowStartHour"); ok {
		p.WindowStart = v
	}
	if v, ok := implIntG(impl, "backupWindowEndHour"); ok {
		p.WindowEnd = v
	}
	if p.WindowStart < 0 || p.WindowEnd > 24 || p.WindowStart >= p.WindowEnd {
		return BackupPlanGCPPlan{}, fmt.Errorf(
			"implementation backup window must satisfy 0 <= backupWindowStartHour (%d) < backupWindowEndHour (%d) <= 24",
			p.WindowStart, p.WindowEnd)
	}

	if !gcpName.MatchString(p.PlanID) {
		return BackupPlanGCPPlan{}, fmt.Errorf("derived backup plan id %q is invalid", p.PlanID)
	}
	return p, nil
}

// implIntG coerces an impl operand to an int (JSON numbers arrive as float64 or, from
// YAML, as int). Absent or non-numeric -> (0, false).
func implIntG(impl map[string]any, key string) (int, bool) {
	switch v := impl[key].(type) {
	case int:
		return v, true
	case int64:
		return int(v), true
	case float64:
		return int(v), true
	default:
		return 0, false
	}
}

// standardSchedule assembles the rule's StandardSchedule. hourlyFrequency rides only
// for HOURLY; WEEKLY needs a day-of-week (SUNDAY, matching the AWS weekly anchor).
func (p BackupPlanGCPPlan) standardSchedule() map[string]any {
	sched := map[string]any{
		"recurrenceType": p.Recurrence,
		"backupWindow": map[string]any{
			"startHourOfDay": p.WindowStart,
			"endHourOfDay":   p.WindowEnd,
		},
		"timeZone": p.TimeZone,
	}
	switch p.Recurrence {
	case "HOURLY":
		sched["hourlyFrequency"] = p.HourlyFreq
	case "WEEKLY":
		sched["daysOfWeek"] = []any{"SUNDAY"}
	}
	return sched
}

// backupRules is the single-rule slice shared by create and patch bodies.
func (p BackupPlanGCPPlan) backupRules() []any {
	return []any{map[string]any{
		"ruleId":              "pv-rule",
		"backupRetentionDays": p.RetentionDays,
		"standardSchedule":    p.standardSchedule(),
	}}
}

// createBody is the backupPlans.create request body. Ownership is labels at birth.
func (p BackupPlanGCPPlan) createBody() map[string]any {
	return map[string]any{
		"resourceType": p.ResourceType,
		"backupVault":  p.BackupVault,
		"backupRules":  p.backupRules(),
		"labels":       p.Labels,
	}
}

// patchBody is the backupPlans.patch body (updateMask=backupRules): the cadence and
// retention both live in the rule, so one masked patch covers them.
func (p BackupPlanGCPPlan) patchBody() map[string]any {
	return map[string]any{"backupRules": p.backupRules()}
}
