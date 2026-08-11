// AWS Backup Plan request building (D153): the semantic core of the AWS
// capability.backup.plan driver — the DR-policy layer ABOVE capability.backup.vault
// (both speak the SAME API host, backup.<region>.amazonaws.com, so this reuses the
// vault's backupBase/backupCall/bkvTags shell). A backup plan is a REST-JSON
// resource whose Rule carries the CADENCE (schedule.frequency -> a cron
// ScheduleExpression, the RPO determinant), the plan-level RETENTION
// (retention.duration -> Lifecycle.DeleteAfterDays) and an optional CROSS-REGION
// copy (copy.crossRegion + copy.destinationRegion -> a Rule CopyAction). The exact
// cron, the target vault, the backup role and the resource selection are operands
// (D26), never capability paths. Immutability/WORM is deliberately NOT here — that is
// a VAULT concern (retention.lockMode). A plan without a selection backs up nothing,
// so create is composite: CreateBackupPlan then CreateBackupSelection.
package aws

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// errAvailabilityClassNotPlacement is the instructive refusal for
// availability.class on a capability that has no availability-zone concept of its
// own — a backup plan (a schedule + retention + selection policy) or a backup vault
// (a storage destination). AZ placement is a property of the RESOURCE being
// protected, not of the schedule or the store; refuse with the teaching rather
// than a bare "no mapping" (D208). Every cloud and the vocab agree availability.class
// is not a backup attribute, so this is a modeling error, not a driver gap.
func errAvailabilityClassNotPlacement(noun string) error {
	return fmt.Errorf(
		"availability.class does not apply to %s: availability-zone placement is a "+
			"property of the RESOURCE being protected (where its data lives), not of a "+
			"backup schedule or store — %s has no availability-zone concept. Declare "+
			"availability.class on the compute/data capability being backed up, not here",
		noun, noun)
}

// backupFrequencies is the closed cadence table: a schedule.frequency duration maps
// to a canonical cron, and a canonical cron reverse-maps to the duration string.
// Deriving the cron from the semantic cadence keeps the round-trip exact (observe
// can always recover schedule.frequency from what it measures). An operator who
// needs a bespoke cron supplies implementation.scheduleExpression (an operand); a
// bespoke cron that is not in this table is honestly NOT reverse-mappable, so observe
// omits schedule.frequency rather than fabricate an RPO.
var backupFrequencies = []struct {
	freqStr string
	cron    string
}{
	{"1h", "cron(0 * ? * * *)"},     // hourly
	{"6h", "cron(0 0/6 ? * * *)"},   // every 6 hours
	{"12h", "cron(0 0/12 ? * * *)"}, // twice daily
	{"24h", "cron(0 5 ? * * *)"},    // daily at 05:00 UTC
	{"168h", "cron(0 5 ? * 1 *)"},   // weekly (Sunday) at 05:00 UTC
}

// frequencyToCron maps a normalized frequency string to its canonical cron.
func frequencyToCron(freqStr string) (string, bool) {
	for _, f := range backupFrequencies {
		if f.freqStr == freqStr {
			return f.cron, true
		}
	}
	return "", false
}

// cronToFrequency reverse-maps a canonical cron to its frequency string.
func cronToFrequency(cron string) (string, bool) {
	for _, f := range backupFrequencies {
		if f.cron == cron {
			return f.freqStr, true
		}
	}
	return "", false
}

// normalizeFrequency parses a schedule.frequency duration and returns a canonical
// whole-hour string ("24h", "168h", ...) so it can index backupFrequencies. Sub-hour
// or non-hour-multiple cadences are refused (the cadence table is hour-granular).
func normalizeFrequency(raw any) (string, error) {
	hours, err := durationToHours(raw)
	if err != nil {
		return "", err
	}
	return strconv.Itoa(hours) + "h", nil
}

// durationToHours parses a duration scalar to whole hours (>=1).
func durationToHours(raw any) (int, error) {
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
		return 0, fmt.Errorf("must be a whole number of hours (the backup cadence table is hour-granular): %q", s)
	}
	return h, nil
}

// BackupPlanName is the deterministic plan name (a stable label + the idempotency
// CreatorRequestId). Unlike a vault, the plan's identity handle is the SERVER-assigned
// BackupPlanId, not this name; this name only labels the plan and idempotates retries.
func BackupPlanName(environment, capability string, generation int) string {
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
	name := "pp-" + slug + tail
	if len(name) > maxLen {
		name = name[:maxLen]
	}
	return name
}

// BackupPlanPlan is the attribute+operand-derived shape a create assembles.
type BackupPlanPlan struct {
	Name             string
	Region           string
	FreqStr          string // normalized cadence ("24h") — the RPO semantics
	Cron             string // the ScheduleExpression actually programmed
	RetentionDays    int
	CrossRegion      bool
	CopyDestRegion   string // parsed from CopyDestVaultArn (residency of the DR copy)
	CopyDestVaultArn string
	// operands
	TargetVaultName     string
	IamRoleArn          string
	SelectionTags       map[string]string
	SelectionResources  []string
	StartWindowMin      int
	CompletionWindowMin int
}

// BuildBackupPlan maps capability.backup.plan attributes + impl operands to a plan.
// Every error is a preflight refusal (D26 / refuse-before-mutate), never a silent drop.
func BuildBackupPlan(environment, capability string,
	attrs, impl map[string]any, generation int) (BackupPlanPlan, error) {
	p := BackupPlanPlan{
		Name:                BackupPlanName(environment, capability, generation),
		StartWindowMin:      60,
		CompletionWindowMin: 180,
	}
	var (
		haveFreq, haveRetention bool
		destRegionAttr          string
		haveDestRegionAttr      bool
		overrideCron            string
	)
	for _, path := range sortedKeys(attrs) {
		raw := attrs[path]
		switch path {
		case "location.region":
			p.Region, _ = raw.(string)
		case "schedule.frequency":
			f, err := normalizeFrequency(raw)
			if err != nil {
				return BackupPlanPlan{}, fmt.Errorf("schedule.frequency: %v", err)
			}
			p.FreqStr = f
			haveFreq = true
		case "retention.duration":
			days, err := durationToDays(raw)
			if err != nil {
				return BackupPlanPlan{}, fmt.Errorf("retention.duration: %v", err)
			}
			p.RetentionDays = days
			haveRetention = true
		case "copy.crossRegion":
			p.CrossRegion = (raw == true)
		case "copy.destinationRegion":
			destRegionAttr, _ = raw.(string)
			haveDestRegionAttr = true
		case "availability.class":
			return BackupPlanPlan{}, errAvailabilityClassNotPlacement("a backup plan")
		case "service.managed":
			if raw != true {
				return BackupPlanPlan{}, fmt.Errorf("service.managed=false cannot be honored by AWS Backup")
			}
		default:
			return BackupPlanPlan{}, fmt.Errorf(
				"attribute %s has no Backup plan mapping — refusing rather than silently dropping it "+
					"(the exact cron, target vault, backup role and resource selection are operands; "+
					"immutability/WORM is a vault concern)", path)
		}
	}

	if !regionOK.MatchString(p.Region) {
		return BackupPlanPlan{}, fmt.Errorf("capability.backup.plan requires a valid location.region")
	}
	if !haveFreq {
		return BackupPlanPlan{}, fmt.Errorf("capability.backup.plan requires schedule.frequency (it determines the RPO)")
	}
	if !haveRetention {
		return BackupPlanPlan{}, fmt.Errorf("capability.backup.plan requires retention.duration")
	}

	// --- schedule: derive the cron from the cadence, or take the operand override ---
	if s, ok := impl["scheduleExpression"].(string); ok && s != "" {
		if !strings.HasPrefix(s, "cron(") && !strings.HasPrefix(s, "rate(") {
			return BackupPlanPlan{}, fmt.Errorf(
				"implementation.scheduleExpression %q must be an AWS cron(...) or rate(...) expression", s)
		}
		overrideCron = s
	}
	cron, ok := frequencyToCron(p.FreqStr)
	if !ok && overrideCron == "" {
		return BackupPlanPlan{}, fmt.Errorf(
			"schedule.frequency %s has no canonical cadence mapping — supported: 1h, 6h, 12h, 24h, 168h "+
				"(or supply an explicit implementation.scheduleExpression cron)", p.FreqStr)
	}
	if overrideCron != "" {
		p.Cron = overrideCron
	} else {
		p.Cron = cron
	}

	// --- cross-region copy (DR) ---
	if p.CrossRegion {
		arn, _ := impl["copyDestinationVaultArn"].(string)
		if arn == "" {
			return BackupPlanPlan{}, fmt.Errorf(
				"copy.crossRegion=true requires implementation.copyDestinationVaultArn " +
					"(the destination backup-vault ARN is an operand; the SEMANTIC fact is copy.destinationRegion)")
		}
		destRegion, err := regionFromBackupArn(arn)
		if err != nil {
			return BackupPlanPlan{}, fmt.Errorf("implementation.copyDestinationVaultArn: %v", err)
		}
		if destRegion == p.Region {
			return BackupPlanPlan{}, fmt.Errorf(
				"copy destination vault is in the plan's own region %q — that is not a cross-region copy", p.Region)
		}
		if haveDestRegionAttr && destRegionAttr != destRegion {
			return BackupPlanPlan{}, fmt.Errorf(
				"copy.destinationRegion %q contradicts the region %q of implementation.copyDestinationVaultArn",
				destRegionAttr, destRegion)
		}
		p.CopyDestRegion = destRegion
		p.CopyDestVaultArn = arn
	} else {
		if haveDestRegionAttr {
			return BackupPlanPlan{}, fmt.Errorf(
				"copy.destinationRegion is set but copy.crossRegion is not true — a destination without a cross-region copy is meaningless")
		}
		if arn, _ := impl["copyDestinationVaultArn"].(string); arn != "" {
			return BackupPlanPlan{}, fmt.Errorf(
				"implementation.copyDestinationVaultArn is set but copy.crossRegion is not true")
		}
	}

	// --- required operands: target vault + backup role ---
	p.TargetVaultName, _ = impl["targetVaultName"].(string)
	if p.TargetVaultName == "" {
		return BackupPlanPlan{}, fmt.Errorf(
			"capability.backup.plan requires implementation.targetVaultName (the vault the plan writes recovery points to — a separate capability.backup.vault)")
	}
	p.IamRoleArn, _ = impl["iamRoleArn"].(string)
	if !strings.HasPrefix(p.IamRoleArn, "arn:aws:iam::") || !strings.Contains(p.IamRoleArn, ":role/") {
		return BackupPlanPlan{}, fmt.Errorf(
			"capability.backup.plan requires implementation.iamRoleArn (the IAM role AWS Backup assumes — an arn:aws:iam::<acct>:role/<name>)")
	}

	// --- required operand: a selection (a plan with no selection backs up nothing) ---
	p.SelectionTags = stringMap(impl["selectionTags"])
	p.SelectionResources = stringSlice(impl["selectionResources"])
	if len(p.SelectionTags) == 0 && len(p.SelectionResources) == 0 {
		return BackupPlanPlan{}, fmt.Errorf(
			"capability.backup.plan requires a selection — implementation.selectionTags (a tag map) " +
				"and/or implementation.selectionResources (resource ARNs); a plan with no selection backs up nothing")
	}

	// --- optional operands: job windows ---
	// D674: same rule for the job windows — a mistyped window silently became the
	// default, and a backup window is a recovery guarantee.
	if v, ok, err := implIntOperand(impl, "startWindowMinutes", "implementation"); err != nil {
		return BackupPlanPlan{}, err
	} else if ok {
		p.StartWindowMin = v
	}
	if v, ok, err := implIntOperand(impl, "completionWindowMinutes", "implementation"); err != nil {
		return BackupPlanPlan{}, err
	} else if ok {
		p.CompletionWindowMin = v
	}
	if p.CompletionWindowMin <= p.StartWindowMin {
		return BackupPlanPlan{}, fmt.Errorf(
			"implementation.completionWindowMinutes (%d) must exceed startWindowMinutes (%d)",
			p.CompletionWindowMin, p.StartWindowMin)
	}
	return p, nil
}

// regionFromBackupArn extracts the region from arn:aws:backup:<region>:<acct>:backup-vault:<name>.
func regionFromBackupArn(arn string) (string, error) {
	parts := strings.Split(arn, ":")
	if len(parts) < 6 || parts[0] != "arn" || parts[2] != "backup" || !strings.HasPrefix(parts[5], "backup-vault") {
		return "", fmt.Errorf("not a backup-vault ARN: %q", arn)
	}
	if !regionOK.MatchString(parts[3]) {
		return "", fmt.Errorf("ARN region %q is invalid", parts[3])
	}
	return parts[3], nil
}

// createPlanBody is the CreateBackupPlan request body. Ownership is tags at birth.
func (p BackupPlanPlan) createPlanBody(capability, environment string) map[string]any {
	rule := map[string]any{
		"RuleName":                "pv-rule",
		"TargetBackupVaultName":   p.TargetVaultName,
		"ScheduleExpression":      p.Cron,
		"StartWindowMinutes":      p.StartWindowMin,
		"CompletionWindowMinutes": p.CompletionWindowMin,
		"Lifecycle":               map[string]any{"DeleteAfterDays": p.RetentionDays},
	}
	if p.CrossRegion {
		rule["CopyActions"] = []any{map[string]any{
			"DestinationBackupVaultArn": p.CopyDestVaultArn,
			"Lifecycle":                 map[string]any{"DeleteAfterDays": p.RetentionDays},
		}}
	}
	return map[string]any{
		"BackupPlan": map[string]any{
			"BackupPlanName": p.Name,
			"Rules":          []any{rule},
		},
		"BackupPlanTags": map[string]string{
			"groundhold-capability":  sanitizeTag(capability),
			"groundhold-environment": sanitizeTag(environment),
		},
		"CreatorRequestId": p.Name,
	}
}

// updatePlanBody is the UpdateBackupPlan body (tags/CreatorRequestId are omitted —
// UpdateBackupPlan replaces the rule set only).
func (p BackupPlanPlan) updatePlanBody() map[string]any {
	body := p.createPlanBody("", "")
	delete(body, "BackupPlanTags")
	delete(body, "CreatorRequestId")
	return body
}

// createSelectionBody is the CreateBackupSelection request body.
func (p BackupPlanPlan) createSelectionBody() map[string]any {
	sel := map[string]any{
		"SelectionName": "pv-sel",
		"IamRoleArn":    p.IamRoleArn,
	}
	if len(p.SelectionResources) > 0 {
		sel["Resources"] = toAnySlice(p.SelectionResources)
	}
	if len(p.SelectionTags) > 0 {
		var conds []any
		for _, k := range sortedStringKeys(p.SelectionTags) {
			conds = append(conds, map[string]any{
				"ConditionType":  "STRINGEQUALS",
				"ConditionKey":   k,
				"ConditionValue": p.SelectionTags[k],
			})
		}
		sel["ListOfTags"] = conds
	}
	return map[string]any{
		"BackupSelection":  sel,
		"CreatorRequestId": p.Name + "-sel",
	}
}

// --- small operand coercers (impl blocks are free-form, D26) ---

func stringMap(raw any) map[string]string {
	m, ok := raw.(map[string]any)
	if !ok {
		return nil
	}
	out := map[string]string{}
	for k, v := range m {
		if s, ok := v.(string); ok {
			out[k] = s
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func stringSlice(raw any) []string {
	s, ok := raw.([]any)
	if !ok {
		return nil
	}
	var out []string
	for _, v := range s {
		if str, ok := v.(string); ok && str != "" {
			out = append(out, str)
		}
	}
	return out
}

func toAnySlice(ss []string) []any {
	out := make([]any, len(ss))
	for i, s := range ss {
		out[i] = s
	}
	return out
}

func sortedStringKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	for i := 0; i < len(out); i++ {
		for j := i + 1; j < len(out); j++ {
			if out[j] < out[i] {
				out[i], out[j] = out[j], out[i]
			}
		}
	}
	return out
}
