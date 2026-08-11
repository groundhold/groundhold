// AWS GuardDuty request building (D154): the PURE, network-free forward map of the
// AWS capability.security.threatdetection vocab — continuous threat detection as a
// governed SECURITY POSTURE (Acme §7: "GuardDuty + EKS Protection"). This file
// validates the shape and REFUSES before any mutation: an unmapped capability
// attribute, a missing core attribute, or an invalid operand is a preflight refusal,
// never a silent drop (invariant #4, D26). The net shell (guardduty_net.go) drives
// the parsed plan through the GuardDuty REST-JSON API.
//
// The detector is a SINGLETON per account per region (like an SES active rule set):
// exactly one detector may exist, so create pre-reads and either converges OURS or
// HONEST-REFUSES a FOREIGN detector — it can never stand up a second. What the
// vocab governs (the posture): detection on/off, and the EKS/malware protection
// surface. The finding-publishing frequency is a tuning OPERAND (impl block, D26),
// never a governed attribute; the findings-export destination is a SEPARATE
// capability, not wired here.
package aws

import (
	"fmt"
)

// guardDutyProtectionFeature is the GuardDuty "Features" name for a protection
// surface (the modern Features API, not the legacy DataSources block).
const (
	gdFeatureEKSAuditLogs = "EKS_AUDIT_LOGS"         // protection.kubernetes -> EKS Protection
	gdFeatureEBSMalware   = "EBS_MALWARE_PROTECTION" // protection.malware -> Malware Protection
)

// guardDutyFreqOK is the closed set of GuardDuty FindingPublishingFrequency values.
// It is an OPERAND (tuning), so an unknown value is a refusal, never a silent default.
func guardDutyFreqOK(f string) bool {
	switch f {
	case "FIFTEEN_MINUTES", "ONE_HOUR", "SIX_HOURS":
		return true
	default:
		return false
	}
}

// GuardDutyPlan is the attribute+operand-derived shape a create assembles: the
// posture (detection on/off, the protection surface) driven by CAPABILITY
// attributes, and the finding-publishing frequency — an operator OPERAND (D26).
type GuardDutyPlan struct {
	Region           string // location.region (where the detector runs; per-region)
	Enabled          bool   // detection.enabled -> CreateDetector Enable (the core switch)
	Kubernetes       bool   // protection.kubernetes -> EKS_AUDIT_LOGS feature
	Malware          bool   // protection.malware -> EBS_MALWARE_PROTECTION feature
	FindingFrequency string // operand (optional) -> FindingPublishingFrequency; default SIX_HOURS
}

// BuildGuardDuty maps capability.security.threatdetection attributes + the impl
// block to a create plan, or REFUSES. Every error is a preflight refusal (never a
// half-build): an unmapped attribute, a missing core attribute, or an invalid
// operand is refused here, before the first GuardDuty mutation (invariant #4, D26).
func BuildGuardDuty(environment, capability string,
	attrs, impl map[string]any, generation int) (GuardDutyPlan, error) {
	p := GuardDutyPlan{FindingFrequency: "SIX_HOURS"} // GuardDuty's own default
	var haveEnabled bool

	// --- CAPABILITY attributes drive the POSTURE (refuse any unmapped attribute) ---
	for _, path := range sortedKeys(attrs) {
		raw := attrs[path]
		switch path {
		case "location.region":
			p.Region, _ = raw.(string)
		case "detection.enabled":
			b, ok := raw.(bool)
			if !ok {
				return GuardDutyPlan{}, fmt.Errorf("detection.enabled must be a bool")
			}
			p.Enabled = b
			haveEnabled = true
		case "protection.kubernetes":
			b, ok := raw.(bool)
			if !ok {
				return GuardDutyPlan{}, fmt.Errorf("protection.kubernetes must be a bool")
			}
			p.Kubernetes = b
		case "protection.malware":
			b, ok := raw.(bool)
			if !ok {
				return GuardDutyPlan{}, fmt.Errorf("protection.malware must be a bool")
			}
			p.Malware = b
		case "service.managed":
			if raw != true {
				return GuardDutyPlan{}, fmt.Errorf(
					"service.managed=false cannot be honored — groundhold manages the detector it stands up")
			}
		default:
			return GuardDutyPlan{}, fmt.Errorf(
				"attribute %s has no GuardDuty mapping — refusing rather than silently dropping it "+
					"(the threatdetection vocab governs detection.enabled + protection.kubernetes/malware; "+
					"the publishing frequency is an operand, the findings export is a separate capability)", path)
		}
	}

	if !regionOK.MatchString(p.Region) {
		return GuardDutyPlan{}, fmt.Errorf(
			"capability.security.threatdetection requires a valid location.region (GuardDuty is per-region)")
	}
	// detection.enabled is the CORE of the posture — refuse a create that does not say
	// whether the detector should be on (never a silent assumption).
	if !haveEnabled {
		return GuardDutyPlan{}, fmt.Errorf(
			"capability.security.threatdetection requires detection.enabled (the core posture switch)")
	}
	// a disabled detector cannot carry a protection surface — refuse the ambiguous shape
	// rather than silently create a detector that ignores the requested protection.
	if !p.Enabled && (p.Kubernetes || p.Malware) {
		return GuardDutyPlan{}, fmt.Errorf(
			"detection.enabled=false with protection.kubernetes/malware=true is contradictory — " +
				"a disabled detector monitors nothing; refusing rather than creating a posture that lies")
	}

	// --- OPERATOR operand (impl block, D26): the finding-publishing frequency ---
	if given := implString(impl, "findingPublishingFrequency"); given != "" {
		if !guardDutyFreqOK(given) {
			return GuardDutyPlan{}, fmt.Errorf(
				"implementation.findingPublishingFrequency %q is not one of FIFTEEN_MINUTES|ONE_HOUR|SIX_HOURS", given)
		}
		p.FindingFrequency = given
	}
	return p, nil
}

// desiredFeatures is the Features array a create/update sends: EKS_AUDIT_LOGS and
// EBS_MALWARE_PROTECTION each ENABLED or DISABLED per the plan. Both are stated
// explicitly (never omitted) so an update turns a surface OFF as decisively as on.
func (p GuardDutyPlan) desiredFeatures() []map[string]any {
	return []map[string]any{
		// D735: camelCase, per the DetectorFeatureConfiguration shape.
		{"name": gdFeatureEKSAuditLogs, "status": featureStatus(p.Kubernetes)},
		{"name": gdFeatureEBSMalware, "status": featureStatus(p.Malware)},
	}
}

func featureStatus(on bool) string {
	if on {
		return "ENABLED"
	}
	return "DISABLED"
}

// classifyGuardDutyChange (D46): PURE — can a capability.security.threatdetection
// transition be honored IN PLACE? detection.enabled and the protection.* surface are
// single-call mutable (UpdateDetector); location.region is unsupported (a detector is
// region-bound — a region change is a NEW detector in another region, not a patch);
// service.managed / cost.monthly are platform/projection properties. Never a silent
// "mutable" — an attribute the service cannot patch is unsupported WITH a reason.
func classifyGuardDutyChange(path string) (string, string) {
	switch path {
	case "detection.enabled":
		return "mutable", "in-place via UpdateDetector (Enable) — toggles the detector on/off"
	case "protection.kubernetes":
		return "mutable", "in-place via UpdateDetector (the EKS_AUDIT_LOGS feature status)"
	case "protection.malware":
		return "mutable", "in-place via UpdateDetector (the EBS_MALWARE_PROTECTION feature status)"
	case "location.region":
		return "unsupported", "a GuardDuty detector is region-bound — a region change is a new detector, not an in-place patch"
	case "service.managed":
		return "unsupported", "platform/projection property — nothing to patch"
	default:
		return "unsupported", "no GuardDuty in-place mapping for " + path
	}
}
