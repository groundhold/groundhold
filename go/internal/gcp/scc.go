// GCP Security Command Center (SCC) request building (D76): the PURE, network-free
// forward map of the GCP capability.security.threatdetection vocab — the SAME
// vocabulary AWS GuardDuty fulfils, now with a second service (parity). This file
// validates the shape and REFUSES before any mutation: an unmapped capability
// attribute, a missing core attribute, or an invalid operand is a preflight
// refusal, never a silent drop (invariant #4, D26). The net shell (scc_net.go)
// drives the parsed plan through the Security Center Management API.
//
// WHAT WE GOVERN (the posture) vs HOW SCC EXPOSES IT — the honest mapping.
// SCC is NOT a per-region detector like GuardDuty; it is an org/project/folder-
// scoped posture whose modules live at locations/global. groundhold governs the
// posture by toggling the securitycentermanagement `securityCenterServices`
// (a.k.a. modules), each a per-parent SINGLETON with an intendedEnablementState:
//   - detection.enabled     -> event-threat-detection  (the core log-based detector)
//   - protection.kubernetes  -> container-threat-detection (GKE control-plane threats)
//   - protection.malware     -> virtual-machine-threat-detection (VM memory malware/
//     crypto-mining scanning — the closest honest SCC analog to GuardDuty's EBS
//     malware protection; documented as an analog, not an identity)
//   - location.region        -> SCC is global (locations/global), not regional; the
//     only honest value is "global" (or omitted). A real regional value is REFUSED.
//   - service.managed        -> const true when observed through the driver
//   - cost.monthly           -> projection / billing-after-deploy
//
// TIER (operand, D26). The SCC subscription tier gates which modules EXIST:
// Standard includes none of Event/Container/VM Threat Detection, so a Standard-tier
// contract that asks for any of them is REFUSED (never a fake success against a
// module the tier cannot provide). The tier is a declared precondition operand —
// groundhold does not change the billing subscription; it validates against it and,
// on the wire, trusts effectiveEnablementState to tell the truth (a tier that
// cannot honor an intended=ENABLED leaves effective=DISABLED, which the net shell
// surfaces as unknown, never a claimed posture).
//
// OWNERSHIP. securityCenterServices carry NO labels and NO free-text field, so
// there is NO ownership marker to stamp (unlike GuardDuty's tags or Cloud Armor's
// description). This resource is an inherently SHARED per-parent singleton: groundhold
// is its CONFIGURATOR, not an exclusive owner. Enabling detection is monotonic-safe
// (turning security ON never harms a co-tenant); the driver therefore CONVERGES the
// posture rather than pretending to own it, and the net shell documents this. It is
// consequently NOT claimable (claim.go honest-refuses scc — nothing to stamp).
package gcp

import (
	"fmt"
	"regexp"
)

// The securitycentermanagement service ids groundhold governs for this capability.
// Fixed, closed set — never user input (safe to interpolate into the REST path).
const (
	sccModuleEventThreat     = "event-threat-detection"           // detection.enabled
	sccModuleContainerThreat = "container-threat-detection"       // protection.kubernetes
	sccModuleVMThreat        = "virtual-machine-threat-detection" // protection.malware
)

// sccModulesSorted is the deterministic order the net shell walks the governed
// modules (a stable order keeps receipts/tests reproducible).
func sccModulesSorted() []string {
	return []string{sccModuleContainerThreat, sccModuleEventThreat, sccModuleVMThreat}
}

// orgIDOK bounds an organization number before it is interpolated into a REST path
// or a providerId (D73 boundary): a GCP org id is a bare number.
var orgIDOK = regexp.MustCompile(`^[0-9]{1,20}$`)

// sccTierOK is the closed set of SCC subscription tiers. tier is an OPERAND (D26),
// so an unknown value is a refusal, never a silent default.
func sccTierOK(t string) bool {
	switch t {
	case "STANDARD", "PREMIUM", "ENTERPRISE":
		return true
	default:
		return false
	}
}

// SCCPlan is the attribute+operand-derived shape a create/converge assembles: the
// governed posture (detection on/off + the protection surface) plus the scope
// (organization or project) and the tier precondition (both operands, D26).
type SCCPlan struct {
	ScopeType  string // "organizations" | "projects" (folders left for a later slice)
	ScopeID    string // org number | project id
	Tier       string // operand: STANDARD | PREMIUM | ENTERPRISE
	Enabled    bool   // detection.enabled     -> event-threat-detection
	Kubernetes bool   // protection.kubernetes -> container-threat-detection
	Malware    bool   // protection.malware    -> virtual-machine-threat-detection
}

// BuildSCC maps capability.security.threatdetection attributes + the impl block to
// a create/converge plan, or REFUSES. Every error is a preflight refusal (never a
// half-build): an unmapped attribute, a missing core attribute, or an invalid
// operand is refused here, before the first SCC mutation (invariant #4, D26).
//
// project is the driver's pinned project — the DEFAULT scope when no organizationId/
// projectId operand is given. generation is accepted for signature symmetry with the
// other builders but is unused: SCC config is a per-parent SINGLETON with no
// generation-discriminated name.
func BuildSCC(project, environment, capability string,
	attrs, impl map[string]any, generation int) (SCCPlan, error) {
	var p SCCPlan

	// --- scope (operand, D26): organization OR project (exactly one) ---
	orgID, _ := impl["organizationId"].(string)
	projID, _ := impl["projectId"].(string)
	if orgID != "" && projID != "" {
		return SCCPlan{}, fmt.Errorf(
			"implementation may set organizationId OR projectId, not both — the SCC scope is ambiguous")
	}
	switch {
	case orgID != "":
		if !orgIDOK.MatchString(orgID) {
			return SCCPlan{}, fmt.Errorf("implementation.organizationId %q is not a valid org number", orgID)
		}
		p.ScopeType, p.ScopeID = "organizations", orgID
	default:
		scope := projID
		if scope == "" {
			scope = project
		}
		if !projectOK.MatchString(scope) {
			return SCCPlan{}, fmt.Errorf(
				"capability.security.threatdetection on SCC requires a valid project scope "+
					"(implementation.projectId or the pinned project); got %q", scope)
		}
		p.ScopeType, p.ScopeID = "projects", scope
	}

	// --- tier (operand, D26): the subscription tier that gates the modules ---
	tier, _ := impl["tier"].(string)
	if tier == "" {
		return SCCPlan{}, fmt.Errorf(
			"capability.security.threatdetection on SCC requires implementation.tier " +
				"(STANDARD|PREMIUM|ENTERPRISE) — it gates which detection modules exist")
	}
	if !sccTierOK(tier) {
		return SCCPlan{}, fmt.Errorf(
			"implementation.tier %q is not one of STANDARD|PREMIUM|ENTERPRISE", tier)
	}
	p.Tier = tier

	// --- CAPABILITY attributes drive the POSTURE (refuse any unmapped attribute) ---
	var haveEnabled bool
	for _, path := range sortedKeysG(attrs) {
		raw := attrs[path]
		switch path {
		case "location.region":
			r, _ := raw.(string)
			// SCC is org/project-scoped and global — the ONLY honest region is "global".
			if r != "" && r != "global" {
				return SCCPlan{}, fmt.Errorf(
					"location.region %q has no SCC mapping — Security Command Center is "+
						"org/project-scoped and its modules are global (locations/global), "+
						"not regional; set location.region=global or omit it", r)
			}
		case "detection.enabled":
			b, ok := raw.(bool)
			if !ok {
				return SCCPlan{}, fmt.Errorf("detection.enabled must be a bool")
			}
			p.Enabled = b
			haveEnabled = true
		case "protection.kubernetes":
			b, ok := raw.(bool)
			if !ok {
				return SCCPlan{}, fmt.Errorf("protection.kubernetes must be a bool")
			}
			p.Kubernetes = b
		case "protection.malware":
			b, ok := raw.(bool)
			if !ok {
				return SCCPlan{}, fmt.Errorf("protection.malware must be a bool")
			}
			p.Malware = b
		case "service.managed":
			if raw != true {
				return SCCPlan{}, fmt.Errorf(
					"service.managed=false cannot be honored — groundhold manages the SCC posture it configures")
			}
		default:
			return SCCPlan{}, fmt.Errorf(
				"attribute %s has no SCC mapping — refusing rather than silently dropping it "+
					"(the threatdetection vocab governs detection.enabled + protection.kubernetes/malware; "+
					"the tier is an operand, the findings export is a separate capability)", path)
		}
	}

	// detection.enabled is the CORE of the posture — refuse a create that does not say
	// whether detection should be on (never a silent assumption).
	if !haveEnabled {
		return SCCPlan{}, fmt.Errorf(
			"capability.security.threatdetection requires detection.enabled (the core posture switch)")
	}
	// a disabled posture cannot carry a protection surface — refuse the ambiguous shape
	// rather than silently configure a posture that lies.
	if !p.Enabled && (p.Kubernetes || p.Malware) {
		return SCCPlan{}, fmt.Errorf(
			"detection.enabled=false with protection.kubernetes/malware=true is contradictory — " +
				"a disabled posture monitors nothing; refusing rather than configuring a posture that lies")
	}
	// TIER gate: Standard includes none of the threat-detection modules — refuse
	// rather than PATCH an intended=ENABLED the tier can never make effective.
	if p.Tier == "STANDARD" && (p.Enabled || p.Kubernetes || p.Malware) {
		return SCCPlan{}, fmt.Errorf(
			"SCC Standard tier does not include Event/Container/VM Threat Detection — " +
				"Premium or Enterprise is required for detection.enabled/protection.*; " +
				"refusing rather than requesting a module the tier cannot provide")
	}

	return p, nil
}

// desiredModules maps the plan to (moduleId -> intendedEnablementState) for the
// modules this capability governs. Every governed module is stated EXPLICITLY
// (ENABLED or DISABLED) so an update turns a surface OFF as decisively as on — a
// protection.kubernetes=false is a real DISABLED, never an omission the API keeps.
func (p SCCPlan) desiredModules() map[string]string {
	return map[string]string{
		sccModuleEventThreat:     enablementState(p.Enabled),
		sccModuleContainerThreat: enablementState(p.Enabled && p.Kubernetes),
		sccModuleVMThreat:        enablementState(p.Enabled && p.Malware),
	}
}

func enablementState(on bool) string {
	if on {
		return "ENABLED"
	}
	return "DISABLED"
}

// classifySCCChange (D46): PURE — can a capability.security.threatdetection
// transition be honored IN PLACE? detection.enabled and the protection.* surface
// are single-call mutable (securityCenterServices.patch of intendedEnablementState);
// location.region is unsupported (SCC is global, nothing regional to patch);
// service.managed / cost.monthly are platform/projection properties. Never a silent
// "mutable" — an attribute the service cannot patch is unsupported WITH a reason.
func classifySCCChange(path string) (string, string) {
	switch path {
	case "detection.enabled":
		return "mutable", "in-place via securityCenterServices.patch (event-threat-detection intendedEnablementState)"
	case "protection.kubernetes":
		return "mutable", "in-place via securityCenterServices.patch (container-threat-detection intendedEnablementState)"
	case "protection.malware":
		return "mutable", "in-place via securityCenterServices.patch (virtual-machine-threat-detection intendedEnablementState)"
	case "location.region":
		return "unsupported", "SCC modules are global (locations/global), not regional — nothing regional to patch"
	case "service.managed":
		return "unsupported", "platform/projection property — nothing to patch"
	default:
		return "unsupported", "no SCC in-place mapping for " + path
	}
}
