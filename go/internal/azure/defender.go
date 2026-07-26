// Microsoft Defender for Cloud request building (D76 parity): the PURE, network-free
// forward map of capability.security.threatdetection on Azure — the SAME vocabulary
// AWS GuardDuty and GCP Security Command Center fulfil, now with a third cloud. This
// file is the CONCEPTUAL TWIN of internal/gcp/scc.go: a subscription-scoped posture,
// not an owned leaf resource; a configurator-not-owner; a monotonic-safe converge.
// Every error is a PREFLIGHT refusal before any mutation (invariant #4, D26).
//
// WHAT WE GOVERN (the posture) vs HOW DEFENDER EXPOSES IT — the honest mapping.
// Defender for Cloud is NOT a single per-region detector (GuardDuty) nor a set of
// modules (SCC); it is a family of per-subscription PLANS (Microsoft.Security/pricings/
// {planName}), each a SINGLETON toggled Free<->Standard by a PUT of pricingTier.
// "Standard" is the plan turned ON (threat detection + alerts active); "Free" is off.
// groundhold governs three plans, mapped honestly and WITHOUT overlap:
//   - detection.enabled     -> VirtualMachines  (Defender for Servers) — Defender's
//     FLAGSHIP workload threat-detection plan (behavioral analytics, alerts, EDR
//     integration). The closest honest analog to GuardDuty's detector / SCC's
//     event-threat-detection: the CORE posture switch. subPlan defaults to P2 (the
//     tier that carries full threat detection); an operand may override it.
//   - protection.kubernetes -> Containers       (Defender for Containers) — control-
//     plane + runtime threat detection for AKS. The exact analog of SCC's
//     container-threat-detection / GuardDuty EKS audit-log protection.
//   - protection.malware    -> StorageAccounts  (Defender for Storage) with the
//     DefenderForStorageV2 subPlan and the OnUploadMalwareScanning extension. This is
//     a DEDICATED, on-by-configuration malware scanner (blobs scanned on upload) — a
//     CLEAN analog to GuardDuty's EBS malware protection, chosen over Servers'
//     agentless malware precisely because it does not overlap the detection.enabled
//     plan (Servers), keeping each vocab attribute on a distinct plan (mirrors SCC's
//     event/container/vm split). Documented as an analog, not an identity.
//   - location.region       -> Defender pricings are SUBSCRIPTION-scoped, not regional
//     (like SCC's locations/global). The only honest value is "global" (or omitted);
//     a real regional value is REFUSED, never silently coerced.
//   - service.managed       -> const true (Defender is a managed service).
//   - cost.monthly          -> projection / billing-after-deploy.
//
// NO SEPARATE TIER OPERAND (unlike SCC). SCC's subscription tier (STANDARD/PREMIUM/
// ENTERPRISE) gated which modules EXIST; Defender has no such envelope — the pricingTier
// per plan IS exactly what detection.enabled/protection.* control. So there is nothing
// to gate against: enabling a plan is the whole act. The per-plan subPlan/extensions
// are the D26 operands.
//
// OWNERSHIP. Microsoft.Security/pricings carry NO tags and NO free-text field — they
// are per-subscription CONFIG singletons, not tagged resources. There is NO ownership
// marker to stamp (exactly like SCC). groundhold is the CONFIGURATOR, not an exclusive
// owner: enabling detection is monotonic-safe (turning security ON never harms a
// co-tenant), so create CONVERGES the posture rather than pretending to own it; delete
// sets the governed plans back to Free (posture off); claim honest-refuses (nothing to
// stamp). Foreign/existing state is converged if compatible and documented.
package azure

import (
	"fmt"
	"regexp"
	"sort"
)

// The Microsoft.Security/pricings plan names groundhold governs for this capability.
// A FIXED, closed set — never user input, safe to interpolate into the ARM path.
const (
	defenderPlanServers    = "VirtualMachines" // detection.enabled (Defender for Servers)
	defenderPlanContainers = "Containers"      // protection.kubernetes (Defender for Containers)
	defenderPlanStorage    = "StorageAccounts" // protection.malware (Defender for Storage)
)

// defenderStorageSubPlan / defenderMalwareExtension name the Storage plan sub-shape
// that carries on-upload malware scanning (the protection.malware analog).
const (
	defenderStorageSubPlan    = "DefenderForStorageV2"
	defenderMalwareExtension  = "OnUploadMalwareScanning"
	defenderServersSubPlanDef = "P2" // Servers subPlan default (full threat detection)
)

// defenderAPIVersion pins the Security pricings API version (subPlan + extensions
// supported).
const defenderAPIVersion = "2024-01-01"

// defenderPlansSorted is the deterministic order the net shell walks the governed
// plans (a stable order keeps receipts/tests reproducible).
func defenderPlansSorted() []string {
	return []string{defenderPlanContainers, defenderPlanStorage, defenderPlanServers}
}

// defenderSubPlanOK bounds a Servers subPlan operand before it rides the wire — a
// closed set (P1 = foundational, P2 = full threat detection). An unknown value is a
// refusal, never a silent default (D26).
var defenderSubPlanOK = regexp.MustCompile(`^P[12]$`)

// DefenderPlan is the attribute+operand-derived posture a create/converge assembles:
// the governed detection posture (detection on/off + the protection surface) plus the
// per-plan operands. The subscription scope is applied at the net layer (d.Subscription,
// like every other Azure service), so the pure builder carries only the posture.
type DefenderPlan struct {
	Enabled        bool   // detection.enabled     -> VirtualMachines (Servers) Standard
	Kubernetes     bool   // protection.kubernetes -> Containers Standard
	Malware        bool   // protection.malware    -> StorageAccounts Standard + malware ext
	ServersSubPlan string // operand: P1 | P2 (default P2)
}

// BuildDefender maps capability.security.threatdetection attributes + the impl block
// to a create/converge posture, or REFUSES. Every error is a preflight refusal (never
// a half-build): an unmapped attribute, a missing core attribute, a contradictory
// shape, or an invalid operand is refused here, before the first pricings PUT
// (invariant #4, D26). generation is accepted for signature symmetry with the other
// builders but is unused: a pricing is a per-subscription SINGLETON with no
// generation-discriminated name.
func BuildDefender(environment, capability string,
	attrs, impl map[string]any, generation int) (DefenderPlan, error) {
	p := DefenderPlan{ServersSubPlan: defenderServersSubPlanDef}

	// --- operand (D26): the Servers subPlan (P1|P2), default P2 (full threat detection) ---
	if sp, ok := impl["serversSubPlan"].(string); ok && sp != "" {
		if !defenderSubPlanOK.MatchString(sp) {
			return DefenderPlan{}, fmt.Errorf(
				"implementation.serversSubPlan %q is not P1|P2 — refusing rather than defaulting silently", sp)
		}
		p.ServersSubPlan = sp
	}

	// --- CAPABILITY attributes drive the POSTURE (refuse any unmapped attribute) ---
	var haveEnabled bool
	paths := make([]string, 0, len(attrs))
	for k := range attrs {
		paths = append(paths, k)
	}
	sort.Strings(paths)
	for _, path := range paths {
		raw := attrs[path]
		switch path {
		case "location.region":
			r, _ := raw.(string)
			// Defender pricings are subscription-scoped — the ONLY honest region is "global".
			if r != "" && r != "global" {
				return DefenderPlan{}, fmt.Errorf(
					"location.region %q has no Defender mapping — Microsoft Defender for Cloud "+
						"pricings are subscription-scoped, not regional; set location.region=global "+
						"or omit it", r)
			}
		case "detection.enabled":
			b, ok := raw.(bool)
			if !ok {
				return DefenderPlan{}, fmt.Errorf("detection.enabled must be a bool")
			}
			p.Enabled = b
			haveEnabled = true
		case "protection.kubernetes":
			b, ok := raw.(bool)
			if !ok {
				return DefenderPlan{}, fmt.Errorf("protection.kubernetes must be a bool")
			}
			p.Kubernetes = b
		case "protection.malware":
			b, ok := raw.(bool)
			if !ok {
				return DefenderPlan{}, fmt.Errorf("protection.malware must be a bool")
			}
			p.Malware = b
		case "service.managed":
			if raw != true {
				return DefenderPlan{}, fmt.Errorf(
					"service.managed=false cannot be honored — groundhold manages the Defender posture it configures")
			}
		default:
			return DefenderPlan{}, fmt.Errorf(
				"attribute %s has no Defender mapping — refusing rather than silently dropping it "+
					"(the threatdetection vocab governs detection.enabled + protection.kubernetes/malware; "+
					"the Servers subPlan is an operand)", path)
		}
	}

	// detection.enabled is the CORE of the posture — refuse a create that does not say
	// whether detection should be on (never a silent assumption).
	if !haveEnabled {
		return DefenderPlan{}, fmt.Errorf(
			"capability.security.threatdetection requires detection.enabled (the core posture switch)")
	}
	// a disabled posture cannot carry a protection surface — refuse the ambiguous shape
	// rather than configuring a posture that lies. (The vocab semantics are shared across
	// clouds: protection.* are surfaces ON detection, so detection off + protection on is
	// a contradictory CONTRACT regardless of Defender's independent-plan implementation.)
	if !p.Enabled && (p.Kubernetes || p.Malware) {
		return DefenderPlan{}, fmt.Errorf(
			"detection.enabled=false with protection.kubernetes/malware=true is contradictory — " +
				"a disabled posture monitors nothing; refusing rather than configuring a posture that lies")
	}
	return p, nil
}

// defenderDesired is the full desired shape of one governed plan: the tier plus (when
// Standard) the subPlan and any extensions. Every governed plan is stated EXPLICITLY
// so an update turns a surface OFF (tier=Free) as decisively as on — a
// protection.kubernetes=false is a real Free, never an omission the API keeps.
type defenderDesired struct {
	tier    string // "Standard" | "Free"
	subPlan string // "" when none
	malware bool   // when true, set the OnUploadMalwareScanning extension enabled
}

// desiredPlans maps the posture to (planName -> desired shape) for the plans this
// capability governs. Standard=on, Free=off; the protection surfaces are gated by
// detection.enabled (a surface cannot be on while detection is off — mirrors SCC).
func (p DefenderPlan) desiredPlans() map[string]defenderDesired {
	servers := defenderDesired{tier: defenderTier(p.Enabled)}
	if p.Enabled {
		servers.subPlan = p.ServersSubPlan
	}
	containers := defenderDesired{tier: defenderTier(p.Enabled && p.Kubernetes)}
	storage := defenderDesired{tier: defenderTier(p.Enabled && p.Malware)}
	if p.Enabled && p.Malware {
		storage.subPlan = defenderStorageSubPlan
		storage.malware = true
	}
	return map[string]defenderDesired{
		defenderPlanServers:    servers,
		defenderPlanContainers: containers,
		defenderPlanStorage:    storage,
	}
}

func defenderTier(on bool) string {
	if on {
		return "Standard"
	}
	return "Free"
}

// classifyDefenderChange (D46): PURE — can a capability.security.threatdetection
// transition be honored IN PLACE? detection.enabled and the protection.* surface are
// single-call mutable (a pricings PUT of pricingTier/subPlan/extensions);
// location.region is unsupported (Defender is subscription-scoped, nothing regional to
// patch); service.managed / cost.monthly are platform/projection properties. Never a
// silent "mutable" — an attribute the service cannot patch is unsupported WITH a reason.
func classifyDefenderChange(path string) (string, string) {
	switch path {
	case "detection.enabled":
		return "mutable", "in-place via Microsoft.Security/pricings PUT (VirtualMachines pricingTier)"
	case "protection.kubernetes":
		return "mutable", "in-place via Microsoft.Security/pricings PUT (Containers pricingTier)"
	case "protection.malware":
		return "mutable", "in-place via Microsoft.Security/pricings PUT (StorageAccounts pricingTier + OnUploadMalwareScanning)"
	case "location.region":
		return "unsupported", "Defender pricings are subscription-scoped, not regional — nothing regional to patch"
	case "service.managed":
		return "unsupported", "platform/projection property — nothing to patch"
	default:
		return "unsupported", "no Defender in-place mapping for " + path
	}
}
