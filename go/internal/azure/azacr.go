// Azure Container Registry request building (D110): the Azure half of the
// capability.registry.image driver — the SAME vocabulary GCP Artifact Registry and AWS
// ECR fulfil. A managed container image registry: regional, public toggle, CMK (Premium
// SKU only). The honest gap this cloud forces: immutable.tags is REFUSED — ACR has no
// registry-level tag-immutability toggle (immutability there is per-repository policy),
// where GCP/AWS expose it as a flag.
//
// security.scanOnPush (fala 2) has an even sharper divergence than GCP. In ECR it is a
// per-repository field (imageScanningConfiguration); in GCP it is the project-level
// Container Scanning API, which the Artifact Registry driver enables at create because no
// other groundhold driver owns it. On Azure, ACR image vulnerability scanning is Microsoft
// Defender for Containers — a SUBSCRIPTION posture (Microsoft.Security/pricings/Containers,
// pricingTier=Standard), NOT a registry property. Crucially it already has its OWN fala-1
// driver: capability.security.threatdetection (defender), whose protection.kubernetes
// governs that exact Containers plan. So the ACR driver does not fake a per-registry field
// and does not reach across to enable a subscription posture another driver owns:
//   - observe MEASURES scanOnPush from the Defender for Containers pricing state (the same
//     plan defender's protection.kubernetes reads) — truthful, never fabricated.
//   - create HONEST-REFUSES scanOnPush=true (nothing per-registry to provision; directs the
//     author to capability.security.threatdetection). scanOnPush=false/absent is accepted.
//   - classify marks it unsupported for in-place patch (a subscription posture, not a
//     per-registry toggle) — deliberately-not-mutable, so no updater is owed.
package azure

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"sort"
)

const acrAPIVersion = "2023-07-01"

// acrNameOK bounds an ACR name: 5-50 alphanumerics (no dashes, globally unique).
var acrNameOK = regexp.MustCompile(`^[a-zA-Z0-9]{5,50}$`)

// ACRPlan is the attribute-derived shape a create assembles.
type ACRPlan struct {
	Name        string
	Region      string
	Public      bool
	CMEK        bool
	KeyVaultKey string
	Sku         string
}

// BuildACR maps capability.registry.image attributes + impl to an ACR plan. Every error
// is a preflight refusal, never a silent drop.
func BuildACR(environment, capability string,
	attrs, impl map[string]any, generation int) (ACRPlan, error) {
	p := ACRPlan{Name: acrName(environment, capability, generation), Sku: "Standard"}
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
		case "network.publicExposure":
			p.Public, _ = raw.(bool)
		case "encryption.customerManagedKeys":
			if raw == true {
				p.CMEK = true
				p.Sku = "Premium" // CMK is Premium-only on ACR
				p.KeyVaultKey, _ = impl["key_vault_key"].(string)
				if p.KeyVaultKey == "" {
					return ACRPlan{}, fmt.Errorf("encryption.customerManagedKeys requires implementation.key_vault_key (a Key Vault key identifier)")
				}
			}
		case "immutable.tags":
			if raw == true {
				return ACRPlan{}, fmt.Errorf(
					"immutable.tags=true cannot be honored on Azure — ACR has no registry-level tag-" +
						"immutability toggle (immutability there is per-repository policy)")
			}
		case "security.scanOnPush":
			if raw == true {
				return ACRPlan{}, fmt.Errorf(
					"security.scanOnPush=true cannot be honored on the ACR registry — Azure has no " +
						"per-registry image-scanning field (the honest divergence from ECR's " +
						"imageScanningConfiguration). ACR vulnerability scanning is Microsoft Defender for " +
						"Containers, a SUBSCRIPTION posture (Microsoft.Security/pricings/Containers); declare it " +
						"via capability.security.threatdetection (protection.kubernetes) — the defender driver — " +
						"not on the registry. groundhold OBSERVES scanOnPush from that Defender posture, but will " +
						"not provision a per-registry field that does not exist")
			}
			// scanOnPush=false/absent: nothing to provision on the registry. The posture is
			// measured from Defender for Containers at observe, never written here.
		case "service.managed":
			if raw != true {
				return ACRPlan{}, fmt.Errorf("service.managed=false cannot be honored by ACR")
			}
		default:
			return ACRPlan{}, fmt.Errorf(
				"attribute %s has no ACR mapping — refusing rather than silently dropping it", path)
		}
	}
	if p.Region == "" {
		return ACRPlan{}, fmt.Errorf("registry requires location.region")
	}
	if !acrNameOK.MatchString(p.Name) {
		return ACRPlan{}, fmt.Errorf("derived registry name %q is invalid", p.Name)
	}
	return p, nil
}

func acrName(environment, capability string, generation int) string {
	hashInput := environment + "|" + capability
	if generation >= 2 {
		hashInput += fmt.Sprintf("|g%d", generation)
	}
	sum := sha256.Sum256([]byte(hashInput))
	return "pv" + hex.EncodeToString(sum[:])[:18]
}

func (p ACRPlan) createBody(tags map[string]any) map[string]any {
	access := "Disabled"
	if p.Public {
		access = "Enabled"
	}
	props := map[string]any{
		"adminUserEnabled":    false,
		"publicNetworkAccess": access,
	}
	if p.CMEK {
		props["encryption"] = map[string]any{
			"status":             "enabled",
			"keyVaultProperties": map[string]any{"keyIdentifier": p.KeyVaultKey},
		}
	}
	return map[string]any{
		"location":   p.Region,
		"tags":       tags,
		"sku":        map[string]any{"name": p.Sku},
		"properties": props,
	}
}

// classifyACRChange (D46 / fala 2): PURE — which capability.registry.image transitions can
// ACR honor in place? The honest divergence from ECR (classifyECRChange) is
// security.scanOnPush. ECR classifies it mutable and patches it per repository
// (PutImageScanningConfiguration). Azure has NO per-registry scanning setting at all: image
// scanning is Microsoft Defender for Containers (Microsoft.Security/pricings/Containers), a
// SUBSCRIPTION posture with its own driver (capability.security.threatdetection). The ACR
// driver must not toggle a subscription-wide plan another driver owns — flipping it would
// change scanning for every registry in the subscription. So it is "unsupported" with a
// truthful reason: deliberately-not-mutable (NOT mutable-without-updater), directing the
// change to the defender driver. Region/CMEK are create-time (a replacement); immutable.tags
// and public exposure are not wired for in-place patch in this slice.
func classifyACRChange(path string) (string, string) {
	switch path {
	case "security.scanOnPush":
		return "unsupported", "scanOnPush on Azure is not a registry property — ACR image " +
			"vulnerability scanning is Microsoft Defender for Containers " +
			"(Microsoft.Security/pricings/Containers, a subscription posture), governed by " +
			"capability.security.threatdetection (the defender driver), not a per-registry toggle " +
			"groundhold can patch on the registry (flipping it would change scanning for every registry " +
			"in the subscription)"
	case "immutable.tags":
		return "unsupported", "ACR has no registry-level tag-immutability toggle " +
			"(immutability there is per-repository policy) — nothing to patch"
	case "network.publicExposure":
		return "unsupported", "in-place patch of network.publicExposure is not wired for ACR in this slice"
	case "location.region", "encryption.customerManagedKeys":
		return "immutable", "an ACR registry's region/CMEK is fixed at creation — a change is a replacement"
	case "service.managed":
		return "unsupported", "platform/projection property — nothing to patch"
	default:
		return "unsupported", "no ACR in-place mapping for " + path
	}
}
