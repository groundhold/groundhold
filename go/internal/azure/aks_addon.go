// AKS cluster-addon driver (D76 fala-3 parity): the Azure half of
// capability.cluster.addon — the SAME vocabulary AWS eks-addon and GCP gke-addon
// fulfil, but a THIRD resource shape, told honestly here.
//
// An EKS managed addon is a SEPARATE, INDEPENDENTLY VERSIONED package under a
// cluster (CreateAddon/UpdateAddon carry an addonVersion). An AKS addon is NOT
// that, and neither is it quite the GKE shape: it is an entry in the managed
// cluster's `properties.addonProfiles` map (azurepolicy, omsagent,
// azureKeyvaultSecretsProvider, ingressApplicationGateway, openServiceMesh,
// httpApplicationRouting, ...), each a UNIFORM `{ enabled: bool, config: {...} }`
// (no GKE-style mixed enabled/disabled polarity). AKS installs and versions the
// addon WITH the cluster — there is no per-addon version to set or read. So:
//
//   - addon.name  -> which key in addonProfiles (canonical, provider-neutral name
//     -> AKS addonProfiles key; an unmapped name is REFUSED, never guessed).
//   - addon.version -> REFUSED. AKS does not version addonProfiles independently;
//     a contract that pins addon.version cannot be honored, so BuildAKSAddon
//     refuses rather than fabricate a version (observe emits a managed-by-cluster
//     diagnostic, never a made-up value — the SAME honesty as gke-addon, the
//     OPPOSITE of eks-addon which does version).
//   - create/update = PUT the managed cluster with addonProfiles.{name}.enabled=
//     true (+ optional config); delete = enabled=false. The operand is the
//     CLUSTER (name + resource group), never provisioned here (D26).
//   - service.managed -> an addonProfile is managed by construction.
//
// STATELESS: a flag carries no durable data. Ownership is STRUCTURAL: the addon
// has NO marker of its own (it is a field on someone else's cluster), so identity
// is the deterministic (cluster, canonical addon name) tuple — never a tag match.
// An AKS addon is therefore NOT claimable: it honest-refuses a takeover-claim,
// because there is nothing on it to stamp (parity with gke-addon/eks-addon).
package azure

import (
	"fmt"
	"sort"
	"strings"
)

// aksAddonAPIVersion is the managedClusters control-plane version this addon
// driver reads/writes. It is addon-specific ON PURPOSE: the aks [cluster] driver
// is authored separately and owns its own api-version constant; keeping this one
// inside the addon files means the two never collide (isolation).
const aksAddonAPIVersion = "2024-05-01"

// aksAddonClusterOK bounds an AKS cluster name before it is interpolated into an
// ARM path (D73 boundary). AKS names are alnum, hyphen and underscore, 1-63,
// start/end alphanumeric.
var aksAddonClusterOK = azNameOK

// aksAddonRegistry maps the canonical addon.name (vocab-level, provider-neutral)
// to its AKS addonProfiles key. Refusing an unknown name is the honesty gate: an
// unmapped addon is refused, never dropped. All AKS profiles share one polarity
// (`enabled` true==on), so no per-entry toggle field is needed (the GKE nuance
// does not exist here).
var aksAddonRegistry = map[string]string{
	"azure-policy":              "azurepolicy",
	"monitoring":                "omsagent",
	"keyvault-secrets-provider": "azureKeyvaultSecretsProvider",
	"ingress-appgw":             "ingressApplicationGateway",
	"open-service-mesh":         "openServiceMesh",
	"http-application-routing":  "httpApplicationRouting",
}

// aksAddonCanonicalNames lists the registry keys (sorted) for error messages.
func aksAddonCanonicalNames() string {
	names := make([]string, 0, len(aksAddonRegistry))
	for k := range aksAddonRegistry {
		names = append(names, k)
	}
	sort.Strings(names)
	return strings.Join(names, ", ")
}

// AKSAddonPlan is the attribute+operand-derived shape a create/update assembles.
// The SHAPE (which addon) is a CAPABILITY attribute; the cluster + resource group
// are OPERATOR operands (impl block, D26) — a separate capability, never
// provisioned here.
type AKSAddonPlan struct {
	AddonName   string         // canonical (capability)
	ProfileKey  string         // resolved AKS addonProfiles key
	ClusterName string         // operand (required)
	ResourceGrp string         // operand (required)
	Config      map[string]any // operand (optional) — addonProfiles.{key}.config passthrough
	Region      string         // optional — location.region (informational; the cluster addresses itself)
}

// BuildAKSAddon maps capability.cluster.addon attributes + implementation
// operands to a plan, or REFUSES. Every error is a preflight refusal (never a
// half-build). The load-bearing divergence from eks-addon: addon.version is
// REFUSED (AKS addon versions track the cluster version, not independently
// settable) and addon.name MUST resolve to a known AKS addonProfiles key.
// generation is unused (the addon identity is the name, not a hashed
// discriminator) but kept for a uniform Build signature across the driver family.
func BuildAKSAddon(environment, capability string,
	attrs, impl map[string]any, generation int) (AKSAddonPlan, error) {
	p := AKSAddonPlan{}
	paths := make([]string, 0, len(attrs))
	for k := range attrs {
		paths = append(paths, k)
	}
	sort.Strings(paths)

	for _, path := range paths {
		raw := attrs[path]
		switch path {
		case "addon.name":
			v, ok := raw.(string)
			if !ok || strings.TrimSpace(v) == "" {
				return AKSAddonPlan{}, fmt.Errorf("addon.name must be a non-empty string (e.g. \"keyvault-secrets-provider\")")
			}
			name := strings.TrimSpace(v)
			key, known := aksAddonRegistry[name]
			if !known {
				return AKSAddonPlan{}, fmt.Errorf(
					"addon.name %q has no AKS addonProfiles mapping — refusing to guess; "+
						"AKS addons are managed-cluster addonProfiles, supported canonical names: %s",
					name, aksAddonCanonicalNames())
			}
			p.AddonName = name
			p.ProfileKey = key
		case "addon.version":
			// The honest divergence from eks-addon: AKS does not version addons
			// independently — they track the cluster version. Pretending to set a
			// version would be a lie, so refuse rather than silently ignore it (the
			// SAME stance gke-addon takes).
			return AKSAddonPlan{}, fmt.Errorf(
				"addon.version cannot be honored by AKS — AKS addon versions track the " +
					"cluster version, not independently settable; refusing rather than " +
					"fabricating a version (upgrade the cluster to move the addon)")
		case "service.managed":
			if raw != true {
				return AKSAddonPlan{}, fmt.Errorf("service.managed=false cannot be honored by AKS (an addonProfile IS managed by construction)")
			}
		case "location.region":
			p.Region, _ = raw.(string)
		default:
			return AKSAddonPlan{}, fmt.Errorf(
				"attribute %s has no AKS addon mapping — refusing rather than silently "+
					"dropping it (the cluster.addon vocab governs addon.name + addon.version)", path)
		}
	}
	if p.AddonName == "" {
		return AKSAddonPlan{}, fmt.Errorf("addon.name is required — refusing to guess which cluster addon to toggle")
	}

	// --- OPERATOR operands (implementation: block, D26) ---
	// Type assertions are inlined (not via a shared impl helper) to keep this
	// driver's symbols isolated from the parallel aks [cluster] author.
	clusterName, _ := impl["clusterName"].(string)
	if p.ClusterName = strings.TrimSpace(clusterName); p.ClusterName == "" {
		return AKSAddonPlan{}, fmt.Errorf("implementation.clusterName is required (the AKS cluster the addon toggles on — a separate capability/operand)")
	}
	rg, _ := impl["resource_group"].(string)
	if p.ResourceGrp = strings.TrimSpace(rg); p.ResourceGrp == "" {
		return AKSAddonPlan{}, fmt.Errorf("implementation.resource_group is required (the AKS cluster's resource group — needed to address the cluster)")
	}
	// addonConfig is OPTIONAL — some addons need config (omsagent's
	// logAnalyticsWorkspaceResourceID, azureKeyvaultSecretsProvider's
	// enableSecretRotation). It is a passthrough of REFERENCES/FLAGS, never key
	// material (D53). Accepted as map[string]any or map[string]string.
	if cfg, ok := impl["addon_config"].(map[string]any); ok {
		p.Config = cfg
	} else if cfgs, ok := impl["addon_config"].(map[string]string); ok {
		m := make(map[string]any, len(cfgs))
		for k, v := range cfgs {
			m[k] = v
		}
		p.Config = m
	}

	if !aksAddonClusterOK.MatchString(p.ClusterName) {
		return AKSAddonPlan{}, fmt.Errorf("implementation.clusterName %q is not a valid AKS cluster name", p.ClusterName)
	}
	if !rgOK.MatchString(p.ResourceGrp) {
		return AKSAddonPlan{}, fmt.Errorf("implementation.resource_group %q is not a valid Azure resource group name", p.ResourceGrp)
	}
	return p, nil
}

// classifyAKSAddonChange (D46): PURE. AKS has NO in-place per-addon patchable
// attribute exposed by the vocab: addon.name is the identity (a different addon
// is a different resource); addon.version is REFUSED as unsupported (AKS does not
// version addons independently — never mutable, so never a mutable-without-updater
// trap); enable/disable is create/delete, not a patch. Nothing is mutable, so no
// updater is (or must be) wired — the honest opposite of eks-addon.
func classifyAKSAddonChange(path string) (string, string) {
	switch path {
	case "addon.name":
		return "immutable", "the addon name is the identity — a different addon is a different resource, not an in-place patch"
	case "addon.version":
		return "unsupported", "AKS does not version addons independently (they track the cluster version) — there is no per-addon version to patch"
	case "service.managed", "location.region":
		return "unsupported", "platform/projection property — nothing to patch"
	default:
		return "unsupported", "no AKS addon in-place mapping for " + path
	}
}
