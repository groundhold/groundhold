// GKE cluster-addon driver (D76 parity): the GCP half of
// capability.cluster.addon — the SAME vocabulary AWS eks-addon fulfils, but a
// DIFFERENT resource shape, and this file tells that difference honestly.
//
// An EKS managed addon is a SEPARATE, INDEPENDENTLY VERSIONED package installed
// UNDER a cluster (CreateAddon/DescribeAddon/UpdateAddon carry an addonVersion).
// A GKE addon is NOT that: it is a FLAG in the cluster's `addonsConfig`
// (httpLoadBalancing, horizontalPodAutoscaling, networkPolicyConfig,
// gcePersistentDiskCsiDriverConfig, gcpFilestoreCsiDriverConfig, dnsCacheConfig,
// gkeBackupAgentConfig, configConnectorConfig, ...). GKE installs and versions
// it WITH the cluster — there is no per-addon version to set or read. So:
//
//   - addon.name  -> which flag in addonsConfig (canonical name -> API field +
//     its enable/disable toggle; some fields toggle on `disabled`, some on
//     `enabled`, and this file maps each HONESTLY rather than guessing).
//   - addon.version -> REFUSED. GKE does not version addons independently; a
//     contract that pins addon.version cannot be honored by GKE, so BuildGKEAddon
//     refuses rather than fabricate a version (observe emits a diagnostic, never
//     a made-up value).
//   - create/update = SetAddonsConfig (a cluster UpdateCluster op) enabling the
//     flag; delete = disabling it. The operand is the CLUSTER (name + location),
//     never provisioned here (D26).
//   - service.managed -> a GKE addon is managed by construction.
//
// STATELESS: a flag carries no durable data. Ownership: the addon has NO marker
// of its own (it is a field on someone else's cluster), so identity is the
// deterministic (cluster, canonical addon name) tuple — never a tag/label match.
// A GKE addon is therefore NOT claimable (no gcpClaimPerms entry): it honest-
// refuses a takeover-claim, because there is nothing on it to stamp.
package gcp

import (
	"fmt"
	"regexp"
	"strings"
)

// gkeAddonContainerBaseURL is the GKE control-plane API. This driver reads and
// writes only the cluster's addonsConfig — never nodes, never workloads.
const gkeAddonContainerBaseURL = "https://container.googleapis.com/v1"

// gkeAddonBaseOverride is a package-level TEST HOOK (httptest server URL). It is
// addon-specific on purpose: the gke [cluster] driver is authored separately and
// owns its own Driver field / base helper; this addon driver keeps its override
// entirely inside its own files so the two never collide (isolation). Production
// wiring may later promote this to a Driver.GKEBaseURL field like the others.
var gkeAddonBaseOverride string

// gkeAddonClusterOK bounds a GKE cluster name (lowercase alnum + hyphen, 1-40,
// starts with a letter) before it is interpolated into a control-plane REST
// path (D73 boundary).
var gkeAddonClusterOK = regexp.MustCompile(`^[a-z][a-z0-9-]{0,38}[a-z0-9]$`)

// gkeAddonLocationOK accepts BOTH a region (us-central1) and a zone
// (us-central1-a) — a GKE cluster may be regional or zonal, so the addon's
// location operand must permit either. Charset only; a real location is
// validated by the API.
var gkeAddonLocationOK = regexp.MustCompile(`^[a-z][a-z0-9-]{0,38}[a-z0-9]$`)

// gkeAddonSpec describes one canonical addon: the JSON key inside addonsConfig
// and the boolean sub-field that toggles it. The nuance this captures honestly:
// legacy addons express enablement as `disabled` (false == on) while newer ones
// use `enabled` (true == on) — mapping them uniformly would silently invert two
// of them.
type gkeAddonSpec struct {
	field  string // JSON key inside cluster.addonsConfig
	toggle string // "enabled" (true==on) or "disabled" (true==off)
}

// gkeAddonRegistry maps the canonical addon.name (vocab-level, provider-neutral)
// to its GKE addonsConfig field + toggle. Refusing an unknown name is the
// honesty gate: an unmapped addon is refused, never dropped.
var gkeAddonRegistry = map[string]gkeAddonSpec{
	"http-load-balancing":        {"httpLoadBalancing", "disabled"},
	"horizontal-pod-autoscaling": {"horizontalPodAutoscaling", "disabled"},
	"network-policy":             {"networkPolicyConfig", "disabled"},
	"gce-pd-csi-driver":          {"gcePersistentDiskCsiDriverConfig", "enabled"},
	"filestore-csi-driver":       {"gcpFilestoreCsiDriverConfig", "enabled"},
	"dns-cache":                  {"dnsCacheConfig", "enabled"},
	"backup-agent":               {"gkeBackupAgentConfig", "enabled"},
	"config-connector":           {"configConnectorConfig", "enabled"},
}

// configFragment builds the addonsConfig sub-object that enables (or disables)
// this addon, respecting the field's toggle polarity.
func (s gkeAddonSpec) configFragment(enable bool) map[string]any {
	val := enable
	if s.toggle == "disabled" {
		val = !enable // a `disabled` field is set false to ENABLE
	}
	return map[string]any{s.field: map[string]any{s.toggle: val}}
}

// addonState is what a cluster's config actually tells us about one addon. It replaces
// a pair of booleans whose false/false meant three different things at once (D801).
type addonState int

const (
	addonAbsent     addonState = iota // no config block at all — the addon is not configured
	addonOn                           // configured and on
	addonOff                          // configured and off
	addonUnreadable                   // a block we cannot interpret — never silently "absent"
)

// readState reverse-reads one addon's enablement from a cluster addonsConfig,
// normalizing the toggle polarity.
//
// D801: the previous version returned (enabled, present) and reported present=false when
// the toggle key was missing from an EXISTING block. That reading is wrong on this API in
// the most common case there is. Google serializes JSON the proto3 way, which OMITS
// fields holding their default value — so an addon that is ON through a `disabled` toggle
// comes back as an EMPTY OBJECT:
//
//	"httpLoadBalancing": {}          <- disabled:false omitted; the addon is ENABLED
//
// Read as "not present", that made an enabled addon invisible to discover, and made
// delete answer "never enabled — nothing to do" about a control that was still on.
//
// An absent toggle is therefore FALSE, and the polarity decides what false means. A
// missing BLOCK is a real absence. A block we cannot parse is neither, and says so.
func (s gkeAddonSpec) readState(addonsConfig map[string]any) addonState {
	raw, exists := addonsConfig[s.field]
	if !exists {
		return addonAbsent
	}
	sub, ok := raw.(map[string]any)
	if !ok {
		return addonUnreadable
	}
	val, exists := sub[s.toggle]
	if !exists {
		val = false // proto3 JSON omits the default
	}
	v, ok := val.(bool)
	if !ok {
		return addonUnreadable
	}
	if s.toggle == "disabled" {
		v = !v
	}
	if v {
		return addonOn
	}
	return addonOff
}

// gkeAddonCanonicalNames lists the registry keys (sorted) for error messages.
func gkeAddonCanonicalNames() string {
	names := make([]string, 0, len(gkeAddonRegistry))
	for k := range gkeAddonRegistry {
		names = append(names, k)
	}
	// small n; a simple insertion keeps it dependency-free and deterministic
	for i := 1; i < len(names); i++ {
		for j := i; j > 0 && names[j-1] > names[j]; j-- {
			names[j-1], names[j] = names[j], names[j-1]
		}
	}
	return strings.Join(names, ", ")
}

// GKEAddonPlan is the attribute+operand-derived shape a create/update assembles.
// The SHAPE (which addon) is a CAPABILITY attribute; the cluster + location are
// OPERATOR operands (impl block, D26) — a separate capability, never provisioned
// here.
type GKEAddonPlan struct {
	AddonName   string       // canonical (capability)
	Spec        gkeAddonSpec // resolved API field + toggle
	ClusterName string       // operand (required)
	Location    string       // operand (required) — region or zone
}

// BuildGKEAddon maps capability.cluster.addon attributes + implementation
// operands to a plan, or REFUSES. Every error is a preflight refusal (never a
// half-build). The load-bearing divergence from EKS: addon.version is REFUSED
// (GKE addon versions track the cluster version, not independently settable) and
// addon.name MUST resolve to a known GKE addonsConfig flag.
func BuildGKEAddon(project, environment, capability string,
	attrs, impl map[string]any, generation int) (GKEAddonPlan, error) {
	p := GKEAddonPlan{}
	locFromAttr := ""
	for _, path := range sortedKeysG(attrs) {
		raw := attrs[path]
		switch path {
		case "addon.name":
			v, ok := raw.(string)
			if !ok || strings.TrimSpace(v) == "" {
				return GKEAddonPlan{}, fmt.Errorf("addon.name must be a non-empty string (e.g. \"gce-pd-csi-driver\")")
			}
			name := strings.TrimSpace(v)
			spec, known := gkeAddonRegistry[name]
			if !known {
				return GKEAddonPlan{}, fmt.Errorf(
					"addon.name %q has no GKE addonsConfig mapping — refusing to guess; "+
						"GKE addons are cluster flags, supported canonical names: %s",
					name, gkeAddonCanonicalNames())
			}
			p.AddonName = name
			p.Spec = spec
		case "addon.version":
			// The honest divergence from eks-addon: GKE does not version addons
			// independently — they track the cluster version. Pretending to set a
			// version would be a lie, so refuse rather than silently ignore it.
			return GKEAddonPlan{}, fmt.Errorf(
				"addon.version cannot be honored by GKE — GKE addon versions track the " +
					"cluster version, not independently settable; refusing rather than " +
					"fabricating a version (upgrade the cluster to move the addon)")
		case "service.managed":
			if raw != true {
				return GKEAddonPlan{}, fmt.Errorf("service.managed=false cannot be honored by GKE (an addonsConfig flag IS managed by construction)")
			}
		case "location.region":
			// location.region scopes the cluster the addon lives on; accepted as a
			// passthrough (the operand's location may also arrive in impl).
			locFromAttr, _ = raw.(string)
		default:
			return GKEAddonPlan{}, fmt.Errorf(
				"attribute %s has no GKE addon mapping — refusing rather than silently "+
					"dropping it (the cluster.addon vocab governs addon.name + addon.version)", path)
		}
	}
	if p.AddonName == "" {
		return GKEAddonPlan{}, fmt.Errorf("addon.name is required — refusing to guess which cluster addon to toggle")
	}

	// --- OPERATOR operands (implementation: block, D26) ---
	// Type assertions are inlined (not via a shared implString helper) to keep
	// this driver's symbols isolated from the parallel gke [cluster] author.
	clusterName, _ := impl["clusterName"].(string)
	if p.ClusterName = strings.TrimSpace(clusterName); p.ClusterName == "" {
		return GKEAddonPlan{}, fmt.Errorf("implementation.clusterName is required (the GKE cluster the addon toggles on — a separate capability/operand)")
	}
	loc, _ := impl["location"].(string)
	p.Location = strings.TrimSpace(loc)
	if p.Location == "" {
		p.Location = strings.TrimSpace(locFromAttr)
	}
	if p.Location == "" {
		return GKEAddonPlan{}, fmt.Errorf("implementation.location (or location.region) is required (the GKE cluster's region/zone — needed to address the cluster)")
	}
	if !projectOK.MatchString(project) {
		return GKEAddonPlan{}, fmt.Errorf("project %q is invalid", project)
	}
	if !gkeAddonClusterOK.MatchString(p.ClusterName) {
		return GKEAddonPlan{}, fmt.Errorf("implementation.clusterName %q is not a valid GKE cluster name", p.ClusterName)
	}
	if !gkeAddonLocationOK.MatchString(p.Location) {
		return GKEAddonPlan{}, fmt.Errorf("location %q is not a valid GKE location", p.Location)
	}
	return p, nil
}

// classifyGKEAddonChange (D46): PURE. Enabling/disabling an addon is a mutable
// in-place SetAddonsConfig on the cluster; addon.name is the identity (a
// different addon is a different resource); addon.version is REFUSED as
// unsupported (GKE does not version addons independently — never mutable, so
// never a mutable-without-updater trap).
func classifyGKEAddonChange(path string) (string, string) {
	switch path {
	case "addon.name":
		return "immutable", "the addon name is the identity — a different addon is a different resource, not an in-place patch"
	case "addon.version":
		return "unsupported", "GKE does not version addons independently (they track the cluster version) — there is no per-addon version to patch"
	case "service.managed", "location.region":
		return "unsupported", "platform/projection property — nothing to patch"
	default:
		return "unsupported", "no GKE addon in-place mapping for " + path
	}
}
