// Azure Kubernetes Service request building (D76 wave-3 parity): the PURE semantic
// core of the Azure capability.cluster.kubernetes driver — the SAME vocabulary
// aws.eks and gcp.gke fulfil, reverse-mapped onto AKS primitives
// (Microsoft.ContainerService/managedClusters, ARM). BuildAKS turns capability
// attributes + operator operands (the implementation: block, D26) into the ONE
// managedClusters PUT body of the composite groundhold OWNS — the CLUSTER plus one
// system agent pool, created together in a single LRO. Everything the cluster
// stands ON (the resource group, the CMEK key in Key Vault, the user-assigned
// identity) is an OPERAND: a separate capability supplied by the implementation
// block, never stood up here (the operand boundary, D26). This file is PURE: it
// validates the shape and REFUSES before any mutation — an unmapped capability
// attribute, an unsupported class (multi-regional) or a missing required operand is
// a preflight refusal, never a silent drop. The net shell (aks_net.go) drives the
// plan through ARM. classifyAKSChange is likewise PURE provider knowledge.
package azure

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// aksNameOK bounds a managed-cluster name (ARM: alphanumeric, underscore, hyphen,
// 1-63, start/end alphanumeric). azResourceName already produces a lowercase
// hash-tailed slug; this is the belt-and-braces check before the name enters an ARM
// path (the D73 injection boundary).
var aksNameOK = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_-]{0,61}[a-zA-Z0-9]$`)

// aksDNSPrefixOK bounds a dnsPrefix (alphanumeric + hyphen, start/end alphanumeric,
// 1-54) before it enters the create body.
var aksDNSPrefixOK = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9-]{0,52}[a-zA-Z0-9]$`)

// aksAgentPoolName is the single system pool name. AKS pool names are 1-12 lowercase
// alphanumeric, starting with a letter — a fixed, deterministic name is enough (the
// pool is recovered from the cluster, not addressed independently).
const aksAgentPoolName = "systempool"

// aksMinorVersion reduces an AKS kubernetesVersion ("1.29.2") to the governed
// Kubernetes MINOR version ("1.29") — the vocab's semantic unit (cluster.version is
// governed for end-of-life/CVE currency, not a patch build). "" if it carries no
// major.minor.
func aksMinorVersion(v string) string {
	v = strings.TrimSpace(v)
	if v == "" {
		return ""
	}
	parts := strings.SplitN(v, ".", 3)
	if len(parts) < 2 {
		return ""
	}
	major, minor := strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1])
	if major == "" || minor == "" {
		return ""
	}
	return major + "." + minor
}

// AKSPlan is the attribute+operand-derived shape a create assembles. The SHAPE
// (version, API-server exposure, secrets/KMS encryption, zonal/regional topology)
// is driven by CAPABILITY attributes; the placement operands (CMEK key, identity,
// node-pool sizing) are OPERATOR input from the candidate implementation: block
// (D26) — separate capabilities, never provisioned by this driver.
type AKSPlan struct {
	Name      string // deterministic cluster name (OR an explicit adopt name — see AdoptByName)
	Region    string // location.region -> managed cluster location
	Version   string // cluster.version -> kubernetesVersion (required)
	DNSPrefix string // operand (defaults to the cluster name)
	Regional  bool   // availability.class == regional (3-zone spread)

	// AdoptByName is set when the candidate supplies implementation.clusterName: the
	// plan targets an EXISTING cluster by its real (custom) name instead of the
	// deterministic pv-aks-<hash>. D261 (mirrors AWS EKS): a brownfield cluster
	// (az/TF-named, e.g. "acme") never matches the deterministic name, so without this
	// the create path targets a name that does not exist. An AKS PUT is create-OR-UPDATE
	// (upsert), so falling through to it at an adoption name would stand up a DUPLICATE.
	// When AdoptByName is set, createAKS REFUSES to PUT if the named cluster is absent
	// (never a duplicate), and the create-only operands (dnsPrefix/ranges/CMEK/identity/
	// nodePool) are optional (a minimal adopt candidate: clusterName + version + region).
	AdoptByName bool

	Exposure           string   // network.apiExposure: public|private|mixed
	EnablePrivate      bool     // private -> enablePrivateCluster
	AuthorizedIPRanges []string // operand: required for mixed, refused otherwise

	EncryptSecrets bool   // encryption.secrets -> azureKeyVaultKms
	KmsKeyID       string // required iff EncryptSecrets (a Key Vault key id REFERENCE)

	// --- node pool operand (implementation: block, D26) ---
	VMSize      string // required
	Count       int    // node count (autoscaling floor when autoscaling)
	MinCount    int    // scaling floor
	MaxCount    int    // scaling ceiling
	Autoscaling bool

	// --- identity operand ---
	IdentityType   string // SystemAssigned (default) | UserAssigned
	UserAssignedID string // required iff IdentityType == UserAssigned (an ARM id REFERENCE)
}

// BuildAKS maps capability.cluster.kubernetes attributes + implementation operands
// to a plan, or REFUSES. Every error is a preflight refusal (never a half-build):
// an unmapped attribute, an unsupported class (multi-regional), or a missing/invalid
// required operand is refused here, before the first AKS mutation (invariant #4, D26).
func BuildAKS(environment, capability string,
	attrs, impl map[string]any, generation int) (AKSPlan, error) {
	if generation < 1 {
		generation = 1
	}
	p := AKSPlan{
		Name:         azResourceName("pv-aks", environment, capability, generation),
		Exposure:     "public", // AKS default; overridden by network.apiExposure
		Autoscaling:  true,
		Regional:     true, // safe default: a 3-zone (regional-HA) node pool
		IdentityType: "SystemAssigned",
	}
	// D261: an explicit clusterName operand targets an EXISTING custom-named cluster
	// (mirror the AWS EKS adopt-by-name path). Present -> adopt that name; absent -> the
	// deterministic greenfield name.
	if explicit := strings.TrimSpace(azStr(impl, "clusterName")); explicit != "" {
		p.Name = explicit
		p.AdoptByName = true
	}
	if !aksNameOK.MatchString(p.Name) {
		return AKSPlan{}, fmt.Errorf("derived cluster name %q is invalid", p.Name)
	}

	paths := make([]string, 0, len(attrs))
	for k := range attrs {
		paths = append(paths, k)
	}
	sort.Strings(paths)

	// --- CAPABILITY attributes drive the SHAPE (refuse any unmapped attribute) ---
	for _, path := range paths {
		raw := attrs[path]
		switch path {
		case "location.region":
			p.Region, _ = raw.(string)
		case "cluster.version":
			v, ok := raw.(string)
			if !ok || strings.TrimSpace(v) == "" {
				return AKSPlan{}, fmt.Errorf("cluster.version must be a non-empty string (e.g. \"1.29\")")
			}
			p.Version = strings.TrimSpace(v)
		case "network.apiExposure":
			s, ok := raw.(string)
			if !ok {
				return AKSPlan{}, fmt.Errorf("network.apiExposure must be a string (public|private|mixed)")
			}
			switch s {
			case "public":
				p.Exposure, p.EnablePrivate = "public", false
			case "private":
				p.Exposure, p.EnablePrivate = "private", true
			case "mixed":
				p.Exposure, p.EnablePrivate = "mixed", false
			default:
				return AKSPlan{}, fmt.Errorf("network.apiExposure %q is not one of public|private|mixed", s)
			}
		case "encryption.secrets":
			b, ok := raw.(bool)
			if !ok {
				return AKSPlan{}, fmt.Errorf("encryption.secrets must be a bool")
			}
			p.EncryptSecrets = b
		case "availability.class":
			s, ok := raw.(string)
			if !ok {
				return AKSPlan{}, fmt.Errorf("availability.class must be a string")
			}
			switch s {
			case "zonal":
				p.Regional = false
			case "regional":
				p.Regional = true
			case "multi-regional":
				return AKSPlan{}, fmt.Errorf(
					"availability.class=multi-regional has no AKS cluster primitive " +
						"(an AKS cluster is single-region; cross-region is a fleet/multi-cluster " +
						"topology) — refusing rather than faking it")
			default:
				return AKSPlan{}, fmt.Errorf("availability.class %q has no AKS mapping", s)
			}
		case "service.managed":
			if raw != true {
				return AKSPlan{}, fmt.Errorf("service.managed=false cannot be honored by AKS (an AKS cluster IS managed by construction)")
			}
		default:
			return AKSPlan{}, fmt.Errorf(
				"attribute %s has no AKS cluster mapping — refusing rather than silently dropping it "+
					"(the cluster.kubernetes vocab governs version + apiExposure + secrets encryption + "+
					"availability topology)", path)
		}
	}

	if p.Version == "" {
		return AKSPlan{}, fmt.Errorf("cluster.version is required — refusing to let AKS pick a default Kubernetes version")
	}
	if strings.TrimSpace(p.Region) == "" {
		return AKSPlan{}, fmt.Errorf("cluster requires location.region (the managed cluster's location)")
	}

	// The create-only operands (dnsPrefix, authorizedIPRanges, CMEK key, identity, node
	// pool) build a NEW cluster; when adopting an existing one by name they are unused,
	// so they are optional in that mode (a minimal adopt candidate: clusterName + version
	// + region). A greenfield create still requires them all.
	if p.AdoptByName {
		return p, nil
	}

	// --- dnsPrefix operand (defaults to the deterministic cluster name) ---
	p.DNSPrefix = strings.TrimSpace(azStr(impl, "dnsPrefix"))
	if p.DNSPrefix == "" {
		p.DNSPrefix = p.Name
	}
	if !aksDNSPrefixOK.MatchString(p.DNSPrefix) {
		return AKSPlan{}, fmt.Errorf("implementation.dnsPrefix %q is not a valid AKS dnsPrefix", p.DNSPrefix)
	}

	// --- authorizedIPRanges operand: required for mixed, refused otherwise ---
	p.AuthorizedIPRanges = toStringSlice(impl["authorizedIPRanges"])
	switch p.Exposure {
	case "mixed":
		if len(p.AuthorizedIPRanges) == 0 {
			return AKSPlan{}, fmt.Errorf(
				"network.apiExposure=mixed requires implementation.authorizedIPRanges (>=1 CIDR) — " +
					"a public API server restricted to authorized ranges IS the authorized-range set; " +
					"refusing to expose the API server to the whole internet under a \"mixed\" label")
		}
	default:
		if len(p.AuthorizedIPRanges) > 0 {
			return AKSPlan{}, fmt.Errorf(
				"implementation.authorizedIPRanges was given but network.apiExposure is %q — "+
					"authorized ranges restrict a public API server (that is \"mixed\"); refusing an ambiguous shape", p.Exposure)
		}
	}

	// --- CMEK key: REQUIRED iff encryption.secrets (a REFERENCE, never key material, D53) ---
	p.KmsKeyID = strings.TrimSpace(azStr(impl, "kmsKeyId"))
	if p.EncryptSecrets && p.KmsKeyID == "" {
		return AKSPlan{}, fmt.Errorf(
			"encryption.secrets=true requires implementation.kmsKeyId (a Key Vault key id) for " +
				"KMS etcd encryption (azureKeyVaultKms) — refusing to claim secrets encryption with no key")
	}
	if !p.EncryptSecrets && p.KmsKeyID != "" {
		return AKSPlan{}, fmt.Errorf(
			"implementation.kmsKeyId was given but encryption.secrets is not true — " +
				"a key only attaches to secrets encryption; refusing an ambiguous shape")
	}

	// --- identity operand (systemAssigned default; userAssigned needs an id) ---
	if idt := strings.TrimSpace(azStr(impl, "identity")); idt != "" {
		switch strings.ToLower(idt) {
		case "systemassigned":
			p.IdentityType = "SystemAssigned"
		case "userassigned":
			p.IdentityType = "UserAssigned"
			p.UserAssignedID = strings.TrimSpace(azStr(impl, "userAssignedIdentityId"))
			if p.UserAssignedID == "" {
				return AKSPlan{}, fmt.Errorf(
					"implementation.identity=userAssigned requires implementation.userAssignedIdentityId " +
						"(the user-assigned identity ARM id — a separate capability/operand)")
			}
		default:
			return AKSPlan{}, fmt.Errorf("implementation.identity %q is not one of systemAssigned|userAssigned", idt)
		}
	}

	// --- node pool operand (required) ---
	np, ok := impl["nodePool"].(map[string]any)
	if !ok {
		return AKSPlan{}, fmt.Errorf("implementation.nodePool is required (the node pool: vmSize, count, min, max, enableAutoScaling)")
	}
	if p.VMSize = strings.TrimSpace(azStr(np, "vmSize")); p.VMSize == "" {
		return AKSPlan{}, fmt.Errorf("implementation.nodePool.vmSize is required")
	}
	cnt, okCnt := asInt64(np["count"])
	if !okCnt {
		return AKSPlan{}, fmt.Errorf("implementation.nodePool requires an integer count")
	}
	p.Count = int(cnt)
	if as, has := np["enableAutoScaling"]; has {
		b, ok := as.(bool)
		if !ok {
			return AKSPlan{}, fmt.Errorf("implementation.nodePool.enableAutoScaling must be a bool")
		}
		p.Autoscaling = b
	}
	if p.Autoscaling {
		mn, okMin := asInt64(np["min"])
		mx, okMax := asInt64(np["max"])
		if !okMin || !okMax {
			return AKSPlan{}, fmt.Errorf("implementation.nodePool requires integer min and max when enableAutoScaling")
		}
		p.MinCount, p.MaxCount = int(mn), int(mx)
		if p.MinCount < 1 || p.MaxCount < p.MinCount {
			return AKSPlan{}, fmt.Errorf(
				"implementation.nodePool sizing is inconsistent (need 1<=min<=max): min=%d max=%d", p.MinCount, p.MaxCount)
		}
		if p.Count < p.MinCount || p.Count > p.MaxCount {
			return AKSPlan{}, fmt.Errorf(
				"implementation.nodePool.count %d is outside [min=%d,max=%d]", p.Count, p.MinCount, p.MaxCount)
		}
	} else if p.Count < 1 {
		return AKSPlan{}, fmt.Errorf("implementation.nodePool.count must be >=1")
	}
	return p, nil
}

// aksZones returns the node pool's availabilityZones for the topology: a regional
// (HA) cluster spreads across all three zones; a zonal cluster omits zones.
func (p AKSPlan) aksZones() []any {
	if p.Regional {
		return []any{"1", "2", "3"}
	}
	return nil
}

// createBody is the managedClusters PUT body: location, identity, ownership tags,
// and the properties (kubernetesVersion, dnsPrefix, one system agent pool, the
// apiServerAccessProfile derived from apiExposure, the optional azureKeyVaultKms
// securityProfile only when asked). Cited: Microsoft.ContainerService/managedClusters.
func (p AKSPlan) createBody(tags map[string]any) map[string]any {
	pool := map[string]any{
		"name":              aksAgentPoolName,
		"mode":              "System",
		"vmSize":            p.VMSize,
		"count":             p.Count,
		"enableAutoScaling": p.Autoscaling,
		"type":              "VirtualMachineScaleSets",
	}
	if p.Autoscaling {
		pool["minCount"] = p.MinCount
		pool["maxCount"] = p.MaxCount
	}
	if z := p.aksZones(); z != nil {
		pool["availabilityZones"] = z
	}
	props := map[string]any{
		"kubernetesVersion": p.Version,
		"dnsPrefix":         p.DNSPrefix,
		"agentPoolProfiles": []any{pool},
	}
	if ap := p.apiServerAccessProfile(); ap != nil {
		props["apiServerAccessProfile"] = ap
	}
	if p.EncryptSecrets {
		props["securityProfile"] = map[string]any{
			"azureKeyVaultKms": map[string]any{
				"enabled":               true,
				"keyId":                 p.KmsKeyID,
				"keyVaultNetworkAccess": "Public",
			},
		}
	}
	return map[string]any{
		"location":   p.Region,
		"tags":       tags,
		"identity":   p.identityBlock(),
		"properties": props,
	}
}

// apiServerAccessProfile maps the network.apiExposure enum to the AKS profile:
// private -> enablePrivateCluster; mixed -> a public API server restricted to the
// authorized IP ranges; public -> no profile (the AKS default, unrestricted).
func (p AKSPlan) apiServerAccessProfile() map[string]any {
	switch p.Exposure {
	case "private":
		return map[string]any{"enablePrivateCluster": true}
	case "mixed":
		ranges := make([]any, 0, len(p.AuthorizedIPRanges))
		for _, r := range p.AuthorizedIPRanges {
			ranges = append(ranges, r)
		}
		return map[string]any{"enablePrivateCluster": false, "authorizedIPRanges": ranges}
	}
	return nil
}

// identityBlock builds the managed-identity block (SystemAssigned by default, or a
// UserAssigned identity by ARM id).
func (p AKSPlan) identityBlock() map[string]any {
	if p.IdentityType == "UserAssigned" {
		return map[string]any{
			"type":                   "UserAssigned",
			"userAssignedIdentities": map[string]any{p.UserAssignedID: map[string]any{}},
		}
	}
	return map[string]any{"type": "SystemAssigned"}
}

// classifyAKSChange (D46): PURE — can a capability.cluster.kubernetes transition be
// honored in place on AKS? cluster.version is an in-place control-plane upgrade (PUT
// kubernetesVersion, an LRO — az aks upgrade); network.apiExposure is in-place for
// the authorized-IP-range set (public<->mixed) but the private/public conversion is
// create-time only (enablePrivateCluster is immutable) — the updater guards that
// honestly. encryption.secrets, availability.class and residency are NOT patched in
// this slice — an honest "unsupported"/"immutable", never a silent claim of
// mutability and never a REPLACE of a stateful cluster.
func classifyAKSChange(path string) (string, string) {
	switch path {
	case "cluster.version":
		return "mutable", "in-place via managedClusters PUT kubernetesVersion (a long-running control-plane upgrade)"
	case "network.apiExposure":
		return "mutable", "in-place via managedClusters PUT authorizedIPRanges (public<->mixed); a public<->private conversion is create-time only (enablePrivateCluster is immutable) and is refused, never replaced"
	case "encryption.secrets":
		return "unsupported", "in-place toggle of KMS etcd (secrets) encryption is not wired for AKS in this slice — groundhold will not replace a stateful cluster"
	case "availability.class":
		return "immutable", "an AKS node pool's zone spread is fixed at creation (the zones ARE the topology) — a change is a replacement, and groundhold will not replace a stateful cluster"
	case "location.region":
		return "immutable", "region is create-time only on an AKS cluster"
	case "service.managed":
		return "unsupported", "platform/projection property — nothing to patch"
	default:
		return "unsupported", "no AKS cluster in-place mapping for " + path
	}
}

// azStr reads a string operand; a non-string or absent key yields "".
func azStr(m map[string]any, key string) string {
	if s, ok := m[key].(string); ok {
		return s
	}
	return ""
}
