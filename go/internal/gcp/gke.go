// GKE request building (D76, wave-3 parity): the PURE semantic core of the GCP
// capability.cluster.kubernetes driver — the SAME vocabulary aws.eks fulfils,
// reverse-mapped onto Google Kubernetes Engine primitives (container.googleapis.com,
// projects/{p}/locations/{loc}/clusters). BuildGKE turns capability attributes +
// operator operands (the implementation: block, D26) into the ONE CreateCluster
// body of the composite groundhold OWNS — the CLUSTER plus one autoscaling NODE POOL,
// created together in a single LRO. Everything the cluster stands ON (the VPC
// network, the subnetwork, the CMEK key) is an OPERAND: a separate capability
// supplied by the implementation block, never stood up here (the operand boundary).
// This file is PURE: it validates the shape and REFUSES before any mutation — an
// unmapped capability attribute or a missing required operand is a preflight
// refusal, never a silent drop. The net shell (gke_net.go) drives the plan through
// the container REST API. classifyGKEChange is likewise PURE provider knowledge.
package gcp

import (
	"fmt"
	"regexp"
	"strings"
)

// gkeNameOK bounds a GKE cluster / node-pool name (RFC1035: lowercase alnum +
// hyphen, start with a letter, end alnum, <=40). resourceName already produces a
// hash-tailed lowercase slug starting with a letter, so this is a belt-and-braces
// check before the name enters a REST path (D73 boundary).
var gkeNameOK = regexp.MustCompile(`^[a-z]([a-z0-9-]{0,38}[a-z0-9])?$`)

// gkeRegionOK / gkeZoneOK classify a GKE location string: a REGION
// ("europe-west1") means a regional cluster (control plane in 3 zones, HA); a
// ZONE ("europe-west1-b") means a zonal cluster. The distinction is the observed
// availability.class, and it bounds the location before it is interpolated into a
// REST path.
var gkeRegionOK = regexp.MustCompile(`^[a-z]+-[a-z]+[0-9]+$`)
var gkeZoneOK = regexp.MustCompile(`^[a-z]+-[a-z]+[0-9]+-[a-z]$`)

// gkeRegionOf returns the residency REGION for any location: a zone collapses to
// its region ("europe-west1-b" -> "europe-west1"); a region is itself.
func gkeRegionOf(location string) string {
	if gkeZoneOK.MatchString(location) {
		if i := strings.LastIndexByte(location, '-'); i > 0 {
			return location[:i]
		}
	}
	return location
}

// gkeMinorVersion reduces a GKE master version ("1.29.1-gke.1589020") to the
// governed Kubernetes MINOR version ("1.29") — the vocab's semantic unit
// (cluster.version is "governed for end-of-life/CVE/compliance currency", not a
// patch build). Returns "" if the string carries no major.minor.
func gkeMinorVersion(v string) string {
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

// GKEPlan is the attribute+operand-derived shape a create assembles. The SHAPE
// (version, API exposure, secrets encryption, zonal/regional topology) is driven
// by CAPABILITY attributes; the placement operands (network, subnetwork, CMEK key,
// node-pool sizing) are OPERATOR input from the candidate implementation: block
// (D26) — separate capabilities, never provisioned by this driver.
type GKEPlan struct {
	Name         string // cluster name (deterministic, OR an explicit adopt name — see AdoptByName)
	NodePoolName string // <Name>-np
	Location     string // region (regional) or zone (zonal) — the cluster's location
	Version      string // cluster.version -> initialClusterVersion (required)
	Regional     bool   // availability.class == regional

	// AdoptByName is set when the candidate supplies implementation.clusterName: the
	// plan targets an EXISTING cluster by its real (custom) name instead of the
	// deterministic name. Mirrors AWS EKS D261: a brownfield cluster (gcloud/TF-named)
	// never matches the deterministic name, so without this the create path describes a
	// name that does not exist and stands up a DUPLICATE. When AdoptByName is set,
	// createGKE REFUSES to create if the named cluster is absent (never a duplicate),
	// and the create-only operands (network/subnetwork/CMEK/nodePool/CIDRs) are optional.
	AdoptByName bool

	Exposure              string   // network.apiExposure: public|private|mixed
	EnablePrivateNodes    bool     // private/mixed -> private nodes
	EnablePrivateEndpoint bool     // private -> master reachable only privately
	MasterAuthorizedCidrs []string // operand: authorized CIDRs (required for mixed)

	EncryptSecrets bool // encryption.secrets -> databaseEncryption ENCRYPTED

	// --- operands (implementation: block, D26) ---
	Network     string // required — the VPC network (a separate capability)
	Subnetwork  string // required — the subnetwork (a separate capability)
	KmsKeyName  string // required iff EncryptSecrets (CMEK operand, a REFERENCE)
	MachineType string // node pool (required)
	MinNodes    int    // node pool scaling floor (per zone)
	MaxNodes    int    // node pool scaling ceiling (per zone)
	Autoscaling bool   // node pool autoscaling
}

// BuildGKE maps capability.cluster.kubernetes attributes + implementation operands
// to a plan, or REFUSES. Every error is a preflight refusal (never a half-build):
// an unmapped attribute, an unsupported class (multi-regional), or a missing/invalid
// required operand is refused here, before the first GKE mutation (D26).
func BuildGKE(project, environment, capability string,
	attrs, impl map[string]any, generation int) (GKEPlan, error) {
	if generation < 1 {
		generation = 1
	}
	// leave headroom for the "-np" node-pool suffix under the 40-char GKE limit.
	name := resourceName(project, environment, capability, generation, 34)
	adoptByName := false
	// ADOPT-BY-NAME (mirror AWS EKS D261): an explicit clusterName operand targets an
	// EXISTING custom-named cluster instead of the deterministic name. Present -> adopt
	// that name; absent -> the deterministic greenfield name.
	if explicit := strings.TrimSpace(gkeStr(impl, "clusterName")); explicit != "" {
		name = explicit
		adoptByName = true
	}
	p := GKEPlan{
		Name:         name,
		NodePoolName: name + "-np",
		AdoptByName:  adoptByName,
		Exposure:     "public", // GKE default; overridden by network.apiExposure
		Autoscaling:  true,
		Regional:     true, // safe default: an HA regional control plane
	}
	if !gkeNameOK.MatchString(p.Name) || !gkeNameOK.MatchString(p.NodePoolName) {
		return GKEPlan{}, fmt.Errorf("derived cluster/node-pool name %q/%q is invalid", p.Name, p.NodePoolName)
	}

	region := ""
	availSet := false
	// --- CAPABILITY attributes drive the SHAPE (refuse any unmapped attribute) ---
	for _, path := range sortedKeysG(attrs) {
		raw := attrs[path]
		switch path {
		case "location.region":
			region, _ = raw.(string)
		case "cluster.version":
			v, ok := raw.(string)
			if !ok || strings.TrimSpace(v) == "" {
				return GKEPlan{}, fmt.Errorf("cluster.version must be a non-empty string (e.g. \"1.29\")")
			}
			p.Version = strings.TrimSpace(v)
		case "network.apiExposure":
			s, ok := raw.(string)
			if !ok {
				return GKEPlan{}, fmt.Errorf("network.apiExposure must be a string (public|private|mixed)")
			}
			switch s {
			case "public":
				p.Exposure, p.EnablePrivateNodes, p.EnablePrivateEndpoint = "public", false, false
			case "private":
				p.Exposure, p.EnablePrivateNodes, p.EnablePrivateEndpoint = "private", true, true
			case "mixed":
				p.Exposure, p.EnablePrivateNodes, p.EnablePrivateEndpoint = "mixed", true, false
			default:
				return GKEPlan{}, fmt.Errorf("network.apiExposure %q is not one of public|private|mixed", s)
			}
		case "encryption.secrets":
			b, ok := raw.(bool)
			if !ok {
				return GKEPlan{}, fmt.Errorf("encryption.secrets must be a bool")
			}
			p.EncryptSecrets = b
		case "availability.class":
			s, ok := raw.(string)
			if !ok {
				return GKEPlan{}, fmt.Errorf("availability.class must be a string")
			}
			switch s {
			case "zonal":
				p.Regional = false
			case "regional":
				p.Regional = true
			case "multi-regional":
				return GKEPlan{}, fmt.Errorf(
					"availability.class=multi-regional has no GKE cluster primitive " +
						"(GKE clusters are zonal or regional; cross-region is a fleet/multi-cluster " +
						"topology) — refusing rather than faking it")
			default:
				return GKEPlan{}, fmt.Errorf("availability.class %q has no GKE mapping", s)
			}
			availSet = true
		case "service.managed":
			if raw != true {
				return GKEPlan{}, fmt.Errorf("service.managed=false cannot be honored by GKE (a GKE cluster IS managed by construction)")
			}
		default:
			return GKEPlan{}, fmt.Errorf(
				"attribute %s has no GKE cluster mapping — refusing rather than silently dropping it "+
					"(the cluster.kubernetes vocab governs version + apiExposure + secrets encryption + "+
					"availability topology)", path)
		}
	}
	_ = availSet

	if p.Version == "" {
		return GKEPlan{}, fmt.Errorf("cluster.version is required — refusing to let GKE pick a default Kubernetes version")
	}
	if region == "" {
		return GKEPlan{}, fmt.Errorf("cluster requires location.region (the control plane's region)")
	}
	if !gkeRegionOK.MatchString(region) {
		return GKEPlan{}, fmt.Errorf("location.region %q is not a valid GCP region identifier", region)
	}

	// --- location resolution: regional -> region; zonal -> a zone within it ---
	if p.Regional {
		p.Location = region
	} else {
		zone := strings.TrimSpace(gkeStr(impl, "zone"))
		if zone == "" {
			zone = region + "-a" // deterministic, documented default for a zonal cluster
		}
		if !gkeZoneOK.MatchString(zone) {
			return GKEPlan{}, fmt.Errorf("implementation.zone %q is not a valid GCP zone", zone)
		}
		if !strings.HasPrefix(zone, region+"-") {
			return GKEPlan{}, fmt.Errorf(
				"implementation.zone %q is not within location.region %q — refusing an inconsistent placement", zone, region)
		}
		p.Location = zone
	}

	// The create-only operands (network, subnetwork, CMEK, node pool, authorized
	// CIDRs) build a NEW cluster; when adopting an existing one BY NAME they are
	// unused, so they are optional in that mode (a minimal adopt candidate:
	// clusterName + the governed attributes). A greenfield create still requires them.
	// The governed capability attributes (validated above) stay required either way,
	// and the pid's project/name/location are all resolved before this return.
	if p.AdoptByName {
		if !projectOK.MatchString(project) {
			return GKEPlan{}, fmt.Errorf("project %q is invalid", project)
		}
		return p, nil
	}

	// --- masterAuthorizedCidrs operand: required for mixed, refused for public ---
	p.MasterAuthorizedCidrs = gkeStrs(impl, "masterAuthorizedCidrs")
	switch p.Exposure {
	case "mixed":
		if len(p.MasterAuthorizedCidrs) == 0 {
			return GKEPlan{}, fmt.Errorf(
				"network.apiExposure=mixed requires implementation.masterAuthorizedCidrs (>=1 CIDR) — " +
					"a public endpoint restricted to authorized networks IS the authorized-network set; " +
					"refusing to expose the API server to the whole internet under a \"mixed\" label")
		}
	case "public":
		if len(p.MasterAuthorizedCidrs) > 0 {
			return GKEPlan{}, fmt.Errorf(
				"implementation.masterAuthorizedCidrs was given but network.apiExposure is public — " +
					"authorized networks restrict a public endpoint (that is \"mixed\"); refusing an ambiguous shape")
		}
	}

	// --- CMEK key: REQUIRED iff encryption.secrets (a REFERENCE, never key material, D53) ---
	p.KmsKeyName = strings.TrimSpace(gkeStr(impl, "kmsKeyName"))
	if p.EncryptSecrets && p.KmsKeyName == "" {
		return GKEPlan{}, fmt.Errorf(
			"encryption.secrets=true requires implementation.kmsKeyName (a Cloud KMS key) for " +
				"application-layer secrets encryption — refusing to claim secrets encryption with no key")
	}
	if !p.EncryptSecrets && p.KmsKeyName != "" {
		return GKEPlan{}, fmt.Errorf(
			"implementation.kmsKeyName was given but encryption.secrets is not true — " +
				"a key only attaches to secrets encryption; refusing an ambiguous shape")
	}

	// --- placement operands (network + subnetwork are separate capabilities) ---
	if p.Network = strings.TrimSpace(gkeStr(impl, "network")); p.Network == "" {
		return GKEPlan{}, fmt.Errorf("implementation.network is required (the VPC network — a separate capability/operand)")
	}
	if p.Subnetwork = strings.TrimSpace(gkeStr(impl, "subnetwork")); p.Subnetwork == "" {
		return GKEPlan{}, fmt.Errorf("implementation.subnetwork is required (the subnetwork — a separate capability/operand)")
	}

	// --- node pool operand (required) ---
	np, ok := impl["nodePool"].(map[string]any)
	if !ok {
		return GKEPlan{}, fmt.Errorf("implementation.nodePool is required (the node pool: machineType, minNodes, maxNodes, autoscaling)")
	}
	if p.MachineType = strings.TrimSpace(gkeStr(np, "machineType")); p.MachineType == "" {
		return GKEPlan{}, fmt.Errorf("implementation.nodePool.machineType is required")
	}
	var okMin, okMax bool
	p.MinNodes, okMin = gkeInt(np, "minNodes")
	p.MaxNodes, okMax = gkeInt(np, "maxNodes")
	if !okMin || !okMax {
		return GKEPlan{}, fmt.Errorf("implementation.nodePool requires integer minNodes and maxNodes")
	}
	if as, has := np["autoscaling"]; has {
		b, ok := as.(bool)
		if !ok {
			return GKEPlan{}, fmt.Errorf("implementation.nodePool.autoscaling must be a bool")
		}
		p.Autoscaling = b
	}
	if p.MinNodes < 0 || p.MaxNodes < 1 || p.MinNodes > p.MaxNodes {
		return GKEPlan{}, fmt.Errorf(
			"implementation.nodePool sizing is inconsistent (need 0<=minNodes<=maxNodes, maxNodes>=1): min=%d max=%d",
			p.MinNodes, p.MaxNodes)
	}
	if !projectOK.MatchString(project) {
		return GKEPlan{}, fmt.Errorf("project %q is invalid", project)
	}
	return p, nil
}

// createClusterBody is the CreateCluster request body ({"cluster": {...}}): name,
// version, network/subnetwork, one autoscaling node pool, the private-cluster /
// authorized-networks config derived from apiExposure, the optional CMEK
// databaseEncryption (only when asked), and the ownership resourceLabels. Cited:
// container v1 projects.locations.clusters.create.
func (p GKEPlan) createClusterBody(capability, environment string) map[string]any {
	node := map[string]any{
		"name":             p.NodePoolName,
		"initialNodeCount": p.MinNodes,
		"config":           map[string]any{"machineType": p.MachineType},
	}
	if p.Autoscaling {
		node["autoscaling"] = map[string]any{
			"enabled":      true,
			"minNodeCount": p.MinNodes,
			"maxNodeCount": p.MaxNodes,
		}
	}
	cluster := map[string]any{
		"name":                  p.Name,
		"initialClusterVersion": p.Version,
		"network":               p.Network,
		"subnetwork":            p.Subnetwork,
		"nodePools":             []any{node},
		"resourceLabels": map[string]any{
			"groundhold-capability":  sanitizeLabel(capability),
			"groundhold-environment": sanitizeLabel(environment),
		},
	}
	if p.EnablePrivateNodes || p.EnablePrivateEndpoint {
		cluster["privateClusterConfig"] = map[string]any{
			"enablePrivateNodes":    p.EnablePrivateNodes,
			"enablePrivateEndpoint": p.EnablePrivateEndpoint,
		}
	}
	if len(p.MasterAuthorizedCidrs) > 0 {
		cluster["masterAuthorizedNetworksConfig"] = gkeAuthorizedNetworks(p.MasterAuthorizedCidrs)
	}
	if p.EncryptSecrets {
		cluster["databaseEncryption"] = map[string]any{
			"state":   "ENCRYPTED",
			"keyName": p.KmsKeyName,
		}
	}
	return map[string]any{"cluster": cluster}
}

// gkeAuthorizedNetworks builds a masterAuthorizedNetworksConfig from a CIDR list.
func gkeAuthorizedNetworks(cidrs []string) map[string]any {
	blocks := make([]any, 0, len(cidrs))
	for _, c := range cidrs {
		blocks = append(blocks, map[string]any{"cidrBlock": c})
	}
	return map[string]any{"enabled": true, "cidrBlocks": blocks}
}

// classifyGKEChange (D46): PURE — can a capability.cluster.kubernetes transition be
// honored in place on GKE? cluster.version is an in-place control-plane upgrade
// (update desiredMasterVersion, an LRO); network.apiExposure is an in-place update
// of the authorized-networks / private-endpoint config. encryption.secrets,
// availability.class and residency are NOT patched in this slice — an honest
// "unsupported"/"immutable", never a silent claim of mutability and never a REPLACE
// of a stateful cluster.
func classifyGKEChange(path string) (string, string) {
	switch path {
	case "cluster.version":
		return "mutable", "in-place via clusters.update desiredMasterVersion (a long-running control-plane upgrade)"
	case "network.apiExposure":
		return "mutable", "in-place via clusters.update (master authorized networks / private endpoint config)"
	case "encryption.secrets":
		return "unsupported", "in-place toggle of application-layer secrets encryption is not wired for GKE in this slice — groundhold will not replace a stateful cluster"
	case "availability.class":
		return "immutable", "a GKE cluster's zonal/regional topology is fixed at creation (the location IS the topology) — a change is a replacement, and groundhold will not replace a stateful cluster"
	case "location.region":
		return "immutable", "region is create-time only on a GKE cluster"
	case "service.managed":
		return "unsupported", "platform/projection property — nothing to patch"
	default:
		return "unsupported", "no GKE cluster in-place mapping for " + path
	}
}

// gkeStr reads a string operand; a non-string or absent key yields "".
func gkeStr(m map[string]any, key string) string {
	if s, ok := m[key].(string); ok {
		return s
	}
	return ""
}

// gkeStrs reads a []string operand, accepting []any (JSON-decoded candidate) or
// []string. Non-string elements are skipped.
func gkeStrs(m map[string]any, key string) []string {
	switch v := m[key].(type) {
	case []string:
		return v
	case []any:
		out := make([]string, 0, len(v))
		for _, e := range v {
			if s, ok := e.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

// gkeInt reads an integer operand, accepting the float64 a JSON decoder produces,
// a plain int, or an integer-valued string. ok=false when absent or non-integral.
func gkeInt(m map[string]any, key string) (int, bool) {
	switch v := m[key].(type) {
	case float64:
		if v != float64(int64(v)) {
			return 0, false
		}
		return int(v), true
	case int:
		return v, true
	case int64:
		return int(v), true
	}
	return 0, false
}
