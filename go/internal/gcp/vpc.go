// VPC request building (D83): the semantic core of the fourth GCP service
// (Compute Engine private networking, capability.network.private), same pure/
// golden pattern as Cloud SQL/Run/GCS. TWO differences the authoring battery
// warns about: (1) a private network is MULTI-RESOURCE — one capability maps to
// a VPC network + a regional subnetwork + (optionally) a default-deny egress
// firewall, with the network as the primary resource (the providerId); (2) VPC
// networks/subnets/firewalls do NOT support labels, so ownership rides in the
// network DESCRIPTION marker plus the deterministic name, not the label
// discipline the other drivers use. CIDR ranges, subnet names and route tables
// are implementation noise (the vocab says so); the capability carries only
// isolation/egress/audit/residency semantics.
package gcp

import (
	"fmt"
	"sort"
)

const computeBaseURL = "https://compute.googleapis.com/compute/v1"

// vpcOwnerMarker is the ownership token embedded in the network description —
// VPC resources have no labels, so this + the deterministic name are the proof
// (checked identically on write and read, as sanitizeLabel is for the others).
func vpcOwnerMarker(capability, environment string) string {
	return "groundhold:capability=" + sanitizeLabel(capability) +
		";environment=" + sanitizeLabel(environment)
}

// NetworkName / SubnetName are the deterministic names — the idempotency
// mechanism, as InstanceName/ServiceName/BucketName are for the other services.
func NetworkName(project, environment, capability string, generation int) string {
	return resourceName(project, environment, capability, generation, 63)
}
func SubnetName(project, environment, capability string, generation int) string {
	return resourceName(project, environment, capability+"-subnet", generation, 63)
}
func EgressFirewallName(project, environment, capability string, generation int) string {
	return resourceName(project, environment, capability+"-deny-egress", generation, 63)
}

// RouterName / NATName are the deterministic names for the Cloud NAT road
// (egress.internet=nat). A Cloud NAT is a config nested inside a regional Cloud
// Router — the router is the realization OPERAND (D26) the vocab hides, the same
// way an AWS NAT hides its EIP/IGW/route-table operands. Deterministic names keep
// create idempotent and delete targetable, as for every other VPC resource.
func RouterName(project, environment, capability string, generation int) string {
	return resourceName(project, environment, capability+"-router", generation, 63)
}
func NATName(project, environment, capability string, generation int) string {
	return resourceName(project, environment, capability+"-nat", generation, 63)
}

// VPCPlan is the ORDERED set of requests a private-network create issues. The
// subnetwork and firewall reference the network by its self-link URL, so the
// network must be created first; the shell (slice 2) sequences them and polls
// each global/regional operation.
type VPCPlan struct {
	NetworkName    string
	Network        Request
	Subnet         Request
	NATRouter      *Request // nil unless egress.internet=nat (Cloud Router carrying a Cloud NAT)
	EgressFirewall *Request // nil unless egress.restricted is required
}

// BuildVPCRequests maps capability.network.private to the compute requests.
// Every error is a refusal apply surfaces in preflight, before any mutation.
func BuildVPCRequests(project, environment, capability string,
	attrs, impl map[string]any, generation int) (VPCPlan, error) {
	if generation < 1 {
		generation = 1
	}
	netName := NetworkName(project, environment, capability, generation)
	subName := SubnetName(project, environment, capability, generation)
	networkURL := fmt.Sprintf("%s/projects/%s/global/networks/%s",
		computeBaseURL, project, netName)

	region := ""
	flowLogs := false
	egressRestricted := false
	// egress.internet is the ROAD mode (orthogonal to egress.restricted, which is
	// DESTINATION discipline). Absent => "none" (back-compat: today's isolated VPC).
	egressInternet := "none"
	// serviceAccess.private maps to Private Google Access on the subnet — the ruch
	// to Google APIs stays on the private backbone (the cleanest GCP analog of an
	// AWS VPC endpoint set: PGA turns *.googleapis.com resolution onto private VIPs
	// with no external IP, whereas AWS needs one interface endpoint per service).
	// PGA has ALWAYS been on for this driver, so absent => true (back-compat).
	serviceAccessPrivate := true

	paths := make([]string, 0, len(attrs))
	for p := range attrs {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	for _, path := range paths {
		raw := attrs[path]
		switch path {
		case "location.region":
			region, _ = raw.(string)
		case "ingress.public":
			// a private network's whole point is no public ingress path; a
			// contract REQUIRING public ingress is not this capability.
			if raw == true {
				return VPCPlan{}, fmt.Errorf(
					"ingress.public=true cannot be honored by a private network")
			}
		case "egress.restricted":
			egressRestricted, _ = raw.(bool)
		case "egress.internet":
			// the ROAD mode. nat is this slice (Cloud Router + Cloud NAT);
			// direct is honestly refused — at GCP a workload egresses "directly"
			// by holding an external IP, a per-INSTANCE property this VPC driver
			// does not provision (the default 0/0 route to the internet gateway
			// already exists on a custom-mode network).
			mode, _ := raw.(string)
			switch mode {
			case "none", "nat":
				egressInternet = mode
			case "direct":
				return VPCPlan{}, fmt.Errorf(
					"egress.internet=direct (workloads reaching the internet via their " +
						"own external IPs) is a per-instance property this VPC driver does " +
						"not provision — use nat for outbound-only egress, or none for isolation")
			default:
				return VPCPlan{}, fmt.Errorf(
					"egress.internet=%q is not a known road (want none|nat|direct)", mode)
			}
		case "serviceAccess.private":
			b, ok := raw.(bool)
			if !ok {
				return VPCPlan{}, fmt.Errorf(
					"serviceAccess.private must be a bool, got %T", raw)
			}
			serviceAccessPrivate = b
		case "flowLogs.enabled":
			flowLogs, _ = raw.(bool)
		case "interconnect.private":
			if raw == true {
				return VPCPlan{}, fmt.Errorf(
					"interconnect.private is not expressible in v0.1 — it needs " +
						"Cloud VPN/Interconnect attachments (a later slice)")
			}
		case "availability.class":
			// A GCP subnetwork is REGIONAL by construction — it spans every zone
			// in the region, so a regional (multi-zone) network is satisfied
			// natively with no extra resource. A zonal-only network is not
			// honestly expressible on GCP; refuse rather than fake it.
			if c, _ := raw.(string); c != "regional" {
				return VPCPlan{}, fmt.Errorf(
					"availability.class=%q is not expressible on GCP — a subnetwork is "+
						"regional (spans all zones in the region); use regional", c)
			}
		case "service.managed":
			if raw != true {
				return VPCPlan{}, fmt.Errorf(
					"service.managed=false cannot be honored by GCP VPC")
			}
		default:
			return VPCPlan{}, fmt.Errorf(
				"attribute %s has no GCP VPC mapping — refusing rather than "+
					"silently dropping it", path)
		}
	}
	if region == "" {
		return VPCPlan{}, fmt.Errorf(
			"capability.network.private requires location.region (the subnet region)")
	}
	// region is interpolated into the subnetwork REST path — charset-validate it
	// in the builder before it reaches a URL (D73 boundary / authoring battery).
	if !gcpName.MatchString(region) {
		return VPCPlan{}, fmt.Errorf(
			"location.region %q is not a valid GCP region identifier", region)
	}
	// egress.restricted and egress.internet are ORTHOGONAL axes, but a default-deny
	// egress firewall (egress.restricted) would drop the very traffic a NAT road
	// carries — the NAT would sit there carrying nothing. Refuse the contradiction
	// rather than build a road that a sibling firewall silently strangles (symmetric
	// with the AWS VPC cross-check of the two egress axes).
	if egressRestricted && egressInternet != "none" {
		return VPCPlan{}, fmt.Errorf(
			"egress.restricted=true installs a default-deny egress firewall that would "+
				"block the egress.internet=%s road (the Cloud NAT would carry no traffic) — "+
				"these conflict; use egress.internet=none with a restricted road, or lift "+
				"the restriction to keep the NAT road", egressInternet)
	}

	// CIDR is implementation noise (the vocab excludes it) — take it from the
	// implementation block, default a private RFC1918 /20.
	cidr, _ := impl["cidr"].(string)
	if cidr == "" {
		cidr = "10.0.0.0/20"
	}

	marker := vpcOwnerMarker(capability, environment)
	plan := VPCPlan{NetworkName: netName}
	plan.Network = Request{
		Method: "POST",
		URL:    fmt.Sprintf("%s/projects/%s/global/networks", computeBaseURL, project),
		Body: map[string]any{
			"name":                  netName,
			"description":           marker,
			"autoCreateSubnetworks": false, // custom mode: no default-allow, no default subnets
			"routingConfig":         map[string]any{"routingMode": "REGIONAL"},
		},
	}
	plan.Subnet = Request{
		Method: "POST",
		URL: fmt.Sprintf("%s/projects/%s/regions/%s/subnetworks",
			computeBaseURL, project, region),
		Body: map[string]any{
			"name":                  subName,
			"description":           marker,
			"network":               networkURL,
			"region":                region,
			"ipCidrRange":           cidr,
			"privateIpGoogleAccess": serviceAccessPrivate, // serviceAccess.private (default on, back-compat)
			"logConfig":             map[string]any{"enable": flowLogs},
		},
	}
	// egress.internet=nat: a regional Cloud Router carrying a Cloud NAT. The NAT is
	// nested in the router (natIpAllocateOption=AUTO_ONLY,
	// sourceSubnetworkIpRangesToNat=ALL_SUBNETWORKS_ALL_IP_RANGES) so every subnet
	// in the network egresses outbound-only — workloads with no external IP reach
	// the internet, but the internet cannot reach them (ingress.public stays false,
	// the same posture the AWS NAT road yields).
	if egressInternet == "nat" {
		r := Request{
			Method: "POST",
			URL: fmt.Sprintf("%s/projects/%s/regions/%s/routers",
				computeBaseURL, project, region),
			Body: map[string]any{
				"name":        RouterName(project, environment, capability, generation),
				"description": marker,
				"network":     networkURL,
				"region":      region,
				"nats": []any{map[string]any{
					"name":                          NATName(project, environment, capability, generation),
					"natIpAllocateOption":           "AUTO_ONLY",
					"sourceSubnetworkIpRangesToNat": "ALL_SUBNETWORKS_ALL_IP_RANGES",
				}},
			},
		}
		plan.NATRouter = &r
	}
	if egressRestricted {
		// default-deny egress at the lowest usable priority — explicit allows
		// (a later slice / impl) sit above it. A private network with restricted
		// egress starts closed.
		fw := Request{
			Method: "POST",
			URL:    fmt.Sprintf("%s/projects/%s/global/firewalls", computeBaseURL, project),
			Body: map[string]any{
				"name":              EgressFirewallName(project, environment, capability, generation),
				"description":       marker,
				"network":           networkURL,
				"direction":         "EGRESS",
				"priority":          65534,
				"destinationRanges": []any{"0.0.0.0/0"},
				"denied":            []any{map[string]any{"IPProtocol": "all"}},
			},
		}
		plan.EgressFirewall = &fw
	}
	return plan, nil
}
