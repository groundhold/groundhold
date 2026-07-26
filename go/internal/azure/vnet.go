// Azure VNet request building (D99): the semantic core of the Azure
// network.private driver — the SAME capability.network.private vocabulary the AWS
// VPC and GCP Compute VPC fulfil. The binding is one virtualNetworks resource with
// an INLINE subnet, plus a constitutive NSG (created first, referenced by the
// subnet) — one binding, the ECS/pubsub-queue composite precedent. Refusals mirror
// the other clouds: public ingress is refused, interconnect.private is refused, and
// flowLogs is refused on Azure because it is a subscription-level Network Watcher
// resource that also needs a storage account — an attribute adding two resources,
// one subscription-scoped, which the one-binding rule forbids.
package azure

import (
	"fmt"
	"sort"
)

// pinned ARM api-versions (per-resource-type — Azure's one drift surface per type).
const (
	networkAPIVersion = "2023-11-01"
)

// VNetPlan is the attribute-derived, provider-agnostic shape a create assembles
// into ARM bodies. The pure builder decides honor-or-refuse; the shell (vnet_net)
// assembles the NSG + VNet JSON and issues the calls.
type VNetPlan struct {
	Name             string
	Region           string
	Environment      string
	Capability       string
	EgressRestricted bool     // -> NSG DenyAllOutbound + subnet defaultOutboundAccess=false
	EgressInternet   string   // "none" | "nat" | "direct" — the egress ROAD (D26 operands hidden). Absent => "none".
	ServiceAccess    bool     // serviceAccess.private: keep provider-API traffic on the Azure backbone via subnet service endpoints
	ServiceEndpoints []string // the service-endpoint set to realize (canonical, or impl["service_endpoints"] override)
}

// defaultVNetServiceEndpoints is the canonical private-service-access set: the
// Azure service-endpoint analog of the AWS VPC-endpoint set. A service endpoint
// keeps traffic to that Azure service's public endpoint on the Microsoft backbone
// (no public-internet hop), the cleanest analog of AWS interface endpoints / GCP
// Private Google Access — and, unlike per-target Private Endpoints (one private IP
// + private-DNS zone per resource), it is a pure subnet property (no extra
// resources), so it stays inside the one-binding rule. WHICH services is a
// realization OPERAND (D26); operators override via implementation.service_endpoints.
var defaultVNetServiceEndpoints = []string{
	"Microsoft.CognitiveServices", "Microsoft.ContainerRegistry", "Microsoft.KeyVault",
	"Microsoft.ServiceBus", "Microsoft.Sql", "Microsoft.Storage",
}

// missingServiceEndpoints returns the required services absent from observed (the
// ⊇ gap — the observe side of serviceAccess.private).
func missingServiceEndpoints(required []string, observed map[string]bool) []string {
	var missing []string
	for _, s := range required {
		if !observed[s] {
			missing = append(missing, s)
		}
	}
	return missing
}

// vnetName is the deterministic name (azNameOK-bounded), the idempotency handle.
func vnetName(environment, capability string, generation int) string {
	return azResourceName("pv-net", environment, capability, generation)
}

// BuildVNet maps capability.network.private attributes to a VNet plan. Every error
// is a refusal apply surfaces in preflight, before any mutation.
func BuildVNet(environment, capability string,
	attrs, impl map[string]any, generation int) (VNetPlan, error) {
	if generation < 1 {
		generation = 1
	}
	p := VNetPlan{Environment: environment, Capability: capability, EgressInternet: "none"}

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
		case "ingress.public":
			if raw == true {
				return VNetPlan{}, fmt.Errorf(
					"ingress.public=true cannot be honored: an Azure VNet has no " +
						"internet-gateway concept — a fresh VNet is private by " +
						"construction; refusing rather than faking a public path")
			}
		case "egress.restricted":
			// DESTINATION discipline (an NSG deny-outbound), NOT the road. Cross-
			// checked against egress.internet after the loop (the two axes conflict
			// only when a restricted NSG would strangle a NAT road).
			b, ok := raw.(bool)
			if !ok {
				return VNetPlan{}, fmt.Errorf("egress.restricted must be a bool, got %T", raw)
			}
			p.EgressRestricted = b
		case "egress.internet":
			// the ROAD mode. Absent => "none" (back-compat: today's isolated VNet).
			// nat = a NAT Gateway (Microsoft.Network/natGateways) with a public IP,
			// associated with the subnet (outbound-only; the internet cannot reach
			// in, so ingress.public stays false — the posture the AWS/GCP NAT roads
			// yield). direct is honestly refused: at Azure a workload egresses
			// "directly" by holding a per-instance/per-NIC public IP, which is not a
			// VNet-layer property this driver provisions.
			mode, _ := raw.(string)
			switch mode {
			case "none", "nat":
				p.EgressInternet = mode
			case "direct":
				return VNetPlan{}, fmt.Errorf(
					"egress.internet=direct (workloads reaching the internet via their " +
						"own per-instance public IPs) is not a VNet-layer property this " +
						"driver provisions — use nat for outbound-only egress, or none for isolation")
			default:
				return VNetPlan{}, fmt.Errorf(
					"egress.internet=%q is not a known road (want none|nat|direct)", mode)
			}
		case "serviceAccess.private":
			// keep provider-API traffic on the Azure backbone via subnet service
			// endpoints. =false is the default posture (none); =true realizes the set.
			b, ok := raw.(bool)
			if !ok {
				return VNetPlan{}, fmt.Errorf("serviceAccess.private must be a bool, got %T", raw)
			}
			p.ServiceAccess = b
		case "flowLogs.enabled":
			if raw == true {
				return VNetPlan{}, fmt.Errorf(
					"flowLogs.enabled is not honored on Azure: VNet flow logs are a " +
						"networkWatchers/flowLogs resource on a SUBSCRIPTION-level Network " +
						"Watcher singleton AND require a storage account destination — an " +
						"attribute that would add two resources (one subscription-scoped); " +
						"refusing rather than smuggling in hidden infrastructure")
			}
		case "interconnect.private":
			return VNetPlan{}, fmt.Errorf(
				"interconnect.private is not modeled (topology, not capability " +
					"semantics) — refused on every provider")
		case "availability.class":
			// An Azure subnet is region-wide; availability-zone placement is a
			// per-RESOURCE choice, not a subnet property. A regional (multi-zone)
			// network is therefore satisfied natively; a zonal-only network is not
			// expressible at the VNet layer — refuse rather than fake it.
			if c, _ := raw.(string); c != "regional" {
				return VNetPlan{}, fmt.Errorf(
					"availability.class=%q is not expressible on Azure — a subnet is "+
						"region-wide and zone choice is per-resource; use regional", c)
			}
		case "service.managed":
			if raw != true {
				return VNetPlan{}, fmt.Errorf("service.managed=false cannot be honored by Azure VNet")
			}
		default:
			return VNetPlan{}, fmt.Errorf(
				"attribute %s has no Azure VNet mapping — refusing rather than "+
					"silently dropping it", path)
		}
	}
	if p.Region == "" {
		return VNetPlan{}, fmt.Errorf("azure vnet requires location.region")
	}
	// egress.restricted and egress.internet are ORTHOGONAL axes, but a restricted
	// NSG (DenyInternetOutbound) would drop the very traffic a NAT road carries —
	// the NAT Gateway would sit there carrying nothing. Refuse the contradiction
	// rather than build a road a sibling NSG silently strangles (symmetric with the
	// AWS/GCP VPC cross-check of the two egress axes).
	if p.EgressRestricted && p.EgressInternet != "none" {
		return VNetPlan{}, fmt.Errorf(
			"egress.restricted=true installs an NSG that denies internet-bound outbound, "+
				"which would block the egress.internet=%s road (the NAT Gateway would carry "+
				"no traffic) — these conflict; use egress.internet=none with a restricted "+
				"road, or lift the restriction to keep the NAT road", p.EgressInternet)
	}
	// serviceAccess.private endpoint set: the canonical set, unless the operator
	// declares a bespoke one via implementation.service_endpoints (a list of Azure
	// service tokens, e.g. ["Microsoft.Storage","Microsoft.KeyVault"]). WHICH
	// endpoints is a realization OPERAND (D26), not the semantic.
	if p.ServiceAccess {
		p.ServiceEndpoints = append([]string(nil), defaultVNetServiceEndpoints...)
		if raw, ok := impl["service_endpoints"]; ok {
			list, ok := raw.([]any)
			if !ok {
				return VNetPlan{}, fmt.Errorf(
					"implementation.service_endpoints must be a list of Azure service tokens (e.g. [\"Microsoft.Storage\",\"Microsoft.Sql\"])")
			}
			var svcs []string
			for _, e := range list {
				s, ok := e.(string)
				if !ok || s == "" {
					return VNetPlan{}, fmt.Errorf("implementation.service_endpoints entries must be non-empty strings")
				}
				svcs = append(svcs, s)
			}
			if len(svcs) == 0 {
				return VNetPlan{}, fmt.Errorf("implementation.service_endpoints, if set, must be non-empty")
			}
			sort.Strings(svcs)
			p.ServiceEndpoints = svcs
		}
	}
	p.Name = vnetName(environment, capability, generation)
	return p, nil
}
