// Cloud VPN request building (D126): the semantic core of the GCP
// capability.vpn.gateway driver. An HA VPN GATEWAY is a single regional compute
// resource (vpnGateways.insert, an LRO). It has no labels, so ownership rides in the
// DESCRIPTION marker (reusing the D82 VPC marker helpers). The gateway is thin — the
// vpnTunnels, the Cloud Router/BGP session and the pre-shared key are opaque impl /
// secrets (D53). ip.stack maps to stackType; both stacks are honored on GCP. The
// gateway is created INTO a network, so implementation.network is a required substrate.
package gcp

import (
	"fmt"
	"strings"
)

// CloudVPNPlan is the attribute-derived shape a create assembles.
type CloudVPNPlan struct {
	Name        string
	Region      string
	Description string // ownership marker
	StackType   string // IPV4_ONLY | IPV4_IPV6
	Network     string // impl substrate (the VPC self-link/name)
}

// BuildCloudVPNGateway maps capability.vpn.gateway attributes + impl to a plan. Every
// error is a preflight refusal, never a silent drop.
func BuildCloudVPNGateway(project, environment, capability string,
	attrs, impl map[string]any, generation int) (CloudVPNPlan, error) {
	if generation < 1 {
		generation = 1
	}
	p := CloudVPNPlan{
		Name:        resourceName(project, environment, capability, generation, 63),
		Description: vpcOwnerMarker(capability, environment),
		StackType:   "IPV4_ONLY",
	}
	for _, path := range sortedKeysG(attrs) {
		raw := attrs[path]
		switch path {
		case "location.region":
			p.Region, _ = raw.(string)
		case "ip.stack":
			s, _ := raw.(string)
			switch s {
			case "ipv4":
				p.StackType = "IPV4_ONLY"
			case "dual-stack":
				p.StackType = "IPV4_IPV6"
			default:
				return CloudVPNPlan{}, fmt.Errorf("ip.stack %q is not a recognized value", s)
			}
		case "service.managed":
			if raw != true {
				return CloudVPNPlan{}, fmt.Errorf("service.managed=false cannot be honored by Cloud VPN")
			}
		default:
			return CloudVPNPlan{}, fmt.Errorf(
				"attribute %s has no Cloud VPN mapping — refusing rather than silently dropping it "+
					"(tunnels, BGP, the pre-shared key are opaque impl / secrets)", path)
		}
	}
	if p.Region == "" {
		return CloudVPNPlan{}, fmt.Errorf("capability.vpn.gateway requires location.region (the gateway region)")
	}
	p.Network, _ = impl["network"].(string)
	if p.Network == "" {
		return CloudVPNPlan{}, fmt.Errorf(
			"Cloud VPN requires implementation.network (the VPC the HA VPN gateway is created into — " +
				"an impl substrate, like the tunnels and Cloud Router it will need)")
	}
	if !gcpName.MatchString(p.Name) {
		return CloudVPNPlan{}, fmt.Errorf("derived gateway name %q is invalid", p.Name)
	}
	return p, nil
}

// insertBody is the vpnGateways.insert request body (region is in the URL path).
func (p CloudVPNPlan) insertBody() map[string]any {
	network := p.Network
	if !strings.Contains(network, "/") {
		network = "global/networks/" + network // a bare name -> a project-relative ref
	}
	return map[string]any{
		"name":        p.Name,
		"description": p.Description,
		"network":     network,
		"stackType":   p.StackType,
	}
}
