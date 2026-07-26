// AWS VPN Gateway request building (D126): the semantic core of the AWS
// capability.vpn.gateway driver. A virtual private gateway (VGW) is a single EC2
// resource with a server-assigned id (vgw-xxx), created via the EC2 Query protocol
// (reusing the network.private driver's ec2PostBase/ec2TagParams). The gateway itself
// is thin — the tunnels, BGP and pre-shared key live on a separate VpnConnection and
// are opaque impl / secrets (D53). ip.stack=dual-stack is REFUSED: a VGW is IPv4-only
// at the gateway level. Ownership is tags applied at birth via TagSpecification.
package aws

import "fmt"

// VpnGatewayPlan is the attribute-derived shape a create assembles.
type VpnGatewayPlan struct {
	Region string
	Tags   map[string]string
}

// BuildVpnGateway maps capability.vpn.gateway attributes + impl to a plan. Every
// error is a preflight refusal, never a silent drop.
func BuildVpnGateway(environment, capability string,
	attrs, impl map[string]any, generation int) (VpnGatewayPlan, error) {
	p := VpnGatewayPlan{
		Tags: map[string]string{
			"groundhold-capability":  sanitizeTag(capability),
			"groundhold-environment": sanitizeTag(environment),
		},
	}
	for _, path := range sortedKeys(attrs) {
		raw := attrs[path]
		switch path {
		case "location.region":
			p.Region, _ = raw.(string)
		case "ip.stack":
			s, _ := raw.(string)
			switch s {
			case "ipv4":
				// the only stack an AWS virtual private gateway terminates
			case "dual-stack":
				return VpnGatewayPlan{}, fmt.Errorf(
					"ip.stack=dual-stack cannot be honored on AWS — a virtual private gateway is " +
						"IPv4-only at the gateway level (IPv6 over a VPN is a per-connection concern)")
			default:
				return VpnGatewayPlan{}, fmt.Errorf("ip.stack %q is not a recognized value", s)
			}
		case "service.managed":
			if raw != true {
				return VpnGatewayPlan{}, fmt.Errorf("service.managed=false cannot be honored by a VPN gateway")
			}
		default:
			return VpnGatewayPlan{}, fmt.Errorf(
				"attribute %s has no VPN gateway mapping — refusing rather than silently dropping it "+
					"(tunnels, BGP, the pre-shared key are opaque impl / secrets)", path)
		}
	}
	if !regionOK.MatchString(p.Region) {
		return VpnGatewayPlan{}, fmt.Errorf("capability.vpn.gateway requires a valid location.region")
	}
	return p, nil
}

// createParams is the CreateVpnGateway Query-protocol parameter map (Type is fixed;
// no AmazonSideAsn — the BGP ASN is opaque tunnel config).
func (p VpnGatewayPlan) createParams() map[string]string {
	params := map[string]string{
		"Action":  "CreateVpnGateway",
		"Version": ec2Version,
		"Type":    "ipsec.1",
	}
	for k, v := range ec2TagParams("vpn-gateway", p.Tags) {
		params[k] = v
	}
	return params
}
