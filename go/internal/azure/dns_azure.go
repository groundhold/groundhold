// Azure DNS request building (D101): the Azure half of the capability.dns.zone
// driver — the SAME vocabulary GCP Cloud DNS and AWS Route 53 fulfil. The sharp
// asymmetry Azure brings: network.publicExposure selects a different ARM RESOURCE
// TYPE, not a flag — Microsoft.Network/dnsZones for a public zone,
// Microsoft.Network/privateDnsZones for a private one (each with its own API
// version). The zone RESOURCE NAME is the domain itself. The RECORDS are data, out
// of band, never touched. DNSSEC signing is a separate dnssecConfigs enablement (a
// child resource), so v0 refuses it — an honest gap, the same stance as Route 53.
package azure

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// dnsZones (public) and privateDnsZones carry different API versions.
const (
	publicDNSAPIVersion  = "2018-05-01"
	privateDNSAPIVersion = "2020-06-01"
)

// azDNSDomainOK bounds a DNS zone name (lowercase labels + a TLD, NO trailing dot —
// Azure uses the bare domain as the resource name) before it is interpolated into
// an ARM path (D73 boundary).
var azDNSDomainOK = regexp.MustCompile(`^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$`)

// AzureDNSPlan is the attribute-derived shape a create assembles.
type AzureDNSPlan struct {
	Domain string // the zone resource name (bare domain, no trailing dot)
	Public bool   // selects dnsZones vs privateDnsZones
}

// BuildAzureDNS maps capability.dns.zone attributes to an Azure DNS plan. Every
// error is a preflight refusal, never a silent drop.
func BuildAzureDNS(environment, capability string,
	attrs, impl map[string]any, generation int) (AzureDNSPlan, error) {
	p := AzureDNSPlan{}
	paths := make([]string, 0, len(attrs))
	for k := range attrs {
		paths = append(paths, k)
	}
	sort.Strings(paths)

	for _, path := range paths {
		raw := attrs[path]
		switch path {
		case "zone.domain":
			dom, _ := raw.(string)
			dom = strings.ToLower(strings.TrimSpace(strings.TrimSuffix(dom, ".")))
			if !azDNSDomainOK.MatchString(dom) {
				return AzureDNSPlan{}, fmt.Errorf("zone.domain %q is not a valid DNS name", dom)
			}
			p.Domain = dom
		case "network.publicExposure":
			p.Public, _ = raw.(bool)
		case "dnssec.enabled":
			if raw == true {
				return AzureDNSPlan{}, fmt.Errorf(
					"dnssec.enabled=true is not wired for Azure DNS in v0 — Azure DNSSEC signing is a " +
						"separate dnssecConfigs enablement (a child resource), not a zone-create property; " +
						"refusing rather than half-configuring (honest one-cloud gap)")
			}
		case "service.managed":
			if raw != true {
				return AzureDNSPlan{}, fmt.Errorf("service.managed=false cannot be honored by Azure DNS")
			}
		default:
			return AzureDNSPlan{}, fmt.Errorf(
				"attribute %s has no Azure DNS mapping — refusing rather than silently dropping it "+
					"(records are data supplied out of band, never a zone attribute)", path)
		}
	}
	if p.Domain == "" {
		return AzureDNSPlan{}, fmt.Errorf("dns zone requires zone.domain")
	}
	return p, nil
}

// providerPath is the ARM resource path — the TYPE forks on public/private.
func (p AzureDNSPlan) providerPath() string {
	if p.Public {
		return "Microsoft.Network/dnsZones/" + p.Domain
	}
	return "Microsoft.Network/privateDnsZones/" + p.Domain
}

func (p AzureDNSPlan) apiVersion() string {
	if p.Public {
		return publicDNSAPIVersion
	}
	return privateDNSAPIVersion
}

// createBody is the zone PUT body. DNS zones are GLOBAL (location "global"); a
// public zone carries zoneType Public, a private zone needs no zoneType.
func (p AzureDNSPlan) createBody(tags map[string]any) map[string]any {
	body := map[string]any{"location": "global", "tags": tags}
	if p.Public {
		body["properties"] = map[string]any{"zoneType": "Public"}
	}
	return body
}
