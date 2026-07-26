// GCP Cloud DNS request building (D101): the semantic core of the GCP
// capability.dns.zone driver — the SAME vocabulary AWS Route 53 and Azure DNS
// fulfil. groundhold provisions the ZONE (its domain, public/private reach, DNSSEC
// state); the RECORDS are data supplied out of band and are never touched here.
// Managed-zone create is SYNCHRONOUS (no LRO). Two honest boundaries: DNSSEC
// applies to PUBLIC zones only (a private zone cannot be internet-signed), and a
// private zone's network associations are topology carried under implementation.
package gcp

import (
	"fmt"
	"regexp"
	"strings"
)

const cloudDNSBaseURL = "https://dns.googleapis.com/dns/v1"

// dnsDomainOK bounds a zone's DNS name (lowercase labels + a TLD) before it is
// interpolated into a request body (D73 boundary). A trailing dot is optional on
// input; the builder normalizes to the FQDN form Cloud DNS requires.
var dnsDomainOK = regexp.MustCompile(`^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}\.?$`)

// DNSZonePlan is the attribute-derived shape a create assembles.
type DNSZonePlan struct {
	Name     string // the deterministic managed-zone resource name
	DNSName  string // the FQDN (trailing dot), e.g. example.com.
	Public   bool
	DNSSEC   bool
	Networks []string // private-zone VPC self-links (impl); empty = none
}

// BuildCloudDNSZone maps capability.dns.zone attributes + impl to a managed-zone
// plan. Every error is a preflight refusal, never a silent drop.
func BuildCloudDNSZone(project, environment, capability string,
	attrs, impl map[string]any, generation int) (DNSZonePlan, error) {
	p := DNSZonePlan{Name: resourceName(project, environment, capability, generation, 63)}
	for _, path := range sortedKeysG(attrs) {
		raw := attrs[path]
		switch path {
		case "zone.domain":
			dom, _ := raw.(string)
			dom = strings.ToLower(strings.TrimSpace(dom))
			if !dnsDomainOK.MatchString(dom) {
				return DNSZonePlan{}, fmt.Errorf("zone.domain %q is not a valid DNS name", dom)
			}
			if !strings.HasSuffix(dom, ".") {
				dom += "." // Cloud DNS requires the FQDN trailing dot
			}
			p.DNSName = dom
		case "network.publicExposure":
			p.Public, _ = raw.(bool)
		case "dnssec.enabled":
			p.DNSSEC, _ = raw.(bool)
		case "service.managed":
			if raw != true {
				return DNSZonePlan{}, fmt.Errorf("service.managed=false cannot be honored by Cloud DNS")
			}
		default:
			return DNSZonePlan{}, fmt.Errorf(
				"attribute %s has no Cloud DNS mapping — refusing rather than silently dropping it "+
					"(records are data supplied out of band, never a zone attribute)", path)
		}
	}
	if p.DNSName == "" {
		return DNSZonePlan{}, fmt.Errorf("dns zone requires zone.domain")
	}
	if p.DNSSEC && !p.Public {
		return DNSZonePlan{}, fmt.Errorf(
			"dnssec.enabled=true cannot be honored on a PRIVATE zone — DNSSEC signs public " +
				"internet resolution; a private zone has no signed delegation path — refusing")
	}
	if !projectOK.MatchString(project) {
		return DNSZonePlan{}, fmt.Errorf("project %q is invalid", project)
	}
	// a private zone's network associations are topology (impl), never a
	// capability path; accept a list of VPC self-links if provided.
	if !p.Public {
		if nets, ok := impl["networks"].([]any); ok {
			for _, n := range nets {
				if s, ok := n.(string); ok && s != "" {
					p.Networks = append(p.Networks, s)
				}
			}
		}
	}
	return p, nil
}

// createBody is the managedZones.create request body. Ownership is labels.
func (p DNSZonePlan) createBody(capability, environment string) map[string]any {
	visibility := "private"
	if p.Public {
		visibility = "public"
	}
	body := map[string]any{
		"name":        p.Name,
		"dnsName":     p.DNSName,
		"description": "groundhold-managed zone",
		"visibility":  visibility,
		"labels": map[string]any{
			"groundhold-capability":  sanitizeLabel(capability),
			"groundhold-environment": sanitizeLabel(environment),
		},
	}
	if p.Public {
		state := "off"
		if p.DNSSEC {
			state = "on"
		}
		body["dnssecConfig"] = map[string]any{"state": state}
	} else {
		nets := make([]any, 0, len(p.Networks))
		for _, n := range p.Networks {
			nets = append(nets, map[string]any{"networkUrl": n})
		}
		body["privateVisibilityConfig"] = map[string]any{"networks": nets}
	}
	return body
}
