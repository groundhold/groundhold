// Route 53 request building (D101): the semantic core of the AWS capability.dns.zone
// driver — the SAME vocabulary GCP Cloud DNS and Azure DNS fulfil. Route 53 is a
// REST-XML, GLOBAL service (SigV4 region us-east-1, no regional endpoint), and its
// hosted-zone Id is SERVER-ASSIGNED (Z...), so — unlike every other AWS driver here
// — the providerId is parsed from the response, not deterministic; a deterministic
// CallerReference is the idempotency key that lets a lost create be recovered. The
// RECORDS are data, out of band, never touched. DNSSEC needs a KMS-backed
// key-signing key + a separate signing ceremony, so v0 refuses it (honest gap).
package aws

import (
	"fmt"
	"regexp"
	"strings"
)

// r53DomainOK bounds a zone's DNS name before it is placed in an XML body.
var r53DomainOK = regexp.MustCompile(`^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}\.?$`)

// hostedZoneIDOK bounds a server-assigned hosted-zone id (Z + uppercase alnum).
var hostedZoneIDOK = regexp.MustCompile(`^Z[A-Z0-9]+$`)

// Route53Plan is the attribute-derived shape a create assembles into an XML body.
type Route53Plan struct {
	DNSName         string // FQDN with trailing dot
	Public          bool
	CallerReference string // deterministic idempotency key
	VPCId           string // private zone (impl); required when private
	VPCRegion       string
}

// BuildRoute53Zone maps capability.dns.zone attributes + impl to a hosted-zone
// plan. Every error is a preflight refusal, never a silent drop.
func BuildRoute53Zone(environment, capability string,
	attrs, impl map[string]any, generation int) (Route53Plan, error) {
	p := Route53Plan{Public: false}
	publicSet := false
	for _, path := range sortedKeys(attrs) {
		raw := attrs[path]
		switch path {
		case "zone.domain":
			dom, _ := raw.(string)
			dom = strings.ToLower(strings.TrimSpace(dom))
			if !r53DomainOK.MatchString(dom) {
				return Route53Plan{}, fmt.Errorf("zone.domain %q is not a valid DNS name", dom)
			}
			if !strings.HasSuffix(dom, ".") {
				dom += "."
			}
			p.DNSName = dom
		case "network.publicExposure":
			p.Public, _ = raw.(bool)
			publicSet = true
		case "dnssec.enabled":
			if raw == true {
				return Route53Plan{}, fmt.Errorf(
					"dnssec.enabled=true is not wired for Route 53 in v0 — Route 53 DNSSEC requires a " +
						"KMS-backed key-signing key and a separate signing enablement; refusing rather " +
						"than half-configuring (honest one-cloud gap)")
			}
		case "service.managed":
			if raw != true {
				return Route53Plan{}, fmt.Errorf("service.managed=false cannot be honored by Route 53")
			}
		default:
			return Route53Plan{}, fmt.Errorf(
				"attribute %s has no Route 53 mapping — refusing rather than silently dropping it "+
					"(records are data supplied out of band, never a zone attribute)", path)
		}
	}
	if p.DNSName == "" {
		return Route53Plan{}, fmt.Errorf("dns zone requires zone.domain")
	}
	_ = publicSet
	// deterministic CallerReference (idempotency key; lets a lost create be found).
	p.CallerReference = "groundhold-" + letterHash(environment+"|"+capability+genSuffix(generation), 20)
	// a private hosted zone MUST be created with an associated VPC (topology, impl).
	if !p.Public {
		p.VPCId, _ = impl["vpc_id"].(string)
		p.VPCRegion, _ = impl["vpc_region"].(string)
		if p.VPCId == "" || p.VPCRegion == "" {
			return Route53Plan{}, fmt.Errorf(
				"a Route 53 PRIVATE hosted zone requires implementation.vpc_id and " +
					"implementation.vpc_region (a private zone is created bound to a VPC)")
		}
	}
	return p, nil
}

// createXML is the CreateHostedZone request body.
func (p Route53Plan) createXML() string {
	var b strings.Builder
	b.WriteString(`<CreateHostedZoneRequest xmlns="https://route53.amazonaws.com/doc/2013-04-01/">`)
	b.WriteString("<Name>" + xmlEscape(p.DNSName) + "</Name>")
	b.WriteString("<CallerReference>" + xmlEscape(p.CallerReference) + "</CallerReference>")
	if !p.Public {
		b.WriteString("<VPC><VPCId>" + xmlEscape(p.VPCId) + "</VPCId>" +
			"<VPCRegion>" + xmlEscape(p.VPCRegion) + "</VPCRegion></VPC>")
	}
	b.WriteString("<HostedZoneConfig><Comment>groundhold-managed zone</Comment>")
	b.WriteString(fmt.Sprintf("<PrivateZone>%t</PrivateZone>", !p.Public))
	b.WriteString("</HostedZoneConfig>")
	b.WriteString("</CreateHostedZoneRequest>")
	return b.String()
}

// tagsXML is the ChangeTagsForResource body adding ownership tags.
func r53TagsXML(capability, environment string) string {
	return `<ChangeTagsForResourceRequest xmlns="https://route53.amazonaws.com/doc/2013-04-01/">` +
		`<AddTags>` +
		`<Tag><Key>groundhold-capability</Key><Value>` + xmlEscape(sanitizeTag(capability)) + `</Value></Tag>` +
		`<Tag><Key>groundhold-environment</Key><Value>` + xmlEscape(sanitizeTag(environment)) + `</Value></Tag>` +
		`</AddTags></ChangeTagsForResourceRequest>`
}

func xmlEscape(s string) string {
	s = strings.ReplaceAll(s, "&", "&amp;")
	s = strings.ReplaceAll(s, "<", "&lt;")
	s = strings.ReplaceAll(s, ">", "&gt;")
	return s
}
