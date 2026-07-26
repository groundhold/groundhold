// Route 53 record building (D262): the semantic core of the AWS capability.dns.record
// driver — a SINGLE record set (name -> value) inside a hosted zone, the SAME
// vocabulary GCP Cloud DNS rrsets and Azure DNS record children fulfil. What an org
// GOVERNS is the record's KIND (dns.type) and where it POINTS (dns.target); the TTL,
// priority and record id are noise. A Route 53 record set carries NO tags, so a
// record's ownership derives from its PARENT ZONE's tags (the zone is the ownership
// boundary) — the net shell refuses to touch a record in a zone that is not ours.
// dns.proxied is a Cloudflare edge concept (orange/grey-cloud); Route 53 resolves
// straight to origin and has no proxy, so v0 refuses it here (honest one-cloud gap).
package aws

import (
	"fmt"
	"strings"
)

// r53RecordTypeOK is the closed set of record kinds v0 governs. A type outside it is
// refused at build rather than sent — complexity is more records, not a wider grammar.
var r53RecordTypeOK = map[string]bool{
	"A": true, "AAAA": true, "CNAME": true, "TXT": true,
	"MX": true, "NS": true, "SRV": true, "CAA": true,
}

// Route53RecordPlan is the attribute+impl-derived shape a create assembles into a
// ChangeResourceRecordSets (UPSERT) body.
type Route53RecordPlan struct {
	ZoneID string // parent hosted-zone id (impl operand; Z...)
	Name   string // FQDN the record set lives at (impl identity; trailing dot)
	Type   string // dns.type (governed): A / AAAA / CNAME / TXT / ...
	Target string // dns.target (governed): the record value
}

// BuildRoute53Record maps capability.dns.record attributes + impl to a record-set
// plan. Every error is a preflight refusal, never a silent drop.
func BuildRoute53Record(environment, capability string,
	attrs, impl map[string]any, generation int) (Route53RecordPlan, error) {
	p := Route53RecordPlan{}
	for _, path := range sortedKeys(attrs) {
		raw := attrs[path]
		switch path {
		case "dns.type":
			t, _ := raw.(string)
			t = strings.ToUpper(strings.TrimSpace(t))
			if !r53RecordTypeOK[t] {
				return Route53RecordPlan{}, fmt.Errorf("dns.type %q is not a record kind Route 53 governs in v0", t)
			}
			p.Type = t
		case "dns.target":
			tg, _ := raw.(string)
			tg = strings.TrimSpace(tg)
			if tg == "" {
				return Route53RecordPlan{}, fmt.Errorf("dns.target must be a non-empty value")
			}
			p.Target = tg
		case "dns.proxied":
			return Route53RecordPlan{}, fmt.Errorf(
				"dns.proxied is a Cloudflare edge concept (proxied vs direct-to-origin) — Route 53 does " +
					"not proxy and resolves straight to origin, so v0 refuses it rather than pretending " +
					"(a proxy-posture contract belongs on an edge provider)")
		case "service.managed":
			if raw != true {
				return Route53RecordPlan{}, fmt.Errorf("service.managed=false cannot be honored by Route 53")
			}
		default:
			return Route53RecordPlan{}, fmt.Errorf(
				"attribute %s has no Route 53 record mapping — refusing rather than silently dropping it", path)
		}
	}
	if p.Type == "" {
		return Route53RecordPlan{}, fmt.Errorf("dns record requires dns.type")
	}
	if p.Target == "" {
		return Route53RecordPlan{}, fmt.Errorf("dns record requires dns.target")
	}
	// zone + name are IDENTITY (the vocab governs type/target, not which record) — impl.
	p.ZoneID, _ = impl["zone_id"].(string)
	if !hostedZoneIDOK.MatchString(p.ZoneID) {
		return Route53RecordPlan{}, fmt.Errorf(
			"a Route 53 record requires implementation.zone_id (the parent hosted-zone id, Z...)")
	}
	name, _ := impl["record_name"].(string)
	name = strings.ToLower(strings.TrimSpace(name))
	if !r53DomainOK.MatchString(name) {
		return Route53RecordPlan{}, fmt.Errorf(
			"a Route 53 record requires implementation.record_name (the FQDN the record set lives at)")
	}
	if !strings.HasSuffix(name, ".") {
		name += "."
	}
	p.Name = name
	return p, nil
}

// changeXML is a ChangeResourceRecordSets body for the given action (UPSERT / DELETE)
// with a default TTL (TTL is operational noise, not a governed fact). TXT values must
// be quoted per the Route 53 wire format; other types take the raw target.
func (p Route53RecordPlan) changeXML(action string) string {
	value := p.Target
	if p.Type == "TXT" {
		value = `"` + strings.ReplaceAll(p.Target, `"`, `\"`) + `"`
	}
	var b strings.Builder
	b.WriteString(`<ChangeResourceRecordSetsRequest xmlns="https://route53.amazonaws.com/doc/2013-04-01/">`)
	b.WriteString("<ChangeBatch><Changes><Change>")
	b.WriteString("<Action>" + action + "</Action>")
	b.WriteString("<ResourceRecordSet>")
	b.WriteString("<Name>" + xmlEscape(p.Name) + "</Name>")
	b.WriteString("<Type>" + p.Type + "</Type>")
	b.WriteString("<TTL>300</TTL>")
	b.WriteString("<ResourceRecords><ResourceRecord><Value>" + xmlEscape(value) + "</Value></ResourceRecord></ResourceRecords>")
	b.WriteString("</ResourceRecordSet>")
	b.WriteString("</Change></Changes></ChangeBatch>")
	b.WriteString("</ChangeResourceRecordSetsRequest>")
	return b.String()
}
