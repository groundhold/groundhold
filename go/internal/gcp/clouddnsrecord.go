// GCP Cloud DNS record building (D262): the semantic core of the GCP
// capability.dns.record driver — a SINGLE rrset (name -> value) inside a Cloud DNS
// managed zone, the SAME vocabulary AWS Route 53 record sets and Azure DNS record
// children fulfil. What an org GOVERNS is the record's KIND (dns.type) and where it
// POINTS (dns.target); the TTL and record id are noise. A Cloud DNS rrset carries NO
// labels, so a record's ownership derives from its PARENT ZONE's labels (the managed
// zone is the ownership boundary) — the net shell refuses to touch a record in a
// zone that is not ours. dns.proxied is a Cloudflare edge concept (orange/grey-cloud);
// Cloud DNS resolves straight to origin and has no proxy, so v0 refuses it here (an
// honest one-cloud gap), never fabricating it as a false on observe.
package gcp

import (
	"fmt"
	"strings"
)

// dnsRecordTypeOK is the closed set of record kinds v0 governs. A type outside it is
// refused at build rather than sent — complexity is more records, not a wider grammar.
var dnsRecordTypeOK = map[string]bool{
	"A": true, "AAAA": true, "CNAME": true, "TXT": true,
	"MX": true, "NS": true, "SRV": true, "CAA": true,
}

// CloudDNSRecordPlan is the attribute+impl-derived shape a create assembles into a
// managedZones.changes body (additions/deletions of one rrset).
type CloudDNSRecordPlan struct {
	Zone   string // parent managed-zone resource name (impl operand)
	Name   string // FQDN the rrset lives at (impl identity; trailing dot)
	Type   string // dns.type (governed): A / AAAA / CNAME / TXT / ...
	Target string // dns.target (governed): the record value
}

// BuildCloudDNSRecord maps capability.dns.record attributes + impl to an rrset plan.
// Every error is a preflight refusal, never a silent drop.
func BuildCloudDNSRecord(project, environment, capability string,
	attrs, impl map[string]any, generation int) (CloudDNSRecordPlan, error) {
	p := CloudDNSRecordPlan{}
	for _, path := range sortedKeysG(attrs) {
		raw := attrs[path]
		switch path {
		case "dns.type":
			t, _ := raw.(string)
			t = strings.ToUpper(strings.TrimSpace(t))
			if !dnsRecordTypeOK[t] {
				return CloudDNSRecordPlan{}, fmt.Errorf("dns.type %q is not a record kind Cloud DNS governs in v0", t)
			}
			p.Type = t
		case "dns.target":
			tg, _ := raw.(string)
			tg = strings.TrimSpace(tg)
			if tg == "" {
				return CloudDNSRecordPlan{}, fmt.Errorf("dns.target must be a non-empty value")
			}
			p.Target = tg
		case "dns.proxied":
			return CloudDNSRecordPlan{}, fmt.Errorf(
				"dns.proxied is a Cloudflare edge concept (proxied vs direct-to-origin) — Cloud DNS does " +
					"not proxy and resolves straight to origin, so v0 refuses it rather than pretending " +
					"(a proxy-posture contract belongs on an edge provider)")
		case "service.managed":
			if raw != true {
				return CloudDNSRecordPlan{}, fmt.Errorf("service.managed=false cannot be honored by Cloud DNS")
			}
		default:
			return CloudDNSRecordPlan{}, fmt.Errorf(
				"attribute %s has no Cloud DNS record mapping — refusing rather than silently dropping it", path)
		}
	}
	if p.Type == "" {
		return CloudDNSRecordPlan{}, fmt.Errorf("dns record requires dns.type")
	}
	if p.Target == "" {
		return CloudDNSRecordPlan{}, fmt.Errorf("dns record requires dns.target")
	}
	if !projectOK.MatchString(project) {
		return CloudDNSRecordPlan{}, fmt.Errorf("project %q is invalid", project)
	}
	// zone + name are IDENTITY (the vocab governs type/target, not which record) — impl.
	p.Zone, _ = impl["zone"].(string)
	if !gcpName.MatchString(p.Zone) {
		return CloudDNSRecordPlan{}, fmt.Errorf(
			"a Cloud DNS record requires implementation.zone (the parent managed-zone name)")
	}
	name, _ := impl["record_name"].(string)
	name = strings.ToLower(strings.TrimSpace(name))
	if !dnsDomainOK.MatchString(name) {
		return CloudDNSRecordPlan{}, fmt.Errorf(
			"a Cloud DNS record requires implementation.record_name (the FQDN the rrset lives at)")
	}
	if !strings.HasSuffix(name, ".") {
		name += "." // Cloud DNS rrset names are FQDNs with a trailing dot
	}
	p.Name = name
	return p, nil
}

// rrset is one ResourceRecordSet with a default TTL (TTL is operational noise, not a
// governed fact). TXT values are quoted per the Cloud DNS wire format; other types
// take the raw target.
func (p CloudDNSRecordPlan) rrset() map[string]any {
	value := p.Target
	if p.Type == "TXT" {
		value = `"` + strings.ReplaceAll(p.Target, `"`, `\"`) + `"`
	}
	return map[string]any{
		"name":    p.Name,
		"type":    p.Type,
		"ttl":     300,
		"rrdatas": []any{value},
	}
}

// additionsBody is a managedZones.changes request that ADDS the plan's rrset.
func (p CloudDNSRecordPlan) additionsBody() map[string]any {
	return map[string]any{"additions": []any{p.rrset()}}
}

// deletionsBody is a managedZones.changes request that removes the EXACT current
// rrset (Cloud DNS deletions must match name/type/ttl/rrdatas verbatim).
func deletionsBody(cur dnsRRSet) map[string]any {
	rrdatas := make([]any, len(cur.Rrdatas))
	for i, r := range cur.Rrdatas {
		rrdatas[i] = r
	}
	return map[string]any{"deletions": []any{map[string]any{
		"name":    cur.Name,
		"type":    cur.Type,
		"ttl":     cur.TTL,
		"rrdatas": rrdatas,
	}}}
}
