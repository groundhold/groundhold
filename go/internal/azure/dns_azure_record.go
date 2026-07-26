// Azure DNS record building (D262): the Azure half of the capability.dns.record
// driver — the SAME vocabulary AWS Route 53 rrsets and GCP Cloud DNS rrsets fulfil.
// An Azure DNS record set is an ARM CHILD resource under a PUBLIC dnsZone, one
// resource per record TYPE (.../dnsZones/{zone}/{TYPE}/{name}). What an org GOVERNS
// is the record's KIND (dns.type) and where it POINTS (dns.target); the TTL, record
// id and priority are noise. A record set carries NO ownership tags of its own, so a
// record's ownership derives from its PARENT ZONE's tags (the zone is the ownership
// boundary) — the net shell refuses to touch a record in a zone that is not ours.
// dns.proxied is a Cloudflare edge concept (orange/grey-cloud); Azure DNS resolves
// straight to origin and has no proxy, so v0 refuses it here (honest one-cloud gap).
// v0 supports PUBLIC zones only (Microsoft.Network/dnsZones).
package azure

import (
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// azDNSRecordTypeOK is the closed set of record kinds v0 governs. A type outside it
// is refused at build rather than sent — complexity is more records, not a wider
// grammar. The map value is the ARM child-path segment for the type (identical to
// the type name for the kinds Azure exposes).
var azDNSRecordTypeOK = map[string]string{
	"A": "A", "AAAA": "AAAA", "CNAME": "CNAME", "TXT": "TXT", "MX": "MX",
}

// azDNSRecordNameOK bounds a record name (relative to the zone: a label, "@" for the
// apex, "*" for a wildcard, or a dotted subname) before it is interpolated into an
// ARM path (the D73 injection boundary). No slashes, colons or spaces.
var azDNSRecordNameOK = regexp.MustCompile(`^[A-Za-z0-9_@*][A-Za-z0-9_.*-]{0,253}$`)

// AzureDNSRecordPlan is the attribute+impl-derived shape a create assembles into a
// record-set PUT body.
type AzureDNSRecordPlan struct {
	ResourceGroup string // parent zone's resource group (impl identity)
	Zone          string // parent public DNS zone name (impl identity; bare domain)
	Name          string // record name relative to the zone (impl identity)
	Type          string // dns.type (governed): A / AAAA / CNAME / TXT / MX
	Target        string // dns.target (governed): the record value
}

// BuildAzureDNSRecord maps capability.dns.record attributes + impl to a record-set
// plan. Every error is a preflight refusal, never a silent drop.
func BuildAzureDNSRecord(environment, capability string,
	attrs, impl map[string]any, generation int) (AzureDNSRecordPlan, error) {
	p := AzureDNSRecordPlan{}
	paths := make([]string, 0, len(attrs))
	for k := range attrs {
		paths = append(paths, k)
	}
	sort.Strings(paths)

	for _, path := range paths {
		raw := attrs[path]
		switch path {
		case "dns.type":
			t, _ := raw.(string)
			t = strings.ToUpper(strings.TrimSpace(t))
			if _, ok := azDNSRecordTypeOK[t]; !ok {
				return AzureDNSRecordPlan{}, fmt.Errorf("dns.type %q is not a record kind Azure DNS governs in v0", t)
			}
			p.Type = t
		case "dns.target":
			tg, _ := raw.(string)
			tg = strings.TrimSpace(tg)
			if tg == "" {
				return AzureDNSRecordPlan{}, fmt.Errorf("dns.target must be a non-empty value")
			}
			p.Target = tg
		case "dns.proxied":
			return AzureDNSRecordPlan{}, fmt.Errorf(
				"dns.proxied is a Cloudflare edge concept (proxied vs direct-to-origin) — Azure DNS does " +
					"not proxy and resolves straight to origin, so v0 refuses it rather than pretending " +
					"(a proxy-posture contract belongs on an edge provider)")
		case "service.managed":
			if raw != true {
				return AzureDNSRecordPlan{}, fmt.Errorf("service.managed=false cannot be honored by Azure DNS")
			}
		default:
			return AzureDNSRecordPlan{}, fmt.Errorf(
				"attribute %s has no Azure DNS record mapping — refusing rather than silently dropping it", path)
		}
	}
	if p.Type == "" {
		return AzureDNSRecordPlan{}, fmt.Errorf("dns record requires dns.type")
	}
	if p.Target == "" {
		return AzureDNSRecordPlan{}, fmt.Errorf("dns record requires dns.target")
	}
	// zone + name + resource group are IDENTITY (the vocab governs type/target, not
	// which record, in which zone) — impl.
	zone, _ := impl["zone"].(string)
	zone = strings.ToLower(strings.TrimSpace(strings.TrimSuffix(zone, ".")))
	if !azDNSDomainOK.MatchString(zone) {
		return AzureDNSRecordPlan{}, fmt.Errorf(
			"an Azure DNS record requires implementation.zone (the parent public DNS zone name)")
	}
	p.Zone = zone
	rg, _ := impl["resourceGroup"].(string)
	if !rgOK.MatchString(rg) {
		return AzureDNSRecordPlan{}, fmt.Errorf(
			"an Azure DNS record requires implementation.resourceGroup (the parent zone's resource group)")
	}
	p.ResourceGroup = rg
	name, _ := impl["record_name"].(string)
	name = strings.TrimSpace(name)
	if !azDNSRecordNameOK.MatchString(name) {
		return AzureDNSRecordPlan{}, fmt.Errorf(
			"an Azure DNS record requires implementation.record_name (the record name relative to the zone, e.g. www or @)")
	}
	p.Name = name
	return p, nil
}

// classifyAzureDNSRecordChange decides how a drifted attribute reconciles. A record
// set PUT is an idempotent upsert, so REPOINTING a record (changing where it points)
// is an in-place PUT of the new value — never a delete+recreate. The record KIND is
// bound to the ARM child path (.../dnsZones/{zone}/{TYPE}/{name}), so a dns.type
// change is a different resource: immutable, a replacement. Everything else is either
// a Cloudflare edge concept Azure DNS cannot honor or a platform/projection property.
func classifyAzureDNSRecordChange(path string) (string, string) {
	switch path {
	case "dns.target":
		return "mutable", "in-place: a record-set PUT is an idempotent upsert, so repointing replaces the value block"
	case "dns.type":
		return "immutable", "the record kind is the ARM child path (.../{TYPE}/{name}) — a type change is a different record, i.e. a replacement"
	case "dns.proxied":
		return "unsupported", "dns.proxied is a Cloudflare edge concept — Azure DNS resolves straight to origin and has no proxy to patch"
	case "service.managed":
		return "unsupported", "platform/projection property — nothing to patch on the record set"
	default:
		return "unsupported", "no Azure DNS record in-place mapping for " + path
	}
}

// childPath is the ARM child resource path for the record set — a PUBLIC zone's
// record child: Microsoft.Network/dnsZones/{zone}/{TYPE}/{name}.
func (p AzureDNSRecordPlan) childPath() string {
	return "Microsoft.Network/dnsZones/" + p.Zone + "/" + azDNSRecordTypeOK[p.Type] + "/" + p.Name
}

// recordProperties is the type-specific recordset properties block. TTL is
// operational noise (a fixed 300), not a governed fact.
func (p AzureDNSRecordPlan) recordProperties() map[string]any {
	props := map[string]any{"TTL": 300}
	switch p.Type {
	case "A":
		props["ARecords"] = []any{map[string]any{"ipv4Address": p.Target}}
	case "AAAA":
		props["AAAARecords"] = []any{map[string]any{"ipv6Address": p.Target}}
	case "CNAME":
		props["CNAMERecord"] = map[string]any{"cname": p.Target}
	case "TXT":
		props["TXTRecords"] = []any{map[string]any{"value": []any{p.Target}}}
	case "MX":
		pref, exch := splitMX(p.Target)
		props["MXRecords"] = []any{map[string]any{"preference": pref, "exchange": exch}}
	}
	return props
}

// createBody is the record-set PUT body.
func (p AzureDNSRecordPlan) createBody() map[string]any {
	return map[string]any{"properties": p.recordProperties()}
}

// splitMX parses an "MX" target of the form "<preference> <exchange>" (e.g.
// "10 mail.example.com"). A bare exchange with no preference defaults to 0.
func splitMX(target string) (int, string) {
	fields := strings.Fields(target)
	if len(fields) >= 2 {
		if pref, err := strconv.Atoi(fields[0]); err == nil {
			return pref, strings.Join(fields[1:], " ")
		}
	}
	return 0, target
}
