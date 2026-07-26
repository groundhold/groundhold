package cloudflare

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"

	"groundhold/internal/provider"
)

// List enumerates existing Cloudflare DNS records as capability.dns.record — the
// cloudflare half of the gentle crawl (D141). Strictly read-only. Cloudflare is not
// region-scoped: the ZONE is the crawlable axis, so `region` is an OPTIONAL zone-name
// FILTER (like upstash's region filter), never a refused scope. Empty = every zone
// on the account; a non-empty region keeps only the zone whose name matches.
//
// The sweep is two-level: GET /zones (paginated) then GET /zones/{id}/dns_records
// (paginated) per zone. Each zone's record sweep is isolated: a zone whose records
// cannot be listed becomes a diagnostic, never a hard failure that hides the rest
// (D44 — a partial crawl is a fact, never a silently short list).
func (d *Driver) List(region string) ([]provider.Discovered, []string, error) {
	if !d.hasToken() {
		return nil, nil, fmt.Errorf("cloudflare discovery requires CLOUDFLARE_API_TOKEN in the environment")
	}
	zones, err := d.listZones()
	if err != nil {
		return nil, nil, fmt.Errorf("zones.list: %v", err)
	}
	var out []provider.Discovered
	var diags []string
	for _, z := range zones {
		if region != "" && z.Name != region {
			continue // another zone — not this filtered sweep
		}
		records, err := d.listRecords(z.ID)
		if err != nil {
			diags = append(diags, fmt.Sprintf("%s: dns_records.list: %v", z.Name, err))
			continue
		}
		for _, rec := range records {
			if rec.ID == "" {
				continue
			}
			out = append(out, provider.Discovered{
				ProviderID:   d.recordProviderID(z.ID, rec.ID),
				ResourceType: "capability.dns.record",
				Observations: mapRecord(rec),
			})
		}
	}
	return out, diags, nil
}

// zone is the subset of a /zones item we read: identity + the name (the filter axis).
type zone struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// dnsRecord is the subset of a /dns_records item we reverse-map. `content` is the
// TARGET (Cloudflare's term). TTL, priority, comment, tags, timestamps are the
// vocab's deliberately-absent noise — never requested into the mapping.
type dnsRecord struct {
	ID      string `json:"id"`
	Type    string `json:"type"`    // A, AAAA, CNAME, TXT, MX, ...
	Name    string `json:"name"`    // the record name (identity, not mapped)
	Content string `json:"content"` // the target value
	Proxied bool   `json:"proxied"` // orange-cloud (edge) vs grey-cloud (direct)
}

// mapRecord is the PURE reverse-map (no I/O) from a Cloudflare DNS record to the
// capability.dns.record attributes it can honestly measure — the same mapping both
// Observe and List use. Every observation is `measured` (read from the live API).
//
//	dns.type      <- type    (the record's kind)
//	dns.target    <- content (where the name points — the correctness fact)
//	dns.proxied   <- proxied (edge/WAF on vs direct-to-origin; the exposure posture)
//	service.managed = true   (a managed cloud DNS record)
//
// TTL / priority / record id / zone metadata are dropped per the vocab's absent
// list. `proxied` is always present on the API item (false for non-proxiable
// TXT/MX), so reporting it is a measurement, not a guess.
func mapRecord(rec dnsRecord) []provider.Observation {
	return []provider.Observation{
		{Path: "dns.type", Value: rec.Type, Derivation: "measured"},
		{Path: "dns.target", Value: rec.Content, Derivation: "measured"},
		{Path: "dns.proxied", Value: rec.Proxied, Derivation: "measured"},
		{Path: "service.managed", Value: true, Derivation: "measured"},
	}
}

// recordProviderID pins the identity: dns:<zoneId>:<recordId>. Cloudflare zone and
// record ids are 32-hex, globally unique and colon-free, so the zone id disambiguates
// records across zones without needing the account/scope in the identity.
func (d *Driver) recordProviderID(zoneID, recordID string) string {
	return fmt.Sprintf("dns:%s:%s", zoneID, recordID)
}

// listZones fetches every zone, following result_info pagination.
func (d *Driver) listZones() ([]zone, error) {
	var zones []zone
	pages, err := d.getPages("/zones", nil)
	if err != nil {
		return nil, err
	}
	for _, body := range pages {
		var doc struct {
			Result []zone `json:"result"`
		}
		if json.Unmarshal(body, &doc) != nil {
			return nil, fmt.Errorf("unreadable zones page")
		}
		zones = append(zones, doc.Result...)
	}
	return zones, nil
}

// listRecords fetches every DNS record in a zone, following result_info pagination.
func (d *Driver) listRecords(zoneID string) ([]dnsRecord, error) {
	var recs []dnsRecord
	pages, err := d.getPages("/zones/"+zoneID+"/dns_records", nil)
	if err != nil {
		return nil, err
	}
	for _, body := range pages {
		var doc struct {
			Result []dnsRecord `json:"result"`
		}
		if json.Unmarshal(body, &doc) != nil {
			return nil, fmt.Errorf("unreadable dns_records page")
		}
		recs = append(recs, doc.Result...)
	}
	return recs, nil
}

// getPages fetches path following Cloudflare's result_info pagination
// (page / total_pages), returning each page's raw body. Following pagination is
// load-bearing for honesty: a silently truncated list is exactly what the gentle
// crawl forbids. A 429 becomes a retryable error (the pace scheduler backs off),
// never a hard stop; success:false is an error, never treated as an empty list.
func (d *Driver) getPages(path string, _ url.Values) ([][]byte, error) {
	var pages [][]byte
	page := 1
	for {
		st, body, err := d.get(fmt.Sprintf("%s?page=%d&per_page=100", path, page))
		if err != nil {
			return nil, err
		}
		switch st {
		case http.StatusOK:
			// fall through
		case http.StatusTooManyRequests:
			return nil, fmt.Errorf("HTTP 429 rate limited (retryable)")
		default:
			return nil, fmt.Errorf("HTTP %d", st)
		}
		var meta struct {
			Success    bool `json:"success"`
			ResultInfo struct {
				Page       int `json:"page"`
				TotalPages int `json:"total_pages"`
			} `json:"result_info"`
		}
		if json.Unmarshal(body, &meta) != nil {
			return nil, fmt.Errorf("unreadable pagination envelope")
		}
		if !meta.Success {
			return nil, fmt.Errorf("cloudflare response success=false")
		}
		pages = append(pages, body)
		if meta.ResultInfo.TotalPages <= page || meta.ResultInfo.TotalPages == 0 {
			return pages, nil
		}
		page++
	}
}
