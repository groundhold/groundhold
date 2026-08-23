// GCP Cloud DNS record network shell (D262): the bearer-signed REST half of the
// capability.dns.record driver. An rrset carries NO labels of its own, so ownership
// is the PARENT ZONE's labels — every mutation first reads the managed zone
// (managedZones.get) and REFUSES a record in a zone that is not ours (the zone is the
// ownership boundary). Within an owned zone a change is safe (we own the whole zone);
// a create whose rrset already exists is idempotent-adopt. The providerId is
// deterministic (project + zone + type + name); no server-assigned id to recover.
package gcp

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"groundhold/internal/provider"
)

func gdnsrecProviderID(project, zone, recordType, name string) string {
	return "gdnsrec:" + project + ":" + zone + ":" + recordType + ":" + name
}

func splitGDNSRecProviderID(providerID string) (project, zone, recordType, name string, err error) {
	parts := strings.SplitN(providerID, ":", 5)
	if len(parts) != 5 || parts[0] != "gdnsrec" {
		return "", "", "", "", fmt.Errorf("providerId %q is not gdnsrec:project:zone:type:name", providerID)
	}
	if !projectOK.MatchString(parts[1]) {
		return "", "", "", "", fmt.Errorf("providerId project %q is invalid", parts[1])
	}
	if !gcpName.MatchString(parts[2]) {
		return "", "", "", "", fmt.Errorf("providerId zone %q is invalid", parts[2])
	}
	if !dnsRecordTypeOK[parts[3]] {
		return "", "", "", "", fmt.Errorf("providerId record type %q is invalid", parts[3])
	}
	if parts[4] == "" {
		return "", "", "", "", fmt.Errorf("providerId record name is empty")
	}
	return parts[1], parts[2], parts[3], parts[4], nil
}

// dnsRRSet is the projection of one ResourceRecordSet the driver reads.
type dnsRRSet struct {
	Name    string   `json:"name"`
	Type    string   `json:"type"`
	TTL     int      `json:"ttl"`
	Rrdatas []string `json:"rrdatas"`
}

// recordZoneOwnedByUs reads the parent managed zone's labels and reports whether
// they are ours. A read that gave no answer is NOT "not ours" (that would fail
// open) — it comes back as an error the caller turns into unknown.
func (d *Driver) recordZoneOwnedByUs(project, zone, capability, environment string) (owned bool, err error) {
	doc, found, rerr := d.getDNSZone(project, zone)
	if rerr != nil {
		return false, rerr
	}
	if !found {
		return false, nil
	}
	return ownsLabels(doc.Labels, capability, environment), nil
}

func (d *Driver) createCloudDNSRecord(environment, capability string,
	attrs, impl map[string]any, generation int) provider.CreateResult {
	plan, err := BuildCloudDNSRecord(d.Project, environment, capability, attrs, impl, generation)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	pid := gdnsrecProviderID(d.Project, plan.Zone, plan.Type, plan.Name)
	// ownership gate: the record lives in a zone; only manage records in OUR zone.
	owned, zerr := d.recordZoneOwnedByUs(d.Project, plan.Zone, capability, environment)
	if zerr != nil {
		return provider.CreateResult{Status: "unknown",
			Reason: "parent managed zone gave no answer — cannot confirm ownership before writing a record; reconcile: " + zerr.Error()}
	}
	if !owned {
		return provider.CreateResult{Status: "failed",
			Reason: "the parent managed zone is not ours (labels do not match) — refusing to write a record into a zone we do not own"}
	}
	changesURL := fmt.Sprintf("%s/projects/%s/managedZones/%s/changes", d.dnsBase(), d.Project, plan.Zone)
	st, body, e := d.call("POST", changesURL, plan.additionsBody())
	switch {
	case e != nil:
		return provider.CreateResult{ProviderID: pid, Status: "unknown",
			Reason: fmt.Sprintf("record change outcome unknown (may have landed): %v", e)}
	case st == http.StatusOK || st == http.StatusCreated:
		return provider.CreateResult{ProviderID: pid, Status: "succeeded"}
	case st == http.StatusConflict:
		// the rrset already exists — we own the zone, so this is an idempotent
		// adopt (bound). observe reports the live target; verify catches any drift.
		return provider.CreateResult{ProviderID: pid, Status: "succeeded"}
	case st >= 500:
		return provider.CreateResult{ProviderID: pid, Status: "unknown",
			Reason: fmt.Sprintf("record change HTTP %d (server error — may have landed) — reconcile", st)}
	default:
		if r := provider.MutationResult(st, gcpErrCode(body), nil, pid, "record change"); r != nil {
			return *r
		}
		return provider.CreateResult{Status: "failed",
			Reason: fmt.Sprintf("record change HTTP %d: %s", st, mutDetail(body))}
	}
}

// getRecordSet finds the single (name,type) rrset in a zone. Returns
// (set, found, readable): a clean list that does not contain the pair is found=false
// (a vanished record, not an error); a transport/HTTP/parse failure is readable=false.
func (d *Driver) getRecordSet(project, zone, name, recordType string) (dnsRRSet, bool, error) {
	const op = "recordSet.get"
	q := url.Values{}
	q.Set("name", name)
	q.Set("type", recordType)
	u := fmt.Sprintf("%s/projects/%s/managedZones/%s/rrsets?%s", d.dnsBase(), project, zone, q.Encode())
	st, body, err := d.call("GET", u, nil)
	if err != nil {
		return dnsRRSet{}, false, readTransport(op, err)
	}
	if st == http.StatusNotFound {
		return dnsRRSet{}, false, nil
	}
	if st != http.StatusOK {
		return dnsRRSet{}, false, readHTTP(op, st, gcpErrCode(body))
	}
	var resp struct {
		Rrsets []dnsRRSet `json:"rrsets"`
	}
	if json.Unmarshal(body, &resp) != nil {
		return dnsRRSet{}, false, readBody(op, st)
	}
	// accept only an EXACT name+type match (a filtered list may still echo siblings).
	for _, s := range resp.Rrsets {
		if strings.EqualFold(strings.TrimSuffix(s.Name, "."), strings.TrimSuffix(name, ".")) && s.Type == recordType {
			return s, true, nil
		}
	}
	return dnsRRSet{}, false, nil
}

// rrsetTarget reads the first rrdata, unquoting a TXT payload back to the raw target
// the contract declares.
// rrsetTarget returns the record set's FIRST value and how many it has (D1237 — the
// count is what lets the caller disclose what a single-string attribute cannot hold).
func rrsetTarget(s dnsRRSet) (string, int) {
	if len(s.Rrdatas) == 0 {
		return "", 0
	}
	v := s.Rrdatas[0]
	if s.Type == "TXT" {
		v = strings.TrimSuffix(strings.TrimPrefix(v, `"`), `"`)
		v = strings.ReplaceAll(v, `\"`, `"`)
	}
	return v, len(s.Rrdatas)
}

func (d *Driver) observeCloudDNSRecord(capability, providerID string) ([]provider.Observation, []string, error) {
	project, zone, recordType, name, err := splitGDNSRecProviderID(providerID)
	if err != nil {
		return nil, nil, err
	}
	if err := d.sameProject(project); err != nil {
		return nil, nil, err
	}
	s, found, rerr := d.getRecordSet(project, zone, name, recordType)
	if rerr != nil {
		return nil, nil, rerr
	}
	if !found {
		// F-LC3 (D519): a BOUND resource the API authoritatively 404s is GONE.
		// A diagnostic alone leaves the binding a no-op forever (D513).
		return []provider.Observation{
			{Path: provider.ResourceAbsentPath, Value: true, Derivation: "measured"},
		}, []string{"record set not found — bound resource is gone (will re-create)"}, nil
	}
	obs := []provider.Observation{
		// Present: clear the marker (F-LC3), or a stale "gone" survives a re-create.
		{Path: provider.ResourceAbsentPath, Value: false, Derivation: "measured"},
		{Path: "dns.type", Value: recordType, Derivation: "measured"},
		{Path: "service.managed", Value: true, Derivation: "measured"},
	}
	var diags []string
	if tgt, n := rrsetTarget(s); tgt != "" {
		obs = append(obs, provider.Observation{Path: "dns.target", Value: tgt, Derivation: "measured"})
		if n > 1 {
			diags = append(diags, "dns.target reports the FIRST of "+strconv.Itoa(n)+
				" values in this record set — the attribute is a single string and cannot "+
				"represent the rest, so a constraint on it is satisfied by one target while "+
				"the name also resolves to the others")
		}
	} else {
		// D1235, the GCP twin.
		diags = append(diags, "dns.target not observed: no target could be read from this "+
			"resource record set (an unsupported type, or a shape this driver does not decode)")
	}
	// dns.proxied is a Cloudflare edge posture — Cloud DNS has no proxy, so it is
	// OMITTED (an honest gap), never fabricated as a false.
	diags = append(diags, "dns.proxied not observed — a Cloudflare edge concept with no Cloud DNS equivalent")
	return obs, diags, nil
}

// updateCloudDNSRecord REPOINTS a record in place: changing dns.target is a patch, not
// a delete+recreate. Cloud DNS has no "modify rrset" call — a repoint is a SINGLE
// managedZones.changes carrying BOTH deletions:[current rrset] and additions:[new
// rrset] atomically (you cannot merely add: the name+type already exists). Ownership is
// the PARENT ZONE's labels, re-checked before writing. Four-valued: transport/5xx ->
// unknown WITH the pinned providerId (may have landed); a foreign zone -> failed; the
// current rrset unreadable -> unknown.
func (d *Driver) updateCloudDNSRecord(capability, environment, providerID string,
	attrs map[string]any, changes []string) provider.CreateResult {
	project, zone, recordType, name, err := splitGDNSRecProviderID(providerID)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	if err := d.sameProject(project); err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	// only dns.target is repointable in place (ClassifyChange gates this).
	for _, path := range changes {
		if path != "dns.target" {
			return provider.CreateResult{Status: "failed",
				Reason: fmt.Sprintf("path %s is not repointable in place on a Cloud DNS record (ClassifyChange should have refused it)", path)}
		}
	}
	target, _ := attrs["dns.target"].(string)
	target = strings.TrimSpace(target)
	if target == "" {
		return provider.CreateResult{Status: "failed", Reason: "dns.target must be a non-empty value to repoint a record"}
	}
	// ownership gate: the record lives in a zone; only repoint records in OUR zone.
	owned, zerr := d.recordZoneOwnedByUs(project, zone, capability, environment)
	if zerr != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown",
			Reason: "pre-update parent-zone read gave no answer — cannot confirm ownership before repointing a record; reconcile: " + zerr.Error()}
	}
	if !owned {
		return provider.CreateResult{Status: "failed",
			Reason: "the parent managed zone is not ours (labels do not match) — refusing to repoint a record in a zone we do not own"}
	}
	// read the CURRENT rrset — the deletion side of the atomic change must match it
	// verbatim (name/type/ttl/rrdatas).
	cur, found, serr := d.getRecordSet(project, zone, name, recordType)
	if serr != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown",
			Reason: "pre-update record read gave no answer — reconcile: " + serr.Error()}
	}
	if !found {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown",
			Reason: "the record to repoint is not present — reconcile (this is a create, not an in-place repoint)"}
	}
	// one atomic change: delete the current rrset AND add the new target.
	desired := CloudDNSRecordPlan{Zone: zone, Name: name, Type: recordType, Target: target}
	body := deletionsBody(cur)
	for k, v := range desired.additionsBody() {
		body[k] = v
	}
	changesURL := fmt.Sprintf("%s/projects/%s/managedZones/%s/changes", d.dnsBase(), project, zone)
	st, respBody, e := d.call("POST", changesURL, body)
	if e != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown",
			Reason: fmt.Sprintf("record repoint outcome unknown (may have landed): %v", e)}
	}
	if st == http.StatusOK || st == http.StatusCreated {
		return provider.CreateResult{ProviderID: providerID, Status: "succeeded"}
	}
	if st >= 500 {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown",
			Reason: fmt.Sprintf("record repoint HTTP %d (server error — may have landed) — reconcile", st)}
	}
	if r := provider.MutationResult(st, gcpErrCode(respBody), nil, providerID, "record repoint"); r != nil {
		return *r
	}
	return provider.CreateResult{Status: "failed",
		Reason: fmt.Sprintf("record repoint HTTP %d: %s", st, mutDetail(respBody))}
}

func (d *Driver) deleteCloudDNSRecord(capability, environment, providerID string) provider.CreateResult {
	project, zone, recordType, name, err := splitGDNSRecProviderID(providerID)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	if err := d.sameProject(project); err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	owned, zerr := d.recordZoneOwnedByUs(project, zone, capability, environment)
	if zerr != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown", Reason: "pre-delete parent-zone read gave no answer — reconcile: " + zerr.Error()}
	}
	if !owned {
		return provider.CreateResult{Status: "failed",
			Reason: "the parent managed zone is not ours (labels do not match) — refusing to delete a record in a zone we do not own"}
	}
	cur, found, serr := d.getRecordSet(project, zone, name, recordType)
	if serr != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown", Reason: "pre-delete record read gave no answer — reconcile: " + serr.Error()}
	}
	if !found {
		return provider.CreateResult{ProviderID: providerID, Status: "succeeded"} // idempotent — already gone
	}
	changesURL := fmt.Sprintf("%s/projects/%s/managedZones/%s/changes", d.dnsBase(), project, zone)
	st, body, e := d.call("POST", changesURL, deletionsBody(cur))
	if e != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown", Reason: fmt.Sprintf("record delete outcome unknown: %v", e)}
	}
	if st == http.StatusOK || st == http.StatusCreated {
		return provider.CreateResult{ProviderID: providerID, Status: "succeeded"}
	}
	if st == http.StatusNotFound || strings.Contains(string(body), "notFound") {
		return provider.CreateResult{ProviderID: providerID, Status: "succeeded"} // already gone — idempotent
	}
	if st >= 500 {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown", Reason: fmt.Sprintf("record delete HTTP %d (server error) — reconcile", st)}
	}
	if r := provider.MutationResult(st, gcpErrCode(body), nil, providerID, "record delete"); r != nil {
		return *r
	}
	return provider.CreateResult{Status: "failed", Reason: fmt.Sprintf("record delete HTTP %d: %s", st, mutDetail(body))}
}
