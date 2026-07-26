// Route 53 record network shell (D262): the SigV4-signed, REST-XML half of the AWS
// capability.dns.record driver. A record set carries NO tags of its own, so ownership
// is the PARENT ZONE's tags — every mutation first reads the hosted zone's tags and
// REFUSES a record in a zone that is not ours (the zone is the ownership boundary).
// Within an owned zone an UPSERT is safe (we own the whole zone), so a lost create is
// simply re-UPSERTed — idempotent, never a duplicate. The providerId is deterministic
// (zone + type + name); no server-assigned id to recover.
package aws

import (
	"encoding/xml"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"groundhold/internal/provider"
)

func r53RecordProviderID(zoneID, recordType, name string) string {
	return "r53rec:" + zoneID + ":" + recordType + ":" + name
}

func splitR53RecordProviderID(providerID string) (zoneID, recordType, name string, err error) {
	parts := strings.SplitN(providerID, ":", 4)
	if len(parts) != 4 || parts[0] != "r53rec" {
		return "", "", "", fmt.Errorf("providerId %q is not r53rec:zone:type:name", providerID)
	}
	if !hostedZoneIDOK.MatchString(parts[1]) {
		return "", "", "", fmt.Errorf("providerId hosted-zone id %q is invalid", parts[1])
	}
	if !r53RecordTypeOK[parts[2]] {
		return "", "", "", fmt.Errorf("providerId record type %q is invalid", parts[2])
	}
	if parts[3] == "" {
		return "", "", "", fmt.Errorf("providerId record name is empty")
	}
	return parts[1], parts[2], parts[3], nil
}

// r53RecordSet is the projection of one ResourceRecordSet the driver reads.
type r53RecordSet struct {
	Name    string `xml:"Name"`
	Type    string `xml:"Type"`
	Records []struct {
		Value string `xml:"Value"`
	} `xml:"ResourceRecords>ResourceRecord"`
}

// zoneOwnedByUs reads the parent zone's tags and reports whether they are ours. The
// second bool is readability: an unreadable tag set is NOT "not ours" (that would
// fail open into refusing / or worse, mutating) — the caller treats it as unknown.
func (d *Driver) zoneOwnedByUs(zoneID, capability, environment string) (owned bool, err error) {
	tags, terr := d.r53Tags(zoneID)
	if terr != nil {
		return false, terr
	}
	return groundholdTagsMatch(tags, capability, environment), nil
}

func (d *Driver) createRoute53Record(environment, capability string,
	attrs, impl map[string]any, generation int) provider.CreateResult {
	plan, err := BuildRoute53Record(environment, capability, attrs, impl, generation)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	pid := r53RecordProviderID(plan.ZoneID, plan.Type, plan.Name)
	// ownership gate: the record lives in a zone; only manage records in OUR zone.
	owned, zerr := d.zoneOwnedByUs(plan.ZoneID, capability, environment)
	if zerr != nil {
		return provider.CreateResult{Status: "unknown",
			Reason: "parent zone tags gave no answer — cannot confirm ownership before writing a record; reconcile: " + zerr.Error()}
	}
	if !owned {
		return provider.CreateResult{Status: "failed",
			Reason: "the parent hosted zone is not ours (tags do not match) — refusing to write a record into a zone we do not own"}
	}
	st, resp, e := d.r53Do("POST", route53Path+"/hostedzone/"+plan.ZoneID+"/rrset", plan.changeXML("UPSERT"))
	switch {
	case e != nil:
		return provider.CreateResult{ProviderID: pid, Status: "unknown",
			Reason: fmt.Sprintf("record UPSERT outcome unknown (may have landed): %v", e)}
	case st == http.StatusOK:
		return provider.CreateResult{ProviderID: pid, Status: "succeeded"}
	case st >= 500:
		return provider.CreateResult{ProviderID: pid, Status: "unknown",
			Reason: fmt.Sprintf("record UPSERT HTTP %d (server error — may have landed) — reconcile", st)}
	default:
		if r := provider.MutationResult(st, r53ErrCode(resp), nil, pid, "record UPSERT"); r != nil {
			return *r
		}
		return provider.CreateResult{Status: "failed",
			Reason: fmt.Sprintf("record UPSERT HTTP %d (%s): %s", st, r53ErrCode(resp), mutDetail(resp))}
	}
}

// listRecordSet finds the single (name,type) record set in a zone. Returns
// (set, found, readable): a clean list that does not contain the pair is found=false
// (a vanished record, not an error); a transport/HTTP/parse failure is readable=false.
func (d *Driver) listRecordSet(zoneID, name, recordType string) (r53RecordSet, bool, error) {
	const op = "ListResourceRecordSets"
	q := url.Values{}
	q.Set("name", name)
	q.Set("type", recordType)
	q.Set("maxitems", "1")
	st, resp, err := d.r53Do("GET", route53Path+"/hostedzone/"+zoneID+"/rrset?"+q.Encode(), "")
	if err != nil {
		return r53RecordSet{}, false, readTransport(op, err)
	}
	if st == http.StatusNotFound || r53ErrCode(resp) == "NoSuchHostedZone" {
		return r53RecordSet{}, false, nil
	}
	if st != http.StatusOK {
		return r53RecordSet{}, false, readHTTP(op, st, ecsErr(resp))
	}
	var r struct {
		Sets []r53RecordSet `xml:"ResourceRecordSets>ResourceRecordSet"`
	}
	if xml.Unmarshal(resp, &r) != nil {
		return r53RecordSet{}, false, readBody(op, st)
	}
	// the list starts AT name/type; accept only an EXACT name+type match (the API may
	// return the next record set when ours is absent).
	for _, s := range r.Sets {
		if strings.EqualFold(strings.TrimSuffix(s.Name, "."), strings.TrimSuffix(name, ".")) && s.Type == recordType {
			return s, true, nil
		}
	}
	return r53RecordSet{}, false, nil
}

// r53RecordTarget reads the first record value, unquoting a TXT payload back to the
// raw target the contract declares.
func r53RecordTarget(s r53RecordSet) string {
	if len(s.Records) == 0 {
		return ""
	}
	v := s.Records[0].Value
	if s.Type == "TXT" {
		v = strings.TrimSuffix(strings.TrimPrefix(v, `"`), `"`)
		v = strings.ReplaceAll(v, `\"`, `"`)
	}
	return v
}

func (d *Driver) observeRoute53Record(capability, providerID string) ([]provider.Observation, []string, error) {
	zoneID, recordType, name, err := splitR53RecordProviderID(providerID)
	if err != nil {
		return nil, nil, err
	}
	s, found, rerr := d.listRecordSet(zoneID, name, recordType)
	if rerr != nil {
		return nil, nil, rerr
	}
	if !found {
		return nil, []string{"record set not found — nothing to observe"}, nil
	}
	obs := []provider.Observation{
		{Path: "dns.type", Value: recordType, Derivation: "measured"},
		{Path: "service.managed", Value: true, Derivation: "measured"},
	}
	if tgt := r53RecordTarget(s); tgt != "" {
		obs = append(obs, provider.Observation{Path: "dns.target", Value: tgt, Derivation: "measured"})
	}
	// dns.proxied is a Cloudflare edge posture — Route 53 has no proxy, so it is
	// OMITTED (an honest gap), never fabricated as a false.
	diags := []string{"dns.proxied not observed — a Cloudflare edge concept with no Route 53 equivalent"}
	return obs, diags, nil
}

// classifyRoute53RecordChange (D46): PURE — can this capability.dns.record
// transition be honored IN PLACE on an existing record set? dns.target is what a
// record POINTS at, and an UPSERT is already a create-or-replace of the (name,type)
// set — so REPOINTING is a patch (no delete+recreate, no DNS resolution gap), hence
// mutable. dns.type is the record's KIND, i.e. its identity — a different type is a
// DIFFERENT record set, a replacement, never a silent in-place edit. dns.proxied is
// a Cloudflare edge concept Route 53 has no equivalent for (refused at build already)
// and service.managed / cost.monthly are platform/projection facts — all unsupported.
func classifyRoute53RecordChange(path string, desired any, impl map[string]any) (string, string) {
	switch path {
	case "dns.target":
		return "mutable", "" // repoint the (name,type) set in place via UPSERT — no resolution gap
	case "dns.type":
		return "immutable", "a record's KIND (dns.type) is its identity — a different type is a different record set (a replacement), not an in-place repoint"
	case "dns.proxied":
		return "unsupported", "dns.proxied is a Cloudflare edge concept with no Route 53 equivalent (refused at build) — nothing to patch"
	case "service.managed":
		return "unsupported", "platform/projection property — nothing to patch"
	default:
		return "unsupported", "no Route 53 record in-place mapping for " + path
	}
}

// updateRoute53Record: REPOINT a record set in place. An UPSERT is a create-or-
// replace of the (name,type) set — so a target change is one UPSERT, never a
// delete+recreate (which would open a DNS resolution gap). Refuse-before-mutate:
// the pinned providerId must be well-formed, the PARENT ZONE must still be ours,
// and the desired plan's identity (zone+type+name) must match the pinned record —
// we only ever repoint THE record we are bound to, never a different one. Four-
// valued per D29/D87: an ambiguous outcome (transport / 5xx) is unknown WITH the
// providerId; a foreign zone is failed; a 4xx/3xx is failed.
func (d *Driver) updateRoute53Record(capability, environment, providerID string,
	attrs, impl map[string]any, changes []string) provider.CreateResult {
	zoneID, _, _, err := splitR53RecordProviderID(providerID)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	// ownership re-check on the PARENT ZONE BEFORE any write (the zone is the
	// ownership boundary; a record carries no tags). An unreadable tag set is
	// unknown, NOT "not ours".
	owned, zerr := d.zoneOwnedByUs(zoneID, capability, environment)
	if zerr != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown",
			Reason: "pre-update parent-zone tag read gave no answer — cannot confirm ownership before repointing; reconcile: " + zerr.Error()}
	}
	if !owned {
		return provider.CreateResult{Status: "failed",
			Reason: "the parent hosted zone is not ours (tags do not match) — refusing to repoint a record in a zone we do not own"}
	}
	// desired plan (create-XML reuse) — a refusal here (an attribute Route 53 cannot
	// honor) surfaces as failed, never a half-applied patch.
	plan, err := BuildRoute53Record(environment, capability, attrs, impl, 1)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	// the desired record's identity MUST match the pinned providerId — dns.type is
	// immutable (classify makes a type change a replacement), so an update only ever
	// changes the target of THIS record. Refuse to repoint a different set.
	if r53RecordProviderID(plan.ZoneID, plan.Type, plan.Name) != providerID {
		return provider.CreateResult{Status: "failed",
			Reason: "desired record identity (zone/type/name) does not match the pinned providerId — refusing to repoint a different record"}
	}
	// an UPSERT is a create-or-replace: repoint the record set to the new target in
	// place. We own the whole zone, so a re-UPSERT is safe and idempotent.
	st, resp, e := d.r53Do("POST", route53Path+"/hostedzone/"+plan.ZoneID+"/rrset", plan.changeXML("UPSERT"))
	switch {
	case e != nil:
		return provider.CreateResult{ProviderID: providerID, Status: "unknown",
			Reason: fmt.Sprintf("record repoint outcome unknown (may have landed): %v", e)}
	case st == http.StatusOK:
		return provider.CreateResult{ProviderID: providerID, Status: "succeeded"}
	case st >= 500:
		return provider.CreateResult{ProviderID: providerID, Status: "unknown",
			Reason: fmt.Sprintf("record repoint HTTP %d (server error — may have landed) — reconcile", st)}
	default:
		if r := provider.MutationResult(st, r53ErrCode(resp), nil, providerID, "record repoint"); r != nil {
			return *r
		}
		return provider.CreateResult{Status: "failed",
			Reason: fmt.Sprintf("record repoint HTTP %d (%s): %s", st, r53ErrCode(resp), mutDetail(resp))}
	}
}

func (d *Driver) deleteRoute53Record(capability, environment, providerID string) provider.CreateResult {
	zoneID, recordType, name, err := splitR53RecordProviderID(providerID)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	owned, zerr := d.zoneOwnedByUs(zoneID, capability, environment)
	if zerr != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown", Reason: "pre-delete parent-zone tag read gave no answer — reconcile: " + zerr.Error()}
	}
	if !owned {
		return provider.CreateResult{Status: "failed",
			Reason: "the parent hosted zone is not ours (tags do not match) — refusing to delete a record in a zone we do not own"}
	}
	s, found, sReadable := d.listRecordSet(zoneID, name, recordType)
	if sReadable != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown",
			Reason: "pre-delete record read gave no answer — reconcile: " + sReadable.Error()}
	}
	if !found {
		return provider.CreateResult{ProviderID: providerID, Status: "succeeded"} // idempotent — already gone
	}
	// Route 53 DELETE needs the rrset's EXACT current value; reconstruct it from the read.
	plan := Route53RecordPlan{ZoneID: zoneID, Name: name, Type: recordType, Target: r53RecordTarget(s)}
	st, resp, e := d.r53Do("POST", route53Path+"/hostedzone/"+zoneID+"/rrset", plan.changeXML("DELETE"))
	if e != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown", Reason: fmt.Sprintf("record delete outcome unknown: %v", e)}
	}
	if st == http.StatusOK {
		return provider.CreateResult{ProviderID: providerID, Status: "succeeded"}
	}
	if strings.Contains(string(resp), "not found") || r53ErrCode(resp) == "InvalidChangeBatch" {
		// the record set was already gone by the time DELETE landed — idempotent.
		return provider.CreateResult{ProviderID: providerID, Status: "succeeded"}
	}
	if st >= 500 {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown", Reason: fmt.Sprintf("record delete HTTP %d (server error) — reconcile", st)}
	}
	if r := provider.MutationResult(st, r53ErrCode(resp), nil, providerID, "record delete"); r != nil {
		return *r
	}
	return provider.CreateResult{Status: "failed", Reason: fmt.Sprintf("record delete HTTP %d (%s)", st, r53ErrCode(resp))}
}
