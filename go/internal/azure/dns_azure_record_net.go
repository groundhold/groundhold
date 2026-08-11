// Azure DNS record network shell (D262): the ARM half of the capability.dns.record
// driver. A record set carries NO ownership tags of its own, so ownership is the
// PARENT ZONE's tags — every mutation first reads the public dnsZone's tags and
// REFUSES a record in a zone that is not ours (the zone is the ownership boundary).
// Within an owned zone a record PUT is an idempotent upsert (we own the whole zone),
// so a lost create is simply re-PUT — never a duplicate. A record set has no ARM
// provisioningState (the PUT is synchronous), so the create does a direct PUT with
// four-valued status handling rather than putAndPoll. The providerId is deterministic
// (sub + rg + zone + type + name); there is no server-assigned id to recover.
package azure

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"groundhold/internal/provider"
)

func azureDNSRecordProviderID(sub, rg, zone, recordType, name string) string {
	return "adnsrec:" + sub + ":" + rg + ":" + zone + ":" + recordType + ":" + name
}

func splitAzureDNSRecordProviderID(providerID string) (sub, rg, zone, recordType, name string, err error) {
	parts := strings.SplitN(providerID, ":", 6)
	if len(parts) != 6 || parts[0] != "adnsrec" {
		return "", "", "", "", "", fmt.Errorf("providerId %q is not adnsrec:sub:rg:zone:type:name", providerID)
	}
	if !subOK.MatchString(parts[1]) || !rgOK.MatchString(parts[2]) {
		return "", "", "", "", "", fmt.Errorf("providerId %q has an invalid sub/rg", providerID)
	}
	if !azDNSDomainOK.MatchString(parts[3]) {
		return "", "", "", "", "", fmt.Errorf("providerId zone %q is invalid", parts[3])
	}
	if _, ok := azDNSRecordTypeOK[parts[4]]; !ok {
		return "", "", "", "", "", fmt.Errorf("providerId record type %q is invalid", parts[4])
	}
	if !azDNSRecordNameOK.MatchString(parts[5]) {
		return "", "", "", "", "", fmt.Errorf("providerId record name %q is invalid", parts[5])
	}
	return parts[1], parts[2], parts[3], parts[4], parts[5], nil
}

// dnsZoneOwnedByUs reads the parent PUBLIC zone's tags and reports whether they
// are ours. A read that gave no answer is NOT "not ours" in a way that could fail
// open — it comes back as an error the caller turns into unknown. A definitive 404
// (the zone is absent), and a malformed sub/rg, are owned=false with a nil error.
func (d *Driver) dnsZoneOwnedByUs(rg, zone, capability, environment string) (owned bool, err error) {
	var doc struct {
		Tags map[string]string `json:"tags"`
	}
	found, rerr := d.armGetInto("dnsZones.get", rg, "Microsoft.Network/dnsZones/"+zone,
		publicDNSAPIVersion, &doc)
	if rerr != nil {
		if re, ok := rerr.(*armReadError); ok && re.Cause == "scope" {
			return false, nil // a malformed sub/rg is a definitive refusal, not a transient
		}
		return false, rerr
	}
	if !found {
		return false, nil
	}
	owned = doc.Tags["groundhold-capability"] == sanitizeAzTag(capability) &&
		doc.Tags["groundhold-environment"] == sanitizeAzTag(environment)
	return owned, nil
}

func (d *Driver) createAzureDNSRecord(environment, capability string,
	attrs, impl map[string]any, generation int) provider.CreateResult {
	plan, err := BuildAzureDNSRecord(environment, capability, attrs, impl, generation)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	if !subOK.MatchString(d.Subscription) {
		return provider.CreateResult{Status: "failed",
			Reason: fmt.Sprintf("azure subscription %q is not a valid GUID", d.Subscription)}
	}
	pid := azureDNSRecordProviderID(d.Subscription, plan.ResourceGroup, plan.Zone, plan.Type, plan.Name)
	// ownership gate: the record lives in a zone; only manage records in OUR zone.
	owned, zerr := d.dnsZoneOwnedByUs(plan.ResourceGroup, plan.Zone, capability, environment)
	if zerr != nil {
		return provider.CreateResult{Status: "unknown",
			Reason: "parent zone tags gave no answer — cannot confirm ownership before writing a record; reconcile: " + zerr.Error()}
	}
	if !owned {
		return provider.CreateResult{Status: "failed",
			Reason: "the parent public DNS zone is not ours (tags do not match, or the zone is absent) — refusing to write a record into a zone we do not own"}
	}
	recURL, e := d.armURL(plan.ResourceGroup, plan.childPath(), publicDNSAPIVersion)
	if e != nil {
		return provider.CreateResult{Status: "failed", Reason: e.Error()}
	}
	body, _ := json.Marshal(plan.createBody())
	st, resp, err := d.doARM("PUT", recURL, body)
	switch {
	case err != nil:
		return provider.CreateResult{ProviderID: pid, Status: "unknown",
			Reason: fmt.Sprintf("record PUT outcome unknown (may have landed): %v", err)}
	case st == http.StatusOK || st == http.StatusCreated:
		return provider.CreateResult{ProviderID: pid, Status: "succeeded"}
	case st >= 500:
		return provider.CreateResult{ProviderID: pid, Status: "unknown",
			Reason: fmt.Sprintf("record PUT HTTP %d (server error — may have landed) — reconcile", st)}
	default:
		if r := provider.MutationResult(st, azErrCode(resp), nil, pid, "record PUT"); r != nil {
			return *r
		}
		return provider.CreateResult{Status: "failed",
			Reason: fmt.Sprintf("record PUT HTTP %d: %s", st, mutDetailAz(resp))}
	}
}

// updateAzureDNSRecord REPOINTS an existing record set in place — a record PUT is an
// idempotent upsert, so changing dns.target is simply PUTting the new value block, no
// delete+recreate. Only mutable paths (dns.target) may reach here; dns.type is the ARM
// child path, so a type change is a replacement, never an update. The parent zone's
// ownership is re-checked before the write (the zone is the ownership boundary).
func (d *Driver) updateAzureDNSRecord(capability, environment, providerID string,
	attrs, impl map[string]any, changes []string) provider.CreateResult {
	sub, rg, zone, recordType, name, err := splitAzureDNSRecordProviderID(providerID)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	if sub != d.Subscription && d.Subscription != "" {
		return provider.CreateResult{Status: "failed",
			Reason: fmt.Sprintf("providerId subscription %q is not the driver's", sub)}
	}
	// only wired mutable paths may reach the updater (fail closed on anything else).
	for _, path := range changes {
		if kind, _ := classifyAzureDNSRecordChange(path); kind != "mutable" {
			return provider.CreateResult{Status: "failed",
				Reason: fmt.Sprintf("azure DNS record in-place update does not honor %q — reconcile", path)}
		}
	}
	// refuse-before-mutate: re-derive + validate the full desired shape (the new target).
	plan, err := BuildAzureDNSRecord(environment, capability, attrs, impl, 1)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	// identity must not drift: the desired record's kind/zone/name must be the bound one
	// (a type/zone/name change is a different record — a replacement, never an update).
	if plan.Type != recordType || plan.Zone != zone || plan.Name != name {
		return provider.CreateResult{Status: "failed",
			Reason: "desired record identity (zone/type/name) differs from the bound providerId — that is a replacement, not an in-place update"}
	}
	// ownership gate: the record lives in a zone; only manage records in OUR zone.
	owned, zerr := d.dnsZoneOwnedByUs(rg, zone, capability, environment)
	if zerr != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown",
			Reason: "parent zone tags gave no answer — cannot confirm ownership before repointing a record; reconcile: " + zerr.Error()}
	}
	if !owned {
		return provider.CreateResult{Status: "failed",
			Reason: "the parent public DNS zone is not ours (tags do not match, or the zone is absent) — refusing to repoint a record in a zone we do not own"}
	}
	recURL, e := d.armURL(rg, plan.childPath(), publicDNSAPIVersion)
	if e != nil {
		return provider.CreateResult{Status: "failed", Reason: e.Error()}
	}
	body, _ := json.Marshal(plan.createBody())
	st, resp, perr := d.doARM("PUT", recURL, body)
	switch {
	case perr != nil:
		return provider.CreateResult{ProviderID: providerID, Status: "unknown",
			Reason: fmt.Sprintf("record repoint PUT outcome unknown (may have landed): %v", perr)}
	case st == http.StatusOK || st == http.StatusCreated:
		return provider.CreateResult{ProviderID: providerID, Status: "succeeded"}
	case st >= 500:
		return provider.CreateResult{ProviderID: providerID, Status: "unknown",
			Reason: fmt.Sprintf("record repoint PUT HTTP %d (server error — may have landed) — reconcile", st)}
	default:
		if r := provider.MutationResult(st, azErrCode(resp), nil, providerID, "record repoint PUT"); r != nil {
			return *r
		}
		return provider.CreateResult{Status: "failed",
			Reason: fmt.Sprintf("record repoint PUT HTTP %d: %s", st, mutDetailAz(resp))}
	}
}

// azureDNSRecordDoc is the projection of one record set the driver reads. Only the
// type-specific value block matters — the TTL and metadata are noise.
type azureDNSRecordDoc struct {
	Properties struct {
		ARecords []struct {
			Ipv4Address string `json:"ipv4Address"`
		} `json:"ARecords"`
		AAAARecords []struct {
			Ipv6Address string `json:"ipv6Address"`
		} `json:"AAAARecords"`
		CNAMERecord struct {
			Cname string `json:"cname"`
		} `json:"CNAMERecord"`
		TXTRecords []struct {
			Value []string `json:"value"`
		} `json:"TXTRecords"`
		MXRecords []struct {
			Preference int    `json:"preference"`
			Exchange   string `json:"exchange"`
		} `json:"MXRecords"`
	} `json:"properties"`
}

// recordTarget reconstructs the governed dns.target from the type-specific value
// block, inverting recordProperties.
func recordTarget(recordType string, doc azureDNSRecordDoc) string {
	switch recordType {
	case "A":
		if len(doc.Properties.ARecords) > 0 {
			return doc.Properties.ARecords[0].Ipv4Address
		}
	case "AAAA":
		if len(doc.Properties.AAAARecords) > 0 {
			return doc.Properties.AAAARecords[0].Ipv6Address
		}
	case "CNAME":
		return doc.Properties.CNAMERecord.Cname
	case "TXT":
		if len(doc.Properties.TXTRecords) > 0 && len(doc.Properties.TXTRecords[0].Value) > 0 {
			return doc.Properties.TXTRecords[0].Value[0]
		}
	case "MX":
		if len(doc.Properties.MXRecords) > 0 {
			return fmt.Sprintf("%d %s", doc.Properties.MXRecords[0].Preference, doc.Properties.MXRecords[0].Exchange)
		}
	}
	return ""
}

func (d *Driver) observeAzureDNSRecord(capability, providerID string) ([]provider.Observation, []string, error) {
	sub, rg, zone, recordType, name, err := splitAzureDNSRecordProviderID(providerID)
	if err != nil {
		return nil, nil, err
	}
	if sub != d.Subscription && d.Subscription != "" {
		return nil, nil, fmt.Errorf("providerId subscription %q is not the driver's", sub)
	}
	childPath := "Microsoft.Network/dnsZones/" + zone + "/" + azDNSRecordTypeOK[recordType] + "/" + name
	recURL, e := d.armURL(rg, childPath, publicDNSAPIVersion)
	if e != nil {
		return nil, nil, e
	}
	st, resp, ge := d.doARM("GET", recURL, nil)
	if ge != nil {
		return nil, nil, fmt.Errorf("dnsRecord.get: %v", ge)
	}
	if st == http.StatusNotFound {
		// F-LC3 (D518): a BOUND resource the API authoritatively 404s is GONE.
		// A diagnostic alone leaves the binding a no-op forever (D513).
		return []provider.Observation{
			{Path: provider.ResourceAbsentPath, Value: true, Derivation: "measured"},
		}, []string{"record set not found — bound resource is gone (will re-create)"}, nil
	}
	if st != http.StatusOK {
		return nil, nil, fmt.Errorf("dnsRecord.get: HTTP %d", st)
	}
	var doc azureDNSRecordDoc
	if json.Unmarshal(resp, &doc) != nil {
		return nil, nil, &armReadError{Op: "dnsRecord.get", Cause: "body", Status: st}
	}
	// Present: clear the marker, or a stale "gone" survives a re-create.
	obs := []provider.Observation{
		{Path: provider.ResourceAbsentPath, Value: false, Derivation: "measured"},
		{Path: "dns.type", Value: recordType, Derivation: "measured"},
		{Path: "service.managed", Value: true, Derivation: "measured"},
	}
	if tgt := recordTarget(recordType, doc); tgt != "" {
		obs = append(obs, provider.Observation{Path: "dns.target", Value: tgt, Derivation: "measured"})
	}
	// dns.proxied is a Cloudflare edge posture — Azure DNS has no proxy, so it is
	// OMITTED (an honest gap), never fabricated as a false.
	diags := []string{"dns.proxied not observed — a Cloudflare edge concept with no Azure DNS equivalent"}
	return obs, diags, nil
}

func (d *Driver) deleteAzureDNSRecord(capability, environment, providerID string) provider.CreateResult {
	sub, rg, zone, recordType, name, err := splitAzureDNSRecordProviderID(providerID)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	if sub != d.Subscription && d.Subscription != "" {
		return provider.CreateResult{Status: "failed",
			Reason: fmt.Sprintf("providerId subscription %q is not the driver's", sub)}
	}
	// ownership gate: only delete records in OUR zone.
	owned, zerr := d.dnsZoneOwnedByUs(rg, zone, capability, environment)
	if zerr != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown",
			Reason: "pre-delete parent-zone tag read gave no answer — reconcile: " + zerr.Error()}
	}
	if !owned {
		return provider.CreateResult{Status: "failed",
			Reason: "the parent public DNS zone is not ours (tags do not match) — refusing to delete a record in a zone we do not own"}
	}
	childPath := "Microsoft.Network/dnsZones/" + zone + "/" + azDNSRecordTypeOK[recordType] + "/" + name
	recURL, e := d.armURL(rg, childPath, publicDNSAPIVersion)
	if e != nil {
		return provider.CreateResult{Status: "failed", Reason: e.Error()}
	}
	dst, dresp, de := d.doARM("DELETE", recURL, nil)
	if de != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown", Reason: fmt.Sprintf("record delete outcome unknown: %v", de)}
	}
	if dst == http.StatusOK || dst == http.StatusNoContent || dst == http.StatusNotFound {
		return provider.CreateResult{ProviderID: providerID, Status: "succeeded"} // idempotent — already gone
	}
	if dst >= 500 {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown", Reason: fmt.Sprintf("record delete HTTP %d (server error) — reconcile", dst)}
	}
	if r := provider.MutationResult(dst, azErrCode(dresp), nil, providerID, "record delete"); r != nil {
		return *r
	}
	return provider.CreateResult{Status: "failed", Reason: fmt.Sprintf("record delete HTTP %d: %s", dst, mutDetailAz(dresp))}
}
