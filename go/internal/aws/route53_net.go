// Route 53 network shell (D101): the SigV4-signed, REST-XML half of the AWS
// capability.dns.zone driver. Route 53 is GLOBAL (signed for us-east-1, no regional
// endpoint). The hosted-zone Id is SERVER-ASSIGNED, so the providerId is parsed
// from the create response (DeterministicID=false); a deterministic CallerReference
// is the idempotency key, so a lost create is recovered by ListHostedZonesByName +
// CallerReference match, never a stranded resource. Ownership is TAGS. The RECORDS
// are never read or written. A zone that still holds records refuses deletion.
package aws

import (
	"encoding/xml"
	"fmt"
	"net/http"
	"strings"

	"groundhold/internal/provider"
)

const route53Path = "/2013-04-01"

func (d *Driver) route53Base() string {
	if d.Route53BaseURL != "" {
		return d.Route53BaseURL
	}
	return "https://route53.amazonaws.com"
}

// r53Do signs (global, us-east-1) and sends a REST-XML request.
func (d *Driver) r53Do(method, path, body string) (int, []byte, error) {
	var b []byte
	if body != "" {
		b = []byte(body)
	}
	return d.doSigned(method, d.route53Base()+path, "route53", "us-east-1",
		map[string]string{"Content-Type": "text/xml"}, b)
}

func r53ProviderID(id string) string { return "r53:" + id }

func splitR53ProviderID(providerID string) (id string, err error) {
	parts := strings.SplitN(providerID, ":", 2)
	if len(parts) != 2 || parts[0] != "r53" {
		return "", fmt.Errorf("providerId %q is not r53:zoneid", providerID)
	}
	if !hostedZoneIDOK.MatchString(parts[1]) {
		return "", fmt.Errorf("providerId hosted-zone id %q is invalid", parts[1])
	}
	return parts[1], nil
}

// stripZoneID turns "/hostedzone/Zxxx" (or "Zxxx") into "Zxxx".
func stripZoneID(raw string) string {
	if i := strings.LastIndex(raw, "/"); i >= 0 {
		return raw[i+1:]
	}
	return raw
}

func r53ErrCode(body []byte) string {
	var e struct {
		Code string `xml:"Error>Code"`
	}
	_ = xml.Unmarshal(body, &e)
	return e.Code
}

type r53HostedZone struct {
	ID              string `xml:"Id"`
	Name            string `xml:"Name"`
	CallerReference string `xml:"CallerReference"`
	Config          struct {
		PrivateZone bool `xml:"PrivateZone"`
	} `xml:"Config"`
}

func (d *Driver) createRoute53(environment, capability string,
	attrs, impl map[string]any, generation int) provider.CreateResult {
	plan, err := BuildRoute53Zone(environment, capability, attrs, impl, generation)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	st, resp, err := d.r53Do("POST", route53Path+"/hostedzone", plan.createXML())
	switch {
	case err != nil:
		// server-assigned id: no deterministic pid, but the CallerReference lets a
		// retry recover — so the outcome is unknown, reconcilable by name.
		return provider.CreateResult{Status: "unknown",
			Reason: fmt.Sprintf("create outcome unknown (may have landed; recover by CallerReference): %v", err)}
	case st == http.StatusCreated || st == http.StatusOK:
		var r struct {
			Zone r53HostedZone `xml:"HostedZone"`
		}
		if xml.Unmarshal(resp, &r) != nil || stripZoneID(r.Zone.ID) == "" {
			return provider.CreateResult{Status: "unknown", Reason: "create returned no hosted-zone id — reconcile by name"}
		}
		id := stripZoneID(r.Zone.ID)
		pid := r53ProviderID(id)
		if r := d.r53Tag(id, capability, environment); r != nil {
			return *r // zone created but tagging failed — unknown/failed WITH the pid
		}
		return provider.CreateResult{ProviderID: pid, Status: "succeeded"}
	case r53ErrCode(resp) == "HostedZoneAlreadyExists":
		// our deterministic CallerReference already made this zone — recover its id.
		return d.recoverRoute53(plan, capability, environment)
	case st >= 500:
		return provider.CreateResult{Status: "unknown",
			Reason: fmt.Sprintf("create HTTP %d (server error — may have landed) — reconcile by name", st)}
	default:
		if r := provider.MutationResult(st, r53ErrCode(resp), nil, "", "create"); r != nil {
			return *r
		}
		return provider.CreateResult{Status: "failed",
			Reason: fmt.Sprintf("create HTTP %d (%s): %s", st, r53ErrCode(resp), mutDetail(resp))}
	}
}

// recoverRoute53 finds the zone our CallerReference already created (list by name,
// match CallerReference), so a duplicate create returns the same handle.
func (d *Driver) recoverRoute53(plan Route53Plan, capability, environment string) provider.CreateResult {
	st, resp, err := d.r53Do("GET", route53Path+"/hostedzonesbyname?dnsname="+plan.DNSName, "")
	if err != nil || st != http.StatusOK {
		return provider.CreateResult{Status: "unknown", Reason: "zone exists (our CallerReference) but list-by-name failed — reconcile"}
	}
	var r struct {
		Zones []r53HostedZone `xml:"HostedZones>HostedZone"`
	}
	if xml.Unmarshal(resp, &r) != nil {
		return provider.CreateResult{Status: "unknown", Reason: "zone exists but list-by-name unparseable — reconcile"}
	}
	for _, z := range r.Zones {
		if z.CallerReference == plan.CallerReference {
			id := stripZoneID(z.ID)
			pid := r53ProviderID(id)
			if r := d.r53Tag(id, capability, environment); r != nil {
				return *r
			}
			return provider.CreateResult{ProviderID: pid, Status: "succeeded"}
		}
	}
	return provider.CreateResult{Status: "failed",
		Reason: "a hosted zone for this domain exists but not from our CallerReference — refusing"}
}

// r53Tag adds ownership tags; nil = ok, non-nil = a terminal result WITH the pid.
func (d *Driver) r53Tag(id, capability, environment string) *provider.CreateResult {
	pid := r53ProviderID(id)
	st, resp, err := d.r53Do("POST", route53Path+"/tags/hostedzone/"+id, r53TagsXML(capability, environment))
	if err != nil {
		return &provider.CreateResult{ProviderID: pid, Status: "unknown", Reason: "zone created; tagging outcome unknown — reconcile"}
	}
	if st >= 500 {
		return &provider.CreateResult{ProviderID: pid, Status: "unknown", Reason: fmt.Sprintf("zone created; tagging HTTP %d (server error) — reconcile", st)}
	}
	if st < 200 || st >= 300 {
		if r := provider.MutationResult(st, r53ErrCode(resp), nil, pid, "tagging"); r != nil {
			return r
		}
		return &provider.CreateResult{ProviderID: pid, Status: "failed", Reason: fmt.Sprintf("zone created but tagging failed: HTTP %d (%s)", st, r53ErrCode(resp))}
	}
	return nil
}

func (d *Driver) r53Tags(id string) (map[string]string, error) {
	const op = "ListTagsForResource"
	st, resp, err := d.r53Do("GET", route53Path+"/tags/hostedzone/"+id, "")
	if err != nil || st != http.StatusOK {
		if err != nil {
			return nil, readTransport(op, err)
		}
		return nil, readHTTP(op, st, ecsErr(resp))
	}
	var r struct {
		Tags []struct {
			Key   string `xml:"Key"`
			Value string `xml:"Value"`
		} `xml:"ResourceTagSet>Tags>Tag"`
	}
	if xml.Unmarshal(resp, &r) != nil {
		return nil, readBody(op, st)
	}
	m := map[string]string{}
	for _, t := range r.Tags {
		m[t.Key] = t.Value
	}
	return m, nil
}

func (d *Driver) getHostedZone(id string) (r53HostedZone, bool, error) {
	const op = "GetHostedZone"
	st, resp, err := d.r53Do("GET", route53Path+"/hostedzone/"+id, "")
	if err != nil {
		return r53HostedZone{}, false, readTransport(op, err)
	}
	if st == http.StatusNotFound || r53ErrCode(resp) == "NoSuchHostedZone" {
		return r53HostedZone{}, false, nil
	}
	if st != http.StatusOK {
		return r53HostedZone{}, false, readHTTP(op, st, ecsErr(resp))
	}
	var r struct {
		Zone r53HostedZone `xml:"HostedZone"`
	}
	if xml.Unmarshal(resp, &r) != nil {
		return r53HostedZone{}, false, readBody(op, st)
	}
	return r.Zone, true, nil
}

func (d *Driver) observeRoute53(capability, providerID string) ([]provider.Observation, []string, error) {
	id, err := splitR53ProviderID(providerID)
	if err != nil {
		return nil, nil, err
	}
	z, found, rerr := d.getHostedZone(id)
	if rerr != nil {
		return nil, nil, rerr
	}
	if !found {
		// F-LC3 (D520): a BOUND resource the API authoritatively 404s is GONE.
		// A diagnostic alone leaves the binding a no-op forever (D513).
		return []provider.Observation{
			{Path: provider.ResourceAbsentPath, Value: true, Derivation: "measured"},
		}, []string{"hosted zone not found — bound resource is gone (will re-create)"}, nil
	}
	obs := []provider.Observation{
		// Present: clear the marker (F-LC3), or a stale "gone" survives a re-create.
		{Path: provider.ResourceAbsentPath, Value: false, Derivation: "measured"},
		{Path: "service.managed", Value: true, Derivation: "measured"},
		{Path: "network.publicExposure", Value: !z.Config.PrivateZone, Derivation: "measured"},
		// v0 never enables Route 53 DNSSEC (refused at build), so it is off.
		{Path: "dnssec.enabled", Value: false, Derivation: "config-intent"},
	}
	if z.Name != "" {
		obs = append(obs, provider.Observation{Path: "zone.domain",
			Value: strings.TrimSuffix(z.Name, "."), Derivation: "measured"})
	}
	return obs, nil, nil
}

func (d *Driver) deleteRoute53(capability, environment, providerID string) provider.CreateResult {
	id, err := splitR53ProviderID(providerID)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	_, found, rerr := d.getHostedZone(id)
	if rerr != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown", Reason: "pre-delete read gave no answer — reconcile: " + rerr.Error()}
	}
	if !found {
		return provider.CreateResult{ProviderID: providerID, Status: "succeeded"} // idempotent
	}
	tags, terr := d.r53Tags(id)
	if terr != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown", Reason: "pre-delete tag read gave no answer — reconcile: " + terr.Error()}
	}
	if !groundholdTagsMatch(tags, capability, environment) {
		return provider.CreateResult{Status: "failed",
			Reason: "hosted zone tags do not match — refusing to delete a resource that is not ours"}
	}
	st, resp, e := d.r53Do("DELETE", route53Path+"/hostedzone/"+id, "")
	if e != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown", Reason: fmt.Sprintf("delete outcome unknown: %v", e)}
	}
	if r53ErrCode(resp) == "NoSuchHostedZone" {
		return provider.CreateResult{ProviderID: providerID, Status: "succeeded"}
	}
	if r53ErrCode(resp) == "HostedZoneNotEmpty" {
		return provider.CreateResult{Status: "failed",
			Reason: "the hosted zone still holds records and cannot be deleted — remove the record set first (never forced)"}
	}
	if st >= 500 {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown", Reason: fmt.Sprintf("delete HTTP %d (server error) — reconcile", st)}
	}
	if st < 200 || st >= 300 {
		if r := provider.MutationResult(st, r53ErrCode(resp), nil, providerID, "delete"); r != nil {
			return *r
		}
		return provider.CreateResult{Status: "failed", Reason: fmt.Sprintf("delete HTTP %d (%s)", st, r53ErrCode(resp))}
	}
	return provider.CreateResult{ProviderID: providerID, Status: "succeeded"}
}
