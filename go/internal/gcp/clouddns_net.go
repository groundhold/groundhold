// GCP Cloud DNS network shell (D101): the bearer-signed REST half of the
// capability.dns.zone driver. Managed-zone create/delete are SYNCHRONOUS (no LRO),
// and the zone resource name is deterministic, so a lost/garbled create (D29)
// always carries the pid. Ownership is labels. The RECORDS are never read or
// written here — groundhold governs the zone envelope, not its contents. A zone that
// still holds user records cannot be deleted (Cloud DNS 400); that is surfaced,
// never forced.
package gcp

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"groundhold/internal/provider"
)

func (d *Driver) dnsBase() string {
	if d.DNSBaseURL != "" {
		return d.DNSBaseURL
	}
	return cloudDNSBaseURL
}

func gdnsProviderID(project, zone string) string { return "gdns:" + project + ":" + zone }

func splitGDNSProviderID(providerID string) (project, zone string, err error) {
	parts := strings.Split(providerID, ":")
	if len(parts) != 3 || parts[0] != "gdns" {
		return "", "", fmt.Errorf("providerId %q is not gdns:project:zone", providerID)
	}
	if !projectOK.MatchString(parts[1]) {
		return "", "", fmt.Errorf("providerId project %q is invalid", parts[1])
	}
	if !gcpName.MatchString(parts[2]) {
		return "", "", fmt.Errorf("providerId zone %q is invalid", parts[2])
	}
	return parts[1], parts[2], nil
}

type dnsZoneDoc struct {
	Name         string            `json:"name"`
	DNSName      string            `json:"dnsName"`
	Visibility   string            `json:"visibility"`
	Labels       map[string]string `json:"labels"`
	DnssecConfig struct {
		State string `json:"state"`
	} `json:"dnssecConfig"`
}

func (d *Driver) getDNSZone(project, zone string) (dnsZoneDoc, bool, error) {
	const op = "dNSZone.get"
	url := fmt.Sprintf("%s/projects/%s/managedZones/%s", d.dnsBase(), project, zone)
	st, body, err := d.call("GET", url, nil)
	if err != nil {
		return dnsZoneDoc{}, false, readTransport(op, err)
	}
	if st == http.StatusNotFound {
		return dnsZoneDoc{}, false, nil
	}
	if st != http.StatusOK {
		return dnsZoneDoc{}, false, readHTTP(op, st, gcpErrCode(body))
	}
	var doc dnsZoneDoc
	if json.Unmarshal(body, &doc) != nil {
		return dnsZoneDoc{}, false, readBody(op, st)
	}
	return doc, true, nil
}

func (d *Driver) createCloudDNS(environment, capability string,
	attrs, impl map[string]any, generation int) provider.CreateResult {
	plan, err := BuildCloudDNSZone(d.Project, environment, capability, attrs, impl, generation)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	pid := gdnsProviderID(d.Project, plan.Name)
	url := fmt.Sprintf("%s/projects/%s/managedZones", d.dnsBase(), d.Project)
	st, body, err := d.call("POST", url, plan.createBody(capability, environment))
	switch {
	case err != nil:
		return provider.CreateResult{ProviderID: pid, Status: "unknown",
			Reason: fmt.Sprintf("create outcome unknown (may have landed): %v", err)}
	case st == http.StatusOK || st == http.StatusCreated:
		return provider.CreateResult{ProviderID: pid, Status: "succeeded"}
	case st == http.StatusConflict:
		doc, found, rerr := d.getDNSZone(d.Project, plan.Name)
		if rerr != nil {
			return provider.CreateResult{ProviderID: pid, Status: "unknown",
				Reason: "name conflict, existing zone gave no answer — reconcile: " + rerr.Error()}
		}
		if !found || doc.Labels["groundhold-capability"] != sanitizeLabel(capability) ||
			doc.Labels["groundhold-environment"] != sanitizeLabel(environment) {
			return provider.CreateResult{Status: "failed",
				Reason: "a managed zone with this name exists and is not ours (labels do not match)"}
		}
		return provider.CreateResult{ProviderID: pid, Status: "succeeded"} // ours, idempotent
	case st >= 500:
		return provider.CreateResult{ProviderID: pid, Status: "unknown",
			Reason: fmt.Sprintf("create HTTP %d (server error — may have landed) — reconcile", st)}
	default:
		if r := provider.MutationResult(st, gcpErrCode(body), nil, pid, "create"); r != nil {
			return *r
		}
		return provider.CreateResult{Status: "failed",
			Reason: fmt.Sprintf("create HTTP %d: %s", st, mutDetail(body))}
	}
}

func (d *Driver) observeCloudDNS(capability, providerID string) ([]provider.Observation, []string, error) {
	project, zone, err := splitGDNSProviderID(providerID)
	if err != nil {
		return nil, nil, err
	}
	if err := d.sameProject(project); err != nil {
		return nil, nil, err
	}
	doc, found, rerr := d.getDNSZone(project, zone)
	if rerr != nil {
		return nil, nil, rerr
	}
	if !found {
		return nil, []string{"managed zone not found — nothing to observe"}, nil
	}
	obs := []provider.Observation{
		{Path: "service.managed", Value: true, Derivation: "measured"},
	}
	if doc.DNSName != "" {
		// report the domain in the declared form (no trailing dot) so it matches
		// a candidate's zone.domain.
		obs = append(obs, provider.Observation{Path: "zone.domain",
			Value: strings.TrimSuffix(doc.DNSName, "."), Derivation: "measured"})
	}
	switch doc.Visibility {
	case "public":
		obs = append(obs, provider.Observation{Path: "network.publicExposure", Value: true, Derivation: "measured"})
	case "private":
		obs = append(obs, provider.Observation{Path: "network.publicExposure", Value: false, Derivation: "measured"})
	}
	obs = append(obs, provider.Observation{Path: "dnssec.enabled",
		Value: doc.DnssecConfig.State == "on", Derivation: "measured"})
	return obs, nil, nil
}

func (d *Driver) deleteCloudDNS(capability, environment, providerID string) provider.CreateResult {
	project, zone, err := splitGDNSProviderID(providerID)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	if err := d.sameProject(project); err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	doc, found, rerr := d.getDNSZone(project, zone)
	if rerr != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown", Reason: "pre-delete read gave no answer — reconcile: " + rerr.Error()}
	}
	if !found {
		return provider.CreateResult{ProviderID: providerID, Status: "succeeded"} // idempotent
	}
	if doc.Labels["groundhold-capability"] != sanitizeLabel(capability) ||
		doc.Labels["groundhold-environment"] != sanitizeLabel(environment) {
		return provider.CreateResult{Status: "failed",
			Reason: "managed zone labels do not match — refusing to delete a resource that is not ours"}
	}
	url := fmt.Sprintf("%s/projects/%s/managedZones/%s", d.dnsBase(), project, zone)
	st, body, e := d.call("DELETE", url, nil)
	if e != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown", Reason: fmt.Sprintf("delete outcome unknown: %v", e)}
	}
	if st == http.StatusNotFound {
		return provider.CreateResult{ProviderID: providerID, Status: "succeeded"}
	}
	if st >= 500 {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown", Reason: fmt.Sprintf("delete HTTP %d (server error) — reconcile", st)}
	}
	if st == http.StatusBadRequest && strings.Contains(string(body), "not empty") {
		return provider.CreateResult{Status: "failed",
			Reason: "the zone still holds records and cannot be deleted — remove the record set first (never forced): " + mutDetail(body)}
	}
	if st < 200 || st >= 300 {
		if r := provider.MutationResult(st, gcpErrCode(body), nil, providerID, "delete"); r != nil {
			return *r
		}
		return provider.CreateResult{Status: "failed", Reason: fmt.Sprintf("delete HTTP %d: %s", st, mutDetail(body))}
	}
	return provider.CreateResult{ProviderID: providerID, Status: "succeeded"}
}
