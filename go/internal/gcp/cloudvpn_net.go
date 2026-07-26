// Cloud VPN network shell (D126): the httptest-covered half of the GCP
// capability.vpn.gateway driver. vpnGateways.insert is a regional compute LRO
// (reusing computeInsert/pollComputeOperation). The gateway name is deterministic, so
// the providerId is knowable BEFORE the response (D29). Ownership is the DESCRIPTION
// marker (HA VPN gateways have no labels). Delete is an LRO; a gateway still holding
// tunnels refuses (resourceInUseByAnotherResource) — never forced.
package gcp

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"groundhold/internal/provider"
)

func cloudVPNProviderID(project, region, name string) string {
	return "gvpn:" + project + ":" + region + ":" + name
}

func splitCloudVPNProviderID(providerID string) (project, region, name string, err error) {
	parts := strings.Split(providerID, ":")
	if len(parts) != 4 || parts[0] != "gvpn" {
		return "", "", "", fmt.Errorf("providerId %q is not gvpn:project:region:name", providerID)
	}
	for i, p := range parts[1:] {
		if !gcpName.MatchString(p) {
			return "", "", "", fmt.Errorf("providerId component %d (%q) is not a valid GCP identifier", i+1, p)
		}
	}
	return parts[1], parts[2], parts[3], nil
}

func (d *Driver) cloudVPNURL(project, region, name string) string {
	return fmt.Sprintf("%s/projects/%s/regions/%s/vpnGateways/%s", d.computeBase(), project, region, name)
}

type cloudVPNDoc struct {
	Description string `json:"description"`
	StackType   string `json:"stackType"`
}

func (d *Driver) cloudVPNGet(project, region, name string) (cloudVPNDoc, bool, error) {
	const op = "cloudVPNGet.get"
	st, body, err := d.call("GET", d.cloudVPNURL(project, region, name), nil)
	if err != nil {
		return cloudVPNDoc{}, false, readTransport(op, err)
	}
	if st == http.StatusNotFound {
		return cloudVPNDoc{}, false, nil
	}
	if st != http.StatusOK {
		return cloudVPNDoc{}, false, readHTTP(op, st, gcpErrCode(body))
	}
	var doc cloudVPNDoc
	if json.Unmarshal(body, &doc) != nil {
		return cloudVPNDoc{}, false, readBody(op, st)
	}
	return doc, true, nil
}

func (d *Driver) createCloudVPN(capability, environment string,
	attrs, impl map[string]any, generation int) provider.CreateResult {
	plan, err := BuildCloudVPNGateway(d.Project, environment, capability, attrs, impl, generation)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	pid := cloudVPNProviderID(d.Project, plan.Region, plan.Name)
	scope := "regions/" + plan.Region
	url := fmt.Sprintf("%s/projects/%s/regions/%s/vpnGateways", d.computeBase(), d.Project, plan.Region)
	status, res := d.computeInsert(url, plan.insertBody(), scope)
	if status == http.StatusConflict {
		// exists — continue ONLY if ours (marker ownership).
		doc, found, rerr := d.cloudVPNGet(d.Project, plan.Region, plan.Name)
		if rerr != nil {
			return provider.CreateResult{ProviderID: pid, Status: "unknown", Reason: "name conflict, existing gateway gave no answer — reconcile: " + rerr.Error()}
		}
		if !found || !markerOurs(doc.Description, capability, environment) {
			return provider.CreateResult{Status: "failed", Reason: "a gateway with this name exists and is not ours (marker does not match)"}
		}
		return provider.CreateResult{ProviderID: pid, Status: "succeeded"}
	}
	if res.Status == "succeeded" {
		res.ProviderID = pid
	} else if res.Status == "unknown" && res.ProviderID == "" {
		res.ProviderID = pid // a 5xx/lost op may have landed — keep the deterministic handle
	}
	return res
}

func (d *Driver) observeCloudVPN(capability, providerID string) ([]provider.Observation, []string, error) {
	project, region, name, err := splitCloudVPNProviderID(providerID)
	if err != nil {
		return nil, nil, err
	}
	if err := d.sameProject(project); err != nil {
		return nil, nil, err
	}
	doc, found, rerr := d.cloudVPNGet(project, region, name)
	if rerr != nil {
		return nil, nil, rerr
	}
	if !found {
		return nil, []string{"vpn gateway not found — nothing to observe"}, nil
	}
	stack := "ipv4"
	if doc.StackType == "IPV4_IPV6" {
		stack = "dual-stack"
	}
	obs := []provider.Observation{
		{Path: "location.region", Value: region, Derivation: "measured"},
		{Path: "service.managed", Value: true, Derivation: "measured"},
		{Path: "ip.stack", Value: stack, Derivation: "measured"},
	}
	return obs, nil, nil
}

func (d *Driver) deleteCloudVPN(capability, environment, providerID string) provider.CreateResult {
	project, region, name, err := splitCloudVPNProviderID(providerID)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	if err := d.sameProject(project); err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	doc, found, rerr := d.cloudVPNGet(project, region, name)
	if rerr != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown", Reason: "pre-delete read gave no answer — reconcile: " + rerr.Error()}
	}
	if !found {
		return provider.CreateResult{ProviderID: providerID, Status: "succeeded"} // idempotent
	}
	if !markerOurs(doc.Description, capability, environment) {
		return provider.CreateResult{Status: "failed",
			Reason: "gateway marker does not match — refusing to delete a resource that is not ours"}
	}
	status, respBody, err := d.call("DELETE", d.cloudVPNURL(project, region, name), nil)
	if err != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown", Reason: fmt.Sprintf("delete outcome unknown: %v", err)}
	}
	if status == http.StatusNotFound {
		return provider.CreateResult{ProviderID: providerID, Status: "succeeded"}
	}
	if status >= 400 {
		if strings.Contains(string(respBody), "resourceInUseByAnotherResource") {
			return provider.CreateResult{Status: "failed",
				Reason: "gateway still has tunnels attached — delete them first (never forced)"}
		}
		res := mutationResult("delete", status, respBody)
		if res.Status == "unknown" {
			res.ProviderID = providerID
		}
		return res
	}
	var op struct {
		Name string `json:"name"`
	}
	if json.Unmarshal(respBody, &op) != nil || op.Name == "" {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown", Reason: "delete response carried no operation — reconcile"}
	}
	res := d.pollComputeOperation("regions/"+region, op.Name)
	if res.Status == "succeeded" {
		res.ProviderID = providerID
	} else if res.Status == "unknown" {
		res.ProviderID = providerID
	}
	return res
}
