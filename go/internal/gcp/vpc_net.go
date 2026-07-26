// VPC network shell + security (D83 slice 2): the thin, httptest-covered half
// of the fourth GCP service. Unlike the single-resource drivers, a private
// network is MULTI-RESOURCE (network -> regional subnet -> optional egress
// firewall), so createVPC is a three-phase state machine: the providerId is
// attached the moment the NETWORK exists (so the ledger binds a partial and a
// re-run/retire can target it), and only an all-resources-present-and-matching
// outcome is `succeeded` — a network without its subnet, or a subnet without
// the egress firewall the contract requires, is `failed`/`unknown`, never a
// lie. Ownership rides in the `description` marker (VPC has no labels), parsed
// not substring-matched. Operations are polled global- or regional-scoped.
package gcp

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"groundhold/internal/provider"
)

func (d *Driver) computeBase() string {
	if d.ComputeBaseURL != "" {
		return d.ComputeBaseURL
	}
	return computeBaseURL
}

func vpcProviderID(project, region, name string) string {
	return "vpc:" + project + ":" + region + ":" + name
}

// splitVPCProviderID validates every component before path interpolation (D73).
// Region rides along because Observe cannot re-derive the subnet name (its hash
// tail differs from the network's) — regional lookups need the scope.
func splitVPCProviderID(providerID string) (project, region, name string, err error) {
	parts := strings.Split(providerID, ":")
	if len(parts) != 4 || parts[0] != "vpc" {
		return "", "", "", fmt.Errorf("providerId %q is not vpc:project:region:name", providerID)
	}
	for i, p := range parts[1:] {
		if !gcpName.MatchString(p) {
			return "", "", "", fmt.Errorf(
				"providerId component %d (%q) is not a valid GCP identifier", i+1, p)
		}
	}
	return parts[1], parts[2], parts[3], nil
}

// parseVPCMarker extracts the ownership marker from a resource description —
// VPC resources have no labels. Parsed, not whole-string equality, so a future
// "groundhold:...;k=v" extension cannot lock the driver out of its own resources.
func parseVPCMarker(desc string) (capability, environment string, ok bool) {
	const p = "groundhold:"
	i := strings.Index(desc, p)
	if i < 0 {
		return "", "", false
	}
	for _, kv := range strings.Split(desc[i+len(p):], ";") {
		k, v, found := strings.Cut(kv, "=")
		switch {
		case !found:
			continue
		case k == "capability":
			capability = v
		case k == "environment":
			environment = v
		}
	}
	return capability, environment, capability != "" && environment != ""
}

// markerOurs compares a description's marker to the sanitized inputs (the write
// side sanitized). Returns false for a missing/foreign marker — the CALLER
// decides unreadable-vs-not-ours from the GET status (three-valued).
func markerOurs(desc, capability, environment string) bool {
	cap, env, ok := parseVPCMarker(desc)
	return ok && cap == sanitizeLabel(capability) && env == sanitizeLabel(environment)
}

// pollComputeOperation polls a Compute LRO. scope is "global" or
// "regions/<region>". DONE with ANY non-nil error is failed; timeout is unknown
// with a scope-prefixed OperationID; an empty op name never reaches here.
func (d *Driver) pollComputeOperation(scope, opName string) provider.CreateResult {
	if opName == "" || !gcpName.MatchString(opName) {
		return provider.CreateResult{Status: "unknown",
			Reason: "operation name missing or invalid — reconcile"}
	}
	deadline := d.Now().Add(d.PollTimeout)
	for {
		status, body, err := d.call("GET", fmt.Sprintf(
			"%s/projects/%s/%s/operations/%s", d.computeBase(), d.Project, scope, opName), nil)
		if err == nil && status == http.StatusOK {
			var op struct {
				Status string `json:"status"`
				Error  *struct {
					Errors []struct {
						Code string `json:"code"`
					} `json:"errors"`
				} `json:"error"`
			}
			if json.Unmarshal(body, &op) == nil && op.Status == "DONE" {
				if op.Error != nil {
					code := "unspecified"
					if len(op.Error.Errors) > 0 {
						code = op.Error.Errors[0].Code
					}
					return provider.CreateResult{Status: "failed",
						Reason: "operation failed: " + code}
				}
				return provider.CreateResult{Status: "succeeded"}
			}
		}
		if d.Now().After(deadline) {
			return provider.CreateResult{Status: "unknown",
				OperationID: scope + ":" + opName,
				Reason:      "compute operation still running at poll timeout — reconcile"}
		}
		time.Sleep(d.PollInterval)
	}
}

// computeInsert issues one insert and polls its operation. A 409 returns
// status=409 to the caller for per-resource reconciliation; every other outcome
// maps by the D29 discipline (5xx unknown, 4xx failed, empty op unknown).
func (d *Driver) computeInsert(url string, body map[string]any, scope string) (int, provider.CreateResult) {
	status, respBody, err := d.call("POST", url, body)
	if err != nil {
		return 0, provider.CreateResult{Status: "unknown",
			Reason: fmt.Sprintf("insert outcome unknown: %v", err)}
	}
	if status == http.StatusConflict {
		return http.StatusConflict, provider.CreateResult{}
	}
	if status >= 400 {
		return status, mutationResult("insert", status, respBody)
	}
	var op struct {
		Name string `json:"name"`
	}
	if json.Unmarshal(respBody, &op) != nil || op.Name == "" {
		return status, provider.CreateResult{Status: "unknown",
			Reason: "insert response carried no operation — reconcile"}
	}
	return status, d.pollComputeOperation(scope, op.Name)
}

// computeGet fetches a resource and returns (description, found, why-not).
// A 404 is an authoritative absence (found=false, nil error); a transport
// error, any other non-200, or an unparseable body is a named read failure —
// never silently treated as "not ours".
func (d *Driver) computeGet(url string) (desc string, found bool, err error) {
	const op = "compute.get"
	status, body, cerr := d.call("GET", url, nil)
	if cerr != nil {
		return "", false, readTransport(op, cerr)
	}
	if status == http.StatusNotFound {
		return "", false, nil
	}
	if status != http.StatusOK {
		return "", false, readHTTP(op, status, gcpErrCode(body))
	}
	var r struct {
		Description string `json:"description"`
	}
	if json.Unmarshal(body, &r) != nil {
		return "", false, readBody(op, status)
	}
	return r.Description, true, nil
}

// networkDoc is the network reconcile/observe read.
type networkDoc struct {
	Description           string   `json:"description"`
	AutoCreateSubnetworks bool     `json:"autoCreateSubnetworks"`
	Subnetworks           []string `json:"subnetworks"`
}

func (d *Driver) getNetwork(project, name string) (doc networkDoc, found bool, err error) {
	const op = "networks.get"
	status, body, cerr := d.call("GET", fmt.Sprintf(
		"%s/projects/%s/global/networks/%s", d.computeBase(), project, name), nil)
	if cerr != nil {
		return networkDoc{}, false, readTransport(op, cerr)
	}
	if status == http.StatusNotFound {
		return networkDoc{}, false, nil
	}
	if status != http.StatusOK {
		return networkDoc{}, false, readHTTP(op, status, gcpErrCode(body))
	}
	if json.Unmarshal(body, &doc) != nil {
		return networkDoc{}, false, readBody(op, status)
	}
	return doc, true, nil
}

// createVPC: network (global) -> subnet (regional) -> optional egress firewall
// (global). The providerId is attached once the network exists; a partial is
// failed/unknown WITH the pid, never succeeded.
func (d *Driver) createVPC(capability, environment string,
	attrs, impl map[string]any, generation int) provider.CreateResult {
	plan, err := BuildVPCRequests(d.Project, environment, capability, attrs, impl, generation)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	region, _ := attrs["location.region"].(string)
	cb := d.computeBase()
	pid := vpcProviderID(d.Project, region, plan.NetworkName)

	// ---- Phase N: network (global) ----
	netURL := fmt.Sprintf("%s/projects/%s/global/networks", cb, d.Project)
	st, res := d.computeInsert(netURL, plan.Network.Body, "global")
	if st == http.StatusConflict {
		doc, found, rerr := d.getNetwork(d.Project, plan.NetworkName)
		switch {
		case rerr != nil:
			return provider.CreateResult{Status: "unknown",
				Reason: "network name conflict, existing network gave no answer — reconcile: " + rerr.Error()}
		case !found:
			return provider.CreateResult{Status: "unknown",
				Reason: "network name conflict, but the conflicting network was gone on the follow-up read — reconcile"}
		case !markerOurs(doc.Description, capability, environment):
			return provider.CreateResult{Status: "failed",
				Reason: "a network with this name exists but is not ours (marker mismatch)"}
		case doc.AutoCreateSubnetworks:
			return provider.CreateResult{Status: "failed",
				Reason: "existing network is auto-mode; conversion is not wired — " +
					"this is a replacement, not a conflict"}
		}
		// ours + custom mode: fall through to the subnet phase (partial-reconcile)
	} else if res.Status != "succeeded" {
		// a 4xx failed is nothing durable; but a lost/5xx UNKNOWN may have landed
		// the network (D29) — the name is deterministic, so carry the pid so a
		// re-run/retire can target an orphan (handle never lost).
		if res.Status == "unknown" {
			res.ProviderID = pid
		}
		return res
	}

	// ---- Phase S: subnet (regional) ----
	subURL := fmt.Sprintf("%s/projects/%s/regions/%s/subnetworks", cb, d.Project, region)
	subGetURL := fmt.Sprintf("%s/projects/%s/regions/%s/subnetworks/%s",
		cb, d.Project, region, plan.Subnet.Body["name"])
	scope := "regions/" + region
	st, res = d.computeInsert(subURL, plan.Subnet.Body, scope)
	if st == http.StatusConflict {
		desc, sfound, rerr := d.computeGet(subGetURL)
		switch {
		case rerr != nil:
			return provider.CreateResult{ProviderID: pid, Status: "unknown",
				Reason: "network created; subnet read gave no answer on conflict — reconcile: " + rerr.Error()}
		case !sfound:
			return provider.CreateResult{ProviderID: pid, Status: "unknown",
				Reason: "network created; the conflicting subnet was gone on the follow-up read — reconcile"}
		case !markerOurs(desc, capability, environment):
			return provider.CreateResult{ProviderID: pid, Status: "failed",
				Reason: "network exists but its subnet name is taken by a foreign resource"}
		}
		// ours — treat as converged for this phase
	} else if res.Status != "succeeded" {
		res.ProviderID = pid // partial: the network exists — bind it (D29)
		if res.Status == "failed" {
			res.Reason = "network created without its subnet: " + res.Reason
		}
		return res
	}

	// ---- Phase R: Cloud NAT router (regional), only for egress.internet=nat ----
	// The network + subnet already stand, so ANY failure here is a PARTIAL composite:
	// unknown/failed WITH the pid (a network whose egress road is not yet wired —
	// reconcile), never a bare failure that implies nothing was created (D29).
	if plan.NATRouter != nil {
		rtrName, _ := plan.NATRouter.Body["name"].(string)
		rtrURL := fmt.Sprintf("%s/projects/%s/regions/%s/routers", cb, d.Project, region)
		rtrGetURL := fmt.Sprintf("%s/projects/%s/regions/%s/routers/%s", cb, d.Project, region, rtrName)
		st, res = d.computeInsert(rtrURL, plan.NATRouter.Body, scope)
		if st == http.StatusConflict {
			desc, rfound, rerr := d.computeGet(rtrGetURL)
			if rerr != nil {
				return provider.CreateResult{ProviderID: pid, Status: "unknown",
					Reason: "network+subnet created; NAT router read gave no answer on conflict — reconcile: " + rerr.Error()}
			}
			if !rfound {
				return provider.CreateResult{ProviderID: pid, Status: "unknown",
					Reason: "network+subnet created; the conflicting NAT router was gone on the follow-up read — reconcile"}
			}
			if !markerOurs(desc, capability, environment) {
				return provider.CreateResult{ProviderID: pid, Status: "failed",
					Reason: "NAT router name taken by a foreign resource — " +
						"egress.internet=nat is NOT realized"}
			}
			// ours — treat as converged for this phase
		} else if res.Status != "succeeded" {
			res.ProviderID = pid
			if res.Status == "failed" {
				res.Reason = "network+subnet created but the Cloud NAT router failed " +
					"(egress.internet=nat NOT realized): " + res.Reason
			}
			return res
		}
	}

	// ---- Phase F: egress firewall (global), only if required ----
	if plan.EgressFirewall != nil {
		fwName, _ := plan.EgressFirewall.Body["name"].(string)
		fwURL := fmt.Sprintf("%s/projects/%s/global/firewalls", cb, d.Project)
		fwGetURL := fmt.Sprintf("%s/projects/%s/global/firewalls/%s", cb, d.Project, fwName)
		st, res = d.computeInsert(fwURL, plan.EgressFirewall.Body, "global")
		if st == http.StatusConflict {
			desc, ffound, rerr := d.computeGet(fwGetURL)
			if rerr != nil {
				return provider.CreateResult{ProviderID: pid, Status: "unknown",
					Reason: "network+subnet created; egress firewall read gave no answer — reconcile: " + rerr.Error()}
			}
			if !ffound {
				return provider.CreateResult{ProviderID: pid, Status: "unknown",
					Reason: "network+subnet created; the conflicting egress firewall was gone on the follow-up read — reconcile"}
			}
			if !markerOurs(desc, capability, environment) {
				return provider.CreateResult{ProviderID: pid, Status: "failed",
					Reason: "egress firewall name taken by a foreign resource — " +
						"egress is NOT restricted as the contract requires"}
			}
		} else if res.Status != "succeeded" {
			res.ProviderID = pid
			if res.Status == "failed" {
				res.Reason = "network+subnet created but egress firewall failed " +
					"(egress NOT restricted): " + res.Reason
			}
			return res
		}
	}

	return provider.CreateResult{ProviderID: pid, Status: "succeeded"}
}

// observeVPC reverse-maps the network + its subnet + firewalls. Honesty gates:
// an unreadable surface emits a diagnostic and NOTHING, never a default value;
// no owned subnet in the pinned region → a diagnostic (a partial create must
// not look converged).
func (d *Driver) observeVPC(capability, providerID string) ([]provider.Observation, []string, error) {
	project, region, name, err := splitVPCProviderID(providerID)
	if err != nil {
		return nil, nil, err
	}
	if err := d.sameProject(project); err != nil {
		return nil, nil, err
	}
	doc, found, rerr := d.getNetwork(project, name)
	if rerr != nil {
		return nil, nil, rerr
	}
	if !found {
		return nil, []string{"network not found — nothing to observe"}, nil
	}

	var obs []provider.Observation
	var diags []string
	obs = append(obs, provider.Observation{Path: "service.managed",
		Value: true, Derivation: "measured"})

	// find OUR subnet in the pinned region among the network's subnetworks[]
	subDesc, subLog, subPGA, subFound, subErr := d.findOwnedSubnet(doc, project, region, capability)
	switch {
	case subErr != nil:
		diags = append(diags, "location.region/flowLogs.enabled/serviceAccess.private "+
			"not observed: "+subErr.Error())
	case !subFound:
		diags = append(diags, "location.region/flowLogs.enabled/serviceAccess.private "+
			"not observed: no groundhold subnet in "+region+" (a partial create)")
	default:
		_ = subDesc
		obs = append(obs, provider.Observation{Path: "location.region",
			Value: region, Derivation: "measured"})
		obs = append(obs, provider.Observation{Path: "flowLogs.enabled",
			Value: subLog, Derivation: "measured"})
		// serviceAccess.private reverse-maps directly from the subnet's Private
		// Google Access flag (its whole realization) — a MEASURED read, symmetric
		// with the AWS endpoint-set superset check.
		obs = append(obs, provider.Observation{Path: "serviceAccess.private",
			Value: subPGA, Derivation: "measured"})
	}

	// egress.internet: the road is read from the regional Cloud Routers. Our router
	// carrying a Cloud NAT config => "nat"; otherwise "none". "direct" (per-instance
	// external IPs) is NOT distinguishable at the VPC layer, so it is never emitted
	// here — a diag records that the direct road is not audited.
	road, roadErr := d.observeEgressRoad(project, region, name, capability)
	if roadErr != nil {
		diags = append(diags, "egress.internet not observed: "+roadErr.Error())
	} else {
		obs = append(obs, provider.Observation{Path: "egress.internet",
			Value: road, Derivation: "measured"})
		if road == "none" {
			diags = append(diags, "egress.internet=none reflects no Cloud NAT road; "+
				"the direct road (per-instance external IPs) is not audited at the VPC layer")
		}
	}

	// egress.restricted + ingress.public from ONE firewalls.list
	fws, fwErr := d.listNetworkFirewalls(project, name)
	if fwErr != nil {
		diags = append(diags, "egress.restricted/network.publicExposure not observed: "+
			fwErr.Error())
	} else {
		obs = append(obs, provider.Observation{Path: "egress.restricted",
			Value: firewallsDenyEgress(fws, capability), Derivation: "measured"})
		obs = append(obs, provider.Observation{Path: "ingress.public",
			Value: firewallsAllowPublicIngress(fws), Derivation: "measured"})
	}
	return obs, diags, nil
}

func (d *Driver) findOwnedSubnet(doc networkDoc, project, region, capability string) (desc string, logEnabled, privateGoogleAccess, found bool, err error) {
	for _, link := range doc.Subnetworks {
		// self-link: .../regions/<region>/subnetworks/<name>
		r, n, ok := regionNameFromSubnetLink(link)
		if !ok || r != region {
			continue
		}
		const op = "subnetworks.get"
		status, body, cerr := d.call("GET", fmt.Sprintf(
			"%s/projects/%s/regions/%s/subnetworks/%s", d.computeBase(), project, r, n), nil)
		if cerr != nil {
			return "", false, false, false, readTransport(op, cerr)
		}
		if status != http.StatusOK {
			return "", false, false, false, readHTTP(op, status, gcpErrCode(body))
		}
		var sub struct {
			Description           string `json:"description"`
			PrivateIpGoogleAccess bool   `json:"privateIpGoogleAccess"`
			LogConfig             struct {
				Enable bool `json:"enable"`
			} `json:"logConfig"`
		}
		if json.Unmarshal(body, &sub) != nil {
			return "", false, false, false, readBody(op, status)
		}
		if cap, _, ok := parseVPCMarker(sub.Description); ok && cap == sanitizeLabel(capability) {
			return sub.Description, sub.LogConfig.Enable, sub.PrivateIpGoogleAccess, true, nil
		}
	}
	return "", false, false, false, nil // read, but none ours
}

// observeEgressRoad reads the egress ROAD from the regional Cloud Routers: our
// router (by marker, on this network) that carries a Cloud NAT config => "nat";
// otherwise "none". A list that gives no answer returns the error — never a
// confident "none".
func (d *Driver) observeEgressRoad(project, region, network, capability string) (road string, err error) {
	const op = "routers.list"
	status, body, cerr := d.call("GET", fmt.Sprintf(
		"%s/projects/%s/regions/%s/routers", d.computeBase(), project, region), nil)
	if cerr != nil {
		return "", readTransport(op, cerr)
	}
	if status != http.StatusOK {
		return "", readHTTP(op, status, gcpErrCode(body))
	}
	var list struct {
		Items []struct {
			Description string           `json:"description"`
			Network     string           `json:"network"`
			Nats        []map[string]any `json:"nats"`
		} `json:"items"`
	}
	if json.Unmarshal(body, &list) != nil {
		return "", readBody(op, status)
	}
	netSuffix := "/networks/" + network
	for _, r := range list.Items {
		// observe gates ownership by capability only (symmetric with findOwnedSubnet
		// and the firewall observers) — the environment tail is not in scope here.
		if cap, _, ok := parseVPCMarker(r.Description); !ok || cap != sanitizeLabel(capability) {
			continue
		}
		if r.Network != "" && !strings.HasSuffix(r.Network, netSuffix) {
			continue // ours by marker but on another network — not this VPC's road
		}
		if len(r.Nats) > 0 {
			return "nat", nil
		}
	}
	return "none", nil
}

type fwRule struct {
	Name         string           `json:"name"`
	Description  string           `json:"description"`
	Direction    string           `json:"direction"`
	Disabled     bool             `json:"disabled"`
	SourceRanges []string         `json:"sourceRanges"`
	Denied       []map[string]any `json:"denied"`
	Allowed      []map[string]any `json:"allowed"`
	DestRanges   []string         `json:"destinationRanges"`
}

func (d *Driver) listNetworkFirewalls(project, network string) ([]fwRule, error) {
	const op = "firewalls.list"
	netLink := fmt.Sprintf("%s/projects/%s/global/networks/%s", d.computeBase(), project, network)
	q := url.QueryEscape(fmt.Sprintf("network=%q", netLink))
	status, body, cerr := d.call("GET", fmt.Sprintf(
		"%s/projects/%s/global/firewalls?filter=%s", d.computeBase(), project, q), nil)
	if cerr != nil {
		return nil, readTransport(op, cerr)
	}
	if status != http.StatusOK {
		return nil, readHTTP(op, status, gcpErrCode(body))
	}
	var list struct {
		Items []fwRule `json:"items"`
	}
	if json.Unmarshal(body, &list) != nil {
		return nil, readBody(op, status)
	}
	return list.Items, nil
}

func firewallsDenyEgress(fws []fwRule, capability string) bool {
	for _, f := range fws {
		if f.Disabled || f.Direction != "EGRESS" {
			continue
		}
		for _, den := range f.Denied {
			if den["IPProtocol"] == "all" && containsCIDR(f.DestRanges, "0.0.0.0/0") {
				return true
			}
		}
	}
	return false
}

func firewallsAllowPublicIngress(fws []fwRule) bool {
	for _, f := range fws {
		if f.Disabled || f.Direction == "EGRESS" {
			continue // ingress rules have direction INGRESS or empty (default)
		}
		if len(f.Allowed) > 0 && (containsCIDR(f.SourceRanges, "0.0.0.0/0") ||
			containsCIDR(f.SourceRanges, "::/0")) {
			return true
		}
	}
	return false
}

func containsCIDR(ranges []string, want string) bool {
	for _, r := range ranges {
		if r == want {
			return true
		}
	}
	return false
}

func regionNameFromSubnetLink(link string) (region, name string, ok bool) {
	// .../regions/<region>/subnetworks/<name>
	ri := strings.Index(link, "/regions/")
	si := strings.Index(link, "/subnetworks/")
	if ri < 0 || si < 0 || si < ri {
		return "", "", false
	}
	region = link[ri+len("/regions/") : si]
	name = link[si+len("/subnetworks/"):]
	if !gcpName.MatchString(region) || !gcpName.MatchString(name) {
		return "", "", false
	}
	return region, name, true
}

// deleteVPC: reverse order (firewalls -> subnet -> network), each ours-by-marker.
// A dependency conflict is data-loss friction (stateful), surfaced never forced.
func (d *Driver) deleteVPC(capability, environment, providerID string) provider.CreateResult {
	project, region, name, err := splitVPCProviderID(providerID)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	if err := d.sameProject(project); err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	doc, found, rerr := d.getNetwork(project, name)
	if rerr != nil {
		return provider.CreateResult{Status: "unknown",
			Reason: "pre-delete network read gave no answer — refusing an ambiguous delete: " + rerr.Error()}
	}
	if !found {
		return provider.CreateResult{ProviderID: providerID, Status: "succeeded"} // idempotent
	}
	if !markerOurs(doc.Description, capability, environment) {
		return provider.CreateResult{Status: "failed",
			Reason: "network marker does not match — refusing to delete a resource that is not ours"}
	}

	// 1. firewalls attached to our network, that are ours
	fws, fwErr := d.listNetworkFirewalls(project, name)
	if fwErr != nil {
		return provider.CreateResult{Status: "unknown",
			Reason: "cannot list firewalls — refusing to delete a network whose rules are unknown: " + fwErr.Error()}
	}
	for _, f := range fws {
		if !markerOurs(f.Description, capability, environment) {
			continue // not ours — leave foreign rules alone
		}
		if f.Name == "" || !gcpName.MatchString(f.Name) {
			continue
		}
		if r := d.computeDelete(fmt.Sprintf("%s/projects/%s/global/firewalls/%s",
			d.computeBase(), project, f.Name), "global"); r.Status != "succeeded" {
			r.ProviderID = providerID // the network still exists — keep the handle
			return r
		}
	}

	// 1b. Cloud NAT routers (egress.internet=nat) on our network, that are ours.
	// BEFORE the subnets: a Cloud NAT that covers a subnet can block that subnet's
	// delete, so the road comes down first (reverse dependency order).
	if r := d.deleteOwnedRouters(project, region, name, capability, environment); r != nil {
		r.ProviderID = providerID // the network still exists — keep the handle
		return *r
	}

	// 2. our subnets in the network
	for _, link := range doc.Subnetworks {
		r, n, ok := regionNameFromSubnetLink(link)
		if !ok {
			continue
		}
		desc, sfound, serr := d.computeGet(fmt.Sprintf("%s/projects/%s/regions/%s/subnetworks/%s",
			d.computeBase(), project, r, n))
		if serr != nil {
			return provider.CreateResult{Status: "unknown",
				Reason: "a subnet read gave no answer — refusing an ambiguous delete: " + serr.Error()}
		}
		if !sfound {
			continue // already gone — nothing to delete
		}
		if !markerOurs(desc, capability, environment) {
			continue
		}
		res := d.computeDelete(fmt.Sprintf("%s/projects/%s/regions/%s/subnetworks/%s",
			d.computeBase(), project, r, n), "regions/"+r)
		if res.Status != "succeeded" {
			if res.Status == "failed" {
				res.Reason = "subnet has attached resources — retiring would strand " +
					"them; remove them explicitly first (retirement is data loss): " + res.Reason
			}
			res.ProviderID = providerID // the network still exists — keep the handle
			return res
		}
	}

	// 3. the network last
	res := d.computeDelete(fmt.Sprintf("%s/projects/%s/global/networks/%s",
		d.computeBase(), project, name), "global")
	if res.Status == "failed" {
		res.Reason = "network still has dependencies (peering/foreign subnets/" +
			"private-service connections) — remove them explicitly first: " + res.Reason
	}
	// succeeded binds the retired identity; a lost/failed final delete keeps the
	// handle too — the network may still exist, so retire can retry (D29).
	res.ProviderID = providerID
	return res
}

// deleteOwnedRouters tears down the Cloud NAT road: our regional routers (by
// marker, on this network) — deleting a router removes its nested Cloud NAT.
// Ownership-gated (foreign routers are never touched) and scoped to THIS network
// (so a sibling generation's router on another network survives). An unreadable
// list refuses the whole delete rather than orphan a road or claim a false
// retirement. nil = the road (or its absence) is cleared.
func (d *Driver) deleteOwnedRouters(project, region, network, capability, environment string) *provider.CreateResult {
	status, body, err := d.call("GET", fmt.Sprintf(
		"%s/projects/%s/regions/%s/routers", d.computeBase(), project, region), nil)
	if err != nil {
		return &provider.CreateResult{Status: "unknown",
			Reason: fmt.Sprintf("cannot list Cloud routers: %v — refusing an ambiguous delete", err)}
	}
	if status == http.StatusNotFound {
		return nil // no routers collection reachable/empty — nothing to tear down
	}
	if status != http.StatusOK {
		return &provider.CreateResult{Status: "unknown",
			Reason: "cannot list Cloud routers — refusing to delete a network whose NAT road is unknown"}
	}
	var list struct {
		Items []struct {
			Name        string `json:"name"`
			Description string `json:"description"`
			Network     string `json:"network"`
		} `json:"items"`
	}
	if json.Unmarshal(body, &list) != nil {
		return &provider.CreateResult{Status: "unknown",
			Reason: "Cloud router list unparseable — refusing an ambiguous delete"}
	}
	netSuffix := "/networks/" + network
	for _, r := range list.Items {
		if !markerOurs(r.Description, capability, environment) {
			continue // not ours — leave foreign routers alone
		}
		if r.Network != "" && !strings.HasSuffix(r.Network, netSuffix) {
			continue // ours by marker but on another network
		}
		if r.Name == "" || !gcpName.MatchString(r.Name) {
			continue
		}
		res := d.computeDelete(fmt.Sprintf("%s/projects/%s/regions/%s/routers/%s",
			d.computeBase(), project, region, r.Name), "regions/"+region)
		if res.Status != "succeeded" {
			return &res
		}
	}
	return nil
}

func (d *Driver) computeDelete(url, scope string) provider.CreateResult {
	status, body, err := d.call("DELETE", url, nil)
	if err != nil {
		return provider.CreateResult{Status: "unknown",
			Reason: fmt.Sprintf("delete outcome unknown: %v", err)}
	}
	if status == http.StatusNotFound {
		return provider.CreateResult{Status: "succeeded"} // idempotent on absence
	}
	if status >= 400 {
		return mutationResult("delete", status, body)
	}
	var op struct {
		Name string `json:"name"`
	}
	if json.Unmarshal(body, &op) != nil || op.Name == "" {
		return provider.CreateResult{Status: "unknown",
			Reason: "delete response carried no operation — reconcile"}
	}
	return d.pollComputeOperation(scope, op.Name)
}
