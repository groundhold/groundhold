// AWS VPN Gateway network shell (D126): the EC2-Query-protocol half of the AWS
// capability.vpn.gateway driver. CreateVpnGateway returns a SERVER-ASSIGNED id
// (vgw-xxx), so — like the VPC driver — the providerId is NOT knowable before the
// response: a lost/garbled create is unknown WITHOUT a pid (honest, D29). Ownership is
// tags (DescribeVpnGateways); delete re-checks tags then DeleteVpnGateway.
package aws

import (
	"encoding/xml"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"

	"groundhold/internal/provider"
)

var vgwIDOK = regexp.MustCompile(`^vgw-[0-9a-f]+$`)

func vgwProviderID(region, vgwID string) string { return "vgw:" + region + ":" + vgwID }

func splitVgwProviderID(providerID string) (region, vgwID string, err error) {
	parts := strings.Split(providerID, ":")
	if len(parts) != 3 || parts[0] != "vgw" {
		return "", "", fmt.Errorf("providerId %q is not vgw:region:vgwId", providerID)
	}
	if !regionOK.MatchString(parts[1]) {
		return "", "", fmt.Errorf("providerId region %q is invalid", parts[1])
	}
	if !vgwIDOK.MatchString(parts[2]) {
		return "", "", fmt.Errorf("providerId vpn gateway id %q is invalid", parts[2])
	}
	return parts[1], parts[2], nil
}

func (d *Driver) createVpnGateway(region, environment, capability string,
	attrs, impl map[string]any, generation int) provider.CreateResult {
	plan, err := BuildVpnGateway(environment, capability, attrs, impl, generation)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	if plan.Region != "" {
		region = plan.Region
	}

	// create-adoption (D253, extended by D409): a vpn gateway id is SERVER-assigned and
	// CreateVpnGateway takes no idempotency token — the EC2 API offers none — so a blind
	// create on a lost ledger, or a retry after a lost response, mints a DUPLICATE
	// gateway. It is a billed resource, and a second one attached to the same VPC is
	// worse than wasted money. Scan for an existing gateway carrying our ownership tags
	// first: exactly one ours -> BIND it, never create; a FOREIGN-tagged gateway never
	// matches (the scan verifies tags itself, it does not trust the server filter);
	// ambiguous (>1) -> refuse to guess; a readable-empty or unreadable scan falls
	// through to the normal create, so a genuine first deploy is never blocked.
	if vgwID, n, serr := d.findVgwByTags(region, capability, environment); serr == nil && n == 1 {
		return provider.CreateResult{ProviderID: vgwProviderID(region, vgwID), Status: "succeeded"}
	} else if serr == nil && n > 1 {
		return provider.CreateResult{Status: "unknown",
			Reason: fmt.Sprintf("multiple vpn gateways carry our ownership tags for %s/%s — "+
				"cannot pick one to adopt; reconcile manually", capability, environment)}
	}

	st, body, err := d.ec2PostBase(region, encodeForm(plan.createParams()))
	if err != nil {
		return provider.CreateResult{Status: "unknown",
			Reason: fmt.Sprintf("create vpn gateway outcome unknown (id server-assigned, may have landed): %v", err)}
	}
	if st >= 500 {
		return provider.CreateResult{Status: "unknown",
			Reason: fmt.Sprintf("create vpn gateway HTTP %d (server error — may have landed) — reconcile", st)}
	}
	if st >= 400 {
		// D237: throttle/503/live-403 -> unknown (the vgw id is server-assigned, no
		// pid yet); only a clean 4xx refusal fails.
		if r := provider.MutationResult(st, ec2ErrCode(body), nil, "", "create vpn gateway"); r != nil {
			return *r
		}
		return provider.CreateResult{Status: "failed",
			Reason: fmt.Sprintf("create vpn gateway: HTTP %d (%s)", st, ec2ErrCode(body))}
	}
	var resp struct {
		VgwID string `xml:"vpnGateway>vpnGatewayId"`
	}
	if xml.Unmarshal(body, &resp) != nil || resp.VgwID == "" {
		return provider.CreateResult{Status: "unknown", Reason: "create vpn gateway returned no id — reconcile"}
	}
	return provider.CreateResult{ProviderID: vgwProviderID(region, resp.VgwID), Status: "succeeded"}
}

// describeVgw reads a VPN gateway's tags + state. found=false with a nil error is
// an authoritative "does not exist"; a non-nil error names the transport/HTTP/
// parse failure.
func (d *Driver) describeVgw(region, vgwID string) (tags map[string]string, found bool, err error) {
	body := encodeForm(map[string]string{"Action": "DescribeVpnGateways", "Version": ec2Version, "VpnGatewayId.1": vgwID})
	st, resp, err := d.ec2PostBase(region, body)
	if err != nil {
		return nil, false, readTransport("DescribeVpnGateways", err)
	}
	if ec2ErrCode(resp) == "InvalidVpnGatewayID.NotFound" {
		return nil, false, nil
	}
	if st != http.StatusOK {
		return nil, false, readHTTP("DescribeVpnGateways", st, ec2ErrCode(resp))
	}
	var out struct {
		Items []struct {
			VgwID string `xml:"vpnGatewayId"`
			State string `xml:"state"`
			Tags  []struct {
				Key   string `xml:"key"`
				Value string `xml:"value"`
			} `xml:"tagSet>item"`
		} `xml:"vpnGatewaySet>item"`
	}
	if xml.Unmarshal(resp, &out) != nil {
		return nil, false, readBody("DescribeVpnGateways", st) // garbled 200 is not "not found"
	}
	for _, it := range out.Items {
		if it.VgwID != vgwID {
			continue
		}
		if it.State == "deleted" {
			return nil, false, nil // a deleted gateway is authoritatively gone
		}
		m := map[string]string{}
		for _, t := range it.Tags {
			m[t.Key] = t.Value
		}
		return m, true, nil
	}
	return nil, false, nil // not in the set — does not exist
}

func (d *Driver) observeVpnGateway(capability, providerID string) ([]provider.Observation, []string, error) {
	region, vgwID, err := splitVgwProviderID(providerID)
	if err != nil {
		return nil, nil, err
	}
	_, found, rerr := d.describeVgw(region, vgwID)
	if rerr != nil {
		return nil, nil, rerr
	}
	if !found {
		// F-LC3 (D520): a BOUND resource the API authoritatively 404s is GONE.
		// A diagnostic alone leaves the binding a no-op forever (D513).
		return []provider.Observation{
			{Path: provider.ResourceAbsentPath, Value: true, Derivation: "measured"},
		}, []string{"vpn gateway not found — bound resource is gone (will re-create)"}, nil
	}
	obs := []provider.Observation{
		// Present: clear the marker (F-LC3), or a stale "gone" survives a re-create.
		{Path: provider.ResourceAbsentPath, Value: false, Derivation: "measured"},
		{Path: "location.region", Value: region, Derivation: "measured"},
		{Path: "service.managed", Value: true, Derivation: "measured"},
		// a virtual private gateway is IPv4-only at the gateway level.
		{Path: "ip.stack", Value: "ipv4", Derivation: "config-intent"},
	}
	return obs, nil, nil
}

func (d *Driver) deleteVpnGateway(capability, environment, providerID string) provider.CreateResult {
	region, vgwID, err := splitVgwProviderID(providerID)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	tags, found, rerr := d.describeVgw(region, vgwID)
	if rerr != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown", Reason: "pre-delete read gave no answer — reconcile: " + rerr.Error()}
	}
	if !found {
		return provider.CreateResult{ProviderID: providerID, Status: "succeeded"} // idempotent
	}
	if !groundholdTagsMatch(tags, capability, environment) {
		return provider.CreateResult{Status: "failed",
			Reason: "vpn gateway tags do not match — refusing to delete a resource that is not ours"}
	}
	st, resp, err := d.ec2PostBase(region, encodeForm(map[string]string{
		"Action": "DeleteVpnGateway", "Version": ec2Version, "VpnGatewayId": vgwID}))
	if err != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown",
			Reason: fmt.Sprintf("delete outcome unknown: %v", err)}
	}
	if ec2ErrCode(resp) == "InvalidVpnGatewayID.NotFound" {
		return provider.CreateResult{ProviderID: providerID, Status: "succeeded"} // idempotent
	}
	if ec2ErrCode(resp) == "IncorrectState" || ec2ErrCode(resp) == "DependencyViolation" {
		return provider.CreateResult{Status: "failed",
			Reason: "vpn gateway is still attached to a VPC or has active connections — detach them first (never forced)"}
	}
	if st >= 500 {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown",
			Reason: fmt.Sprintf("delete HTTP %d (server error) — reconcile", st)}
	}
	if st < 200 || st >= 300 {
		// D237: throttle/503/live-403 -> unknown WITH the pid (keep the handle), never failed.
		if r := provider.MutationResult(st, ec2ErrCode(resp), nil, providerID, "delete vpn gateway"); r != nil {
			return *r
		}
		return provider.CreateResult{Status: "failed", Reason: fmt.Sprintf("delete HTTP %d (%s)", st, ec2ErrCode(resp))}
	}
	// ---- poll to absence (D968 class, D981) ----
	// DeleteVpnGateway is async: the gateway enters "deleting", not gone. Reporting
	// succeeded here tombstones an hourly-billable gateway still live. Poll describeVgw
	// to a confirmed absence; unknown on timeout keeps the handle.
	deadline := d.Now().Add(d.PollTimeout)
	for {
		if _, found, rerr := d.describeVgw(region, vgwID); rerr == nil && !found {
			return provider.CreateResult{ProviderID: providerID, Status: "succeeded"} // confirmed gone
		}
		if d.Now().After(deadline) {
			return provider.CreateResult{ProviderID: providerID, Status: "unknown",
				Reason: "vpn gateway still deleting at poll timeout — reconcile via DescribeVpnGateways"}
		}
		time.Sleep(d.PollInterval)
	}
}

// findVgwByTags scans for a vpn gateway carrying our ownership tags and returns (when
// there is exactly one) its id. It VERIFIES the tags on each gateway that comes back —
// never trusting the server-side filter alone — so a foreign gateway can never be
// adopted. Any transport/HTTP/parse failure returns an error, and the caller then falls
// back to a normal create rather than blocking a genuine first deploy. Mirrors
// findVpcByTags (D253).
func (d *Driver) findVgwByTags(region, capability, environment string) (vgwID string, count int, err error) {
	body := encodeForm(map[string]string{"Action": "DescribeVpnGateways", "Version": ec2Version,
		"Filter.1.Name": "tag:groundhold-capability", "Filter.1.Value.1": sanitizeTag(capability),
		"Filter.2.Name": "tag:groundhold-environment", "Filter.2.Value.1": sanitizeTag(environment),
		"Filter.3.Name": "state", "Filter.3.Value.1": "available"})
	st, resp, e := d.ec2PostBase(region, body)
	if e != nil {
		return "", 0, readTransport("DescribeVpnGateways", e)
	}
	if st != http.StatusOK {
		return "", 0, readHTTP("DescribeVpnGateways", st, ec2ErrCode(resp))
	}
	var out struct {
		Items []struct {
			VgwID string `xml:"vpnGatewayId"`
			State string `xml:"state"`
			Tags  []struct {
				Key   string `xml:"key"`
				Value string `xml:"value"`
			} `xml:"tagSet>item"`
		} `xml:"vpnGatewaySet>item"`
	}
	if xml.Unmarshal(resp, &out) != nil {
		return "", 0, readBody("DescribeVpnGateways", st)
	}
	var owned []string
	for _, v := range out.Items {
		m := map[string]string{}
		for _, t := range v.Tags {
			m[t.Key] = t.Value
		}
		if v.VgwID != "" && v.State != "deleted" && v.State != "deleting" &&
			groundholdTagsMatch(m, capability, environment) {
			owned = append(owned, v.VgwID)
		}
	}
	if len(owned) == 1 {
		return owned[0], 1, nil
	}
	return "", len(owned), nil
}
