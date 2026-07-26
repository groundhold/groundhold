// AWS receipt reconciliation, BATCH 8 (D57): six services whose identity is
// SERVER-ASSIGNED at create with NO practical list-by-tag wrapper to recover it —
// vpc, kms, cloudfront, apigateway, route53health, vpngateway. Unlike the
// deterministically-named services (eks/elasticache, which recompute the id),
// these rely on TIER 1: the providerId persisted on the receipt. Apply now
// persists the id even for an unknown create, so a modern receipt carries it; a
// pre-persistence receipt honestly CANNOT be concluded here (unknown, never a
// fabricated verdict). STRICTLY READ-ONLY — split the pid to validate, DESCRIBE by
// that id, conclude four-valued via concludeByStatus.
package aws

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"net/http"
	"strings"

	"groundhold/internal/provider"
)

// rc8Unrecorded is the honest refusal when the receipt carries no targetProviderId
// (a pre-persistence pending create). The id is server-assigned and was not
// recorded, so reconcile has no handle to read — unknown keeps the receipt pending.
func rc8Unrecorded(service string) provider.ReconcileResult {
	return provider.ReconcileResult{Status: "unknown",
		Reason: service + " id is server-assigned and was not recorded on the receipt — reconcile manually"}
}

// rc8BadPID refuses when the recorded providerId does not parse — a malformed handle
// cannot address a resource, so we never guess against the wrong one.
func rc8BadPID(service string, err error) provider.ReconcileResult {
	return provider.ReconcileResult{Status: "unknown",
		Reason: service + " reconcile could not parse the recorded providerId: " + err.Error()}
}

// reconcileVPC concludes a pending VPC create from the tier-1 pid. DescribeVpcs
// surfaces existence + ownership tags; a VPC returned by the API is synchronously
// available (there is no long provisioning phase and the reference describe carries
// no transient state), so existence is the readiness proxy. Region-scoped — the
// region travels IN the pid.
func (d *Driver) reconcileVPC(capability, environment, providerID string) provider.ReconcileResult {
	if providerID == "" {
		return rc8Unrecorded("vpc")
	}
	region, vpcID, err := splitAWSVpcProviderID(providerID)
	if err != nil {
		return rc8BadPID("vpc", err)
	}
	tags, found, rerr := d.describeVpc(region, vpcID)
	ours := found && groundholdTagsMatch(tags, capability, environment)
	return concludeByStatus(providerID, "vpc "+vpcID, found, rerr, ours, found, false)
}

// reconcileKMS concludes a pending KMS key create from the tier-1 pid. DescribeKey
// gives the KeyState (Enabled → ready; PendingDeletion → terminal-failed); a
// separate ListResourceTags read establishes ownership. Region-scoped (region in
// the pid). A NotFound describe is a readable absence — the create did not land.
func (d *Driver) reconcileKMS(capability, environment, providerID string) provider.ReconcileResult {
	if providerID == "" {
		return rc8Unrecorded("kms")
	}
	region, keyID, err := splitAWSKMSProviderID(providerID)
	if err != nil {
		return rc8BadPID("kms", err)
	}
	state, found, rerr := d.rc8DescribeKMSState(region, keyID)
	ours := false
	if found {
		tags, terr := d.kmsTags(region, keyID)
		if terr != nil {
			rerr = terr // ownership gave no answer — cannot attribute it; unknown
		} else {
			ours = groundholdTagsMatch(tags, capability, environment)
		}
	}
	return concludeByStatus(providerID, "kms key "+keyID, found, rerr, ours,
		state == "Enabled", state == "PendingDeletion")
}

// reconcileCloudFront concludes a pending distribution create from the tier-1 pid.
// CloudFront is GLOBAL (no region guard). GetDistribution gives the Status (Deployed
// → ready; InProgress → still provisioning → unknown); ownership is a separate
// ListTagsForResource read keyed by the distribution ARN.
func (d *Driver) reconcileCloudFront(capability, environment, providerID string) provider.ReconcileResult {
	if providerID == "" {
		return rc8Unrecorded("cloudfront")
	}
	_, distID, err := splitCFProviderID(providerID)
	if err != nil {
		return rc8BadPID("cloudfront", err)
	}
	doc, _, found, rerr := d.getCF(distID)
	ours := false
	if found {
		tags, terr := d.cfTags(doc.ARN)
		if terr != nil {
			rerr = terr
		} else {
			ours = groundholdTagsMatch(tags, capability, environment)
		}
	}
	return concludeByStatus(providerID, "cloudfront distribution "+distID, found, rerr, ours,
		doc.Status == "Deployed", false)
}

// reconcileApiGW concludes a pending HTTP API create from the tier-1 pid. An HTTP
// API is synchronous once created, so existence is readiness; GetApi returns the
// ownership tags inline. Region-scoped (region in the pid).
func (d *Driver) reconcileApiGW(capability, environment, providerID string) provider.ReconcileResult {
	if providerID == "" {
		return rc8Unrecorded("apigateway")
	}
	region, _, apiID, err := splitApiGWProviderID(providerID)
	if err != nil {
		return rc8BadPID("apigateway", err)
	}
	api, found, rerr := d.getAPI(region, apiID)
	ours := found && groundholdTagsMatch(api.Tags, capability, environment)
	return concludeByStatus(providerID, "api "+apiID, found, rerr, ours, found, false)
}

// reconcileRoute53Health concludes a pending health-check create from the tier-1
// pid. Route 53 is GLOBAL (no region guard). GetHealthCheck is synchronous, so
// existence is readiness; a separate ListTagsForResource read establishes ownership.
func (d *Driver) reconcileRoute53Health(capability, environment, providerID string) provider.ReconcileResult {
	if providerID == "" {
		return rc8Unrecorded("route53health")
	}
	id, err := splitR53HCProviderID(providerID)
	if err != nil {
		return rc8BadPID("route53health", err)
	}
	found, rerr := d.rc8HealthCheckExists(id)
	ours := false
	if found {
		tags, terr := d.r53hcTags(id)
		if terr != nil {
			rerr = terr
		} else {
			ours = groundholdTagsMatch(tags, capability, environment)
		}
	}
	return concludeByStatus(providerID, "route53 health check "+id, found, rerr, ours, found, false)
}

// reconcileVpnGateway concludes a pending VPN gateway create from the tier-1 pid.
// DescribeVpnGateways gives the State (available → ready; pending → provisioning →
// unknown; deleting/deleted → terminal-failed) plus the ownership tags inline.
// Region-scoped (region in the pid).
func (d *Driver) reconcileVpnGateway(capability, environment, providerID string) provider.ReconcileResult {
	if providerID == "" {
		return rc8Unrecorded("vpngateway")
	}
	region, vgwID, err := splitVgwProviderID(providerID)
	if err != nil {
		return rc8BadPID("vpngateway", err)
	}
	tags, state, found, rerr := d.rc8DescribeVgw(region, vgwID)
	ours := found && groundholdTagsMatch(tags, capability, environment)
	return concludeByStatus(providerID, "vpn gateway "+vgwID, found, rerr, ours,
		state == "available", state == "deleting" || state == "deleted")
}

// ---- describe reads that surface the status the existing helpers don't ----

// rc8DescribeKMSState reads a KMS key's KeyState. A NotFound is a readable absence;
// any transport/HTTP/parse failure is unreadable (never a fabricated absence).
func (d *Driver) rc8DescribeKMSState(region, keyID string) (state string, found bool, err error) {
	st, resp, err := d.kmsCall(region, "DescribeKey", fmt.Sprintf(`{"KeyId":%q}`, keyID))
	if err != nil {
		return "", false, readTransport("DescribeKey", err)
	}
	if strings.Contains(ecsErr(resp), "NotFound") {
		return "", false, nil
	}
	if st != http.StatusOK {
		return "", false, readHTTP("DescribeKey", st, ecsErr(resp))
	}
	var out struct {
		KeyMetadata struct {
			KeyState string `json:"KeyState"`
		} `json:"KeyMetadata"`
	}
	if json.Unmarshal(resp, &out) != nil || out.KeyMetadata.KeyState == "" {
		return "", false, readBody("DescribeKey", st)
	}
	return out.KeyMetadata.KeyState, true, nil
}

// rc8HealthCheckExists reports whether a Route 53 health check exists. A 404 is a
// readable absence; any other non-200 (or transport error) is unreadable.
func (d *Driver) rc8HealthCheckExists(id string) (found bool, err error) {
	st, _, e := d.r53Do("GET", "/2013-04-01/healthcheck/"+id, "")
	if e != nil {
		return false, readTransport("GetHealthCheck", e)
	}
	if st == http.StatusNotFound {
		return false, nil
	}
	if st != http.StatusOK {
		return false, readHTTP("GetHealthCheck", st, "")
	}
	return true, nil
}

// rc8DescribeVgw reads a VPN gateway's tags + State. Unlike the delete-path
// describeVgw (which folds "deleted" into a bare absence), this surfaces the raw
// State so reconcile can tell available (ready) from pending (provisioning) from
// deleting/deleted (terminal-failed). A NotFound is a readable absence.
func (d *Driver) rc8DescribeVgw(region, vgwID string) (tags map[string]string, state string, found bool, err error) {
	body := encodeForm(map[string]string{"Action": "DescribeVpnGateways", "Version": ec2Version, "VpnGatewayId.1": vgwID})
	st, resp, err := d.ec2PostBase(region, body)
	if err != nil {
		return nil, "", false, readTransport("DescribeVpnGateways", err)
	}
	if ec2ErrCode(resp) == "InvalidVpnGatewayID.NotFound" {
		return nil, "", false, nil
	}
	if st != http.StatusOK {
		return nil, "", false, readHTTP("DescribeVpnGateways", st, ec2ErrCode(resp))
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
		return nil, "", false, readBody("DescribeVpnGateways", st)
	}
	for _, it := range out.Items {
		if it.VgwID != vgwID {
			continue
		}
		m := map[string]string{}
		for _, t := range it.Tags {
			m[t.Key] = t.Value
		}
		return m, it.State, true, nil
	}
	return nil, "", false, nil // not in the set — does not exist
}
