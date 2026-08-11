// Read-only discovery sweeps (gap batch B): the same two-step shape as the
// discover_aws.go sweeps — a List/Describe call gives IDs, then the EXISTING
// observe reverse-map turns each ID into real, measured observations. Never a
// fabricated empty list (a transport/HTTP/parse failure is an error, not
// "nothing here"); never an all-unknown record (an observe that fails for one
// resource is a diagnostic + skip, like discoverECS). All helpers here are
// prefixed by service to stay collision-free with the sibling gap batch. D53:
// none of these read a secret or key VALUE — KMS observe reads key metadata only.
package aws

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"net/http"
	"net/url"

	"groundhold/internal/provider"
)

// discoverKMS enumerates customer master keys in the region as
// capability.key.encryption. ListKeys returns key ids; observeAWSKMS reads
// DescribeKey + GetKeyRotationStatus (metadata only — the key material is never
// read, D53). Per-key isolation: an unreadable DescribeKey is a diagnostic.
func (d *Driver) discoverKMS(region string) ([]provider.Discovered, []string, error) {
	// D817: FOLLOW the pages. ListKeys answers 100 at a time and says so twice — a
	// Truncated flag and a NextMarker (botocore kms/2014-11-01: input Marker, output
	// NextMarker, more_results Truncated). Honour BOTH: stop only when neither says
	// there is more.
	type kmsKey struct {
		KeyID string `json:"KeyId"`
	}
	var keys []kmsKey
	marker := ""
	for page := 0; ; page++ {
		if page >= maxAWSListPages {
			return nil, nil, fmt.Errorf("kms ListKeys: more than %d pages", maxAWSListPages)
		}
		req := "{}"
		if marker != "" {
			b, _ := json.Marshal(struct {
				Marker string `json:"Marker"`
			}{marker})
			req = string(b)
		}
		st, body, err := d.kmsCall(region, "ListKeys", req)
		if err != nil {
			return nil, nil, fmt.Errorf("kms ListKeys: %v", err)
		}
		if st != http.StatusOK {
			return nil, nil, fmt.Errorf("kms ListKeys: HTTP %d: %s", st, ecsErr(body))
		}
		var r struct {
			Keys       []kmsKey `json:"Keys"`
			Truncated  bool     `json:"Truncated"`
			NextMarker string   `json:"NextMarker"`
		}
		if err := json.Unmarshal(body, &r); err != nil {
			return nil, nil, readBody("kms ListKeys", st)
		}
		keys = append(keys, r.Keys...)
		if !r.Truncated || r.NextMarker == "" {
			break
		}
		marker = r.NextMarker
	}
	var out []provider.Discovered
	var diags []string
	for _, k := range keys {
		if k.KeyID == "" {
			continue
		}
		pid := awsKMSProviderID(region, k.KeyID)
		obs, odiags, oerr := d.observeAWSKMS("", pid)
		if oerr != nil {
			diags = append(diags, k.KeyID+": "+oerr.Error())
			continue
		}
		for _, dg := range odiags {
			diags = append(diags, k.KeyID+": "+dg)
		}
		out = append(out, provider.Discovered{
			ProviderID:   pid,
			ResourceType: "capability.key.encryption",
			Observations: provider.WithoutAbsence(obs),
		})
	}
	return out, diags, nil
}

// discoverMSK enumerates MSK clusters in the region as
// capability.messaging.kafka. ListClustersV2 (no filter) lists the region's
// clusters; the account (for the providerId) is resolved once via STS. Each is
// reverse-mapped by the SAME observe.
func (d *Driver) discoverMSK(region string) ([]provider.Discovered, []string, error) {
	account, err := d.discoverAccount()
	if err != nil {
		return nil, nil, fmt.Errorf("msk: %v", err)
	}
	st, body, err := d.mskDo("GET", region, mskPath, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("msk ListClustersV2: %v", err)
	}
	if st != http.StatusOK {
		return nil, nil, fmt.Errorf("msk ListClustersV2: HTTP %d: %s", st, mskErr(body))
	}
	// restJson1 camelCase wire names (D879): PascalCase parsed every clusterName empty
	// and the loop below skipped it — discovery would report ZERO msk clusters on a real
	// account that has them, the dangerous false-absence direction.
	var r struct {
		ClusterInfoList []struct {
			ClusterName string `json:"clusterName"`
		} `json:"clusterInfoList"`
	}
	if err := json.Unmarshal(body, &r); err != nil {
		return nil, nil, readBody("msk ListClustersV2", st)
	}
	var out []provider.Discovered
	var diags []string
	for _, c := range r.ClusterInfoList {
		if c.ClusterName == "" {
			continue
		}
		pid := mskProviderID(region, account, c.ClusterName)
		obs, odiags, oerr := d.observeMSK("", pid)
		if oerr != nil {
			diags = append(diags, c.ClusterName+": "+oerr.Error())
			continue
		}
		for _, dg := range odiags {
			diags = append(diags, c.ClusterName+": "+dg)
		}
		out = append(out, provider.Discovered{
			ProviderID:   pid,
			ResourceType: "capability.messaging.kafka",
			Observations: provider.WithoutAbsence(obs),
		})
	}
	return out, diags, nil
}

// discoverOpenSearch enumerates OpenSearch domains in the region as
// capability.search.index. ListDomainNames returns names; the account (for the
// providerId) is resolved once via STS. Each is reverse-mapped by the SAME
// observe (DescribeDomain).
func (d *Driver) discoverOpenSearch(region string) ([]provider.Discovered, []string, error) {
	account, err := d.discoverAccount()
	if err != nil {
		return nil, nil, fmt.Errorf("opensearch: %v", err)
	}
	st, body, err := d.openSearchDo("GET", region, openSearchAccountPath+"/domain", nil)
	if err != nil {
		return nil, nil, fmt.Errorf("opensearch ListDomainNames: %v", err)
	}
	if st != http.StatusOK {
		return nil, nil, fmt.Errorf("opensearch ListDomainNames: HTTP %d: %s", st, osErr(body))
	}
	var r struct {
		DomainNames []struct {
			DomainName string `json:"DomainName"`
		} `json:"DomainNames"`
	}
	if err := json.Unmarshal(body, &r); err != nil {
		return nil, nil, readBody("opensearch ListDomainNames", st)
	}
	var out []provider.Discovered
	var diags []string
	for _, dm := range r.DomainNames {
		if dm.DomainName == "" {
			continue
		}
		pid := openSearchProviderID(region, account, dm.DomainName)
		obs, odiags, oerr := d.observeOpenSearch("", pid)
		if oerr != nil {
			diags = append(diags, dm.DomainName+": "+oerr.Error())
			continue
		}
		for _, dg := range odiags {
			diags = append(diags, dm.DomainName+": "+dg)
		}
		out = append(out, provider.Discovered{
			ProviderID:   pid,
			ResourceType: "capability.search.index",
			Observations: provider.WithoutAbsence(obs),
		})
	}
	return out, diags, nil
}

// discoverRedshiftServerless enumerates Redshift Serverless workgroups in the
// region as capability.warehouse.analytics. ListWorkgroups is region-scoped; the
// providerId is region:name. Each is reverse-mapped by the SAME observe
// (GetWorkgroup + GetNamespace).
func (d *Driver) discoverRedshiftServerless(region string) ([]provider.Discovered, []string, error) {
	st, body, err := d.rssCall(region, "ListWorkgroups", "{}")
	if err != nil {
		return nil, nil, fmt.Errorf("redshift-serverless ListWorkgroups: %v", err)
	}
	if st != http.StatusOK {
		return nil, nil, fmt.Errorf("redshift-serverless ListWorkgroups: HTTP %d: %s", st, ecsErr(body))
	}
	var r struct {
		Workgroups []struct {
			WorkgroupName string `json:"workgroupName"`
		} `json:"workgroups"`
	}
	if err := json.Unmarshal(body, &r); err != nil {
		return nil, nil, readBody("redshift-serverless ListWorkgroups", st)
	}
	var out []provider.Discovered
	var diags []string
	for _, wg := range r.Workgroups {
		if wg.WorkgroupName == "" {
			continue
		}
		pid := rssProviderID(region, wg.WorkgroupName)
		obs, odiags, oerr := d.observeRedshiftServerless("", pid)
		if oerr != nil {
			diags = append(diags, wg.WorkgroupName+": "+oerr.Error())
			continue
		}
		for _, dg := range odiags {
			diags = append(diags, wg.WorkgroupName+": "+dg)
		}
		out = append(out, provider.Discovered{
			ProviderID:   pid,
			ResourceType: "capability.warehouse.analytics",
			Observations: provider.WithoutAbsence(obs),
		})
	}
	return out, diags, nil
}

// discoverRoute53 enumerates hosted zones as capability.dns.zone. Route 53 is
// GLOBAL (signed us-east-1, region ignored). ListHostedZones returns zone ids;
// each is reverse-mapped by the SAME observe (GetHostedZone). The RECORDS are
// never read. Private zones are surfaced too — brownfield is honest.
func (d *Driver) discoverRoute53(region string) ([]provider.Discovered, []string, error) {
	_ = region // Route 53 is global; the endpoint is region-independent.
	// D817: FOLLOW the pages. ListHostedZones caps at 100 zones and answers IsTruncated +
	// NextMarker (botocore route53/2013-04-01: input Marker, output NextMarker,
	// more_results IsTruncated). A DNS zone missed here is a zone the tool reports as
	// unmanaged when it is not there at all.
	type r53Zone struct {
		ID string `xml:"Id"`
	}
	var zones []r53Zone
	marker := ""
	for page := 0; ; page++ {
		if page >= maxAWSListPages {
			return nil, nil, fmt.Errorf("route53 ListHostedZones: more than %d pages", maxAWSListPages)
		}
		path := route53Path + "/hostedzone"
		if marker != "" {
			path += "?marker=" + url.QueryEscape(marker)
		}
		st, body, err := d.r53Do("GET", path, "")
		if err != nil {
			return nil, nil, fmt.Errorf("route53 ListHostedZones: %v", err)
		}
		if st != http.StatusOK {
			return nil, nil, fmt.Errorf("route53 ListHostedZones: HTTP %d: %s", st, r53ErrCode(body))
		}
		var r struct {
			Zones       []r53Zone `xml:"HostedZones>HostedZone"`
			IsTruncated bool      `xml:"IsTruncated"`
			NextMarker  string    `xml:"NextMarker"`
		}
		if err := xml.Unmarshal(body, &r); err != nil {
			return nil, nil, fmt.Errorf("route53 ListHostedZones: %w", err)
		}
		zones = append(zones, r.Zones...)
		if !r.IsTruncated || r.NextMarker == "" {
			break
		}
		marker = r.NextMarker
	}
	var out []provider.Discovered
	var diags []string
	for _, z := range zones {
		id := stripZoneID(z.ID)
		if id == "" {
			continue
		}
		pid := r53ProviderID(id)
		obs, odiags, oerr := d.observeRoute53("", pid)
		if oerr != nil {
			diags = append(diags, id+": "+oerr.Error())
			continue
		}
		for _, dg := range odiags {
			diags = append(diags, id+": "+dg)
		}
		out = append(out, provider.Discovered{
			ProviderID:   pid,
			ResourceType: "capability.dns.zone",
			Observations: provider.WithoutAbsence(obs),
		})
	}
	return out, diags, nil
}

// discoverRoute53Health enumerates Route 53 health checks as
// capability.monitoring.uptime. GLOBAL (signed us-east-1, region ignored).
// ListHealthChecks returns ids; each is reverse-mapped by the SAME observe
// (GetHealthCheck).
func (d *Driver) discoverRoute53Health(region string) ([]provider.Discovered, []string, error) {
	_ = region // Route 53 is global; the endpoint is region-independent.
	st, body, err := d.r53Do("GET", "/2013-04-01/healthcheck", "")
	if err != nil {
		return nil, nil, fmt.Errorf("route53 ListHealthChecks: %v", err)
	}
	if st != http.StatusOK {
		return nil, nil, fmt.Errorf("route53 ListHealthChecks: HTTP %d: %s", st, r53ErrCode(body))
	}
	var r struct {
		Checks []struct {
			ID string `xml:"Id"`
		} `xml:"HealthChecks>HealthCheck"`
	}
	if err := xml.Unmarshal(body, &r); err != nil {
		return nil, nil, fmt.Errorf("route53 ListHealthChecks: %w", err)
	}
	var out []provider.Discovered
	var diags []string
	for _, c := range r.Checks {
		if c.ID == "" {
			continue
		}
		pid := r53hcProviderID(c.ID)
		obs, odiags, oerr := d.observeRoute53HealthCheck("", pid)
		if oerr != nil {
			diags = append(diags, c.ID+": "+oerr.Error())
			continue
		}
		for _, dg := range odiags {
			diags = append(diags, c.ID+": "+dg)
		}
		out = append(out, provider.Discovered{
			ProviderID:   pid,
			ResourceType: "capability.monitoring.uptime",
			Observations: provider.WithoutAbsence(obs),
		})
	}
	return out, diags, nil
}

// discoverVpnGateway enumerates virtual private gateways in the region as
// capability.vpn.gateway. DescribeVpnGateways (no filter) is region-scoped; a
// deleted gateway is skipped (authoritatively gone). Each live one is
// reverse-mapped by the SAME observe (DescribeVpnGateways).
func (d *Driver) discoverVpnGateway(region string) ([]provider.Discovered, []string, error) {
	st, body, err := d.ec2PostBase(region, encodeForm(map[string]string{
		"Action": "DescribeVpnGateways", "Version": ec2Version}))
	if err != nil {
		return nil, nil, fmt.Errorf("ec2 DescribeVpnGateways: %v", err)
	}
	if st != http.StatusOK {
		return nil, nil, fmt.Errorf("ec2 DescribeVpnGateways: HTTP %d: %s", st, ec2ErrCode(body))
	}
	var r struct {
		Items []struct {
			VgwID string `xml:"vpnGatewayId"`
			State string `xml:"state"`
		} `xml:"vpnGatewaySet>item"`
	}
	if err := xml.Unmarshal(body, &r); err != nil {
		return nil, nil, fmt.Errorf("ec2 DescribeVpnGateways: %w", err)
	}
	var out []provider.Discovered
	var diags []string
	for _, it := range r.Items {
		if it.VgwID == "" || it.State == "deleted" {
			continue
		}
		pid := vgwProviderID(region, it.VgwID)
		obs, odiags, oerr := d.observeVpnGateway("", pid)
		if oerr != nil {
			diags = append(diags, it.VgwID+": "+oerr.Error())
			continue
		}
		for _, dg := range odiags {
			diags = append(diags, it.VgwID+": "+dg)
		}
		out = append(out, provider.Discovered{
			ProviderID:   pid,
			ResourceType: "capability.vpn.gateway",
			Observations: provider.WithoutAbsence(obs),
		})
	}
	return out, diags, nil
}

// discoverWAF enumerates CLOUDFRONT-scope WebACLs as capability.security.waf.
// WAFv2 at CLOUDFRONT scope is GLOBAL (served by us-east-1, region ignored);
// the account (for the providerId) is resolved once via STS. ListWebACLs returns
// names; each is reverse-mapped by the SAME observe (ListWebACLs + GetWebACL).
func (d *Driver) discoverWAF(region string) ([]provider.Discovered, []string, error) {
	_ = region // CLOUDFRONT-scope WAFv2 is global (us-east-1).
	account, err := d.discoverAccount()
	if err != nil {
		return nil, nil, fmt.Errorf("waf: %v", err)
	}
	st, body, err := d.wafCall("ListWebACLs", jsonBody(map[string]any{"Scope": "CLOUDFRONT", "Limit": 100}))
	if err != nil {
		return nil, nil, fmt.Errorf("wafv2 ListWebACLs: %v", err)
	}
	if st != http.StatusOK {
		return nil, nil, fmt.Errorf("wafv2 ListWebACLs: HTTP %d: %s", st, wafErr(body))
	}
	var r struct {
		WebACLs []struct {
			Name string `json:"Name"`
		} `json:"WebACLs"`
	}
	if err := json.Unmarshal(body, &r); err != nil {
		return nil, nil, readBody("wafv2 ListWebACLs", st)
	}
	var out []provider.Discovered
	var diags []string
	for _, a := range r.WebACLs {
		if a.Name == "" {
			continue
		}
		pid := wafProviderID(account, a.Name)
		obs, odiags, oerr := d.observeWAF("", pid)
		if oerr != nil {
			diags = append(diags, a.Name+": "+oerr.Error())
			continue
		}
		for _, dg := range odiags {
			diags = append(diags, a.Name+": "+dg)
		}
		out = append(out, provider.Discovered{
			ProviderID:   pid,
			ResourceType: "capability.security.waf",
			Observations: provider.WithoutAbsence(obs),
		})
	}
	return out, diags, nil
}
