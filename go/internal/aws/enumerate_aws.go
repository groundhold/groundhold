// AWS scope enumeration (D141/parity): the crawl scope for AWS is a REGION, so a
// scopeless `groundhold pair aws` must fan out across the account's ENABLED regions
// instead of silently crawling one. Enumerate lists them via EC2 DescribeRegions
// (Query protocol, SigV4 — the same signed EC2 plumbing discoverVPC uses). The
// DescribeRegions call itself is made against a bootstrap region (the driver's own
// region, or us-east-1) since it needs some endpoint to reach. A failure is an
// error — the crawl records the provider incomplete — never a fabricated empty list.
package aws

import (
	"encoding/xml"
	"fmt"
	"net/http"

	"groundhold/internal/provider"
)

// compile-time proof the AWS driver satisfies the scope-enumeration contract.
var _ provider.Enumerator = (*Driver)(nil)

// Enumerate returns the account's enabled AWS regions (opt-in-not-required plus
// any opted-in), the crawlable scopes the gentle crawl fans out to. By default
// DescribeRegions omits regions the account has not enabled, which is exactly the
// set we want to crawl.
func (d *Driver) Enumerate() (scopes []string, diags []string, err error) {
	bootstrap := d.Region
	if bootstrap == "" {
		bootstrap = "us-east-1" // DescribeRegions needs an endpoint; any valid region works
	}
	st, body, err := d.ec2PostBase(bootstrap, encodeForm(map[string]string{
		"Action": "DescribeRegions", "Version": ec2Version}))
	if err != nil {
		return nil, nil, fmt.Errorf("ec2 DescribeRegions: %v", err)
	}
	if st != http.StatusOK {
		return nil, nil, fmt.Errorf("ec2 DescribeRegions: HTTP %d: %s", st, ec2ErrCode(body))
	}
	var r struct {
		Names []string `xml:"regionInfo>item>regionName"`
	}
	if err := xml.Unmarshal(body, &r); err != nil {
		return nil, nil, fmt.Errorf("ec2 DescribeRegions: %w", err)
	}
	for _, name := range r.Names {
		if name == "" {
			continue
		}
		scopes = append(scopes, name)
	}
	return scopes, diags, nil
}
