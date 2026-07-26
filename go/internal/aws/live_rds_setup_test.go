package aws

import (
	"encoding/xml"
	"fmt"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"
)

// TestLiveRDSSetupSubnetGroup provisions the environment PREREQUISITE for the RDS
// roundtrip: a DB subnet group spanning 2 AZs (regions whose default VPC has no
// default subnets need this). Gated on GROUNDHOLD_LIVE_RDS_SETUP=1. Idempotent-ish:
// re-creating an existing subnet/group is tolerated. Prints the group name to feed
// GROUNDHOLD_LIVE_RDS_SUBNET_GROUP. This is scaffolding, NOT a driver test.
func TestLiveRDSSetupSubnetGroup(t *testing.T) {
	if os.Getenv("GROUNDHOLD_LIVE_RDS_SETUP") != "1" || os.Getenv("AWS_ACCESS_KEY_ID") == "" {
		t.Skip("live RDS setup disabled (set GROUNDHOLD_LIVE_RDS_SETUP=1 with real creds)")
	}
	region := os.Getenv("AWS_DEFAULT_REGION")
	if region == "" {
		region = "eu-central-1"
	}
	d := NewDriver(region)
	d.Now = time.Now
	const groupName = "groundhold-live-rds"
	const scaffoldCIDR = "10.42.0.0/16"

	// ---- scaffold VPC (this account has no default VPC): reuse a tagged one or
	// create it. Tagged groundhold-scaffold so it is recognizable/cleanable. ----
	vpcID := d.ensureScaffoldVPC(t, region, scaffoldCIDR)
	sub1CIDR := "10.42.240.0/24"
	sub2CIDR := "10.42.241.0/24"

	// ---- two AZs ----
	st, body, err := d.ec2PostBase(region, ec2Form(map[string]string{
		"Action": "DescribeAvailabilityZones", "Version": "2016-11-15",
	}))
	if err != nil || st != 200 {
		t.Fatalf("DescribeAvailabilityZones: st=%d err=%v", st, err)
	}
	var azs struct {
		Names []string `xml:"availabilityZoneInfo>item>zoneName"`
	}
	if xml.Unmarshal(body, &azs) != nil || len(azs.Names) < 2 {
		t.Fatalf("need >=2 AZs, got %v", azs.Names)
	}
	az1, az2 := azs.Names[0], azs.Names[1]

	sub1 := d.ensureSubnet(t, region, vpcID, sub1CIDR, az1)
	sub2 := d.ensureSubnet(t, region, vpcID, sub2CIDR, az2)
	t.Logf("subnets: %s (%s), %s (%s)", sub1, az1, sub2, az2)

	// ---- DB subnet group ----
	st, body, err = d.rdsPost(region, rdsSimpleBody("CreateDBSubnetGroup", map[string]string{
		"DBSubnetGroupName":        groupName,
		"DBSubnetGroupDescription": "groundhold live RDS test scaffold",
		"SubnetIds.member.1":       sub1,
		"SubnetIds.member.2":       sub2,
	}))
	code := rdsErrCode(body)
	if err == nil && (st == 200 || code == "DBSubnetGroupAlreadyExists") {
		t.Logf("DB subnet group ready: %s (set GROUNDHOLD_LIVE_RDS_SUBNET_GROUP=%s)", groupName, groupName)
		return
	}
	t.Fatalf("CreateDBSubnetGroup: st=%d code=%s body=%s", st, code, mutDetail(body))
}

// ensureScaffoldVPC reuses a groundhold-scaffold-tagged VPC or creates one.
func (d *Driver) ensureScaffoldVPC(t *testing.T, region, cidr string) string {
	t.Helper()
	// reuse?
	st, body, err := d.ec2PostBase(region, ec2Form(map[string]string{
		"Action": "DescribeVpcs", "Version": "2016-11-15",
		"Filter.1.Name": "tag:groundhold-scaffold", "Filter.1.Value.1": "live-rds",
	}))
	if err == nil && st == 200 {
		var r struct {
			IDs []string `xml:"vpcSet>item>vpcId"`
		}
		if xml.Unmarshal(body, &r) == nil && len(r.IDs) > 0 {
			t.Logf("reusing scaffold vpc=%s", r.IDs[0])
			return r.IDs[0]
		}
	}
	// create
	st, body, err = d.ec2PostBase(region, ec2Form(map[string]string{
		"Action": "CreateVpc", "Version": "2016-11-15", "CidrBlock": cidr,
		"TagSpecification.1.ResourceType": "vpc",
		"TagSpecification.1.Tag.1.Key":    "groundhold-scaffold",
		"TagSpecification.1.Tag.1.Value":  "live-rds",
	}))
	if err != nil || st != 200 {
		t.Fatalf("CreateVpc: st=%d err=%v body=%s", st, err, mutDetail(body))
	}
	var r struct {
		ID string `xml:"vpc>vpcId"`
	}
	if xml.Unmarshal(body, &r) != nil || r.ID == "" {
		t.Fatalf("CreateVpc: no vpcId in %s", mutDetail(body))
	}
	t.Logf("created scaffold vpc=%s", r.ID)
	return r.ID
}

// ensureSubnet creates a subnet (tolerating an existing overlapping one by
// reusing the first subnet already in the CIDR) and returns its id.
func (d *Driver) ensureSubnet(t *testing.T, region, vpcID, cidr, az string) string {
	t.Helper()
	st, body, err := d.ec2PostBase(region, ec2Form(map[string]string{
		"Action": "CreateSubnet", "Version": "2016-11-15",
		"VpcId": vpcID, "CidrBlock": cidr, "AvailabilityZone": az,
		"TagSpecification.1.ResourceType": "subnet",
		"TagSpecification.1.Tag.1.Key":    "groundhold-scaffold",
		"TagSpecification.1.Tag.1.Value":  "live-rds",
	}))
	if err == nil && st == 200 {
		var r struct {
			ID string `xml:"subnet>subnetId"`
		}
		if xml.Unmarshal(body, &r) == nil && r.ID != "" {
			return r.ID
		}
	}
	// already there? find it by CIDR
	if ec2ErrCode(body) == "InvalidSubnet.Conflict" || strings.Contains(string(body), "conflicts") {
		st2, b2, e2 := d.ec2PostBase(region, ec2Form(map[string]string{
			"Action": "DescribeSubnets", "Version": "2016-11-15",
			"Filter.1.Name": "cidrBlock", "Filter.1.Value.1": cidr,
			"Filter.2.Name": "vpc-id", "Filter.2.Value.1": vpcID,
		}))
		if e2 == nil && st2 == 200 {
			var r struct {
				IDs []string `xml:"subnetSet>item>subnetId"`
			}
			if xml.Unmarshal(b2, &r) == nil && len(r.IDs) > 0 {
				return r.IDs[0]
			}
		}
	}
	t.Fatalf("CreateSubnet %s/%s: st=%d: %s", cidr, az, st, mutDetail(body))
	return ""
}

func ec2Form(p map[string]string) string {
	keys := make([]string, 0, len(p))
	for k := range p {
		keys = append(keys, k)
	}
	// stable order not required for the wire; sort for determinism
	for i := 0; i < len(keys); i++ {
		for j := i + 1; j < len(keys); j++ {
			if keys[j] < keys[i] {
				keys[i], keys[j] = keys[j], keys[i]
			}
		}
	}
	var parts []string
	for _, k := range keys {
		parts = append(parts, url.QueryEscape(k)+"="+url.QueryEscape(p[k]))
	}
	return strings.Join(parts, "&")
}

var _ = fmt.Sprintf
