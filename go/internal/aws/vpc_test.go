package aws

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func awsVpcAttrs() map[string]any {
	return map[string]any{
		"location.region":   "eu-central-1",
		"ingress.public":    false,
		"egress.restricted": true,
		"flowLogs.enabled":  false,
		"service.managed":   true,
	}
}

func TestBuildAWSVPCGolden(t *testing.T) {
	plan, err := BuildAWSVPC("000000000000", "prod", "net", awsVpcAttrs(), nil, 1)
	if err != nil {
		t.Fatal(err)
	}
	if plan.CIDR != "10.0.0.0/16" || plan.SubnetCIDR != "10.0.0.0/24" {
		t.Fatalf("default CIDRs = %s / %s", plan.CIDR, plan.SubnetCIDR)
	}
	body := plan.createVpcBody()
	if !strings.Contains(body, "Action=CreateVpc") || !strings.Contains(body, "CidrBlock=10.0.0.0%2F16") {
		t.Fatalf("vpc body: %s", body)
	}
	if !strings.Contains(body, "groundhold-capability") {
		t.Fatalf("ownership tag missing: %s", body)
	}
	if plan.FlowLogs {
		t.Fatal("flow logs not requested")
	}
}

func TestBuildAWSVPCZonalDefault(t *testing.T) {
	// No availability.class (back-compat) => one subnet, AWS-chosen AZ.
	plan, err := BuildAWSVPC("000000000000", "prod", "net", awsVpcAttrs(), nil, 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.PrivateSubnets) != 1 {
		t.Fatalf("zonal default: want 1 private subnet, got %d", len(plan.PrivateSubnets))
	}
	if plan.PrivateSubnets[0].CIDR != "10.0.0.0/24" || plan.PrivateSubnets[0].AZ != "" {
		t.Fatalf("zonal subnet = %+v (want 10.0.0.0/24, no pinned AZ)", plan.PrivateSubnets[0])
	}
}

func TestBuildAWSVPCRegionalMultiAZ(t *testing.T) {
	a := awsVpcAttrs()
	a["availability.class"] = "regional"
	plan, err := BuildAWSVPC("000000000000", "prod", "net", a, nil, 1)
	if err != nil {
		t.Fatal(err)
	}
	// Regional AWS network = >=2 subnets across >=2 AZs (AWS subnets are AZ-bound).
	if len(plan.PrivateSubnets) != 2 {
		t.Fatalf("regional: want 2 private subnets, got %d (%+v)", len(plan.PrivateSubnets), plan.PrivateSubnets)
	}
	got := map[string]string{}
	for _, s := range plan.PrivateSubnets {
		got[s.AZ] = s.CIDR
	}
	if got["eu-central-1a"] != "10.0.0.0/24" || got["eu-central-1b"] != "10.0.2.0/24" {
		t.Fatalf("regional subnets = %+v (want a=10.0.0.0/24, b=10.0.2.0/24)", plan.PrivateSubnets)
	}
	// distinct AZs and distinct CIDRs
	if plan.PrivateSubnets[0].AZ == plan.PrivateSubnets[1].AZ ||
		plan.PrivateSubnets[0].CIDR == plan.PrivateSubnets[1].CIDR {
		t.Fatalf("regional subnets must span distinct AZs and CIDRs: %+v", plan.PrivateSubnets)
	}
}

func TestBuildAWSVPCRegionalOperatorOverride(t *testing.T) {
	a := awsVpcAttrs()
	a["availability.class"] = "regional"
	impl := map[string]any{
		"subnet_cidrs":       []any{"172.16.1.0/24", "172.16.2.0/24", "172.16.3.0/24"},
		"availability_zones": []any{"eu-central-1a", "eu-central-1b", "eu-central-1c"},
	}
	plan, err := BuildAWSVPC("000000000000", "prod", "net", a, impl, 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.PrivateSubnets) != 3 {
		t.Fatalf("override: want 3 subnets, got %d", len(plan.PrivateSubnets))
	}
	if plan.PrivateSubnets[2].CIDR != "172.16.3.0/24" || plan.PrivateSubnets[2].AZ != "eu-central-1c" {
		t.Fatalf("override third subnet = %+v", plan.PrivateSubnets[2])
	}
}

func TestBuildAWSVPCRegionalRefusals(t *testing.T) {
	// regional with a non-/24 base and no explicit subnet_cidrs -> refuse (no guess).
	a := awsVpcAttrs()
	a["availability.class"] = "regional"
	impl := map[string]any{"subnet_cidr": "10.0.0.0/20"}
	if _, err := BuildAWSVPC("000000000000", "prod", "net", a, impl, 1); err == nil {
		t.Fatal("regional with a /20 base and no subnet_cidrs must refuse to guess")
	}
	// bogus availability.class value -> refuse (also caught by the vocab enum).
	a2 := awsVpcAttrs()
	a2["availability.class"] = "galactic"
	if _, err := BuildAWSVPC("000000000000", "prod", "net", a2, nil, 1); err == nil {
		t.Fatal("availability.class=galactic must refuse")
	}
}

func TestBuildAWSVPCRefusals(t *testing.T) {
	cases := map[string]struct {
		a func(map[string]any)
		i map[string]any
	}{
		"public ingress": {func(a map[string]any) { a["ingress.public"] = true }, nil},
		// egress.restricted=true is honored ONLY with no road; asking for it on a
		// NAT road needs egress SGs this slice does not build -> refuse (the axes
		// are unravelled: egress.restricted=false alone no longer refuses).
		"restricted+nat road": {func(a map[string]any) {
			a["egress.restricted"] = true
			a["egress.internet"] = "nat"
		}, nil},
		"direct road not built": {func(a map[string]any) { a["egress.internet"] = "direct" }, nil},
		"bad egress mode":       {func(a map[string]any) { a["egress.internet"] = "sometimes" }, nil},
		"interconnect":          {func(a map[string]any) { a["interconnect.private"] = true }, nil},
		"unknown attr":          {func(a map[string]any) { a["engine.protocol"] = "x" }, nil},
		"no region":             {func(a map[string]any) { delete(a, "location.region") }, nil},
		"flowlogs no dst":       {func(a map[string]any) { a["flowLogs.enabled"] = true }, nil},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			a := awsVpcAttrs()
			c.a(a)
			if _, err := BuildAWSVPC("acct", "prod", "net", a, c.i, 1); err == nil {
				t.Fatalf("expected refusal for %q", name)
			}
		})
	}
}

func TestBuildAWSVPCFlowLogsWithDest(t *testing.T) {
	a := awsVpcAttrs()
	a["flowLogs.enabled"] = true
	plan, err := BuildAWSVPC("acct", "prod", "net", a,
		map[string]any{"flow_log_destination": "grp", "flow_log_role_arn": "arn:role"}, 1)
	if err != nil {
		t.Fatal(err)
	}
	if !plan.FlowLogs || plan.FlowLogDst != "grp" {
		t.Fatalf("flow logs not honored: %+v", plan)
	}
}

// The EKS substrate contract: egress.internet=nat + egress.restricted=false must
// be REALIZABLE (the whole point of the slice — private nodes need outbound to
// bootstrap). The two axes are orthogonal: restricted=false never refuses.
func TestBuildAWSVPCNatEgress(t *testing.T) {
	a := awsVpcAttrs()
	a["egress.internet"] = "nat"
	a["egress.restricted"] = false
	plan, err := BuildAWSVPC("acct", "prod", "net", a, nil, 1)
	if err != nil {
		t.Fatalf("nat + restricted=false must be realizable, got: %v", err)
	}
	if plan.EgressInternet != "nat" {
		t.Fatalf("EgressInternet = %q, want nat", plan.EgressInternet)
	}
	if plan.PublicSubnetCIDR == "" || plan.PublicSubnetCIDR == plan.SubnetCIDR {
		t.Fatalf("nat needs a distinct public subnet, got %q vs %q", plan.PublicSubnetCIDR, plan.SubnetCIDR)
	}
}

// egress.restricted=false with no road is fine too (orthogonal permission, not a
// requirement that a road exist) — it must NOT refuse the way it used to.
func TestBuildAWSVPCRestrictedFalseNoRoad(t *testing.T) {
	a := awsVpcAttrs()
	a["egress.restricted"] = false // egress.internet absent => none
	if _, err := BuildAWSVPC("acct", "prod", "net", a, nil, 1); err != nil {
		t.Fatalf("egress.restricted=false must no longer refuse on its own: %v", err)
	}
}

// awsVpcNatServer is a stateful fake that lands the full NAT composite on create
// and reflects the private->NAT / public->IGW route topology on observe.
func awsVpcNatServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			b := make([]byte, r.ContentLength)
			r.Body.Read(b)
			action := ""
			for _, kv := range strings.Split(string(b), "&") {
				if strings.HasPrefix(kv, "Action=") {
					action = strings.TrimPrefix(kv, "Action=")
				}
			}
			switch action {
			case "CreateVpc":
				_, _ = w.Write([]byte(`<CreateVpcResponse><vpc><vpcId>vpc-0abc123</vpcId></vpc></CreateVpcResponse>`))
			case "CreateSubnet":
				_, _ = w.Write([]byte(`<CreateSubnetResponse><subnet><subnetId>subnet-0x</subnetId></subnet></CreateSubnetResponse>`))
			case "CreateInternetGateway":
				_, _ = w.Write([]byte(`<CreateInternetGatewayResponse><internetGateway><internetGatewayId>igw-01</internetGatewayId></internetGateway></CreateInternetGatewayResponse>`))
			case "AllocateAddress":
				_, _ = w.Write([]byte(`<AllocateAddressResponse><allocationId>eipalloc-01</allocationId></AllocateAddressResponse>`))
			case "CreateNatGateway":
				_, _ = w.Write([]byte(`<CreateNatGatewayResponse><natGateway><natGatewayId>nat-01</natGatewayId></natGateway></CreateNatGatewayResponse>`))
			case "DescribeNatGateways":
				_, _ = w.Write([]byte(`<DescribeNatGatewaysResponse><natGatewaySet><item><natGatewayId>nat-01</natGatewayId><state>available</state></item></natGatewaySet></DescribeNatGatewaysResponse>`))
			case "CreateRouteTable":
				_, _ = w.Write([]byte(`<CreateRouteTableResponse><routeTable><routeTableId>rtb-01</routeTableId></routeTable></CreateRouteTableResponse>`))
			case "DescribeVpcs":
				_, _ = w.Write([]byte(`<DescribeVpcsResponse><vpcSet><item><vpcId>vpc-0abc123</vpcId></item></vpcSet></DescribeVpcsResponse>`))
			case "DescribeInternetGateways":
				_, _ = w.Write([]byte(`<DescribeInternetGatewaysResponse><internetGatewaySet><item><internetGatewayId>igw-01</internetGatewayId></item></internetGatewaySet></DescribeInternetGatewaysResponse>`))
			case "DescribeRouteTables":
				// private RT -> NAT, public RT -> IGW (plus the local route)
				_, _ = w.Write([]byte(`<DescribeRouteTablesResponse><routeTableSet>` +
					`<item><routeTableId>rtb-priv</routeTableId><routeSet>` +
					`<item><destinationCidrBlock>10.0.0.0/16</destinationCidrBlock><gatewayId>local</gatewayId></item>` +
					`<item><destinationCidrBlock>0.0.0.0/0</destinationCidrBlock><natGatewayId>nat-01</natGatewayId></item>` +
					`</routeSet></item>` +
					`<item><routeTableId>rtb-pub</routeTableId><routeSet>` +
					`<item><destinationCidrBlock>0.0.0.0/0</destinationCidrBlock><gatewayId>igw-01</gatewayId></item>` +
					`</routeSet></item>` +
					`</routeTableSet></DescribeRouteTablesResponse>`))
			case "DescribeFlowLogs":
				_, _ = w.Write([]byte(`<DescribeFlowLogsResponse><flowLogSet/></DescribeFlowLogsResponse>`))
			case "DescribeVpcEndpoints":
				_, _ = w.Write([]byte(`<DescribeVpcEndpointsResponse><vpcEndpointSet/></DescribeVpcEndpointsResponse>`))
			case "CreateSecurityGroup":
				_, _ = w.Write([]byte(`<CreateSecurityGroupResponse><groupId>sg-01</groupId></CreateSecurityGroupResponse>`))
			case "AttachInternetGateway", "CreateRoute", "AssociateRouteTable", "AuthorizeSecurityGroupIngress":
				_, _ = w.Write([]byte(`<Response/>`))
			default:
				w.WriteHeader(400)
			}
		}))
}

func TestCreateAWSVPCNatEgress(t *testing.T) {
	srv := awsVpcNatServer(t)
	defer srv.Close()
	d := awsVpcTestDriver(t, srv)
	a := awsVpcAttrs()
	a["egress.internet"] = "nat"
	a["egress.restricted"] = false
	res := d.createAWSVPC("eu-central-1", "000000000000", "prod", "net", a, nil, 1)
	if res.Status != "succeeded" || res.ProviderID != "vpc:eu-central-1:vpc-0abc123" {
		t.Fatalf("nat-egress create must succeed with the vpc pid, got %+v", res)
	}
}

func TestObserveAWSVPCNatEgress(t *testing.T) {
	srv := awsVpcNatServer(t)
	defer srv.Close()
	d := awsVpcTestDriver(t, srv)
	obs, _, err := d.observeAWSVPC("net", "vpc:eu-central-1:vpc-0abc123")
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]any{}
	for _, o := range obs {
		got[o.Path] = o.Value
	}
	if got["egress.internet"] != "nat" {
		t.Fatalf("private->NAT route must observe egress.internet=nat, got %v", got["egress.internet"])
	}
	// NAT does not make workloads addressable: ingress stays false despite the IGW
	if got["ingress.public"] != false {
		t.Fatalf("nat road must observe ingress.public=false (IGW serves NAT only), got %v", got["ingress.public"])
	}
	// an unfiltered NAT road is not destination-restricted
	if got["egress.restricted"] != false {
		t.Fatalf("nat road must observe egress.restricted=false, got %v", got["egress.restricted"])
	}
}

// awsVpcServer routes EC2 Query actions (by the Action= form param).
func awsVpcServer(t *testing.T, tagCap string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			b := make([]byte, r.ContentLength)
			r.Body.Read(b)
			action := ""
			for _, kv := range strings.Split(string(b), "&") {
				if strings.HasPrefix(kv, "Action=") {
					action = strings.TrimPrefix(kv, "Action=")
				}
			}
			switch action {
			case "CreateVpc":
				_, _ = w.Write([]byte(`<CreateVpcResponse><vpc><vpcId>vpc-0abc123</vpcId></vpc></CreateVpcResponse>`))
			case "CreateSubnet":
				_, _ = w.Write([]byte(`<CreateSubnetResponse><subnet><subnetId>subnet-0x</subnetId></subnet></CreateSubnetResponse>`))
			case "DescribeVpcs":
				// D253 create-adoption scan is tag-FILTERED; the create Op's happy
				// path represents "no pre-existing VPC", so the scan finds nothing
				// and a genuine create runs. A by-VpcId describe (observe/delete
				// ownership gate) still returns the owned VPC.
				if strings.Contains(string(b), "Filter.1.Name") {
					_, _ = w.Write([]byte(`<DescribeVpcsResponse><vpcSet/></DescribeVpcsResponse>`))
				} else {
					_, _ = w.Write([]byte(`<DescribeVpcsResponse><vpcSet><item><vpcId>vpc-0abc123</vpcId>` +
						`<tagSet><item><key>groundhold-capability</key><value>` + tagCap + `</value></item>` +
						`<item><key>groundhold-environment</key><value>prod</value></item></tagSet>` +
						`</item></vpcSet></DescribeVpcsResponse>`))
				}
			case "DescribeInternetGateways":
				_, _ = w.Write([]byte(`<DescribeInternetGatewaysResponse><internetGatewaySet/></DescribeInternetGatewaysResponse>`))
			case "DescribeFlowLogs":
				_, _ = w.Write([]byte(`<DescribeFlowLogsResponse><flowLogSet/></DescribeFlowLogsResponse>`))
			case "DescribeRouteTables":
				_, _ = w.Write([]byte(`<DescribeRouteTablesResponse><routeTableSet/></DescribeRouteTablesResponse>`))
			case "DescribeNatGateways":
				_, _ = w.Write([]byte(`<DescribeNatGatewaysResponse><natGatewaySet/></DescribeNatGatewaysResponse>`))
			case "DescribeAddresses":
				_, _ = w.Write([]byte(`<DescribeAddressesResponse><addressesSet/></DescribeAddressesResponse>`))
			case "DescribeSubnets":
				_, _ = w.Write([]byte(`<DescribeSubnetsResponse><subnetSet><item><subnetId>subnet-0x</subnetId></item></subnetSet></DescribeSubnetsResponse>`))
			case "DescribeVpcEndpoints":
				_, _ = w.Write([]byte(`<DescribeVpcEndpointsResponse><vpcEndpointSet/></DescribeVpcEndpointsResponse>`))
			case "CreateSecurityGroup":
				_, _ = w.Write([]byte(`<CreateSecurityGroupResponse><groupId>sg-01</groupId></CreateSecurityGroupResponse>`))
			case "DescribeSecurityGroups":
				// empty child list (like the route-table/NAT/EIP stubs above): the VPC
				// tag on DescribeVpcs is the sole ownership gate the honesty harness
				// probes. Owned-SG teardown is exercised by TestDeleteAWSVPCBaselineSG.
				_, _ = w.Write([]byte(`<DescribeSecurityGroupsResponse><securityGroupInfo/></DescribeSecurityGroupsResponse>`))
			case "DeleteSubnet", "DeleteVpc", "DeleteFlowLogs", "DeleteVpcEndpoints",
				"DisassociateRouteTable", "DeleteRouteTable", "DeleteNatGateway",
				"ReleaseAddress", "DetachInternetGateway", "DeleteInternetGateway",
				"AuthorizeSecurityGroupIngress", "DeleteSecurityGroup":
				_, _ = w.Write([]byte(`<Response/>`))
			default:
				w.WriteHeader(400)
			}
		}))
}

func awsVpcTestDriver(t *testing.T, srv *httptest.Server) *Driver {
	t.Helper()
	t.Setenv("AWS_ACCESS_KEY_ID", "AKID")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "secret")
	d := NewDriver("eu-central-1")
	d.EC2BaseURL = srv.URL
	d.Account = "000000000000"
	return d
}

func TestCreateAWSVPC(t *testing.T) {
	srv := awsVpcServer(t, "net")
	defer srv.Close()
	d := awsVpcTestDriver(t, srv)
	res := d.createAWSVPC("eu-central-1", "000000000000", "prod", "net", awsVpcAttrs(), nil, 1)
	if res.Status != "succeeded" || res.ProviderID != "vpc:eu-central-1:vpc-0abc123" {
		t.Fatalf("got %+v, want succeeded + vpc pid", res)
	}
}

func TestObserveAWSVPC(t *testing.T) {
	srv := awsVpcServer(t, "net")
	defer srv.Close()
	d := awsVpcTestDriver(t, srv)
	obs, _, err := d.observeAWSVPC("net", "vpc:eu-central-1:vpc-0abc123")
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]any{}
	for _, o := range obs {
		got[o.Path] = o.Value
	}
	if got["ingress.public"] != false {
		t.Fatalf("no IGW => not public, got %v", got["ingress.public"])
	}
	if got["egress.restricted"] != true {
		t.Fatalf("no IGW => egress restricted, got %v", got["egress.restricted"])
	}
}

func TestDeleteAWSVPCForeignRefused(t *testing.T) {
	srv := awsVpcServer(t, "other")
	defer srv.Close()
	d := awsVpcTestDriver(t, srv)
	res := d.deleteAWSVPC("net", "prod", "vpc:eu-central-1:vpc-0abc123")
	if res.Status != "failed" || !strings.Contains(res.Reason, "not ours") {
		t.Fatalf("a foreign-tagged vpc must refuse, got %+v", res)
	}
}

func TestDeleteAWSVPCOurs(t *testing.T) {
	srv := awsVpcServer(t, "net")
	defer srv.Close()
	d := awsVpcTestDriver(t, srv)
	res := d.deleteAWSVPC("net", "prod", "vpc:eu-central-1:vpc-0abc123")
	if res.Status != "succeeded" {
		t.Fatalf("delete of an owned vpc must succeed, got %+v", res)
	}
}

// ---- serviceAccess.private (VPC endpoints) --------------------------------

func TestBuildAWSVPCServiceAccess(t *testing.T) {
	a := awsVpcAttrs()
	a["serviceAccess.private"] = true
	plan, err := BuildAWSVPC("acct", "prod", "net", a, nil, 1)
	if err != nil {
		t.Fatal(err)
	}
	if !plan.ServiceAccess {
		t.Fatal("serviceAccess.private=true must set plan.ServiceAccess")
	}
	// the canonical set: S3 gateway + the interface API set.
	want := map[string]bool{"s3": true, "ecr.api": true, "ecr.dkr": true, "sts": true,
		"secretsmanager": true, "logs": true, "sqs": true, "bedrock-runtime": true, "kms": true}
	if len(plan.EndpointServices) != len(want) {
		t.Fatalf("endpoint set = %v, want %d canonical services", plan.EndpointServices, len(want))
	}
	for _, s := range plan.EndpointServices {
		if !want[s] {
			t.Fatalf("unexpected endpoint service %q in %v", s, plan.EndpointServices)
		}
	}
}

func TestBuildAWSVPCServiceAccessOverride(t *testing.T) {
	a := awsVpcAttrs()
	a["serviceAccess.private"] = true
	plan, err := BuildAWSVPC("acct", "prod", "net", a,
		map[string]any{"vpc_endpoints": []any{"s3", "sts", "logs"}}, 1)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(plan.EndpointServices, ",") != "logs,s3,sts" {
		t.Fatalf("override endpoint set = %v, want [logs s3 sts] sorted", plan.EndpointServices)
	}
}

func TestBuildAWSVPCServiceAccessBadOverride(t *testing.T) {
	a := awsVpcAttrs()
	a["serviceAccess.private"] = true
	for name, impl := range map[string]map[string]any{
		"not a list":  {"vpc_endpoints": "s3"},
		"empty list":  {"vpc_endpoints": []any{}},
		"non-strings": {"vpc_endpoints": []any{"s3", 7}},
	} {
		if _, err := BuildAWSVPC("acct", "prod", "net", a, impl, 1); err == nil {
			t.Fatalf("expected refusal for %q override", name)
		}
	}
}

// awsVpcEndpointsServer lands the endpoint composite on create and reports the
// given AVAILABLE service set on observe (short svc tokens -> com.amazonaws...).
func awsVpcEndpointsServer(t *testing.T, region string, available []string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			b := make([]byte, r.ContentLength)
			r.Body.Read(b)
			action := ""
			for _, kv := range strings.Split(string(b), "&") {
				if strings.HasPrefix(kv, "Action=") {
					action = strings.TrimPrefix(kv, "Action=")
				}
			}
			switch action {
			case "CreateVpc":
				_, _ = w.Write([]byte(`<CreateVpcResponse><vpc><vpcId>vpc-0abc123</vpcId></vpc></CreateVpcResponse>`))
			case "CreateSubnet":
				_, _ = w.Write([]byte(`<CreateSubnetResponse><subnet><subnetId>subnet-0x</subnetId></subnet></CreateSubnetResponse>`))
			case "DescribeRouteTables":
				_, _ = w.Write([]byte(`<DescribeRouteTablesResponse><routeTableSet><item><routeTableId>rtb-01</routeTableId></item></routeTableSet></DescribeRouteTablesResponse>`))
			case "CreateVpcEndpoint":
				_, _ = w.Write([]byte(`<CreateVpcEndpointResponse><vpcEndpoint><vpcEndpointId>vpce-01</vpcEndpointId><state>available</state></vpcEndpoint></CreateVpcEndpointResponse>`))
			case "CreateSecurityGroup":
				_, _ = w.Write([]byte(`<CreateSecurityGroupResponse><groupId>sg-01</groupId></CreateSecurityGroupResponse>`))
			case "AuthorizeSecurityGroupIngress":
				_, _ = w.Write([]byte(`<Response/>`))
			case "DescribeVpcs":
				_, _ = w.Write([]byte(`<DescribeVpcsResponse><vpcSet><item><vpcId>vpc-0abc123</vpcId>` +
					`<tagSet><item><key>groundhold-capability</key><value>net</value></item>` +
					`<item><key>groundhold-environment</key><value>prod</value></item></tagSet>` +
					`</item></vpcSet></DescribeVpcsResponse>`))
			case "DescribeInternetGateways":
				_, _ = w.Write([]byte(`<DescribeInternetGatewaysResponse><internetGatewaySet/></DescribeInternetGatewaysResponse>`))
			case "DescribeFlowLogs":
				_, _ = w.Write([]byte(`<DescribeFlowLogsResponse><flowLogSet/></DescribeFlowLogsResponse>`))
			case "DescribeVpcEndpoints":
				items := ""
				for _, svc := range available {
					items += `<item><vpcEndpointId>vpce-` + svc + `</vpcEndpointId>` +
						`<serviceName>com.amazonaws.` + region + `.` + svc + `</serviceName>` +
						`<state>available</state>` +
						`<tagSet><item><key>groundhold-capability</key><value>net</value></item>` +
						`<item><key>groundhold-environment</key><value>prod</value></item></tagSet></item>`
				}
				_, _ = w.Write([]byte(`<DescribeVpcEndpointsResponse><vpcEndpointSet>` + items + `</vpcEndpointSet></DescribeVpcEndpointsResponse>`))
			default:
				w.WriteHeader(400)
			}
		}))
}

func TestCreateAWSVPCServiceAccess(t *testing.T) {
	srv := awsVpcEndpointsServer(t, "eu-central-1", defaultVPCEndpointServices)
	defer srv.Close()
	d := awsVpcTestDriver(t, srv)
	a := awsVpcAttrs()
	a["serviceAccess.private"] = true
	res := d.createAWSVPC("eu-central-1", "000000000000", "prod", "net", a, nil, 1)
	if res.Status != "succeeded" || res.ProviderID != "vpc:eu-central-1:vpc-0abc123" {
		t.Fatalf("service-access create must succeed with the vpc pid, got %+v", res)
	}
}

func TestObserveAWSVPCServiceAccessComplete(t *testing.T) {
	srv := awsVpcEndpointsServer(t, "eu-central-1", defaultVPCEndpointServices)
	defer srv.Close()
	d := awsVpcTestDriver(t, srv)
	obs, _, err := d.observeAWSVPC("net", "vpc:eu-central-1:vpc-0abc123")
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]any{}
	for _, o := range obs {
		got[o.Path] = o.Value
	}
	if got["serviceAccess.private"] != true {
		t.Fatalf("observed set ⊇ required must yield serviceAccess.private=true, got %v", got["serviceAccess.private"])
	}
}

func TestObserveAWSVPCServiceAccessIncomplete(t *testing.T) {
	// drop one required service -> measured false + a diag naming exactly it.
	partial := []string{"s3", "ecr.api", "ecr.dkr", "sts", "secretsmanager", "logs", "bedrock-runtime", "kms"} // no sqs
	srv := awsVpcEndpointsServer(t, "eu-central-1", partial)
	defer srv.Close()
	d := awsVpcTestDriver(t, srv)
	obs, diags, err := d.observeAWSVPC("net", "vpc:eu-central-1:vpc-0abc123")
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]any{}
	for _, o := range obs {
		got[o.Path] = o.Value
	}
	if got["serviceAccess.private"] != false {
		t.Fatalf("an incomplete set must be a MEASURED false, got %v", got["serviceAccess.private"])
	}
	found := false
	for _, d := range diags {
		if strings.Contains(d, "sqs") {
			found = true
		}
	}
	if !found {
		t.Fatalf("diag must name the missing endpoint (sqs), got %v", diags)
	}
}

// ---- baseline security group (ingress.public posture as an object) --------

// A contract that names ingress.public authors a baseline SG whose default rule
// admits intra-VPC traffic only — the posture becomes a materialized object.
func TestBuildAWSVPCBaselineSG(t *testing.T) {
	plan, err := BuildAWSVPC("acct", "prod", "net", awsVpcAttrs(), nil, 1)
	if err != nil {
		t.Fatal(err)
	}
	if !plan.BaselineSG {
		t.Fatal("ingress.public declared => baseline SG must be authored")
	}
	if len(plan.BaselineIngress) != 1 || plan.BaselineIngress[0].Protocol != "-1" ||
		plan.BaselineIngress[0].CIDR != "10.0.0.0/16" {
		t.Fatalf("safe default baseline ingress must be intra-VPC only, got %+v", plan.BaselineIngress)
	}
}

// A contract that names NEITHER ingress.public nor a baseline_sg impl behaves as
// before: no baseline SG (back-compat).
func TestBuildAWSVPCNoBaselineByDefault(t *testing.T) {
	a := map[string]any{"location.region": "eu-central-1", "service.managed": true}
	plan, err := BuildAWSVPC("acct", "prod", "net", a, nil, 1)
	if err != nil {
		t.Fatal(err)
	}
	if plan.BaselineSG {
		t.Fatal("no ingress.public / baseline_sg => no baseline SG (back-compat)")
	}
}

// impl.baseline_sg=true forces the baseline SG even without ingress.public.
func TestBuildAWSVPCBaselineForced(t *testing.T) {
	a := map[string]any{"location.region": "eu-central-1", "service.managed": true}
	plan, err := BuildAWSVPC("acct", "prod", "net", a, map[string]any{"baseline_sg": true}, 1)
	if err != nil {
		t.Fatal(err)
	}
	if !plan.BaselineSG {
		t.Fatal("impl.baseline_sg=true must author a baseline SG")
	}
}

// A custom baseline rule (a port operand) is honored; the safe default is replaced.
func TestBuildAWSVPCBaselineOverride(t *testing.T) {
	a := awsVpcAttrs()
	plan, err := BuildAWSVPC("acct", "prod", "net", a,
		map[string]any{"baseline_sg_ingress": []any{
			map[string]any{"protocol": "tcp", "port": 443, "cidr": "10.0.0.0/16"}}}, 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.BaselineIngress) != 1 || plan.BaselineIngress[0].Protocol != "tcp" ||
		plan.BaselineIngress[0].FromPort != 443 || plan.BaselineIngress[0].CIDR != "10.0.0.0/16" {
		t.Fatalf("override rule not honored: %+v", plan.BaselineIngress)
	}
}

// groundhold NEVER authors a rule that opens the world — it would contradict the
// private posture. A baseline rule with 0.0.0.0/0 (or ::/0) is refused at build.
func TestBuildAWSVPCBaselineRefuseOpen(t *testing.T) {
	a := awsVpcAttrs()
	for name, cidr := range map[string]string{"v4 open": "0.0.0.0/0", "v6 open": "::/0"} {
		_, err := BuildAWSVPC("acct", "prod", "net", a,
			map[string]any{"baseline_sg_ingress": []any{
				map[string]any{"protocol": "tcp", "port": 443, "cidr": cidr}}}, 1)
		if err == nil {
			t.Fatalf("%s: authoring a world-open baseline rule must refuse", name)
		}
	}
}

func TestBuildAWSVPCBaselineBadOverride(t *testing.T) {
	a := awsVpcAttrs()
	for name, impl := range map[string]map[string]any{
		"not a list":   {"baseline_sg_ingress": "s3"},
		"empty list":   {"baseline_sg_ingress": []any{}},
		"missing cidr": {"baseline_sg_ingress": []any{map[string]any{"protocol": "tcp", "port": 443}}},
		"tcp no port":  {"baseline_sg_ingress": []any{map[string]any{"protocol": "tcp", "cidr": "10.0.0.0/16"}}},
	} {
		if _, err := BuildAWSVPC("acct", "prod", "net", a, impl, 1); err == nil {
			t.Fatalf("expected refusal for %q", name)
		}
	}
}

// Create authors the baseline SG (CreateSecurityGroup + AuthorizeSecurityGroupIngress).
func TestCreateAWSVPCBaselineSG(t *testing.T) {
	srv := awsVpcServer(t, "net")
	defer srv.Close()
	d := awsVpcTestDriver(t, srv)
	res := d.createAWSVPC("eu-central-1", "000000000000", "prod", "net", awsVpcAttrs(), nil, 1)
	if res.Status != "succeeded" || res.ProviderID != "vpc:eu-central-1:vpc-0abc123" {
		t.Fatalf("baseline-SG create must succeed with the vpc pid, got %+v", res)
	}
}

// awsVpcSGServer serves an observe with a caller-chosen security-group posture.
func awsVpcSGServer(t *testing.T, sgItems string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			b := make([]byte, r.ContentLength)
			r.Body.Read(b)
			action := ""
			for _, kv := range strings.Split(string(b), "&") {
				if strings.HasPrefix(kv, "Action=") {
					action = strings.TrimPrefix(kv, "Action=")
				}
			}
			switch action {
			case "DescribeVpcs":
				_, _ = w.Write([]byte(`<DescribeVpcsResponse><vpcSet><item><vpcId>vpc-0abc123</vpcId></item></vpcSet></DescribeVpcsResponse>`))
			case "DescribeInternetGateways":
				_, _ = w.Write([]byte(`<DescribeInternetGatewaysResponse><internetGatewaySet/></DescribeInternetGatewaysResponse>`))
			case "DescribeRouteTables":
				_, _ = w.Write([]byte(`<DescribeRouteTablesResponse><routeTableSet/></DescribeRouteTablesResponse>`))
			case "DescribeFlowLogs":
				_, _ = w.Write([]byte(`<DescribeFlowLogsResponse><flowLogSet/></DescribeFlowLogsResponse>`))
			case "DescribeVpcEndpoints":
				_, _ = w.Write([]byte(`<DescribeVpcEndpointsResponse><vpcEndpointSet/></DescribeVpcEndpointsResponse>`))
			case "DescribeSecurityGroups":
				_, _ = w.Write([]byte(`<DescribeSecurityGroupsResponse><securityGroupInfo>` + sgItems + `</securityGroupInfo></DescribeSecurityGroupsResponse>`))
			default:
				w.WriteHeader(400)
			}
		}))
}

// An SG in the VPC with a 0.0.0.0/0 ingress rule flips ingress.public to true,
// even with NO IGW route. This is the trap: a rule a controller appended at
// runtime is WITNESSED (never auto-revoked) and surfaces the posture honestly.
func TestObserveAWSVPCOpenIngressSG(t *testing.T) {
	open := `<item><groupId>sg-open</groupId><groupName>foreign</groupName>` +
		`<ipPermissions><item><ipProtocol>tcp</ipProtocol><fromPort>443</fromPort><toPort>443</toPort>` +
		`<ipRanges><item><cidrIp>0.0.0.0/0</cidrIp></item></ipRanges></item></ipPermissions></item>`
	srv := awsVpcSGServer(t, open)
	defer srv.Close()
	d := awsVpcTestDriver(t, srv)
	obs, _, err := d.observeAWSVPC("net", "vpc:eu-central-1:vpc-0abc123")
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]any{}
	for _, o := range obs {
		got[o.Path] = o.Value
	}
	if got["ingress.public"] != true {
		t.Fatalf("an open 0.0.0.0/0 SG rule must observe ingress.public=true, got %v", got["ingress.public"])
	}
}

// An IPv6 ::/0 ingress rule is equally a public door.
func TestObserveAWSVPCOpenIngressSGv6(t *testing.T) {
	open := `<item><groupId>sg-open6</groupId><groupName>foreign</groupName>` +
		`<ipPermissions><item><ipProtocol>-1</ipProtocol>` +
		`<ipv6Ranges><item><cidrIpv6>::/0</cidrIpv6></item></ipv6Ranges></item></ipPermissions></item>`
	srv := awsVpcSGServer(t, open)
	defer srv.Close()
	d := awsVpcTestDriver(t, srv)
	obs, _, err := d.observeAWSVPC("net", "vpc:eu-central-1:vpc-0abc123")
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]any{}
	for _, o := range obs {
		got[o.Path] = o.Value
	}
	if got["ingress.public"] != true {
		t.Fatalf("an open ::/0 SG rule must observe ingress.public=true, got %v", got["ingress.public"])
	}
}

// A baseline SG closed to the world (intra-VPC only) + no IGW => ingress.public=false.
func TestObserveAWSVPCClosedSG(t *testing.T) {
	closed := `<item><groupId>sg-01</groupId><groupName>net-prod-baseline</groupName>` +
		`<ipPermissions><item><ipProtocol>-1</ipProtocol>` +
		`<ipRanges><item><cidrIp>10.0.0.0/16</cidrIp></item></ipRanges></item></ipPermissions></item>`
	srv := awsVpcSGServer(t, closed)
	defer srv.Close()
	d := awsVpcTestDriver(t, srv)
	obs, _, err := d.observeAWSVPC("net", "vpc:eu-central-1:vpc-0abc123")
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]any{}
	for _, o := range obs {
		got[o.Path] = o.Value
	}
	if got["ingress.public"] != false {
		t.Fatalf("a closed baseline SG + no IGW must observe ingress.public=false, got %v", got["ingress.public"])
	}
}

// awsVpcSGDeleteServer serves a delete whose DescribeSecurityGroups returns the
// given SG items (the VPC + every other child list is owned/empty so the delete
// reaches the SG teardown).
func awsVpcSGDeleteServer(t *testing.T, sgItems string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			b := make([]byte, r.ContentLength)
			r.Body.Read(b)
			action := ""
			for _, kv := range strings.Split(string(b), "&") {
				if strings.HasPrefix(kv, "Action=") {
					action = strings.TrimPrefix(kv, "Action=")
				}
			}
			switch action {
			case "DescribeVpcs":
				_, _ = w.Write([]byte(`<DescribeVpcsResponse><vpcSet><item><vpcId>vpc-0abc123</vpcId>` +
					`<tagSet><item><key>groundhold-capability</key><value>net</value></item>` +
					`<item><key>groundhold-environment</key><value>prod</value></item></tagSet>` +
					`</item></vpcSet></DescribeVpcsResponse>`))
			case "DescribeFlowLogs":
				_, _ = w.Write([]byte(`<DescribeFlowLogsResponse><flowLogSet/></DescribeFlowLogsResponse>`))
			case "DescribeVpcEndpoints":
				_, _ = w.Write([]byte(`<DescribeVpcEndpointsResponse><vpcEndpointSet/></DescribeVpcEndpointsResponse>`))
			case "DescribeRouteTables":
				_, _ = w.Write([]byte(`<DescribeRouteTablesResponse><routeTableSet/></DescribeRouteTablesResponse>`))
			case "DescribeNatGateways":
				_, _ = w.Write([]byte(`<DescribeNatGatewaysResponse><natGatewaySet/></DescribeNatGatewaysResponse>`))
			case "DescribeAddresses":
				_, _ = w.Write([]byte(`<DescribeAddressesResponse><addressesSet/></DescribeAddressesResponse>`))
			case "DescribeInternetGateways":
				_, _ = w.Write([]byte(`<DescribeInternetGatewaysResponse><internetGatewaySet/></DescribeInternetGatewaysResponse>`))
			case "DescribeSecurityGroups":
				_, _ = w.Write([]byte(`<DescribeSecurityGroupsResponse><securityGroupInfo>` + sgItems + `</securityGroupInfo></DescribeSecurityGroupsResponse>`))
			case "DescribeSubnets":
				_, _ = w.Write([]byte(`<DescribeSubnetsResponse><subnetSet/></DescribeSubnetsResponse>`))
			case "DeleteSecurityGroup", "DeleteVpc":
				_, _ = w.Write([]byte(`<Response/>`))
			default:
				w.WriteHeader(400)
			}
		}))
}

// An owned baseline SG is torn down (DeleteSecurityGroup) during the VPC delete.
func TestDeleteAWSVPCBaselineSG(t *testing.T) {
	owned := `<item><groupId>sg-01</groupId><groupName>net-prod-baseline</groupName>` +
		`<tagSet><item><key>groundhold-capability</key><value>net</value></item>` +
		`<item><key>groundhold-environment</key><value>prod</value></item></tagSet></item>`
	srv := awsVpcSGDeleteServer(t, owned)
	defer srv.Close()
	d := awsVpcTestDriver(t, srv)
	res := d.deleteAWSVPC("net", "prod", "vpc:eu-central-1:vpc-0abc123")
	if res.Status != "succeeded" {
		t.Fatalf("delete with an owned baseline SG must succeed, got %+v", res)
	}
}

// A foreign SG (a controller's SG, or the untagged default) is TOLERATED, never
// deleted — author-vs-witness: converge must not fight the LB/EKS controller.
func TestDeleteAWSVPCForeignSGTolerated(t *testing.T) {
	foreign := `<item><groupId>sg-default</groupId><groupName>default</groupName></item>` +
		`<item><groupId>sg-alb</groupId><groupName>k8s-alb</groupName>` +
		`<tagSet><item><key>groundhold-capability</key><value>someone-else</value></item></tagSet></item>`
	srv := awsVpcSGDeleteServer(t, foreign)
	defer srv.Close()
	d := awsVpcTestDriver(t, srv)
	res := d.deleteAWSVPC("net", "prod", "vpc:eu-central-1:vpc-0abc123")
	if res.Status != "succeeded" {
		t.Fatalf("foreign/default SGs must be skipped (not force-deleted), delete should still succeed, got %+v", res)
	}
}

func TestSplitAWSVpcProviderID(t *testing.T) {
	if _, _, err := splitAWSVpcProviderID("vpc:eu-central-1:vpc-0abc123"); err != nil {
		t.Fatalf("valid id rejected: %v", err)
	}
	for _, bad := range []string{"eu:vpc-1", "ecs:eu-central-1:vpc-1", "vpc:eu-central-1:notavpc"} {
		if _, _, err := splitAWSVpcProviderID(bad); err == nil {
			t.Errorf("accepted malformed vpc id %q", bad)
		}
	}
}

// vpcScanServer serves ONLY a tag-filtered DescribeVpcs returning a single VPC
// with the given tags — the create-adoption scan fixture (D253).
func vpcScanServer(t *testing.T, vpcID, capTag, envTag string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b := make([]byte, r.ContentLength)
		r.Body.Read(b)
		if strings.Contains(string(b), "Action=DescribeVpcs") {
			_, _ = w.Write([]byte(`<DescribeVpcsResponse><vpcSet><item><vpcId>` + vpcID + `</vpcId>` +
				`<tagSet><item><key>groundhold-capability</key><value>` + capTag + `</value></item>` +
				`<item><key>groundhold-environment</key><value>` + envTag + `</value></item></tagSet>` +
				`</item></vpcSet></DescribeVpcsResponse>`))
			return
		}
		t.Errorf("create-adoption must not call %s — bind the existing VPC, never create/mutate", string(b))
		w.WriteHeader(400)
	}))
}

// TestFindVpcByTags_VerifiesOwnership (D253): the scan binds a VPC only when its
// tags provably match ours — a FOREIGN-tagged VPC (server filter loose / a
// poisoned response) is never counted, so it is never adopted.
func TestFindVpcByTags_VerifiesOwnership(t *testing.T) {
	// ours -> counted
	srv := vpcScanServer(t, "vpc-ours", "net", "prod")
	d := awsVpcTestDriver(t, srv)
	if id, n, err := d.findVpcByTags("eu-central-1", "net", "prod"); err != nil || n != 1 || id != "vpc-ours" {
		t.Fatalf("our-tagged VPC must count as 1 ours, got id=%q n=%d err=%v", id, n, err)
	}
	srv.Close()
	// foreign -> NOT counted
	srv2 := vpcScanServer(t, "vpc-foreign", "someone-else", "prod")
	d2 := awsVpcTestDriver(t, srv2)
	if id, n, err := d2.findVpcByTags("eu-central-1", "net", "prod"); err != nil || n != 0 || id != "" {
		t.Fatalf("a FOREIGN-tagged VPC must never be counted as ours, got id=%q n=%d err=%v", id, n, err)
	}
	srv2.Close()
}

// TestCreateAWSVPC_AdoptsExistingOwned (D253): a create whose tag-scan finds our
// existing VPC BINDS it (succeeded + its pid) and issues NO mutation — a
// lost-ledger converge re-adopts reality instead of duplicating.
func TestCreateAWSVPC_AdoptsExistingOwned(t *testing.T) {
	srv := vpcScanServer(t, "vpc-existing", "net", "prod") // default -> t.Errorf on any mutation
	defer srv.Close()
	d := awsVpcTestDriver(t, srv)
	res := d.createAWSVPC("eu-central-1", "000000000000", "prod", "net", awsVpcAttrs(), nil, 1)
	if res.Status != "succeeded" || res.ProviderID != awsVpcProviderID("eu-central-1", "vpc-existing") {
		t.Fatalf("must adopt the existing owned VPC (no mutation), got %+v", res)
	}
}

// D280 (F1): a regional network's PUBLIC side spans the same AZs as the
// private side — 2 public subnets (first hosts the NAT), every public subnet
// on the IGW route table, every private subnet on the NAT route table.
func TestCreateAWSVPCRegionalNatMultiAZ(t *testing.T) {
	type subnetReq struct{ cidr, az string }
	var subnets []subnetReq
	var associations []string
	rtCount := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b := make([]byte, r.ContentLength)
		r.Body.Read(b)
		body := string(b)
		form, _ := url.ParseQuery(body)
		switch form.Get("Action") {
		case "CreateVpc":
			_, _ = w.Write([]byte(`<CreateVpcResponse><vpc><vpcId>vpc-reg</vpcId></vpc></CreateVpcResponse>`))
		case "DescribeVpcs":
			_, _ = w.Write([]byte(`<DescribeVpcsResponse><vpcSet/></DescribeVpcsResponse>`))
		case "CreateSubnet":
			subnets = append(subnets, subnetReq{form.Get("CidrBlock"), form.Get("AvailabilityZone")})
			id := fmt.Sprintf("subnet-%02d", len(subnets))
			_, _ = w.Write([]byte(`<CreateSubnetResponse><subnet><subnetId>` + id + `</subnetId></subnet></CreateSubnetResponse>`))
		case "CreateInternetGateway":
			_, _ = w.Write([]byte(`<r><internetGatewayId>igw-1</internetGatewayId></r>`))
		case "AttachInternetGateway":
			_, _ = w.Write([]byte(`<r/>`))
		case "AllocateAddress":
			_, _ = w.Write([]byte(`<r><allocationId>eip-1</allocationId></r>`))
		case "CreateNatGateway":
			if got := form.Get("SubnetId"); got != "subnet-03" {
				t.Errorf("NAT must live in the FIRST public subnet (subnet-03), got %s", got)
			}
			_, _ = w.Write([]byte(`<r><natGatewayId>nat-1</natGatewayId></r>`))
		case "DescribeNatGateways":
			_, _ = w.Write([]byte(`<r><natGatewaySet><item><state>available</state></item></natGatewaySet></r>`))
		case "CreateRouteTable":
			rtCount++
			_, _ = w.Write([]byte(fmt.Sprintf(`<r><routeTableId>rtb-%d</routeTableId></r>`, rtCount)))
		case "CreateRoute":
			_, _ = w.Write([]byte(`<r/>`))
		case "AssociateRouteTable":
			associations = append(associations, form.Get("RouteTableId")+":"+form.Get("SubnetId"))
			_, _ = w.Write([]byte(`<r/>`))
		case "CreateSecurityGroup":
			_, _ = w.Write([]byte(`<r><groupId>sg-01</groupId></r>`))
		case "AuthorizeSecurityGroupIngress":
			_, _ = w.Write([]byte(`<r/>`))
		default:
			t.Errorf("unexpected action %q", form.Get("Action"))
			w.WriteHeader(400)
		}
	}))
	defer srv.Close()
	d := awsVpcTestDriver(t, srv)
	a := awsVpcAttrs()
	a["availability.class"] = "regional"
	a["egress.internet"] = "nat"
	a["egress.restricted"] = false
	res := d.createAWSVPC("eu-central-1", "000000000000", "prod", "net", a, nil, 1)
	if res.Status != "succeeded" {
		t.Fatalf("regional nat create = %+v", res)
	}
	// 2 private (10.0.0.0/24 + 10.0.2.0/24) then 2 public (10.0.1.0/24 + 10.0.3.0/24),
	// each pair across eu-central-1a/b
	want := []subnetReq{
		{"10.0.0.0/24", "eu-central-1a"}, {"10.0.2.0/24", "eu-central-1b"},
		{"10.0.1.0/24", "eu-central-1a"}, {"10.0.3.0/24", "eu-central-1b"},
	}
	if fmt.Sprint(subnets) != fmt.Sprint(want) {
		t.Fatalf("subnets = %v, want %v", subnets, want)
	}
	// rtb-1 = public (IGW): both public subnets; rtb-2 = private (NAT): both private
	wantAssoc := []string{"rtb-1:subnet-03", "rtb-1:subnet-04", "rtb-2:subnet-01", "rtb-2:subnet-02"}
	if fmt.Sprint(associations) != fmt.Sprint(wantAssoc) {
		t.Fatalf("associations = %v, want %v", associations, wantAssoc)
	}
}

// D280: public CIDR resolution — derived odd-octet chain, explicit override,
// and a non-/24 base refusing with the operand named.
func TestPublicSubnetCIDRs(t *testing.T) {
	got, err := publicSubnetCIDRs("10.0.1.0/24", nil, 3)
	if err != nil || fmt.Sprint(got) != "[10.0.1.0/24 10.0.3.0/24 10.0.5.0/24]" {
		t.Fatalf("chain = %v (%v)", got, err)
	}
	got, err = publicSubnetCIDRs("10.9.0.0/20", map[string]any{
		"public_subnet_cidrs": []any{"10.9.16.0/24", "10.9.17.0/24"}}, 2)
	if err != nil || len(got) != 2 {
		t.Fatalf("override = %v (%v)", got, err)
	}
	if _, err = publicSubnetCIDRs("10.9.0.0/20", nil, 2); err == nil ||
		!strings.Contains(err.Error(), "public_subnet_cidrs") {
		t.Fatalf("non-/24 base must refuse naming the operand, got %v", err)
	}
}
