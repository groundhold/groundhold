package aws

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

// Weapon 2 (D87) for the AWS VPC — the metamorphic write/read round-trip. The
// one attribute a private VPC both WRITES at create and READS at observe is
// flowLogs.enabled: create either issues CreateFlowLogs or does not, observe
// reverse-maps DescribeFlowLogs presence. A STATEFUL fake records whether a flow
// log was created and reflects it; a driver that reads DescribeFlowLogs from the
// wrong element, or inverts the len>0 test, fails here.
//
// ingress.public / egress.restricted are DELIBERATELY excluded: a fresh VPC
// never gets an Internet Gateway (create refuses ingress.public=true), so those
// attributes are constant-by-construction, not create-written round-trippers.
func metamorphicVPCServer(t *testing.T) *httptest.Server {
	t.Helper()
	flowLogsCreated := false
	return httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			raw, _ := io.ReadAll(r.Body)
			form, _ := url.ParseQuery(string(raw))
			switch form.Get("Action") {
			// ---- create writes ----
			case "CreateVpc":
				_, _ = w.Write([]byte(`<CreateVpcResponse><vpc><vpcId>vpc-0abc123</vpcId></vpc></CreateVpcResponse>`))
			case "CreateSubnet":
				_, _ = w.Write([]byte(`<CreateSubnetResponse><subnet><subnetId>subnet-0x</subnetId></subnet></CreateSubnetResponse>`))
			case "CreateFlowLogs":
				flowLogsCreated = true
				_, _ = w.Write([]byte(`<CreateFlowLogsResponse><flowLogIdSet><item>fl-123</item></flowLogIdSet>` +
					`<flowLogId>fl-123</flowLogId></CreateFlowLogsResponse>`))
			case "CreateSecurityGroup":
				// ingress.public declared => a baseline SG is authored at create
				_, _ = w.Write([]byte(`<CreateSecurityGroupResponse><groupId>sg-01</groupId></CreateSecurityGroupResponse>`))
			case "AuthorizeSecurityGroupIngress":
				_, _ = w.Write([]byte(`<Response/>`))
			// ---- observe reads reflect the recorded state ----
			case "DescribeVpcs":
				// D253: the tag-FILTERED create-adoption scan finds nothing (this
				// round-trip is a genuine create), so the real create writes still
				// run; a by-VpcId observe read returns the recorded VPC.
				if form.Get("Filter.1.Name") != "" {
					_, _ = w.Write([]byte(`<DescribeVpcsResponse><vpcSet/></DescribeVpcsResponse>`))
					return
				}
				_, _ = w.Write([]byte(`<DescribeVpcsResponse><vpcSet><item><vpcId>vpc-0abc123</vpcId>` +
					`<tagSet><item><key>groundhold-capability</key><value>net</value></item>` +
					`<item><key>groundhold-environment</key><value>prod</value></item></tagSet>` +
					`</item></vpcSet></DescribeVpcsResponse>`))
			case "DescribeInternetGateways":
				// a fresh private VPC has no IGW -> ingress.public stays false
				_, _ = w.Write([]byte(`<DescribeInternetGatewaysResponse><internetGatewaySet/></DescribeInternetGatewaysResponse>`))
			case "DescribeSecurityGroups":
				// the baseline SG is closed to the world (empty here = no open rule)
				_, _ = w.Write([]byte(`<DescribeSecurityGroupsResponse><securityGroupInfo/></DescribeSecurityGroupsResponse>`))
			case "DescribeRouteTables":
				_, _ = w.Write([]byte(`<DescribeRouteTablesResponse><routeTableSet/></DescribeRouteTablesResponse>`))
			case "DescribeFlowLogs":
				if flowLogsCreated {
					_, _ = w.Write([]byte(`<DescribeFlowLogsResponse><flowLogSet>` +
						`<item><flowLogId>fl-123</flowLogId></item></flowLogSet></DescribeFlowLogsResponse>`))
					return
				}
				_, _ = w.Write([]byte(`<DescribeFlowLogsResponse><flowLogSet/></DescribeFlowLogsResponse>`))
			default:
				w.WriteHeader(400)
			}
		}))
}

func TestMetamorphicVPCRoundTrip(t *testing.T) {
	cases := []struct {
		name     string
		flowLogs bool
	}{
		{"no-flow-logs", false},
		{"flow-logs-enabled", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			srv := metamorphicVPCServer(t)
			defer srv.Close()
			d := awsVpcTestDriver(t, srv)

			attrs := map[string]any{
				"location.region":   "eu-central-1",
				"ingress.public":    false,
				"egress.restricted": true,
				"flowLogs.enabled":  c.flowLogs,
				"service.managed":   true,
			}
			var impl map[string]any
			if c.flowLogs {
				impl = map[string]any{
					"flow_log_destination": "arn:aws:logs:eu-central-1:000000000000:log-group:vpc",
					"flow_log_role_arn":    "arn:aws:iam::000000000000:role/flow",
				}
			}
			res := d.createAWSVPC("eu-central-1", "000000000000", "prod", "net", attrs, impl, 1)
			if res.Status != "succeeded" {
				t.Fatalf("create failed: %+v", res)
			}
			obs, _, err := d.observeAWSVPC("net", res.ProviderID)
			if err != nil {
				t.Fatalf("observe: %v", err)
			}
			got := map[string]any{}
			for _, o := range obs {
				got[o.Path] = o.Value
			}
			// the metamorphic invariant: Observe reverse-maps what Create wrote.
			if got["flowLogs.enabled"] != c.flowLogs {
				t.Errorf("flowLogs.enabled round-trip broke: wrote %v, observed %v", c.flowLogs, got["flowLogs.enabled"])
			}
			if got["location.region"] != "eu-central-1" {
				t.Errorf("region round-trip broke: observed %v", got["location.region"])
			}
			// ingress.public is private-by-construction (no IGW ever created); assert
			// it never flips to public, but it is not a create-written round-tripper.
			if got["ingress.public"] != false {
				t.Errorf("private VPC must observe ingress.public=false, got %v", got["ingress.public"])
			}
		})
	}
}
