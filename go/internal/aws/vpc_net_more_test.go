package aws

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// This file rounds out vpc_net.go coverage: buildServiceEndpoints,
// vpcRouteTableIDs and pollVpcEndpoint all showed 0% despite
// TestCreateAWSVPCServiceAccess (vpc_test.go) exercising serviceAccess.private
// — because that fixture's DescribeVpcs handler does not distinguish the
// create-adoption SCAN (tag-filtered) from a by-id describe, so createAWSVPC's
// D253 create-adoption pre-read always finds a "pre-existing" VPC and returns
// early, before ANY endpoint code runs. (Test-fixture blind spot, not a
// production bug — reported alongside this coverage round, not fixed here per
// the house rule against touching round-1/other test files' fixtures.)
//
// endpointFreshVPCServer gates the create-adoption scan correctly (empty on
// the tag-filtered scan, like awsVpcServer in vpc_test.go) so a genuine create
// runs all the way to buildServiceEndpoints.
type endpointFreshVPCServer struct {
	routeTables    []string // route table ids DescribeRouteTables reports; nil = none
	routeTablesErr bool     // DescribeRouteTables fails outright
	interfaceState string   // state DescribeVpcEndpoints reports for an interface endpoint
	epSeq          int
}

func (f *endpointFreshVPCServer) handler(t *testing.T) *httptest.Server {
	t.Helper()
	if f.interfaceState == "" {
		f.interfaceState = "available"
	}
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b := make([]byte, r.ContentLength)
		_, _ = r.Body.Read(b)
		body := string(b)
		action := formAction(body)
		switch action {
		case "CreateVpc":
			_, _ = w.Write([]byte(`<CreateVpcResponse><vpc><vpcId>vpc-0abc123</vpcId></vpc></CreateVpcResponse>`))
		case "CreateSubnet":
			_, _ = w.Write([]byte(`<CreateSubnetResponse><subnet><subnetId>subnet-0x</subnetId></subnet></CreateSubnetResponse>`))
		case "DescribeVpcs":
			if strings.Contains(body, "Filter.1.Name") {
				_, _ = w.Write([]byte(`<DescribeVpcsResponse><vpcSet/></DescribeVpcsResponse>`)) // no adoption match
			} else {
				_, _ = w.Write([]byte(`<DescribeVpcsResponse><vpcSet><item><vpcId>vpc-0abc123</vpcId>` +
					`<tagSet><item><key>groundhold-capability</key><value>net</value></item>` +
					`<item><key>groundhold-environment</key><value>prod</value></item></tagSet>` +
					`</item></vpcSet></DescribeVpcsResponse>`))
			}
		case "DescribeRouteTables":
			if f.routeTablesErr {
				w.WriteHeader(http.StatusInternalServerError)
				_, _ = w.Write([]byte(`<ErrorResponse><Error><Code>InternalError</Code></Error></ErrorResponse>`))
				return
			}
			items := ""
			for _, id := range f.routeTables {
				items += "<item><routeTableId>" + id + "</routeTableId></item>"
			}
			_, _ = w.Write([]byte(`<DescribeRouteTablesResponse><routeTableSet>` + items + `</routeTableSet></DescribeRouteTablesResponse>`))
		case "CreateVpcEndpoint":
			f.epSeq++
			id := "vpce-" + itoaLB(f.epSeq)
			_, _ = w.Write([]byte(`<CreateVpcEndpointResponse><vpcEndpoint><vpcEndpointId>` + id + `</vpcEndpointId><state>pending</state></vpcEndpoint></CreateVpcEndpointResponse>`))
		case "DescribeVpcEndpoints":
			_, _ = w.Write([]byte(`<DescribeVpcEndpointsResponse><vpcEndpointSet><item><state>` + f.interfaceState + `</state></item></vpcEndpointSet></DescribeVpcEndpointsResponse>`))
		case "CreateSecurityGroup":
			_, _ = w.Write([]byte(`<CreateSecurityGroupResponse><groupId>sg-01</groupId></CreateSecurityGroupResponse>`))
		case "AuthorizeSecurityGroupIngress":
			_, _ = w.Write([]byte(`<Response/>`))
		default:
			w.WriteHeader(http.StatusBadRequest)
		}
	}))
}

// itoaLB is a tiny int->string helper (avoids importing strconv just for ids).
func itoaLB(n int) string {
	if n == 0 {
		return "0"
	}
	digits := ""
	for n > 0 {
		digits = string(rune('0'+n%10)) + digits
		n /= 10
	}
	return digits
}

func endpointFreshDriver(t *testing.T, srv *httptest.Server) *Driver {
	t.Helper()
	t.Setenv("AWS_ACCESS_KEY_ID", "AKID")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "secret")
	d := NewDriver("eu-central-1")
	d.EC2BaseURL = srv.URL
	d.Account = "000000000000"
	d.PollInterval = time.Millisecond
	d.PollTimeout = 2 * time.Second
	return d
}

// TestBuildServiceEndpoints_GatewayAndInterface: a genuine (non-adopted) create
// with serviceAccess.private=true lands BOTH an S3 gateway endpoint (associated
// with every route table) and an interface endpoint (placed in the private
// subnet, PrivateDnsEnabled) — the real create path, not the adoption no-op.
func TestBuildServiceEndpoints_GatewayAndInterface(t *testing.T) {
	f := &endpointFreshVPCServer{routeTables: []string{"rtb-01", "rtb-02"}}
	srv := f.handler(t)
	defer srv.Close()
	d := endpointFreshDriver(t, srv)
	a := awsVpcAttrs()
	a["serviceAccess.private"] = true
	res := d.createAWSVPC("eu-central-1", "000000000000", "prod", "net", a,
		map[string]any{"vpc_endpoints": []any{"s3", "sts"}}, 1)
	if res.Status != "succeeded" || res.ProviderID != "vpc:eu-central-1:vpc-0abc123" {
		t.Fatalf("fresh create with service access must succeed, got %+v", res)
	}
	if f.epSeq != 2 {
		t.Fatalf("want 2 CreateVpcEndpoint calls (1 gateway + 1 interface), got %d", f.epSeq)
	}
}

// TestBuildServiceEndpoints_NoRouteTablesFound: a gateway endpoint is declared
// but the VPC has no route tables to associate it with — unknown WITH the pid
// (a partial network), never a silently-unrouted gateway endpoint.
func TestBuildServiceEndpoints_NoRouteTablesFound(t *testing.T) {
	f := &endpointFreshVPCServer{routeTables: nil}
	srv := f.handler(t)
	defer srv.Close()
	d := endpointFreshDriver(t, srv)
	a := awsVpcAttrs()
	a["serviceAccess.private"] = true
	res := d.createAWSVPC("eu-central-1", "000000000000", "prod", "net", a,
		map[string]any{"vpc_endpoints": []any{"s3"}}, 1)
	if res.Status != "unknown" || !strings.Contains(res.Reason, "no route tables found") {
		t.Fatalf("an empty route table set must be unknown naming the gap, got %+v", res)
	}
	if res.ProviderID == "" {
		t.Fatalf("the partial-composite result must still carry the pid, got %+v", res)
	}
}

// TestVpcRouteTableIDs_TransportErrorIsUnknown: an unreachable/failing
// DescribeRouteTables is ambiguous — unknown WITH the pid (reconcile the
// partial network), never treated as "no route tables" (which would itself
// error) and never a crash.
func TestVpcRouteTableIDs_TransportErrorIsUnknown(t *testing.T) {
	f := &endpointFreshVPCServer{routeTablesErr: true}
	srv := f.handler(t)
	defer srv.Close()
	d := endpointFreshDriver(t, srv)
	a := awsVpcAttrs()
	a["serviceAccess.private"] = true
	res := d.createAWSVPC("eu-central-1", "000000000000", "prod", "net", a,
		map[string]any{"vpc_endpoints": []any{"s3"}}, 1)
	if res.Status != "unknown" || !strings.Contains(res.Reason, "cannot list route tables") {
		t.Fatalf("a failing route table list must be unknown naming the gap, got %+v", res)
	}
}

// TestPollVpcEndpoint_TimeoutIsUnknown: an interface endpoint stuck pending
// past the poll deadline is unknown WITH the pid, never a false succeeded.
func TestPollVpcEndpoint_TimeoutIsUnknown(t *testing.T) {
	f := &endpointFreshVPCServer{interfaceState: "pending"}
	srv := f.handler(t)
	defer srv.Close()
	d := endpointFreshDriver(t, srv)
	d.PollTimeout = 30 * time.Millisecond
	a := awsVpcAttrs()
	a["serviceAccess.private"] = true
	res := d.createAWSVPC("eu-central-1", "000000000000", "prod", "net", a,
		map[string]any{"vpc_endpoints": []any{"sts"}}, 1)
	if res.Status != "unknown" || !strings.Contains(res.Reason, "poll timeout") {
		t.Fatalf("a stuck-pending interface endpoint must time out unknown, got %+v", res)
	}
}

// TestPollVpcEndpoint_FailedStateIsUnknown: an interface endpoint that enters a
// terminal wrong state (failed) is unknown WITH the pid, never a false
// succeeded and never a bare failed that hides the standing VPC.
func TestPollVpcEndpoint_FailedStateIsUnknown(t *testing.T) {
	f := &endpointFreshVPCServer{interfaceState: "failed"}
	srv := f.handler(t)
	defer srv.Close()
	d := endpointFreshDriver(t, srv)
	a := awsVpcAttrs()
	a["serviceAccess.private"] = true
	res := d.createAWSVPC("eu-central-1", "000000000000", "prod", "net", a,
		map[string]any{"vpc_endpoints": []any{"sts"}}, 1)
	if res.Status != "unknown" || !strings.Contains(res.Reason, `"failed"`) {
		t.Fatalf("a failed interface endpoint must be unknown naming the state, got %+v", res)
	}
}
