package aws

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// D863. `describeVpcSecurityGroupPosture` asks whether ANY security group in the VPC opens
// a door to everywhere, and observe turns a NO into `egress.restricted = true` with
// derivation "measured" — a security guarantee, asserted.
//
// A negative answer to "does any element satisfy P" is the one claim a single page cannot
// support. EC2 returns up to a thousand security groups per page and hands back a
// NextToken; the VPC quota is 2500. So on a large estate the open group can sit on page
// two and the tool measures the estate as restricted while it is not — the same shape as
// D847, and the file's own comment records a field report of exactly this consequence
// ("a hard constraint satisfied on a network whose every security group allowed -1 to
// 0.0.0.0/0").
//
// D861's rule needed this refinement: "is the list empty" IS settled by one page, because
// pages fill in order. "Does any element satisfy P", with P checked here rather than by the
// service, is not — a NO needs the last page.
func TestSecurityGroupPostureReadsEveryPage(t *testing.T) {
	var calls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		calls++
		if !strings.Contains(string(body), "NextToken=page2") {
			// A page of well-behaved groups, and more to come.
			_, _ = w.Write([]byte(`<DescribeSecurityGroupsResponse><securityGroupInfo>` +
				`<item><groupId>sg-tidy</groupId><ipPermissions/><ipPermissionsEgress>` +
				`<item><ipProtocol>tcp</ipProtocol><ipRanges><item><cidrIp>10.0.0.0/8</cidrIp></item></ipRanges></item>` +
				`</ipPermissionsEgress></item>` +
				`</securityGroupInfo><nextToken>page2</nextToken></DescribeSecurityGroupsResponse>`))
			return
		}
		// The door, on the second page.
		_, _ = w.Write([]byte(`<DescribeSecurityGroupsResponse><securityGroupInfo>` +
			`<item><groupId>sg-open</groupId><ipPermissions/><ipPermissionsEgress>` +
			`<item><ipProtocol>-1</ipProtocol><ipRanges><item><cidrIp>0.0.0.0/0</cidrIp></item></ipRanges></item>` +
			`</ipPermissionsEgress></item>` +
			`</securityGroupInfo></DescribeSecurityGroupsResponse>`))
	}))
	defer srv.Close()

	d := NewDriver("eu-central-1")
	d.creds = Credentials{AccessKeyID: "AKID", SecretAccessKey: "secret"}
	d.EC2BaseURL = srv.URL

	_, openEgress, err := d.describeVpcSecurityGroupPosture("eu-central-1", "vpc-1")
	if err != nil {
		t.Fatalf("posture: %v", err)
	}
	if !openEgress {
		t.Fatalf("a group allowing -1 to 0.0.0.0/0 sat on page two and the posture came back "+
			"CLOSED after %d page(s). observe turns that into egress.restricted=true, "+
			"derivation measured — a security guarantee asserted from an unfinished read (D863).",
			calls)
	}
}

// TestSecurityGroupPostureRefusesAnUnfinishedSweep: a chain that never ends must be an
// error, never a posture. "I stopped looking" and "there is nothing there" are different
// answers, and only one of them may become a measured attribute.
func TestSecurityGroupPostureRefusesAnUnfinishedSweep(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`<DescribeSecurityGroupsResponse><securityGroupInfo>` +
			`<item><groupId>sg-x</groupId><ipPermissions/><ipPermissionsEgress/></item>` +
			`</securityGroupInfo><nextToken>more</nextToken></DescribeSecurityGroupsResponse>`))
	}))
	defer srv.Close()

	d := NewDriver("eu-central-1")
	d.creds = Credentials{AccessKeyID: "AKID", SecretAccessKey: "secret"}
	d.EC2BaseURL = srv.URL

	_, _, err := d.describeVpcSecurityGroupPosture("eu-central-1", "vpc-1")
	if err == nil {
		t.Fatal("an endless page chain returned a posture instead of an error — the sweep " +
			"gave up and the answer became a measured security attribute")
	}
}
