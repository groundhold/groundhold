package aws

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// D864. The sibling of D863, one call earlier in the same observe. `describeVpcRoutes`
// answers "does this VPC have a default route, and through what" from an UNPAGED
// DescribeRouteTables, and observe turns the answer into `egress.internet` — and, when it
// comes back "none", into `egress.restricted = true` — both derivation "measured".
//
// EC2 returns a hundred route tables per page and hands back a token; the per-VPC quota is
// 200, and one table per subnet is an ordinary layout. So the internet gateway route sits
// on page two and the tool measures a network as having NO road to the internet.
func TestVpcRoutesReadEveryPage(t *testing.T) {
	var calls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		calls++
		if !strings.Contains(string(body), "NextToken=page2") {
			_, _ = w.Write([]byte(`<DescribeRouteTablesResponse><routeTableSet>` +
				`<item><routeSet><item><destinationCidrBlock>10.0.0.0/16</destinationCidrBlock>` +
				`<gatewayId>local</gatewayId></item></routeSet></item>` +
				`</routeTableSet><nextToken>page2</nextToken></DescribeRouteTablesResponse>`))
			return
		}
		_, _ = w.Write([]byte(`<DescribeRouteTablesResponse><routeTableSet>` +
			`<item><routeSet><item><destinationCidrBlock>0.0.0.0/0</destinationCidrBlock>` +
			`<gatewayId>igw-abc123</gatewayId></item></routeSet></item>` +
			`</routeTableSet></DescribeRouteTablesResponse>`))
	}))
	defer srv.Close()

	d := NewDriver("eu-central-1")
	d.creds = Credentials{AccessKeyID: "AKID", SecretAccessKey: "secret"}
	d.EC2BaseURL = srv.URL

	_, hasIgw, err := d.describeVpcRoutes("eu-central-1", "vpc-1")
	if err != nil {
		t.Fatalf("routes: %v", err)
	}
	if !hasIgw {
		t.Fatalf("the internet gateway route was on page two and the scan reported NO road "+
			"after %d page(s). observe turns that into egress.internet=none and "+
			"egress.restricted=true, both measured (D864).", calls)
	}
}

// TestVpcRoutesRefuseAnUnfinishedSweep: an endless chain must end as an error. A road
// reported absent because the reader gave up is the same false measurement as one
// reported absent from page one.
func TestVpcRoutesRefuseAnUnfinishedSweep(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`<DescribeRouteTablesResponse><routeTableSet>` +
			`<item><routeSet><item><destinationCidrBlock>10.0.0.0/16</destinationCidrBlock>` +
			`<gatewayId>local</gatewayId></item></routeSet></item>` +
			`</routeTableSet><nextToken>more</nextToken></DescribeRouteTablesResponse>`))
	}))
	defer srv.Close()

	d := NewDriver("eu-central-1")
	d.creds = Credentials{AccessKeyID: "AKID", SecretAccessKey: "secret"}
	d.EC2BaseURL = srv.URL

	if _, _, err := d.describeVpcRoutes("eu-central-1", "vpc-1"); err == nil {
		t.Fatal("an endless page chain returned a road instead of an error")
	}
}
