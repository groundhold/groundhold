package aws

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// D865. `vpcRouteTableIDs` collects "every route table id in the VPC ... so the S3 gateway
// endpoint routes S3 traffic from every subnet" — from ONE page. A hundred tables per page,
// two hundred per VPC, one table per subnet being an ordinary layout.
//
// Truncated, the endpoint is associated with the tables that fit on page one and the create
// reports SUCCEEDED. The subnets behind the rest keep sending S3 traffic off the backbone,
// and nothing says so — the promise in the comment is the promise the capability makes.
//
// The function already refuses on an unreadable or empty list ("reconcile the partial
// network"), which is the right instinct; a truncated list is neither, and was the one case
// it could not see.
func TestGatewayRouteTablesReadEveryPage(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if !strings.Contains(string(body), "NextToken=page2") {
			_, _ = w.Write([]byte(`<DescribeRouteTablesResponse><routeTableSet>` +
				`<item><routeTableId>rtb-page1</routeTableId></item>` +
				`</routeTableSet><nextToken>page2</nextToken></DescribeRouteTablesResponse>`))
			return
		}
		_, _ = w.Write([]byte(`<DescribeRouteTablesResponse><routeTableSet>` +
			`<item><routeTableId>rtb-page2</routeTableId></item>` +
			`</routeTableSet></DescribeRouteTablesResponse>`))
	}))
	defer srv.Close()

	d := NewDriver("eu-central-1")
	d.creds = Credentials{AccessKeyID: "AKID", SecretAccessKey: "secret"}
	d.EC2BaseURL = srv.URL

	ids, res := d.vpcRouteTableIDs("eu-central-1", "vpc:pid", "vpc-1")
	if res != nil {
		t.Fatalf("unexpected refusal: %+v", res)
	}
	var got2 bool
	for _, id := range ids {
		if id == "rtb-page2" {
			got2 = true
		}
	}
	if !got2 {
		t.Fatalf("the S3 gateway endpoint would be wired into %v — the tables on page two "+
			"are missing, so their subnets keep sending S3 traffic off the backbone while "+
			"the create reports success (D865)", ids)
	}
}

// TestGatewayRouteTablesRefuseAnUnfinishedSweep: the function's whole discipline is to
// refuse rather than wire a partial network. An endless chain must refuse too.
func TestGatewayRouteTablesRefuseAnUnfinishedSweep(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`<DescribeRouteTablesResponse><routeTableSet>` +
			`<item><routeTableId>rtb-x</routeTableId></item>` +
			`</routeTableSet><nextToken>more</nextToken></DescribeRouteTablesResponse>`))
	}))
	defer srv.Close()

	d := NewDriver("eu-central-1")
	d.creds = Credentials{AccessKeyID: "AKID", SecretAccessKey: "secret"}
	d.EC2BaseURL = srv.URL

	ids, res := d.vpcRouteTableIDs("eu-central-1", "vpc:pid", "vpc-1")
	if res == nil {
		t.Fatalf("an endless page chain returned %d ids and no refusal — a partial network "+
			"wired as if complete", len(ids))
	}
	if res.Status != "unknown" {
		t.Fatalf("status = %q, want unknown", res.Status)
	}
}
