package aws

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// D1005: ELBv2 DescribeLoadBalancers paginates (Marker in, NextMarker out) at PageSize
// 400, and unlike EC2 does NOT return everything when unbounded. discoverLoadBalancers
// once read page one only, so a region past 400 balancers dropped the rest from
// discovery — a real public ALB reported not-present. This drives the fake to hand back
// a NextMarker and asserts the sweep follows it: the page-two balancer must be discovered.
func TestDiscoverLoadBalancersFollowsPages(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		body := string(b)
		switch {
		case strings.Contains(body, "DescribeLoadBalancers"):
			if strings.Contains(body, "Marker=p2") {
				_, _ = w.Write([]byte(`<DescribeLoadBalancersResponse><DescribeLoadBalancersResult><LoadBalancers><member>` +
					`<LoadBalancerArn>arn:aws:elasticloadbalancing:eu-central-1:000000000000:loadbalancer/app/lb-page2/aaaa</LoadBalancerArn>` +
					`<LoadBalancerName>lb-page2</LoadBalancerName><Scheme>internet-facing</Scheme>` +
					`</member></LoadBalancers></DescribeLoadBalancersResult></DescribeLoadBalancersResponse>`))
				return
			}
			_, _ = w.Write([]byte(`<DescribeLoadBalancersResponse><DescribeLoadBalancersResult><LoadBalancers><member>` +
				`<LoadBalancerArn>arn:aws:elasticloadbalancing:eu-central-1:000000000000:loadbalancer/app/lb-page1/bbbb</LoadBalancerArn>` +
				`<LoadBalancerName>lb-page1</LoadBalancerName><Scheme>internet-facing</Scheme>` +
				`</member></LoadBalancers><NextMarker>p2</NextMarker></DescribeLoadBalancersResult></DescribeLoadBalancersResponse>`))
		case strings.Contains(body, "DescribeListeners"):
			_, _ = w.Write([]byte(`<DescribeListenersResponse><DescribeListenersResult><Listeners><member>` +
				`<Protocol>HTTPS</Protocol><Port>443</Port>` +
				`<ListenerArn>arn:aws:elasticloadbalancing:eu-central-1:000000000000:listener/app/x/y/z</ListenerArn>` +
				`</member></Listeners></DescribeListenersResult></DescribeListenersResponse>`))
		default:
			http.Error(w, "unexpected: "+body, 400)
		}
	}))
	defer srv.Close()

	d := discoverDriver(t, srv)
	out, _, err := d.discoverLoadBalancers("eu-central-1")
	if err != nil {
		t.Fatalf("discoverLoadBalancers: %v", err)
	}
	found := map[string]bool{}
	for _, disc := range out {
		found[disc.ProviderID] = true
	}
	if !found[elbv2ProviderID("eu-central-1", "lb-page1")] {
		t.Errorf("page-one balancer missing from discovery: %v", found)
	}
	if !found[elbv2ProviderID("eu-central-1", "lb-page2")] {
		t.Errorf("page-two balancer was dropped — the sweep stopped at page one despite a "+
			"NextMarker, so a real load balancer would read as not-present-in-estate: %v", found)
	}
}
