package gcp

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// pagedComputeServer serves the two Compute listings the VPC observer reduces, each in TWO
// pages. Compute's own discovery document says both take a `pageToken` and return a
// `nextPageToken`, and that `maxResults` defaults to 500 — so this is what the API does by
// default, not a contrived shape.
func pagedComputeServer(t *testing.T, routersPage2, firewallsPage2 string) *httptest.Server {
	t.Helper()
	marker := `groundhold:capability=app-net;environment=prod`
	netDoc := `{"description":"` + marker + `","autoCreateSubnetworks":false,` +
		`"subnetworks":["https://x/projects/acme-prod/regions/europe-central2/subnetworks/app-net-subnet-1"]}`
	second := func(r *http.Request) bool { return strings.Contains(r.URL.RawQuery, "pageToken") }
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := r.URL.Path
		switch {
		case strings.HasSuffix(p, "/routers") && r.Method == "GET":
			if second(r) {
				_, _ = w.Write([]byte(routersPage2))
				return
			}
			// page one: a router of ours with NO nat, and more to come.
			_, _ = w.Write([]byte(`{"items":[{"name":"other-router",` +
				`"description":"` + marker + `",` +
				`"network":"https://x/projects/acme-prod/global/networks/app-net-1"}],` +
				`"nextPageToken":"p2"}`))
		case strings.Contains(p, "/firewalls") && r.Method == "GET":
			if second(r) {
				_, _ = w.Write([]byte(firewallsPage2))
				return
			}
			_, _ = w.Write([]byte(`{"items":[{"name":"quiet-rule",` +
				`"description":"` + marker + `","direction":"INGRESS",` +
				`"allowed":[{"IPProtocol":"tcp"}],"sourceRanges":["10.0.0.0/8"]}],` +
				`"nextPageToken":"p2"}`))
		case strings.Contains(p, "/subnetworks/") && r.Method == "GET":
			_, _ = w.Write([]byte(`{"description":"` + marker + `","privateIpGoogleAccess":true,` +
				`"logConfig":{"enable":true,"flowSampling":0.5}}`))
		case strings.Contains(p, "/networks/") && r.Method == "GET":
			_, _ = w.Write([]byte(netDoc))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
}

// TestGCPEgressRoadReadsEveryRouterPage is D870.
//
// `egress.internet` is emitted with derivation "measured", and the vocabulary defines its
// `none` as "no road (isolated by construction)". The observer decides it by asking whether
// ANY router in the region carries a Cloud NAT — the question a single page cannot answer
// NO to (D863) — over a listing Compute pages at 500.
//
// So a network whose NAT router sits on page two is reported ISOLATED. A contract asserting
// isolation passes on an estate whose workloads reach the internet, which is the direction
// the freeze admits.
func TestGCPEgressRoadReadsEveryRouterPage(t *testing.T) {
	marker := `groundhold:capability=app-net;environment=prod`
	srv := pagedComputeServer(t, `{"items":[{"name":"app-net-router-1",`+
		`"description":"`+marker+`",`+
		`"network":"https://x/projects/acme-prod/global/networks/app-net-1",`+
		`"nats":[{"name":"app-net-nat-1"}]}]}`, `{"items":[]}`)
	defer srv.Close()
	d := vpcDriver(t, srv)

	road, err := d.observeEgressRoad("acme-prod", "europe-central2", "app-net-1", "app-net")
	if err != nil {
		t.Fatalf("road: %v", err)
	}
	if road != "nat" {
		t.Fatalf("egress.internet = %q — the Cloud NAT router sat on page two, and %q is "+
			"published as measured with the meaning \"no road (isolated by construction)\". "+
			"A contract asserting isolation would pass on a network that reaches the "+
			"internet (D870).", road, road)
	}
}

// TestGCPIngressPublicReadsEveryFirewallPage: the same shape in the attribute that says
// whether the world can reach this network. A NO from page one becomes
// `ingress.public = false`, measured — a reachable network reported private, which is the
// D694 shape this freeze exists to admit.
//
// The server-side `network=` filter narrows the listing to one network. That is not a
// bound: Compute still pages at 500 and hands back a token.
func TestGCPIngressPublicReadsEveryFirewallPage(t *testing.T) {
	marker := `groundhold:capability=app-net;environment=prod`
	srv := pagedComputeServer(t, `{"items":[]}`,
		`{"items":[{"name":"open-to-the-world","description":"`+marker+`",`+
			`"direction":"INGRESS","allowed":[{"IPProtocol":"tcp","ports":["22"]}],`+
			`"sourceRanges":["0.0.0.0/0"]}]}`)
	defer srv.Close()
	d := vpcDriver(t, srv)

	fws, err := d.listNetworkFirewalls("acme-prod", "app-net-1")
	if err != nil {
		t.Fatalf("firewalls: %v", err)
	}
	if !firewallsAllowPublicIngress(fws) {
		t.Fatalf("ingress.public came back false over %d rule(s) — the rule allowing "+
			"0.0.0.0/0 was on page two. That is a network the world can reach, reported "+
			"private and measured (D870).", len(fws))
	}
}

// TestGCPVPCReadsRefuseAnUnfinishedSweep: an endless chain must be an error, never a
// posture. The shared loop bounds it; what this pins is that the VPC reads USE the loop,
// so the bound is theirs too — a partial list here comes out as a security attribute.
func TestGCPVPCReadsRefuseAnUnfinishedSweep(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"items":[],"nextPageToken":"always-more"}`))
	}))
	defer srv.Close()
	d := vpcDriver(t, srv)

	if road, err := d.observeEgressRoad("acme-prod", "europe-central2", "app-net-1", "app-net"); err == nil {
		t.Fatalf("an endless router page chain returned %q instead of an error", road)
	}
	if fws, err := d.listNetworkFirewalls("acme-prod", "app-net-1"); err == nil {
		t.Fatalf("an endless firewall page chain returned %d rules instead of an error", len(fws))
	}
}
