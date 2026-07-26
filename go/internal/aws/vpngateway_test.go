package aws

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"groundhold/internal/certifynet"
	"groundhold/internal/provider"
)

func vgwAttrs() map[string]any {
	return map[string]any{
		"location.region": "eu-central-1",
		"ip.stack":        "ipv4",
		"service.managed": true,
	}
}

func TestBuildVpnGatewayHonors(t *testing.T) {
	p, err := BuildVpnGateway("prod", "site", vgwAttrs(), nil, 1)
	if err != nil {
		t.Fatal(err)
	}
	if p.Region != "eu-central-1" || p.Tags["groundhold-capability"] != "site" {
		t.Fatalf("plan = %+v", p)
	}
	params := p.createParams()
	if params["Action"] != "CreateVpnGateway" || params["Type"] != "ipsec.1" {
		t.Fatalf("createParams = %+v", params)
	}
}

func TestBuildVpnGatewayRefusals(t *testing.T) {
	cases := map[string]map[string]any{
		"dual-stack-refused": {"ip.stack": "dual-stack"}, // honest gap
		"bad-stack":          {"ip.stack": "ipv6-only"},
		"unmanaged":          {"service.managed": false},
		"unknown-attr":       {"tunnel.psk": "x"},
		"bad-region":         {"location.region": "nope"},
	}
	for name, extra := range cases {
		a := vgwAttrs()
		for k, v := range extra {
			a[k] = v
		}
		if _, err := BuildVpnGateway("prod", "site", a, nil, 1); err == nil {
			t.Errorf("%s: expected refusal, got none", name)
		}
	}
}

// vgwServer is a happy EC2-Query double. Create returns a server-assigned vgw id;
// Describe reflects owner tags.
func vgwServer(t *testing.T, capLabel string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			b := make([]byte, r.ContentLength)
			_, _ = r.Body.Read(b)
			switch queryAction(b) {
			case "CreateVpnGateway":
				_, _ = w.Write([]byte(`<CreateVpnGatewayResponse><vpnGateway><vpnGatewayId>vgw-0abc123</vpnGatewayId>` +
					`<state>available</state></vpnGateway></CreateVpnGatewayResponse>`))
			case "DescribeVpnGateways":
				_, _ = w.Write([]byte(`<DescribeVpnGatewaysResponse><vpnGatewaySet><item>` +
					`<vpnGatewayId>vgw-0abc123</vpnGatewayId><state>available</state>` +
					`<tagSet><item><key>groundhold-capability</key><value>` + capLabel + `</value></item>` +
					`<item><key>groundhold-environment</key><value>prod</value></item></tagSet>` +
					`</item></vpnGatewaySet></DescribeVpnGatewaysResponse>`))
			case "DeleteVpnGateway":
				_, _ = w.Write([]byte(`<DeleteVpnGatewayResponse/>`))
			default:
				w.WriteHeader(400)
			}
		}))
}

func vgwDriver(t *testing.T, srv *httptest.Server) *Driver {
	t.Helper()
	t.Setenv("AWS_ACCESS_KEY_ID", "AKID")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "secret")
	d := NewDriver("eu-central-1")
	d.Account = "000000000000"
	d.EC2BaseURL = srv.URL
	d.PollInterval = time.Millisecond
	d.PollTimeout = 2 * time.Second
	return d
}

func TestCreateObserveDeleteVpnGateway(t *testing.T) {
	srv := vgwServer(t, "site")
	defer srv.Close()
	d := vgwDriver(t, srv)
	res := d.Create("vpngateway", "site", "prod", vgwAttrs(), nil, "k", 1)
	if res.Status != "succeeded" || res.ProviderID != "vgw:eu-central-1:vgw-0abc123" {
		t.Fatalf("create: %+v", res)
	}
	obs, _, err := d.observeVpnGateway("site", res.ProviderID)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]any{}
	for _, o := range obs {
		got[o.Path] = o.Value
	}
	if got["ip.stack"] != "ipv4" || got["location.region"] != "eu-central-1" || got["service.managed"] != true {
		t.Fatalf("observe: %+v", got)
	}
	if del := d.Delete("vpngateway", "site", "prod", res.ProviderID, "k"); del.Status != "succeeded" {
		t.Fatalf("delete: %+v", del)
	}
}

func TestDeleteVpnGatewayForeignRefused(t *testing.T) {
	srv := vgwServer(t, "someone-else")
	defer srv.Close()
	d := vgwDriver(t, srv)
	res := d.Delete("vpngateway", "site", "prod", "vgw:eu-central-1:vgw-0abc123", "k")
	if res.Status != "failed" || !strings.Contains(res.Reason, "not ours") {
		t.Fatalf("foreign gateway must refuse delete, got %+v", res)
	}
}

func TestHonestyHarnessVpnGateway(t *testing.T) {
	t.Setenv("AWS_ACCESS_KEY_ID", "AKID")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "secret")
	pid := "vgw:eu-central-1:vgw-0abc123"
	p := &certifynet.Probe{
		// AssertTransient left false — D237 TODO: this driver's create/delete ladder
		// still maps 429/503/403 to terminal failed (and drops the providerId); it must
		// route through provider.MutationResult before the transient invariant can lock.
		Name:            "aws/vpngateway",
		AssertTransient: true,         // D237: create/delete route through provider.MutationResult
		Classify:        queryXMLRole, // Create/Delete opaque; Describe reads
		OwnerTagValue:   "site",
		DeterministicID: false, // the vgw id is server-assigned
		New: func(happyURL string, rt http.RoundTripper) provider.Provider {
			return newHonestyDriver(happyURL, rt)
		},
		Ops: []certifynet.Op{
			{
				Name:  "create",
				Happy: func() *httptest.Server { return vgwServer(t, "site") },
				Run: func(pr provider.Provider) provider.CreateResult {
					return pr.Create("vpngateway", "site", "prod", vgwAttrs(), nil, "k", 1)
				},
			},
			{
				Name:  "delete",
				Happy: func() *httptest.Server { return vgwServer(t, "site") },
				Run: func(pr provider.Provider) provider.CreateResult {
					return pr.Delete("vpngateway", "site", "prod", pid, "k")
				},
			},
		},
	}
	certifynet.CertifyDriverNet(t, p)
}
