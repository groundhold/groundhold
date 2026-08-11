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
	deleted := false
	return httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			b := make([]byte, r.ContentLength)
			_, _ = r.Body.Read(b)
			switch queryAction(b) {
			case "CreateVpnGateway":
				_, _ = w.Write([]byte(`<CreateVpnGatewayResponse><vpnGateway><vpnGatewayId>vgw-0abc123</vpnGatewayId>` +
					`<state>available</state></vpnGateway></CreateVpnGatewayResponse>`))
			case "DescribeVpnGateways":
				// D409 create-adoption scan is tag-FILTERED; the create Op's happy path
				// represents "no pre-existing gateway", so the scan finds nothing and a
				// genuine create runs. A by-id describe (observe/delete ownership gate)
				// still returns the owned gateway. Mirrors the D253 VPC fixture.
				if strings.Contains(string(b), "Filter.1.Name") {
					_, _ = w.Write([]byte(`<DescribeVpnGatewaysResponse><vpnGatewaySet/></DescribeVpnGatewaysResponse>`))
					return
				}
				// once deleted, the by-id describe reports state=deleted — which describeVgw
				// treats as authoritatively gone, so the delete's poll-to-absence (D981)
				// confirms gone.
				state := "available"
				if deleted {
					state = "deleted"
				}
				_, _ = w.Write([]byte(`<DescribeVpnGatewaysResponse><vpnGatewaySet><item>` +
					`<vpnGatewayId>vgw-0abc123</vpnGatewayId><state>` + state + `</state>` +
					`<tagSet><item><key>groundhold-capability</key><value>` + capLabel + `</value></item>` +
					`<item><key>groundhold-environment</key><value>prod</value></item></tagSet>` +
					`</item></vpnGatewaySet></DescribeVpnGatewaysResponse>`))
			case "DeleteVpnGateway":
				deleted = true
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

// TestDeleteVpnGatewayAsyncNotGoneIsUnknown pins D981: a gateway delete the provider
// ACCEPTS but that stays present (deleting, not deleted) must report unknown — never a
// terminal "succeeded" that tombstones an hourly-billable gateway still live.
func TestDeleteVpnGatewayAsyncNotGoneIsUnknown(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b := make([]byte, r.ContentLength)
		_, _ = r.Body.Read(b)
		switch queryAction(b) {
		case "DescribeVpnGateways": // never gone — owned, still "deleting"
			_, _ = w.Write([]byte(`<DescribeVpnGatewaysResponse><vpnGatewaySet><item>` +
				`<vpnGatewayId>vgw-0abc123</vpnGatewayId><state>deleting</state>` +
				`<tagSet><item><key>groundhold-capability</key><value>site</value></item>` +
				`<item><key>groundhold-environment</key><value>prod</value></item></tagSet>` +
				`</item></vpnGatewaySet></DescribeVpnGatewaysResponse>`))
		case "DeleteVpnGateway":
			_, _ = w.Write([]byte(`<DeleteVpnGatewayResponse/>`))
		default:
			w.WriteHeader(400)
		}
	}))
	defer srv.Close()
	d := vgwDriver(t, srv)
	d.PollTimeout = 5 * time.Millisecond // the gateway never reaches "deleted" → times out fast
	res := d.Delete("vpngateway", "site", "prod", "vgw:eu-central-1:vgw-0abc123", "k")
	if res.Status != "unknown" {
		t.Fatalf("an accepted-but-still-deleting gateway must be unknown (keep the handle), got %+v", res)
	}
}

func TestHonestyHarnessVpnGateway(t *testing.T) {
	t.Setenv("AWS_ACCESS_KEY_ID", "AKID")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "secret")
	pid := "vgw:eu-central-1:vgw-0abc123"
	p := &certifynet.Probe{
		Name:            "aws/vpngateway",
		AssertTransient: true,         // D237: create/delete route through provider.MutationResult
		Classify:        queryXMLRole, // Create/Delete opaque; Describe reads
		OwnerTagValue:   "site",
		DeterministicID: false, // the vgw id is server-assigned
		// F-LC3 (D521): protocol-aware gone estate.
		ObserveAbsent: func(pr provider.Provider) ([]provider.Observation, []string, error) {
			return pr.Observe("vpngateway", "site", pid)
		},
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

// vgwScanServer serves ONLY the tag-filtered DescribeVpnGateways, returning one gateway
// with the given tags — the create-adoption scan fixture (D409, mirroring D253's
// vpcScanServer). Anything else is a mutation the adoption must not send.
func vgwScanServer(t *testing.T, vgwID, capTag, envTag string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b := make([]byte, r.ContentLength)
		_, _ = r.Body.Read(b)
		if strings.Contains(string(b), "Action=DescribeVpnGateways") {
			_, _ = w.Write([]byte(`<DescribeVpnGatewaysResponse><vpnGatewaySet><item>` +
				`<vpnGatewayId>` + vgwID + `</vpnGatewayId><state>available</state>` +
				`<tagSet><item><key>groundhold-capability</key><value>` + capTag + `</value></item>` +
				`<item><key>groundhold-environment</key><value>` + envTag + `</value></item></tagSet>` +
				`</item></vpnGatewaySet></DescribeVpnGatewaysResponse>`))
			return
		}
		t.Errorf("create-adoption must not call %s — bind the existing gateway, never create", string(b))
		w.WriteHeader(400)
	}))
}

// TestFindVgwByTags_VerifiesOwnership (D409): the scan binds a gateway only when its
// tags provably match ours. A FOREIGN-tagged gateway is never counted, so it is never
// adopted — and it is also never touched, because the create then stands up our own.
func TestFindVgwByTags_VerifiesOwnership(t *testing.T) {
	srv := vgwScanServer(t, "vgw-ours", "site", "prod")
	defer srv.Close()
	d := vgwDriver(t, srv)
	if id, n, err := d.findVgwByTags("eu-central-1", "site", "prod"); err != nil || n != 1 || id != "vgw-ours" {
		t.Fatalf("ours must be found: id=%q n=%d err=%v", id, n, err)
	}

	srv2 := vgwScanServer(t, "vgw-foreign", "someone-else", "prod")
	defer srv2.Close()
	d2 := vgwDriver(t, srv2)
	if id, n, err := d2.findVgwByTags("eu-central-1", "site", "prod"); err != nil || n != 0 || id != "" {
		t.Fatalf("a foreign gateway must never be counted: id=%q n=%d err=%v", id, n, err)
	}
}

// TestCreateVpnGateway_AdoptsExistingOwned (D409): the bug this fixes. A vpn gateway id
// is server-assigned and CreateVpnGateway takes no idempotency token, so before the scan
// a converge against a lost ledger stood up a SECOND billed gateway.
func TestCreateVpnGateway_AdoptsExistingOwned(t *testing.T) {
	srv := vgwScanServer(t, "vgw-0abc123", "site", "prod") // errors on any mutation
	defer srv.Close()
	d := vgwDriver(t, srv)
	res := d.createVpnGateway("eu-central-1", "prod", "site", vgwAttrs(), nil, 1)
	if res.Status != "succeeded" || res.ProviderID != vgwProviderID("eu-central-1", "vgw-0abc123") {
		t.Fatalf("must adopt the existing owned gateway (no CreateVpnGateway), got %+v", res)
	}
}

func vgwQueryRole(_ *http.Request, body []byte) certifynet.Role {
	if strings.Contains(string(body), "Action=Describe") {
		return certifynet.RoleRead
	}
	return certifynet.RoleMutateOpaque
}

// TestAdoptsExistingVpnGateway enrols vpngateway in the D391 class gate — the enrolment
// that found the bug.
func TestAdoptsExistingVpnGateway(t *testing.T) {
	t.Setenv("AWS_ACCESS_KEY_ID", "AKID")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "secret")
	p := &certifynet.ExistingProbe{
		Name:           "aws/vpngateway",
		Classify:       vgwQueryRole,
		ExistingServer: func() *httptest.Server { return vgwScanServer(t, "vgw-0abc123", "site", "prod") },
		New: func(happyURL string, rt http.RoundTripper) provider.Provider {
			d := NewDriver("eu-central-1")
			d.HTTP = &http.Client{Transport: rt}
			d.Account = "000000000000" // no STS round-trip: the gate must not leave the fake
			d.EC2BaseURL = happyURL
			d.PollInterval = time.Millisecond
			d.PollTimeout = 2 * time.Second
			return d
		},
		Create: func(pr provider.Provider) provider.CreateResult {
			return pr.Create("vpngateway", "site", "prod", vgwAttrs(), nil, "site", 1)
		},
		PID: vgwProviderID("eu-central-1", "vgw-0abc123"),
	}
	certifynet.CertifyCreateAdoptsExisting(t, p)
}
