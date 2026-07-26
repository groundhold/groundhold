package gcp

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"groundhold/internal/certifynet"
	"groundhold/internal/provider"
)

func vpnAttrs() map[string]any {
	return map[string]any{
		"location.region": "europe-west1",
		"ip.stack":        "ipv4",
		"service.managed": true,
	}
}

func vpnImpl() map[string]any {
	return map[string]any{"network": "projects/acme-prod/global/networks/prod-vpc"}
}

func TestBuildCloudVPNHonors(t *testing.T) {
	p, err := BuildCloudVPNGateway("acme-prod", "prod", "site", vpnAttrs(), vpnImpl(), 1)
	if err != nil {
		t.Fatal(err)
	}
	if !gcpName.MatchString(p.Name) || p.StackType != "IPV4_ONLY" {
		t.Fatalf("plan = %+v", p)
	}
	if !strings.Contains(p.Description, "capability=site") {
		t.Fatalf("marker missing: %q", p.Description)
	}
}

func TestBuildCloudVPNDualStack(t *testing.T) {
	a := vpnAttrs()
	a["ip.stack"] = "dual-stack"
	p, err := BuildCloudVPNGateway("acme-prod", "prod", "site", a, vpnImpl(), 1)
	if err != nil {
		t.Fatal(err)
	}
	if p.StackType != "IPV4_IPV6" {
		t.Fatalf("dual-stack must map to IPV4_IPV6, got %q", p.StackType)
	}
}

func TestBuildCloudVPNRefusals(t *testing.T) {
	type c struct{ attrs, impl map[string]any }
	cases := map[string]c{
		"no-network":   {vpnAttrs(), map[string]any{}},
		"bad-stack":    {map[string]any{"location.region": "europe-west1", "ip.stack": "ipv6-only"}, vpnImpl()},
		"unmanaged":    {map[string]any{"location.region": "europe-west1", "service.managed": false}, vpnImpl()},
		"unknown-attr": {map[string]any{"location.region": "europe-west1", "tunnel.psk": "x"}, vpnImpl()},
		"no-location":  {map[string]any{"service.managed": true}, vpnImpl()},
	}
	for name, tc := range cases {
		if _, err := BuildCloudVPNGateway("acme-prod", "prod", "site", tc.attrs, tc.impl, 1); err == nil {
			t.Errorf("%s: expected refusal, got none", name)
		}
	}
}

// vpnServer is a happy compute-LRO double. Insert returns an op; the op polls DONE;
// GET reflects the marker + stackType.
func vpnServer(t *testing.T, capLabel, stackType string) *httptest.Server {
	t.Helper()
	marker := vpcOwnerMarker(capLabel, "prod")
	return httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			switch {
			case strings.Contains(r.URL.Path, "/operations/"):
				_, _ = w.Write([]byte(`{"status":"DONE"}`))
			case r.Method == "POST" && strings.HasSuffix(r.URL.Path, "/vpnGateways"):
				_, _ = w.Write([]byte(`{"name":"op-create"}`))
			case r.Method == "DELETE":
				_, _ = w.Write([]byte(`{"name":"op-delete"}`))
			case r.Method == "GET":
				_, _ = w.Write([]byte(`{"description":"` + marker + `","stackType":"` + stackType + `"}`))
			default:
				w.WriteHeader(404)
			}
		}))
}

func vpnDriver(t *testing.T, srv *httptest.Server) *Driver {
	t.Helper()
	t.Setenv("GROUNDHOLD_GCP_ACCESS_TOKEN", "test-token")
	d := NewDriver("acme-prod")
	d.ComputeBaseURL = srv.URL
	d.Now = time.Now
	d.PollInterval = time.Millisecond
	d.PollTimeout = 2 * time.Second
	return d
}

func TestCreateObserveDeleteCloudVPN(t *testing.T) {
	srv := vpnServer(t, "site", "IPV4_ONLY")
	defer srv.Close()
	d := vpnDriver(t, srv)
	res := d.Create("vpngateway", "site", "prod", vpnAttrs(), vpnImpl(), "k", 1)
	if res.Status != "succeeded" || !strings.HasPrefix(res.ProviderID, "gvpn:acme-prod:europe-west1:") {
		t.Fatalf("create: %+v", res)
	}
	obs, _, err := d.observeCloudVPN("site", res.ProviderID)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]any{}
	for _, o := range obs {
		got[o.Path] = o.Value
	}
	if got["ip.stack"] != "ipv4" || got["location.region"] != "europe-west1" || got["service.managed"] != true {
		t.Fatalf("observe: %+v", got)
	}
	if del := d.Delete("vpngateway", "site", "prod", res.ProviderID, "k"); del.Status != "succeeded" {
		t.Fatalf("delete: %+v", del)
	}
}

func TestObserveCloudVPNDualStack(t *testing.T) {
	srv := vpnServer(t, "site", "IPV4_IPV6")
	defer srv.Close()
	d := vpnDriver(t, srv)
	obs, _, err := d.observeCloudVPN("site", cloudVPNProviderID("acme-prod", "europe-west1", "pv-site-x"))
	if err != nil {
		t.Fatal(err)
	}
	for _, o := range obs {
		if o.Path == "ip.stack" && o.Value != "dual-stack" {
			t.Fatalf("IPV4_IPV6 must observe dual-stack, got %v", o.Value)
		}
	}
}

func TestDeleteCloudVPNForeignRefused(t *testing.T) {
	srv := vpnServer(t, "someone-else", "IPV4_ONLY")
	defer srv.Close()
	d := vpnDriver(t, srv)
	pid := cloudVPNProviderID("acme-prod", "europe-west1", resourceName("acme-prod", "prod", "site", 1, 63))
	res := d.Delete("vpngateway", "site", "prod", pid, "k")
	if res.Status != "failed" || !strings.Contains(res.Reason, "not ours") {
		t.Fatalf("foreign gateway must refuse delete, got %+v", res)
	}
}

func TestHonestyHarnessCloudVPN(t *testing.T) {
	t.Setenv("GROUNDHOLD_GCP_ACCESS_TOKEN", "test-token")
	pid := cloudVPNProviderID("acme-prod", "europe-west1", resourceName("acme-prod", "prod", "site", 1, 63))
	p := &certifynet.Probe{
		AssertTransient: true, // D237 sweep
		Name:            "gcp/vpngateway",
		Classify:        gcpOpRole, // LRO create/delete parse the operation name
		OwnerTagValue:   "site",
		DeterministicID: true, // the gateway name is a chosen slug+hash
		New: func(happyURL string, rt http.RoundTripper) provider.Provider {
			return newGcpHonestyDriver(happyURL, rt)
		},
		Ops: []certifynet.Op{
			{
				Name:  "create",
				Happy: func() *httptest.Server { return vpnServer(t, "site", "IPV4_ONLY") },
				Run: func(pr provider.Provider) provider.CreateResult {
					return pr.Create("vpngateway", "site", "prod", vpnAttrs(), vpnImpl(), "k", 1)
				},
			},
			{
				Name:  "delete",
				Happy: func() *httptest.Server { return vpnServer(t, "site", "IPV4_ONLY") },
				Run: func(pr provider.Provider) provider.CreateResult {
					return pr.Delete("vpngateway", "site", "prod", pid, "k")
				},
			},
		},
	}
	certifynet.CertifyDriverNet(t, p)
}
