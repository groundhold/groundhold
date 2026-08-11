package gcp

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// computeServer routes the Compute v1 calls for the VPC shell. POSTs return an
// operation; operation GETs return DONE (or an injected error); resource GETs
// return docs carrying the ownership marker. Method is asserted per route.
// failOp: if non-empty, ONLY the operation whose name contains it DONE-errors
// (so a partial-failure test can fail exactly the subnet op, not the network).
// gcpSubnetLogConfig lets a test model a subnet whose flow logging is enabled but
// samples nothing (D742). Default: enabled with no rate stated, which is GCP's default.
var gcpSubnetLogConfig = `{"enable":true}`

// gcpFirewallRules is the firewalls.list body. It carried ONE deny-egress rule and no
// sourceRanges at all, so `firewallsAllowPublicIngress` never returned true in any test
// — the branch that decides whether the world can reach this network was unexercised
// (D756). Default: the owned deny-egress rule, unchanged.
var gcpFirewallRules = gcpDenyEgressOnly

const gcpDenyEgressOnly = `{"items":[{"name":"app-net-deny-egress-1",` +
	`"description":"groundhold:capability=app-net;environment=prod","direction":"EGRESS",` +
	`"denied":[{"IPProtocol":"all"}],"destinationRanges":["0.0.0.0/0"]}]}`

func computeServer(t *testing.T, failOp string) *httptest.Server {
	t.Helper()
	marker := `groundhold:capability=app-net;environment=prod`
	netDoc := `{"description":"` + marker + `","autoCreateSubnetworks":false,` +
		`"subnetworks":["https://x/projects/acme-prod/regions/europe-central2/subnetworks/app-net-subnet-1"]}`
	return httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			p := r.URL.Path
			switch {
			case strings.Contains(p, "/operations/"):
				if r.Method != "GET" {
					t.Errorf("operations.get must be GET, got %s", r.Method)
				}
				if failOp != "" && strings.Contains(p, failOp) {
					_, _ = w.Write([]byte(`{"status":"DONE","error":{"errors":[{"code":"SUBNET_RANGE_CONFLICT"}]}}`))
				} else {
					_, _ = w.Write([]byte(`{"status":"DONE"}`))
				}
			case r.Method == "POST" && strings.HasSuffix(p, "/networks"):
				_, _ = w.Write([]byte(`{"name":"op-net"}`))
			case r.Method == "POST" && strings.HasSuffix(p, "/subnetworks"):
				_, _ = w.Write([]byte(`{"name":"op-sub"}`))
			case r.Method == "POST" && strings.HasSuffix(p, "/firewalls"):
				_, _ = w.Write([]byte(`{"name":"op-fw"}`))
			case r.Method == "POST" && strings.HasSuffix(p, "/routers"):
				_, _ = w.Write([]byte(`{"name":"op-rtr"}`))
			case strings.HasSuffix(p, "/routers") && r.Method == "GET":
				// list — a Cloud NAT router owned by us, on the app-net network
				_, _ = w.Write([]byte(`{"items":[{"name":"app-net-router-1",` +
					`"description":"` + marker + `",` +
					`"network":"https://x/projects/acme-prod/global/networks/app-net-1",` +
					`"nats":[{"name":"app-net-nat-1"}]}]}`))
			case strings.Contains(p, "/routers/") && r.Method == "GET":
				_, _ = w.Write([]byte(`{"description":"` + marker + `","nats":[{"name":"app-net-nat-1"}]}`))
			case strings.Contains(p, "/firewalls") && r.Method == "GET":
				// list (filter query) — whatever rules this test wants the network to have
				_, _ = w.Write([]byte(gcpFirewallRules))
			case strings.Contains(p, "/subnetworks/") && r.Method == "GET":
				_, _ = w.Write([]byte(`{"description":"` + marker + `","privateIpGoogleAccess":true,"logConfig":` +
					gcpSubnetLogConfig + `}`))
			case strings.Contains(p, "/networks/") && r.Method == "GET":
				_, _ = w.Write([]byte(netDoc))
			case r.Method == "DELETE":
				_, _ = w.Write([]byte(`{"name":"op-del"}`))
			default:
				w.WriteHeader(http.StatusNotFound)
			}
		}))
}

func vpcDriver(t *testing.T, srv *httptest.Server) *Driver {
	t.Helper()
	t.Setenv("GROUNDHOLD_GCP_ACCESS_TOKEN", "test-token")
	d := NewDriver("acme-prod")
	d.ComputeBaseURL = srv.URL
	return d
}

func TestCreateVPCHappyPath(t *testing.T) {
	srv := computeServer(t, "")
	defer srv.Close()
	d := vpcDriver(t, srv)
	res := d.createVPC("app-net", "prod", vpcAttrs(), nil, 1)
	if res.Status != "succeeded" || !strings.HasPrefix(res.ProviderID, "vpc:acme-prod:europe-central2:") {
		t.Fatalf("got %+v, want succeeded + vpc-prefixed id", res)
	}
}

// A subnet operation that DONE-errors is a partial: failed, but WITH the pid
// (the network exists and must be bound so retire can target it). D29.
func TestCreateVPCPartialSubnetFailKeepsPid(t *testing.T) {
	srv := computeServer(t, "op-sub") // fail ONLY the subnet operation
	defer srv.Close()
	d := vpcDriver(t, srv)
	res := d.createVPC("app-net", "prod", vpcAttrs(), nil, 1)
	if res.Status != "failed" || res.ProviderID == "" {
		t.Fatalf("a partial (network without subnet) must be failed WITH a pid, got %+v", res)
	}
	if !strings.Contains(res.Reason, "network created without its subnet") {
		t.Fatalf("reason must name the partial, got %q", res.Reason)
	}
}

func TestCreateVPCEgressFirewall(t *testing.T) {
	srv := computeServer(t, "")
	defer srv.Close()
	d := vpcDriver(t, srv)
	a := vpcAttrs()
	a["egress.restricted"] = true
	res := d.createVPC("app-net", "prod", a, nil, 1)
	if res.Status != "succeeded" {
		t.Fatalf("egress-restricted create must succeed, got %+v", res)
	}
}

func TestObserveVPC(t *testing.T) {
	srv := computeServer(t, "")
	defer srv.Close()
	d := vpcDriver(t, srv)
	obs, _, err := d.observeVPC("app-net", "vpc:acme-prod:europe-central2:app-net-1")
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]any{}
	for _, o := range obs {
		got[o.Path] = o.Value
	}
	if got["location.region"] != "europe-central2" {
		t.Fatalf("region = %v", got["location.region"])
	}
	if got["flowLogs.enabled"] != true {
		t.Fatalf("flowLogs = %v", got["flowLogs.enabled"])
	}
	if got["egress.restricted"] != true {
		t.Fatalf("egress.restricted = %v (deny-egress rule present)", got["egress.restricted"])
	}
	if got["ingress.public"] != false {
		t.Fatalf("ingress.public = %v (no 0.0.0.0/0 allow-ingress)", got["ingress.public"])
	}
	if got["serviceAccess.private"] != true {
		t.Fatalf("serviceAccess.private = %v (subnet privateIpGoogleAccess=true)", got["serviceAccess.private"])
	}
	if got["egress.internet"] != "nat" {
		t.Fatalf("egress.internet = %v (owned router carries a Cloud NAT)", got["egress.internet"])
	}
}

// egress.internet=nat inserts a Cloud NAT router after the subnet; the create
// composite must still succeed with a vpc-prefixed pid.
func TestCreateVPCNatRoad(t *testing.T) {
	srv := computeServer(t, "")
	defer srv.Close()
	d := vpcDriver(t, srv)
	a := vpcAttrs()
	a["egress.internet"] = "nat"
	res := d.createVPC("app-net", "prod", a, nil, 1)
	if res.Status != "succeeded" || !strings.HasPrefix(res.ProviderID, "vpc:acme-prod:") {
		t.Fatalf("nat-road create must succeed with a pid, got %+v", res)
	}
}

// A NAT router insert that DONE-errors is a partial: failed WITH the pid (the
// network+subnet stand and must be bound so retire can target the road). D29.
func TestCreateVPCNatRouterFailKeepsPid(t *testing.T) {
	srv := computeServer(t, "op-rtr") // fail ONLY the router operation
	defer srv.Close()
	d := vpcDriver(t, srv)
	a := vpcAttrs()
	a["egress.internet"] = "nat"
	res := d.createVPC("app-net", "prod", a, nil, 1)
	if res.Status != "failed" || res.ProviderID == "" {
		t.Fatalf("a partial (network+subnet without NAT router) must be failed WITH a pid, got %+v", res)
	}
	if !strings.Contains(res.Reason, "Cloud NAT router failed") {
		t.Fatalf("reason must name the partial NAT road, got %q", res.Reason)
	}
}

func TestDeleteVPCReverseOrder(t *testing.T) {
	srv := computeServer(t, "")
	defer srv.Close()
	d := vpcDriver(t, srv)
	res := d.deleteVPC("app-net", "prod", "vpc:acme-prod:europe-central2:app-net-1")
	if res.Status != "succeeded" {
		t.Fatalf("delete of an owned network must succeed, got %+v", res)
	}
}

func TestDeleteVPCForeignMarkerRefused(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			// network exists but carries a foreign marker
			_, _ = w.Write([]byte(`{"description":"groundhold:capability=other;environment=prod",` +
				`"autoCreateSubnetworks":false}`))
		}))
	defer srv.Close()
	d := vpcDriver(t, srv)
	res := d.deleteVPC("app-net", "prod", "vpc:acme-prod:europe-central2:app-net-1")
	if res.Status != "failed" || !strings.Contains(res.Reason, "not ours") {
		t.Fatalf("a foreign-marker network must refuse delete, got %+v", res)
	}
}

func TestSplitAndMarkerVPC(t *testing.T) {
	if _, _, _, err := splitVPCProviderID("vpc:proj:europe-central2:net-1"); err != nil {
		t.Fatalf("valid id rejected: %v", err)
	}
	for _, bad := range []string{"proj:r:n", "gcs:proj:r:n", "vpc:proj:r:n:x", "vpc:proj:UP:n"} {
		if _, _, _, err := splitVPCProviderID(bad); err == nil {
			t.Errorf("accepted malformed vpc id %q", bad)
		}
	}
	if _, _, ok := parseVPCMarker("groundhold:capability=c;environment=e;future=x"); !ok {
		t.Error("marker parse must tolerate a future ;k=v extension")
	}
	if _, _, ok := parseVPCMarker("no marker here"); ok {
		t.Error("absent marker must not parse ok")
	}
}

// D742: a GCP subnet with `logConfig.enable: true` and `flowSampling: 0` records NO
// flows. `enable` is the switch, not the outcome — the same shape D725 fixed on AWS one
// cloud over, and both fields arrive in the same subnetworks.get body. An ABSENT rate is
// GCP's platform default and must not be read as zero: absent and zero are two answers.
//
// Driven through observeVPC. Three earlier attempts in this family were written as
// re-computations of the driver's own expression, which is green by construction (D726,
// D739); this one asks the driver.
func TestGCPFlowLogsRequireActualSampling(t *testing.T) {
	cases := []struct {
		name      string
		logConfig string
		want      bool
	}{
		{"enabled with a rate", `{"enable":true,"flowSampling":0.5}`, true},
		{"enabled, explicit zero — nothing is recorded", `{"enable":true,"flowSampling":0}`, false},
		{"enabled, no rate stated — the platform default applies", `{"enable":true}`, true},
		{"switched off", `{"enable":false}`, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			old := gcpSubnetLogConfig
			gcpSubnetLogConfig = c.logConfig
			defer func() { gcpSubnetLogConfig = old }()

			srv := computeServer(t, "")
			defer srv.Close()
			d := vpcDriver(t, srv)
			obs, _, err := d.observeVPC("app-net", "vpc:acme-prod:europe-central2:app-net-1")
			if err != nil {
				t.Fatal(err)
			}
			var got any
			for _, o := range obs {
				if o.Path == "flowLogs.enabled" {
					got = o.Value
				}
			}
			if got != c.want {
				t.Fatalf("flowLogs.enabled = %v, want %v — a subnet sampling nothing "+
					"records no flows, whatever its enable flag says", got, c.want)
			}
		})
	}
}

// D756. `ingress.public` says whether the world can reach this network, and its true
// branch had never run: no fixture in this package carried `sourceRanges`, so
// firewallsAllowPublicIngress could only ever return false. The single assertion on the
// attribute pinned the safe side. A sweep of every field the drivers DECODE against every
// field the fixtures SERVE found 22 such fields across three clouds; this one is on a
// security attribute, so it is exercised in both directions here.
func TestGCPIngressPublicSeesAnOpenRule(t *testing.T) {
	const marker = `groundhold:capability=app-net;environment=prod`
	rule := func(extra string) string {
		return `{"items":[{"name":"app-net-in-1","description":"` + marker + `"` + extra + `}]}`
	}
	cases := []struct {
		name  string
		rules string
		want  bool
	}{
		{"an allow-ingress rule open to the world",
			rule(`,"allowed":[{"IPProtocol":"tcp"}],"sourceRanges":["0.0.0.0/0"]`), true},
		{"open to the world over IPv6",
			rule(`,"allowed":[{"IPProtocol":"tcp"}],"sourceRanges":["::/0"]`), true},
		{"the same rule DISABLED opens nothing",
			rule(`,"disabled":true,"allowed":[{"IPProtocol":"tcp"}],"sourceRanges":["0.0.0.0/0"]`), false},
		{"an allow-ingress rule from one office range",
			rule(`,"allowed":[{"IPProtocol":"tcp"}],"sourceRanges":["203.0.113.0/24"]`), false},
		{"a DENY rule from the world is not an opening",
			rule(`,"denied":[{"IPProtocol":"tcp"}],"sourceRanges":["0.0.0.0/0"]`), false},
		{"only the deny-egress rule", gcpDenyEgressOnly, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			old := gcpFirewallRules
			gcpFirewallRules = c.rules
			defer func() { gcpFirewallRules = old }()

			srv := computeServer(t, "")
			defer srv.Close()
			d := vpcDriver(t, srv)
			obs, _, err := d.observeVPC("app-net", "vpc:acme-prod:europe-central2:app-net-1")
			if err != nil {
				t.Fatal(err)
			}
			var got any
			for _, o := range obs {
				if o.Path == "ingress.public" {
					got = o.Value
				}
			}
			if got != c.want {
				t.Fatalf("ingress.public = %v, want %v — this attribute is how a contract "+
					"asks whether the world can reach the network (D756)", got, c.want)
			}
		})
	}
}
