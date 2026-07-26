package gcp

import (
	"strings"
	"testing"
)

func vpcAttrs() map[string]any {
	return map[string]any{
		"location.region":   "europe-central2",
		"ingress.public":    false,
		"egress.restricted": false,
		"flowLogs.enabled":  true,
		"service.managed":   true,
	}
}

func TestBuildVPCGolden(t *testing.T) {
	plan, err := BuildVPCRequests("acme-prod", "prod", "app-net", vpcAttrs(), nil, 1)
	if err != nil {
		t.Fatal(err)
	}
	// network: custom mode, ownership marker in description
	if plan.Network.Method != "POST" || !strings.HasSuffix(plan.Network.URL, "/global/networks") {
		t.Fatalf("network req = %s %s", plan.Network.Method, plan.Network.URL)
	}
	if plan.Network.Body["autoCreateSubnetworks"] != false {
		t.Fatal("a private network must be CUSTOM mode (no default-allow subnets)")
	}
	if !strings.Contains(plan.Network.Body["description"].(string), "groundhold:capability=app-net") {
		t.Fatalf("ownership marker missing from description: %v", plan.Network.Body["description"])
	}
	// subnet: region, flow logs on, references the network, default CIDR
	sub := plan.Subnet.Body
	if sub["region"] != "europe-central2" || sub["privateIpGoogleAccess"] != true {
		t.Fatalf("subnet = %v", sub)
	}
	if lc := sub["logConfig"].(map[string]any); lc["enable"] != true {
		t.Fatal("flowLogs.enabled must set subnet logConfig.enable")
	}
	if sub["ipCidrRange"] != "10.0.0.0/20" {
		t.Fatalf("default CIDR = %v", sub["ipCidrRange"])
	}
	if !strings.Contains(sub["network"].(string), "/global/networks/") {
		t.Fatalf("subnet must reference the network URL: %v", sub["network"])
	}
	if plan.EgressFirewall != nil {
		t.Fatal("no egress firewall unless egress.restricted is required")
	}
}

func TestBuildVPCAvailabilityClass(t *testing.T) {
	// regional is native — a GCP subnetwork spans all zones in the region.
	a := vpcAttrs()
	a["availability.class"] = "regional"
	if _, err := BuildVPCRequests("acme-prod", "prod", "app-net", a, nil, 1); err != nil {
		t.Fatalf("regional must be accepted natively on GCP: %v", err)
	}
	// zonal is not expressible on GCP (subnets are regional) -> refuse, not fake.
	a2 := vpcAttrs()
	a2["availability.class"] = "zonal"
	if _, err := BuildVPCRequests("acme-prod", "prod", "app-net", a2, nil, 1); err == nil {
		t.Fatal("zonal must be refused on GCP (a subnetwork is regional)")
	}
}

func TestVPCEgressRestrictedAddsDenyFirewall(t *testing.T) {
	a := vpcAttrs()
	a["egress.restricted"] = true
	plan, err := BuildVPCRequests("p", "prod", "app-net", a, nil, 1)
	if err != nil {
		t.Fatal(err)
	}
	if plan.EgressFirewall == nil {
		t.Fatal("egress.restricted must add a default-deny egress firewall")
	}
	fw := plan.EgressFirewall.Body
	if fw["direction"] != "EGRESS" {
		t.Fatalf("firewall direction = %v", fw["direction"])
	}
	denied := fw["denied"].([]any)
	if len(denied) != 1 || denied[0].(map[string]any)["IPProtocol"] != "all" {
		t.Fatalf("must deny all egress, got %v", denied)
	}
}

func TestVPCCidrFromImpl(t *testing.T) {
	plan, err := BuildVPCRequests("p", "prod", "app-net", vpcAttrs(),
		map[string]any{"cidr": "192.168.16.0/22"}, 1)
	if err != nil {
		t.Fatal(err)
	}
	if plan.Subnet.Body["ipCidrRange"] != "192.168.16.0/22" {
		t.Fatalf("impl CIDR not honored: %v", plan.Subnet.Body["ipCidrRange"])
	}
}

// egress.internet=nat adds a Cloud NAT router (name/marker/nats), leaving PGA on.
func TestVPCEgressInternetNatAddsRouter(t *testing.T) {
	a := vpcAttrs()
	a["egress.internet"] = "nat"
	plan, err := BuildVPCRequests("acme-prod", "prod", "app-net", a, nil, 1)
	if err != nil {
		t.Fatal(err)
	}
	if plan.NATRouter == nil {
		t.Fatal("egress.internet=nat must add a Cloud NAT router")
	}
	body := plan.NATRouter.Body
	if plan.NATRouter.Method != "POST" || !strings.HasSuffix(plan.NATRouter.URL, "/routers") {
		t.Fatalf("router req = %s %s", plan.NATRouter.Method, plan.NATRouter.URL)
	}
	if !strings.Contains(body["description"].(string), "groundhold:capability=app-net") {
		t.Fatalf("router marker missing: %v", body["description"])
	}
	nats := body["nats"].([]any)
	if len(nats) != 1 {
		t.Fatalf("router must carry exactly one Cloud NAT, got %v", nats)
	}
	nat := nats[0].(map[string]any)
	if nat["sourceSubnetworkIpRangesToNat"] != "ALL_SUBNETWORKS_ALL_IP_RANGES" ||
		nat["natIpAllocateOption"] != "AUTO_ONLY" {
		t.Fatalf("NAT config = %v", nat)
	}
}

// egress.internet absent/none => no router (back-compat).
func TestVPCEgressInternetNoneNoRouter(t *testing.T) {
	plan, err := BuildVPCRequests("p", "prod", "app-net", vpcAttrs(), nil, 1)
	if err != nil {
		t.Fatal(err)
	}
	if plan.NATRouter != nil {
		t.Fatal("no egress.internet (or none) must NOT add a router")
	}
}

// serviceAccess.private controls Private Google Access; default (absent) is on.
func TestVPCServiceAccessPrivateControlsPGA(t *testing.T) {
	a := vpcAttrs()
	a["serviceAccess.private"] = false
	plan, err := BuildVPCRequests("p", "prod", "app-net", a, nil, 1)
	if err != nil {
		t.Fatal(err)
	}
	if plan.Subnet.Body["privateIpGoogleAccess"] != false {
		t.Fatalf("serviceAccess.private=false must disable PGA, got %v", plan.Subnet.Body["privateIpGoogleAccess"])
	}
	a["serviceAccess.private"] = true
	plan, _ = BuildVPCRequests("p", "prod", "app-net", a, nil, 1)
	if plan.Subnet.Body["privateIpGoogleAccess"] != true {
		t.Fatal("serviceAccess.private=true must enable PGA")
	}
}

func TestVPCRefusals(t *testing.T) {
	cases := map[string]func(a map[string]any){
		"public ingress":      func(a map[string]any) { a["ingress.public"] = true },
		"interconnect":        func(a map[string]any) { a["interconnect.private"] = true },
		"unmanaged":           func(a map[string]any) { a["service.managed"] = false },
		"no region":           func(a map[string]any) { delete(a, "location.region") },
		"unknown attr":        func(a map[string]any) { a["engine.protocol"] = "x" },
		"egress direct":       func(a map[string]any) { a["egress.internet"] = "direct" },
		"egress bad road":     func(a map[string]any) { a["egress.internet"] = "highway" },
		"restricted vs road":  func(a map[string]any) { a["egress.restricted"] = true; a["egress.internet"] = "nat" },
		"svc access non-bool": func(a map[string]any) { a["serviceAccess.private"] = "yes" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			a := vpcAttrs()
			mutate(a)
			if _, err := BuildVPCRequests("p", "prod", "app-net", a, nil, 1); err == nil {
				t.Fatalf("expected refusal for %q", name)
			}
		})
	}
}
