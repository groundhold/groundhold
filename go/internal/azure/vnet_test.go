package azure

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

const testSub = "00000000-0000-0000-0000-000000000001"

func vnetAttrs() map[string]any {
	return map[string]any{
		"location.region":   "eastus",
		"ingress.public":    false,
		"egress.restricted": true,
		"flowLogs.enabled":  false,
		"service.managed":   true,
	}
}

func TestBuildVNetHonorsAndNames(t *testing.T) {
	p, err := BuildVNet("prod", "backbone", vnetAttrs(), nil, 1)
	if err != nil {
		t.Fatal(err)
	}
	if p.Region != "eastus" || !p.EgressRestricted {
		t.Fatalf("plan = %+v", p)
	}
	if !azNameOK.MatchString(p.Name) || !strings.HasPrefix(p.Name, "pv-net-") {
		t.Fatalf("name %q invalid", p.Name)
	}
}

func TestBuildVNetAvailabilityClass(t *testing.T) {
	// regional is native — an Azure subnet is region-wide, zone choice is
	// per-resource, so a multi-zone network needs no extra VNet resource.
	a := vnetAttrs()
	a["availability.class"] = "regional"
	if _, err := BuildVNet("prod", "backbone", a, nil, 1); err != nil {
		t.Fatalf("regional must be accepted natively on Azure: %v", err)
	}
	// zonal is not expressible at the VNet layer -> refuse.
	a2 := vnetAttrs()
	a2["availability.class"] = "zonal"
	if _, err := BuildVNet("prod", "backbone", a2, nil, 1); err == nil {
		t.Fatal("zonal must be refused on Azure (a subnet is region-wide)")
	}
}

func TestBuildVNetRefusals(t *testing.T) {
	cases := map[string]map[string]any{
		"ingress.public=true": {"location.region": "eastus", "ingress.public": true, "service.managed": true},
		"flowLogs.enabled":    {"location.region": "eastus", "flowLogs.enabled": true, "service.managed": true},
		"interconnect":        {"location.region": "eastus", "interconnect.private": true, "service.managed": true},
		"unmanaged":           {"location.region": "eastus", "service.managed": false},
		"missing region":      {"service.managed": true},
		"unknown attr":        {"location.region": "eastus", "durability.class": "regional", "service.managed": true},
	}
	for name, a := range cases {
		if _, err := BuildVNet("prod", "backbone", a, nil, 1); err == nil {
			t.Errorf("%s: expected refusal, got none", name)
		}
	}
}

// armFake is a stateful ARM double: PUT records + returns 201; GET returns the
// resource with provisioningState Succeeded + our tags; DELETE returns 200.
func armFake(t *testing.T, tagCap string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			switch r.Method {
			case "PUT":
				w.WriteHeader(201)
				_, _ = w.Write([]byte(`{"properties":{"provisioningState":"Succeeded"}}`))
			case "GET":
				_, _ = w.Write([]byte(`{"location":"eastus",` +
					`"tags":{"groundhold-capability":"` + tagCap + `","groundhold-environment":"prod"},` +
					`"properties":{"provisioningState":"Succeeded","subnets":[{"properties":{` +
					`"networkSecurityGroup":{"id":"/subscriptions/x/resourceGroups/rg/providers/Microsoft.Network/networkSecurityGroups/n"}}}]}}`))
			case "DELETE":
				w.WriteHeader(200)
			default:
				w.WriteHeader(404)
			}
		}))
}

func vnetTestDriver(t *testing.T, srv *httptest.Server) *Driver {
	t.Helper()
	d := NewDriver(testSub)
	d.BaseURL = srv.URL
	d.token = "test-token"
	d.Now = time.Now
	d.PollInterval = time.Millisecond
	d.PollTimeout = 2 * time.Second
	return d
}

func TestCreateObserveDeleteVNet(t *testing.T) {
	srv := armFake(t, "backbone")
	defer srv.Close()
	d := vnetTestDriver(t, srv)
	impl := map[string]any{"resource_group": "rg1"}

	res := d.createVNet("prod", "backbone", vnetAttrs(), impl, 1)
	if res.Status != "succeeded" || res.ProviderID == "" {
		t.Fatalf("create: %+v", res)
	}
	obs, _, err := d.observeVNet("backbone", res.ProviderID)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]any{}
	for _, o := range obs {
		got[o.Path] = o.Value
	}
	if got["location.region"] != "eastus" || got["egress.restricted"] != true {
		t.Fatalf("observe: %+v", got)
	}
	del := d.deleteVNet("backbone", "prod", res.ProviderID)
	if del.Status != "succeeded" {
		t.Fatalf("delete: %+v", del)
	}
}

// TestAzureDeleteAndConfirmAsyncNotGone pins D971 for every ARM delete: a 202
// Accepted is a long-running delete — the resource is still deleting, not gone. It
// must report unknown (keep the handle), never a terminal "succeeded" that
// tombstones a resource still live. deleteAndConfirm is the shared fold behind
// ~15 Azure deletes, so this covers all of them.
func TestAzureDeleteAndConfirmAsyncNotGone(t *testing.T) {
	url := "/subscriptions/x/resourceGroups/rg/providers/Microsoft.Network/virtualNetworks/vnet?api-version=2023-05-01"
	srv := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			switch r.Method {
			case "DELETE":
				w.WriteHeader(202) // accepted, long-running
			case "GET": // the resource is still present (deleting)
				w.WriteHeader(200)
				_, _ = w.Write([]byte(`{"properties":{"provisioningState":"Deleting"}}`))
			default:
				w.WriteHeader(404)
			}
		}))
	defer srv.Close()
	d := vnetTestDriver(t, srv)
	d.PollTimeout = 5 * time.Millisecond // the resource never leaves Deleting → times out fast
	res := d.deleteAndConfirm(srv.URL+url, "pid", "test resource")
	if res.Status != "unknown" {
		t.Fatalf("a 202-accepted delete whose resource is still present must be unknown (keep the "+
			"handle), got %+v — reporting succeeded tombstones a resource still live", res)
	}
}

// TestAzureDeleteAndConfirm202PollsToGone: a 202 whose resource then reads 404 is
// genuinely gone — succeeded, once confirmed.
func TestAzureDeleteAndConfirm202PollsToGone(t *testing.T) {
	url := "/subscriptions/x/resourceGroups/rg/providers/Microsoft.Network/virtualNetworks/vnet?api-version=2023-05-01"
	srv := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			switch r.Method {
			case "DELETE":
				w.WriteHeader(202)
			default: // GET → gone
				w.WriteHeader(404)
			}
		}))
	defer srv.Close()
	d := vnetTestDriver(t, srv)
	res := d.deleteAndConfirm(srv.URL+url, "pid", "test resource")
	if res.Status != "succeeded" {
		t.Fatalf("a 202-accepted delete polled to a confirmed 404 must succeed, got %+v", res)
	}
}

func TestDeleteVNetForeignRefused(t *testing.T) {
	srv := armFake(t, "someone-else")
	defer srv.Close()
	d := vnetTestDriver(t, srv)
	res := d.deleteVNet("backbone", "prod", vnetProviderID(testSub, "rg1", "pv-net-backbone-prod-abcd1234"))
	if res.Status != "failed" || !strings.Contains(res.Reason, "not ours") {
		t.Fatalf("foreign vnet must refuse delete, got %+v", res)
	}
}

func TestBuildVNetEgressInternetAndServiceAccess(t *testing.T) {
	// nat + serviceAccess.private (canonical endpoint set)
	p, err := BuildVNet("prod", "backbone", map[string]any{
		"location.region":       "eastus",
		"egress.internet":       "nat",
		"serviceAccess.private": true,
		"service.managed":       true,
	}, nil, 1)
	if err != nil {
		t.Fatal(err)
	}
	if p.EgressInternet != "nat" || !p.ServiceAccess {
		t.Fatalf("plan = %+v", p)
	}
	if len(p.ServiceEndpoints) != len(defaultVNetServiceEndpoints) {
		t.Fatalf("service endpoints = %v", p.ServiceEndpoints)
	}

	// impl override of the service-endpoint set (a realization operand)
	p, err = BuildVNet("prod", "backbone", map[string]any{
		"location.region":       "eastus",
		"serviceAccess.private": true,
		"service.managed":       true,
	}, map[string]any{"service_endpoints": []any{"Microsoft.Storage", "Microsoft.Sql"}}, 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(p.ServiceEndpoints) != 2 || p.ServiceEndpoints[0] != "Microsoft.Sql" {
		t.Fatalf("override endpoints (want sorted) = %v", p.ServiceEndpoints)
	}

	// egress.internet absent => none (back-compat), no endpoints
	p, err = BuildVNet("prod", "backbone", map[string]any{
		"location.region": "eastus", "service.managed": true}, nil, 1)
	if err != nil || p.EgressInternet != "none" || p.ServiceAccess {
		t.Fatalf("back-compat plan = %+v err=%v", p, err)
	}
}

func TestBuildVNetEgressInternetRefusals(t *testing.T) {
	cases := map[string]map[string]any{
		"direct honestly refused": {"location.region": "eastus", "egress.internet": "direct", "service.managed": true},
		"unknown road":            {"location.region": "eastus", "egress.internet": "sideways", "service.managed": true},
		"restricted vs nat":       {"location.region": "eastus", "egress.internet": "nat", "egress.restricted": true, "service.managed": true},
	}
	for name, a := range cases {
		if _, err := BuildVNet("prod", "backbone", a, nil, 1); err == nil {
			t.Errorf("%s: expected refusal, got none", name)
		}
	}
	// bad impl.service_endpoints
	if _, err := BuildVNet("prod", "backbone", map[string]any{
		"location.region": "eastus", "serviceAccess.private": true, "service.managed": true},
		map[string]any{"service_endpoints": "Microsoft.Storage"}, 1); err == nil {
		t.Error("non-list service_endpoints must refuse")
	}
}

// natFake records PUT paths and serves a GET vnet with the NAT road + service
// endpoints on the subnet, so observe reverse-maps egress.internet + serviceAccess.
func natFake(t *testing.T, puts *[]string) *httptest.Server {
	t.Helper()
	eps := ""
	for i, s := range defaultVNetServiceEndpoints {
		if i > 0 {
			eps += ","
		}
		eps += `{"service":"` + s + `"}`
	}
	return httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			switch r.Method {
			case "PUT":
				*puts = append(*puts, r.URL.Path)
				w.WriteHeader(201)
				_, _ = w.Write([]byte(`{"properties":{"provisioningState":"Succeeded"}}`))
			case "GET":
				_, _ = w.Write([]byte(`{"location":"eastus",` +
					`"tags":{"groundhold-capability":"backbone","groundhold-environment":"prod"},` +
					`"properties":{"provisioningState":"Succeeded","subnets":[{"properties":{` +
					`"natGateway":{"id":"/subscriptions/x/resourceGroups/rg/providers/Microsoft.Network/natGateways/g"},` +
					`"serviceEndpoints":[` + eps + `]}}]}}`))
			case "DELETE":
				w.WriteHeader(200)
			default:
				w.WriteHeader(404)
			}
		}))
}

func TestCreateObserveVNetNATAndServiceEndpoints(t *testing.T) {
	var puts []string
	srv := natFake(t, &puts)
	defer srv.Close()
	d := vnetTestDriver(t, srv)
	attrs := map[string]any{
		"location.region":       "eastus",
		"egress.internet":       "nat",
		"serviceAccess.private": true,
		"service.managed":       true,
	}
	res := d.createVNet("prod", "backbone", attrs, map[string]any{"resource_group": "rg1"}, 1)
	if res.Status != "succeeded" {
		t.Fatalf("create: %+v", res)
	}
	// the NAT road created a public IP + a NAT gateway before the vnet
	sawPIP, sawNAT := false, false
	for _, p := range puts {
		if strings.Contains(p, "/publicIPAddresses/") {
			sawPIP = true
		}
		if strings.Contains(p, "/natGateways/") {
			sawNAT = true
		}
	}
	if !sawPIP || !sawNAT {
		t.Fatalf("NAT road PUTs missing: pip=%v nat=%v puts=%v", sawPIP, sawNAT, puts)
	}
	obs, _, err := d.observeVNet("backbone", res.ProviderID)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]any{}
	for _, o := range obs {
		got[o.Path] = o.Value
	}
	if got["egress.internet"] != "nat" || got["serviceAccess.private"] != true {
		t.Fatalf("observe: %+v", got)
	}
	if del := d.deleteVNet("backbone", "prod", res.ProviderID); del.Status != "succeeded" {
		t.Fatalf("delete: %+v", del)
	}
}

func TestCreateVNetNoTokenRefuses(t *testing.T) {
	d := NewDriver(testSub)
	d.token = "" // no token
	res := d.Create("vnet", "backbone", "prod", vnetAttrs(), map[string]any{"resource_group": "rg1"}, "k", 1)
	if res.Status != "failed" || !strings.Contains(res.Reason, "no Azure access token") {
		t.Fatalf("no token must refuse before mutating, got %+v", res)
	}
}

// D744: "a subnet references a network security group" is not a measurement of
// destination discipline — an NSG whose only outbound rule allows any destination
// restricts nothing, and the container's presence stood for the rules inside it. The
// two directions are not symmetric: no group at all genuinely measures that nothing
// restricts egress, which is why only the `true` side moved to config-intent.
func TestAzureEgressRestrictedDoesNotMeasureAContainer(t *testing.T) {
	t.Run("a group is attached — its rules were not read", func(t *testing.T) {
		srv := armFake(t, "backbone")
		defer srv.Close()
		d := vnetTestDriver(t, srv)
		res := d.createVNet("prod", "backbone", vnetAttrs(), map[string]any{"resource_group": "rg1"}, 1)
		if res.Status != "succeeded" {
			t.Fatalf("create: %+v", res)
		}
		obs, diags, err := d.observeVNet("backbone", res.ProviderID)
		if err != nil {
			t.Fatal(err)
		}
		for _, o := range obs {
			if o.Path != "egress.restricted" {
				continue
			}
			if o.Value != true || o.Derivation != "config-intent" {
				t.Fatalf("egress.restricted = %v/%s, want true/config-intent — the group's "+
					"outbound rules were never read", o.Value, o.Derivation)
			}
		}
		var saidWhy bool
		for _, dg := range diags {
			if strings.Contains(dg, "outbound rules were not read") {
				saidWhy = true
			}
		}
		if !saidWhy {
			t.Fatalf("withholding the measurement without saying why is its own defect: %v", diags)
		}
	})
}

// D940: deleteAndConfirm never returns nil, so the leaf-delete guard `r != nil`
// returned unconditionally and the NAT-companion cleanup (NSG, NAT gateway, public
// IP) was unreachable dead code — a billable NAT gateway + public IP orphaned while
// retire reported succeeded. A succeeded vnet delete must fall through to reclaim
// its driver-created companions.
func TestDeleteVNetReclaimsNATCompanions(t *testing.T) {
	var deletes []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case "GET":
			_, _ = w.Write([]byte(`{"location":"eastus",` +
				`"tags":{"groundhold-capability":"backbone","groundhold-environment":"prod"},` +
				`"properties":{"provisioningState":"Succeeded"}}`))
		case "DELETE":
			deletes = append(deletes, r.URL.Path)
			w.WriteHeader(200)
		default:
			w.WriteHeader(404)
		}
	}))
	defer srv.Close()
	d := vnetTestDriver(t, srv)

	res := d.deleteVNet("backbone", "prod", vnetProviderID(testSub, "rg1", "pv-net-backbone-prod-abcd1234"))
	if res.Status != "succeeded" {
		t.Fatalf("delete: %+v", res)
	}
	for _, seg := range []string{"/networkSecurityGroups/", "/natGateways/", "/publicIPAddresses/"} {
		found := false
		for _, p := range deletes {
			if strings.Contains(p, seg) {
				found = true
			}
		}
		if !found {
			t.Errorf("companion %s was never DELETEd — dead-code cleanup (D940); deletes=%v", seg, deletes)
		}
	}
}

// D943: for a brownfield-adopted vnet with an arbitrary name, the derived companion
// name (`<vnet>-nsg` etc — a very common Azure convention) could be a FOREIGN resource
// groundhold never created. The companion cleanup (reachable since D940) must read each
// companion's tags and NEVER delete one that is not ours.
func TestDeleteVNetLeavesForeignCompanionsUntouched(t *testing.T) {
	var deletes []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case "GET":
			if strings.Contains(r.URL.Path, "/virtualNetworks/") {
				// the parent vnet is ours (adopted)
				_, _ = w.Write([]byte(`{"location":"eastus",` +
					`"tags":{"groundhold-capability":"backbone","groundhold-environment":"prod"},` +
					`"properties":{"provisioningState":"Succeeded"}}`))
				return
			}
			// a FOREIGN sibling sits at the derived companion name (no groundhold tags)
			_, _ = w.Write([]byte(`{"location":"eastus","tags":{"owner":"someone-else"},` +
				`"properties":{"provisioningState":"Succeeded"}}`))
		case "DELETE":
			deletes = append(deletes, r.URL.Path)
			w.WriteHeader(200)
		default:
			w.WriteHeader(404)
		}
	}))
	defer srv.Close()
	d := vnetTestDriver(t, srv)

	res := d.deleteVNet("backbone", "prod", vnetProviderID(testSub, "rg1", "hub-vnet"))
	if res.Status != "succeeded" {
		t.Fatalf("delete: %+v", res)
	}
	// the vnet itself (ours) must be deleted; NO foreign companion may be
	sawVnet := false
	for _, p := range deletes {
		if strings.Contains(p, "/virtualNetworks/") {
			sawVnet = true
		}
		for _, seg := range []string{"/networkSecurityGroups/", "/natGateways/", "/publicIPAddresses/"} {
			if strings.Contains(p, seg) {
				t.Errorf("D943 FOREIGN-DELETE: companion %s was deleted despite not being ours — deletes=%v", seg, deletes)
			}
		}
	}
	if !sawVnet {
		t.Errorf("the owned vnet was not deleted — deletes=%v", deletes)
	}
}
