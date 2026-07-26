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
