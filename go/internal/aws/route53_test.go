package aws

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"groundhold/internal/certifynet"
	"groundhold/internal/provider"
)

func r53Attrs() map[string]any {
	return map[string]any{
		"zone.domain":            "example.com",
		"network.publicExposure": true,
		"service.managed":        true,
	}
}

func TestBuildRoute53Honors(t *testing.T) {
	p, err := BuildRoute53Zone("prod", "apex", r53Attrs(), nil, 1)
	if err != nil {
		t.Fatal(err)
	}
	if p.DNSName != "example.com." || !p.Public || p.CallerReference == "" {
		t.Fatalf("plan = %+v", p)
	}
	xml := p.createXML()
	if !strings.Contains(xml, "<PrivateZone>false</PrivateZone>") ||
		!strings.Contains(xml, "<Name>example.com.</Name>") {
		t.Fatalf("xml = %s", xml)
	}
	// determinism: same inputs -> same CallerReference
	p2, _ := BuildRoute53Zone("prod", "apex", r53Attrs(), nil, 1)
	if p.CallerReference != p2.CallerReference {
		t.Fatal("CallerReference must be deterministic")
	}
}

func TestBuildRoute53Refusals(t *testing.T) {
	base := func() map[string]any {
		return map[string]any{"zone.domain": "example.com", "network.publicExposure": true, "service.managed": true}
	}
	cases := map[string]struct {
		extra map[string]any
		impl  map[string]any
	}{
		"unmanaged":      {map[string]any{"service.managed": false}, nil},
		"dnssec-v0-gap":  {map[string]any{"dnssec.enabled": true}, nil},
		"record-attr":    {map[string]any{"records.a": "1.2.3.4"}, nil},
		"bad-domain":     {map[string]any{"zone.domain": "not a domain"}, nil},
		"private-no-vpc": {map[string]any{"network.publicExposure": false}, nil},
	}
	for name, c := range cases {
		a := base()
		for k, v := range c.extra {
			a[k] = v
		}
		if _, err := BuildRoute53Zone("prod", "apex", a, c.impl, 1); err == nil {
			t.Errorf("%s: expected refusal, got none", name)
		}
	}
	// a private zone WITH a vpc is fine
	priv := base()
	priv["network.publicExposure"] = false
	if _, err := BuildRoute53Zone("prod", "apex", priv,
		map[string]any{"vpc_id": "vpc-123", "vpc_region": "eu-central-1"}, 1); err != nil {
		t.Errorf("private zone with a vpc should build: %v", err)
	}
	if _, err := BuildRoute53Zone("prod", "apex",
		map[string]any{"network.publicExposure": true, "service.managed": true}, nil, 1); err == nil {
		t.Error("missing zone.domain must refuse")
	}
}

func r53Server(t *testing.T, tagCap, privateZone string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			switch {
			case r.Method == "POST" && r.URL.Path == "/2013-04-01/hostedzone":
				w.WriteHeader(201)
				_, _ = w.Write([]byte(`<CreateHostedZoneResponse><HostedZone>` +
					`<Id>/hostedzone/Z123ABC</Id><Name>example.com.</Name>` +
					`<Config><PrivateZone>` + privateZone + `</PrivateZone></Config>` +
					`</HostedZone></CreateHostedZoneResponse>`))
			case r.Method == "POST" && strings.HasPrefix(r.URL.Path, "/2013-04-01/tags/"):
				_, _ = w.Write([]byte(`<ChangeTagsForResourceResponse></ChangeTagsForResourceResponse>`))
			case r.Method == "GET" && strings.HasPrefix(r.URL.Path, "/2013-04-01/tags/"):
				_, _ = w.Write([]byte(`<ListTagsForResourceResponse><ResourceTagSet><Tags>` +
					`<Tag><Key>groundhold-capability</Key><Value>` + tagCap + `</Value></Tag>` +
					`<Tag><Key>groundhold-environment</Key><Value>prod</Value></Tag>` +
					`</Tags></ResourceTagSet></ListTagsForResourceResponse>`))
			case r.Method == "GET" && strings.HasPrefix(r.URL.Path, "/2013-04-01/hostedzone/"):
				_, _ = w.Write([]byte(`<GetHostedZoneResponse><HostedZone>` +
					`<Id>/hostedzone/Z123ABC</Id><Name>example.com.</Name>` +
					`<Config><PrivateZone>` + privateZone + `</PrivateZone></Config>` +
					`</HostedZone></GetHostedZoneResponse>`))
			case r.Method == "DELETE":
				_, _ = w.Write([]byte(`<DeleteHostedZoneResponse></DeleteHostedZoneResponse>`))
			default:
				w.WriteHeader(404)
			}
		}))
}

func r53Driver(t *testing.T, srv *httptest.Server) *Driver {
	t.Helper()
	t.Setenv("AWS_ACCESS_KEY_ID", "AKID")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "secret")
	d := NewDriver("eu-central-1")
	d.Route53BaseURL = srv.URL
	return d
}

func TestCreateObserveDeleteRoute53(t *testing.T) {
	srv := r53Server(t, "apex", "false")
	defer srv.Close()
	d := r53Driver(t, srv)
	res := d.createRoute53("prod", "apex", r53Attrs(), nil, 1)
	if res.Status != "succeeded" || res.ProviderID != "r53:Z123ABC" {
		t.Fatalf("create: %+v", res)
	}
	obs, _, err := d.observeRoute53("apex", res.ProviderID)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]any{}
	for _, o := range obs {
		got[o.Path] = o.Value
	}
	if got["zone.domain"] != "example.com" || got["network.publicExposure"] != true ||
		got["dnssec.enabled"] != false {
		t.Fatalf("observe: %+v", got)
	}
	if del := d.deleteRoute53("apex", "prod", res.ProviderID); del.Status != "succeeded" {
		t.Fatalf("delete: %+v", del)
	}
}

func TestDeleteRoute53ForeignRefused(t *testing.T) {
	srv := r53Server(t, "someone-else", "false")
	defer srv.Close()
	d := r53Driver(t, srv)
	res := d.deleteRoute53("apex", "prod", "r53:Z123ABC")
	if res.Status != "failed" || !strings.Contains(res.Reason, "not ours") {
		t.Fatalf("foreign zone must refuse delete, got %+v", res)
	}
}

// TestClaimRoute53 pins F23: route53 claim is wired — adopting a zone then applying no
// longer refuses ("cannot yet claim"). Claim stamps the ownership tags via route53's
// native ChangeTagsForResource (the same path create uses) and concludes succeeded.
func TestClaimRoute53(t *testing.T) {
	srv := r53Server(t, "apex", "false")
	defer srv.Close()
	d := r53Driver(t, srv)
	res := d.Claim("route53", "apex", "prod", r53ProviderID("Z123ABC"))
	if res.Status != "succeeded" || res.ProviderID != r53ProviderID("Z123ABC") {
		t.Fatalf("route53 claim must stamp tags and succeed, got %+v", res)
	}
	// a malformed providerId is a clean failed, never a fabricated success.
	if bad := d.Claim("route53", "apex", "prod", "not-a-zone"); bad.Status != "failed" {
		t.Fatalf("a malformed route53 pid must fail cleanly, got %+v", bad)
	}
}

// r53ExistingServer: our deterministic CallerReference already made this zone, so the
// create is answered HostedZoneAlreadyExists and recoverRoute53 must find it by name
// and match the reference — the same handle, never a second zone.
func r53ExistingServer(t *testing.T, tagCap, callerRef string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			switch {
			case r.Method == "POST" && r.URL.Path == "/2013-04-01/hostedzone":
				w.WriteHeader(409)
				_, _ = w.Write([]byte(`<ErrorResponse><Error><Code>HostedZoneAlreadyExists</Code>` +
					`</Error></ErrorResponse>`))
			case r.Method == "GET" && strings.HasPrefix(r.URL.Path, "/2013-04-01/hostedzonesbyname"):
				_, _ = w.Write([]byte(`<ListHostedZonesByNameResponse><HostedZones><HostedZone>` +
					`<Id>/hostedzone/Z123ABC</Id><Name>example.com.</Name>` +
					`<CallerReference>` + callerRef + `</CallerReference>` +
					`<Config><PrivateZone>false</PrivateZone></Config>` +
					`</HostedZone></HostedZones></ListHostedZonesByNameResponse>`))
			case r.Method == "GET" && strings.HasPrefix(r.URL.Path, "/2013-04-01/tags/"):
				_, _ = w.Write([]byte(`<ListTagsForResourceResponse><ResourceTagSet><Tags>` +
					`<Tag><Key>groundhold-capability</Key><Value>` + tagCap + `</Value></Tag>` +
					`<Tag><Key>groundhold-environment</Key><Value>prod</Value></Tag>` +
					`</Tags></ResourceTagSet></ListTagsForResourceResponse>`))
			case r.Method == "POST" && strings.HasPrefix(r.URL.Path, "/2013-04-01/tags/"):
				_, _ = w.Write([]byte(`<ChangeTagsForResourceResponse></ChangeTagsForResourceResponse>`))
			case r.Method == "GET" && strings.HasPrefix(r.URL.Path, "/2013-04-01/hostedzone/"):
				_, _ = w.Write([]byte(`<GetHostedZoneResponse><HostedZone>` +
					`<Id>/hostedzone/Z123ABC</Id><Name>example.com.</Name>` +
					`<Config><PrivateZone>false</PrivateZone></Config>` +
					`</HostedZone></GetHostedZoneResponse>`))
			default:
				w.WriteHeader(404)
			}
		}))
}

func r53Role(req *http.Request, _ []byte) certifynet.Role {
	if req.Method == http.MethodGet {
		return certifynet.RoleRead
	}
	return certifynet.RoleMutateOpaque
}

// TestAdoptsExistingRoute53 enrols route53 in the D391 gate. A hosted zone id is
// SERVER-assigned, so without recovery a retry mints a second zone for the same domain —
// the CallerReference is what makes that recoverable, and this asserts the recovery.
func TestAdoptsExistingRoute53(t *testing.T) {
	t.Setenv("AWS_ACCESS_KEY_ID", "AKID")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "secret")
	plan, err := BuildRoute53Zone("prod", "apex", r53Attrs(), nil, 1)
	if err != nil {
		t.Fatal(err)
	}
	p := &certifynet.ExistingProbe{
		Name:           "aws/route53",
		Classify:       r53Role,
		ExistingServer: func() *httptest.Server { return r53ExistingServer(t, "apex", plan.CallerReference) },
		New: func(happyURL string, rt http.RoundTripper) provider.Provider {
			d := NewDriver("eu-central-1")
			d.HTTP = &http.Client{Transport: rt}
			d.Route53BaseURL = happyURL
			d.Account = "000000000000" // no STS round-trip: the gate must not leave the fake
			return d
		},
		Create: func(pr provider.Provider) provider.CreateResult {
			return pr.Create("route53", "apex", "prod", r53Attrs(), nil, "apex", 1)
		},
		PID:              r53ProviderID("Z123ABC"),
		AllowedMutations: 2, // the refused create + the ownership tag write
	}
	certifynet.CertifyCreateAdoptsExisting(t, p)
}
