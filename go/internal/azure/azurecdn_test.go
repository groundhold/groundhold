package azure

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"groundhold/internal/certifynet"
	"groundhold/internal/provider"
)

func azCDNAttrs() map[string]any {
	return map[string]any{
		"origin.domain":   "origin.example.com",
		"viewer.protocol": "https-only",
		"service.managed": true,
	}
}

func azCDNImpl() map[string]any { return map[string]any{"resource_group": "rg1"} }

func TestBuildAzureCDNHonors(t *testing.T) {
	p, err := BuildAzureCDN("prod", "edge", azCDNAttrs(), azCDNImpl(), 1)
	if err != nil {
		t.Fatal(err)
	}
	if p.OriginDomain != "origin.example.com" || p.HTTPAllowed || !p.HTTPSAllowed {
		t.Fatalf("plan = %+v", p)
	}
	ep := p.endpointBody()["properties"].(map[string]any)
	if ep["isHttpAllowed"] != false || ep["isHttpsAllowed"] != true {
		t.Fatalf("endpoint = %+v", ep)
	}
}

func TestBuildAzureCDNRefusals(t *testing.T) {
	cases := map[string]map[string]any{
		"redirect-refused": {"viewer.protocol": "redirect-to-https"}, // needs a delivery rule
		"bad-viewer":       {"viewer.protocol": "carrier-pigeon"},
		"bad-domain":       {"origin.domain": "not a domain"},
		"unmanaged":        {"service.managed": false},
		"unknown-attr":     {"cdn.tier": "x"},
	}
	for name, extra := range cases {
		a := azCDNAttrs()
		for k, v := range extra {
			a[k] = v
		}
		if _, err := BuildAzureCDN("prod", "edge", a, azCDNImpl(), 1); err == nil {
			t.Errorf("%s: expected refusal, got none", name)
		}
	}
	a := azCDNAttrs()
	delete(a, "origin.domain")
	if _, err := BuildAzureCDN("prod", "edge", a, azCDNImpl(), 1); err == nil {
		t.Error("missing origin.domain must refuse")
	}
}

// TestBuildAzureCDNCachePolicy pins the D331 cache_policy operand. Azure's default is
// header-honoring (no deliveryPolicy), so no dangerous default to fix; cache_policy:
// disabled attaches a global CacheExpiration BypassCache rule; honor is the no-op
// default; an unknown value refuses (closed vocabulary).
func TestBuildAzureCDNCachePolicy(t *testing.T) {
	// default: no deliveryPolicy (header-honoring — Azure's safe default).
	p, err := BuildAzureCDN("prod", "edge", azCDNAttrs(), azCDNImpl(), 1)
	if err != nil {
		t.Fatal(err)
	}
	if p.CacheBypass {
		t.Fatal("default must be header-honoring (no cache bypass)")
	}
	if _, has := p.endpointBody()["properties"].(map[string]any)["deliveryPolicy"]; has {
		t.Fatal("default endpoint must carry no deliveryPolicy")
	}
	// honor: still the header-honoring default.
	impl := azCDNImpl()
	impl["cache_policy"] = "honor"
	if p, err = BuildAzureCDN("prod", "edge", azCDNAttrs(), impl, 1); err != nil || p.CacheBypass {
		t.Fatalf("honor must not bypass: %+v err=%v", p, err)
	}
	// disabled: a global CacheExpiration BypassCache rule.
	impl["cache_policy"] = "disabled"
	p, err = BuildAzureCDN("prod", "edge", azCDNAttrs(), impl, 1)
	if err != nil || !p.CacheBypass {
		t.Fatalf("disabled must bypass: %+v err=%v", p, err)
	}
	dp, has := p.endpointBody()["properties"].(map[string]any)["deliveryPolicy"]
	if !has {
		t.Fatal("disabled endpoint must carry a deliveryPolicy")
	}
	rule := dp.(map[string]any)["rules"].([]any)[0].(map[string]any)
	act := rule["actions"].([]any)[0].(map[string]any)
	params := act["parameters"].(map[string]any)
	if act["name"] != "CacheExpiration" || params["cacheBehavior"] != azCacheBypass {
		t.Fatalf("bypass rule = %+v", act)
	}
	// unknown value refuses.
	impl["cache_policy"] = "aggressive"
	if _, err := BuildAzureCDN("prod", "edge", azCDNAttrs(), impl, 1); err == nil {
		t.Error("unsupported cache_policy must refuse")
	}
}

const azKVSecretID = "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg1/" +
	"providers/Microsoft.KeyVault/vaults/gh-vault/secrets/gh-cert"

// TestBuildAzureCDNCustomDomain pins the D332 aliases + certificate operands. A managed
// cert takes certificateSource: Cdn (Azure-native, no external resource); a Key Vault
// secret id takes AzureKeyVault (BYO). A $ref refuses honestly (no certificate.tls twin).
func TestBuildAzureCDNCustomDomain(t *testing.T) {
	impl := azCDNImpl()
	impl["aliases"] = []any{"api.acme.eu", "www.acme.eu"}
	impl["certificate"] = "managed"
	p, err := BuildAzureCDN("prod", "edge", azCDNAttrs(), impl, 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Aliases) != 2 || p.Aliases[0] != "api.acme.eu" || !p.CertManaged {
		t.Fatalf("plan = %+v", p)
	}
	if got := customDomainResourceName("api.acme.eu"); got != "api-acme-eu" {
		t.Fatalf("custom domain name = %q", got)
	}
	if b := p.customHTTPSBody(); b["certificateSource"] != "Cdn" {
		t.Fatalf("managed https body = %+v", b)
	}
	// BYO Key Vault secret.
	impl["certificate"] = azKVSecretID
	p, err = BuildAzureCDN("prod", "edge", azCDNAttrs(), impl, 1)
	if err != nil || p.CertKeyVault == nil || p.CertKeyVault.vault != "gh-vault" || p.CertKeyVault.secret != "gh-cert" {
		t.Fatalf("byo plan = %+v err=%v", p, err)
	}
	b := p.customHTTPSBody()
	if b["certificateSource"] != "AzureKeyVault" {
		t.Fatalf("byo https body = %+v", b)
	}
	params := b["certificateSourceParameters"].(map[string]any)
	if params["vaultName"] != "gh-vault" || params["secretName"] != "gh-cert" {
		t.Fatalf("byo params = %+v", params)
	}
}

// TestBuildAzureCDNCustomDomainRefusals pins the fail-closed edges: aliases without a
// cert, a cert without aliases, a $ref (no certificate.tls Azure twin), a bad cert
// string, and a non-list aliases operand.
func TestBuildAzureCDNCustomDomainRefusals(t *testing.T) {
	cases := map[string]map[string]any{
		"alias-without-cert": {"aliases": []any{"api.acme.eu"}},
		"cert-without-alias": {"certificate": "managed"},
		"cert-ref-refused": {"aliases": []any{"api.acme.eu"},
			"certificate": map[string]any{"$ref": map[string]any{"capability": "cert", "output": "certificateArn"}}},
		"cert-bad-string": {"aliases": []any{"api.acme.eu"}, "certificate": "acm-arn"},
		"alias-not-list":  {"aliases": "api.acme.eu", "certificate": "managed"},
		"alias-bad-fqdn":  {"aliases": []any{"not a domain"}, "certificate": "managed"},
	}
	for name, extra := range cases {
		t.Run(name, func(t *testing.T) {
			impl := azCDNImpl()
			for k, v := range extra {
				impl[k] = v
			}
			if _, err := BuildAzureCDN("prod", "edge", azCDNAttrs(), impl, 1); err == nil {
				t.Errorf("%s: expected refusal, got none", name)
			}
		})
	}
}

// TestCreateAzureCDNCustomDomainGolden is the httptest golden: the create issues the
// customDomains PUT (hostName) and the enableCustomHttps POST (certificateSource), and
// cache_policy: disabled sends the endpoint deliveryPolicy.
func TestCreateAzureCDNCustomDomainGolden(t *testing.T) {
	var epBody, cdBody, httpsBody string
	srv := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			body, _ := io.ReadAll(r.Body)
			switch {
			case r.Method == "POST" && strings.Contains(r.URL.Path, "/enableCustomHttps"):
				httpsBody = string(body)
				w.WriteHeader(202)
			case r.Method == "PUT" && strings.Contains(r.URL.Path, "/customDomains/"):
				cdBody = string(body)
				w.WriteHeader(200)
				_, _ = w.Write([]byte(`{"properties":{"provisioningState":"Succeeded"}}`))
			case r.Method == "PUT" && strings.Contains(r.URL.Path, "/endpoints/"):
				epBody = string(body)
				w.WriteHeader(200)
				_, _ = w.Write([]byte(`{"properties":{"provisioningState":"Succeeded"}}`))
			case r.Method == "PUT":
				w.WriteHeader(200)
				_, _ = w.Write([]byte(`{"properties":{"provisioningState":"Succeeded"}}`))
			case r.Method == "GET":
				// the profile pre-read must carry OUR tags (refuseForeignUpsert).
				w.WriteHeader(200)
				_, _ = w.Write([]byte(`{"tags":{"groundhold-capability":"edge","groundhold-environment":"prod"},` +
					`"properties":{"provisioningState":"Succeeded"}}`))
			default:
				w.WriteHeader(404)
			}
		}))
	defer srv.Close()
	d := azCDNDriver(t, srv)
	impl := azCDNImpl()
	impl["aliases"] = []any{"api.acme.eu"}
	impl["certificate"] = "managed"
	impl["cache_policy"] = "disabled"
	res := d.createAzureCDN("prod", "edge", azCDNAttrs(), impl, 1)
	if res.Status != "succeeded" {
		t.Fatalf("create: %+v", res)
	}
	if !strings.Contains(cdBody, `"hostName":"api.acme.eu"`) {
		t.Fatalf("customDomains body missing hostName: %s", cdBody)
	}
	if !strings.Contains(httpsBody, `"certificateSource":"Cdn"`) {
		t.Fatalf("enableCustomHttps body missing certificateSource Cdn: %s", httpsBody)
	}
	if !strings.Contains(epBody, `"cacheBehavior":"BypassCache"`) {
		t.Fatalf("endpoint body missing cache bypass: %s", epBody)
	}
}

func azCDNServer(t *testing.T, capLabel, origin string, httpAllowed bool) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			isEndpoint := strings.Contains(r.URL.Path, "/endpoints/")
			switch r.Method {
			case "PUT":
				w.WriteHeader(200)
				_, _ = w.Write([]byte(`{"properties":{"provisioningState":"Succeeded"}}`))
			case "GET":
				if isEndpoint {
					_, _ = w.Write([]byte(`{"properties":{"isHttpAllowed":` + azBoolStr(httpAllowed) + `,"isHttpsAllowed":true,` +
						`"origins":[{"name":"origin1","properties":{"hostName":"` + origin + `"}}]}}`))
					return
				}
				_, _ = w.Write([]byte(`{"tags":{"groundhold-capability":"` + capLabel + `","groundhold-environment":"prod"},` +
					`"properties":{"provisioningState":"Succeeded"}}`))
			case "DELETE":
				w.WriteHeader(200)
			default:
				w.WriteHeader(404)
			}
		}))
}

func azBoolStr(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

func azCDNDriver(t *testing.T, srv *httptest.Server) *Driver {
	t.Helper()
	d := NewDriver(testSub)
	d.BaseURL = srv.URL
	d.token = "test-token"
	d.Now = time.Now
	d.PollInterval = time.Millisecond
	d.PollTimeout = 2 * time.Second
	return d
}

func TestCreateObserveDeleteAzureCDN(t *testing.T) {
	srv := azCDNServer(t, "edge", "origin.example.com", false)
	defer srv.Close()
	d := azCDNDriver(t, srv)
	res := d.createAzureCDN("prod", "edge", azCDNAttrs(), azCDNImpl(), 1)
	if res.Status != "succeeded" || !strings.HasPrefix(res.ProviderID, "azcdn:"+testSub+":rg1:") {
		t.Fatalf("create: %+v", res)
	}
	obs, _, err := d.observeAzureCDN("edge", res.ProviderID)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]any{}
	for _, o := range obs {
		got[o.Path] = o.Value
	}
	if got["origin.domain"] != "origin.example.com" || got["viewer.protocol"] != "https-only" {
		t.Fatalf("observe: %+v", got)
	}
	if del := d.deleteAzureCDN("edge", "prod", res.ProviderID); del.Status != "succeeded" {
		t.Fatalf("delete: %+v", del)
	}
}

func TestDeleteAzureCDNForeignRefused(t *testing.T) {
	srv := azCDNServer(t, "someone-else", "origin.example.com", false)
	defer srv.Close()
	d := azCDNDriver(t, srv)
	pid := azureCDNProviderID(testSub, "rg1", azCDNProfileName("prod", "edge", 1), azResourceName("pv-ep", "prod", "edge", 1))
	res := d.deleteAzureCDN("edge", "prod", pid)
	if res.Status != "failed" || !strings.Contains(res.Reason, "not ours") {
		t.Fatalf("foreign profile must refuse delete, got %+v", res)
	}
}

func TestHonestyHarnessAzureCDN(t *testing.T) {
	pid := azureCDNProviderID(testSub, "rg1", azCDNProfileName("prod", "edge", 1), azResourceName("pv-ep", "prod", "edge", 1))
	p := &certifynet.Probe{
		// AssertTransient left false — D237 TODO: this driver's create/delete ladder
		// still maps 429/503/403 to terminal failed (and drops the providerId); it must
		// route through provider.MutationResult before the transient invariant can lock.
		Name:            "azure/azurecdn",
		Classify:        armRole,
		OwnerTagValue:   "edge",
		AssertTransient: true, // D237
		DeterministicID: true,
		New: func(happyURL string, rt http.RoundTripper) provider.Provider {
			d := NewDriver(testSub)
			d.BaseURL = happyURL
			d.HTTP = &http.Client{Transport: rt}
			d.token = "test-token"
			d.Now = time.Now
			d.PollInterval = time.Millisecond
			d.PollTimeout = 2 * time.Second
			return d
		},
		Ops: []certifynet.Op{
			{
				Name:  "create",
				Happy: func() *httptest.Server { return azCDNServer(t, "edge", "origin.example.com", false) },
				Run: func(pr provider.Provider) provider.CreateResult {
					return pr.Create("azurecdn", "edge", "prod", azCDNAttrs(), azCDNImpl(), "k", 1)
				},
			},
			{
				Name:  "delete",
				Happy: func() *httptest.Server { return azCDNServer(t, "edge", "origin.example.com", false) },
				Run: func(pr provider.Provider) provider.CreateResult {
					return pr.Delete("azurecdn", "edge", "prod", pid, "k")
				},
			},
		},
	}
	certifynet.CertifyDriverNet(t, p)
}

// Weapon 2 (D87), the metamorphic write/read round-trip for
// capability.cdn.distribution on Azure CDN.
func TestMetamorphicAzureCDNRoundTrip(t *testing.T) {
	cases := []struct {
		name       string
		viewer     string
		wantHTTP   bool
		wantViewer string
	}{
		{"https-only", "https-only", false, "https-only"},
		{"allow-all", "allow-all", true, "allow-all"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var httpAllowed bool
			var origin string
			srv := httptest.NewServer(http.HandlerFunc(
				func(w http.ResponseWriter, r *http.Request) {
					isEndpoint := strings.Contains(r.URL.Path, "/endpoints/")
					switch r.Method {
					case "PUT":
						if isEndpoint {
							body, _ := io.ReadAll(r.Body)
							var doc struct {
								Properties struct {
									IsHttpAllowed bool `json:"isHttpAllowed"`
									Origins       []struct {
										Properties struct {
											HostName string `json:"hostName"`
										} `json:"properties"`
									} `json:"origins"`
								} `json:"properties"`
							}
							_ = json.Unmarshal(body, &doc)
							httpAllowed = doc.Properties.IsHttpAllowed
							if len(doc.Properties.Origins) > 0 {
								origin = doc.Properties.Origins[0].Properties.HostName
							}
						}
						w.WriteHeader(200)
						_, _ = w.Write([]byte(`{"properties":{"provisioningState":"Succeeded"}}`))
					case "GET":
						if isEndpoint {
							_, _ = w.Write([]byte(`{"properties":{"isHttpAllowed":` + azBoolStr(httpAllowed) + `,"isHttpsAllowed":true,` +
								`"origins":[{"properties":{"hostName":"` + origin + `"}}]}}`))
							return
						}
						_, _ = w.Write([]byte(`{"tags":{"groundhold-capability":"edge","groundhold-environment":"prod"},"properties":{"provisioningState":"Succeeded"}}`))
					default:
						w.WriteHeader(200)
					}
				}))
			defer srv.Close()
			d := azCDNDriver(t, srv)
			a := azCDNAttrs()
			a["viewer.protocol"] = c.viewer
			res := d.createAzureCDN("prod", "edge", a, azCDNImpl(), 1)
			if res.Status != "succeeded" {
				t.Fatalf("create: %+v", res)
			}
			obs, _, err := d.observeAzureCDN("edge", res.ProviderID)
			if err != nil {
				t.Fatal(err)
			}
			got := map[string]any{}
			for _, o := range obs {
				got[o.Path] = o.Value
			}
			if got["viewer.protocol"] != c.wantViewer {
				t.Errorf("viewer round-trip: want %q got %v", c.wantViewer, got["viewer.protocol"])
			}
		})
	}
}
