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

// azCDNRoute returns the route body's properties for a plan (test helper).
func azCDNRouteProps(p AzureCDNPlan) map[string]any {
	return p.routeBody(testSub, "rg1")["properties"].(map[string]any)
}

func TestBuildAzureCDNHonors(t *testing.T) {
	p, err := BuildAzureCDN("prod", "edge", azCDNAttrs(), azCDNImpl(), 1)
	if err != nil {
		t.Fatal(err)
	}
	if p.OriginDomain != "origin.example.com" || p.HTTPAllowed || !p.HTTPSAllowed || p.Redirect {
		t.Fatalf("plan = %+v", p)
	}
	// https-only: the route accepts only Https, no redirect.
	rt := azCDNRouteProps(p)
	sp := rt["supportedProtocols"].([]any)
	if len(sp) != 1 || sp[0] != "Https" || rt["httpsRedirect"] != "Disabled" {
		t.Fatalf("route = %+v", rt)
	}
	// the origin carries origin.domain as hostName + host header.
	or := p.originBody()["properties"].(map[string]any)
	if or["hostName"] != "origin.example.com" || or["originHostHeader"] != "origin.example.com" {
		t.Fatalf("origin = %+v", or)
	}
	// the profile is the AFD Standard SKU.
	if p.profileBody(nil)["sku"].(map[string]any)["name"] != "Standard_AzureFrontDoor" {
		t.Fatalf("profile sku = %+v", p.profileBody(nil))
	}
}

func TestBuildAzureCDNRefusals(t *testing.T) {
	cases := map[string]map[string]any{
		"bad-viewer":   {"viewer.protocol": "carrier-pigeon"},
		"bad-domain":   {"origin.domain": "not a domain"},
		"unmanaged":    {"service.managed": false},
		"unknown-attr": {"cdn.tier": "x"},
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

// TestBuildAzureCDNRedirectHonored (D999): the classic CDN refused
// viewer.protocol=redirect-to-https; AFD honors it natively via the route's
// httpsRedirect=Enabled (accepting Http+Https and 301-ing to HTTPS).
func TestBuildAzureCDNRedirectHonored(t *testing.T) {
	a := azCDNAttrs()
	a["viewer.protocol"] = "redirect-to-https"
	p, err := BuildAzureCDN("prod", "edge", a, azCDNImpl(), 1)
	if err != nil {
		t.Fatalf("redirect-to-https must be honored on AFD, got %v", err)
	}
	if !p.HTTPAllowed || !p.Redirect {
		t.Fatalf("plan = %+v", p)
	}
	rt := azCDNRouteProps(p)
	sp := rt["supportedProtocols"].([]any)
	if len(sp) != 2 || rt["httpsRedirect"] != "Enabled" {
		t.Fatalf("redirect route = %+v", rt)
	}
}

// TestBuildAzureCDNCachePolicy pins the D331 cache_policy operand mapped onto AFD.
// AFD caching is OFF by default, so the header-honoring default (and cache_policy:
// honor) ATTACHES a cacheConfiguration; cache_policy: disabled OMITS it (no caching) —
// the inverse wire of classic CDN's bypass rule. An unknown value refuses.
func TestBuildAzureCDNCachePolicy(t *testing.T) {
	// default: caching enabled honoring origin headers -> cacheConfiguration present.
	p, err := BuildAzureCDN("prod", "edge", azCDNAttrs(), azCDNImpl(), 1)
	if err != nil {
		t.Fatal(err)
	}
	if p.CacheBypass {
		t.Fatal("default must not bypass")
	}
	if _, has := azCDNRouteProps(p)["cacheConfiguration"]; !has {
		t.Fatal("default route must carry a cacheConfiguration")
	}
	// honor: same as default.
	impl := azCDNImpl()
	impl["cache_policy"] = "honor"
	if p, err = BuildAzureCDN("prod", "edge", azCDNAttrs(), impl, 1); err != nil || p.CacheBypass {
		t.Fatalf("honor must not bypass: %+v err=%v", p, err)
	}
	if _, has := azCDNRouteProps(p)["cacheConfiguration"]; !has {
		t.Fatal("honor route must carry a cacheConfiguration")
	}
	// disabled: no caching -> NO cacheConfiguration.
	impl["cache_policy"] = "disabled"
	p, err = BuildAzureCDN("prod", "edge", azCDNAttrs(), impl, 1)
	if err != nil || !p.CacheBypass {
		t.Fatalf("disabled must bypass: %+v err=%v", p, err)
	}
	if _, has := azCDNRouteProps(p)["cacheConfiguration"]; has {
		t.Fatal("disabled route must carry NO cacheConfiguration")
	}
	// unknown value refuses.
	impl["cache_policy"] = "aggressive"
	if _, err := BuildAzureCDN("prod", "edge", azCDNAttrs(), impl, 1); err == nil {
		t.Error("unsupported cache_policy must refuse")
	}
}

const azKVSecretID = "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg1/" +
	"providers/Microsoft.KeyVault/vaults/gh-vault/secrets/gh-cert"

// TestBuildAzureCDNCustomDomain pins the D332/D999 aliases + certificate operands on
// AFD. A managed cert is tlsSettings.certificateType ManagedCertificate (Azure-native,
// no external resource); a Key Vault secret id lands as a profile secret referenced by
// certificateType CustomerCertificate. A $ref refuses (no certificate.tls twin).
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
	tls := p.customDomainBody(testSub, "rg1", "api.acme.eu")["properties"].(map[string]any)["tlsSettings"].(map[string]any)
	if tls["certificateType"] != "ManagedCertificate" {
		t.Fatalf("managed tlsSettings = %+v", tls)
	}
	// the route must associate the custom domain by id.
	cds := azCDNRouteProps(p)["customDomains"].([]any)
	if len(cds) != 2 || !strings.Contains(cds[0].(map[string]any)["id"].(string), "/customDomains/api-acme-eu") {
		t.Fatalf("route customDomains = %+v", cds)
	}
	// BYO Key Vault secret: a profile secret + a CustomerCertificate reference.
	impl["aliases"] = []any{"api.acme.eu"}
	impl["certificate"] = azKVSecretID
	p, err = BuildAzureCDN("prod", "edge", azCDNAttrs(), impl, 1)
	if err != nil || p.CertKeyVault == nil || p.CertKeyVault.vault != "gh-vault" || p.CertKeyVault.secret != "gh-cert" {
		t.Fatalf("byo plan = %+v err=%v", p, err)
	}
	sec := p.secretBody()["properties"].(map[string]any)["parameters"].(map[string]any)
	if sec["type"] != "CustomerCertificate" || !strings.Contains(sec["secretSource"].(map[string]any)["id"].(string), "/vaults/gh-vault/secrets/gh-cert") {
		t.Fatalf("byo secret = %+v", sec)
	}
	tls = p.customDomainBody(testSub, "rg1", "api.acme.eu")["properties"].(map[string]any)["tlsSettings"].(map[string]any)
	if tls["certificateType"] != "CustomerCertificate" || !strings.Contains(tls["secret"].(map[string]any)["id"].(string), "/secrets/"+p.secretName()) {
		t.Fatalf("byo tlsSettings = %+v", tls)
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

// TestCreateAzureCDNCustomDomainGolden is the httptest golden: the AFD create issues the
// customDomains PUT (tlsSettings ManagedCertificate) and the route PUT (associating the
// custom domain), and cache_policy: disabled omits the route's cacheConfiguration.
func TestCreateAzureCDNCustomDomainGolden(t *testing.T) {
	var cdBody, rtBody string
	srv := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			body, _ := io.ReadAll(r.Body)
			switch {
			case r.Method == "PUT" && strings.Contains(r.URL.Path, "/customDomains/"):
				cdBody = string(body)
				w.WriteHeader(200)
				_, _ = w.Write([]byte(`{"properties":{"provisioningState":"Succeeded"}}`))
			case r.Method == "PUT" && strings.Contains(r.URL.Path, "/routes/"):
				rtBody = string(body)
				w.WriteHeader(200)
				_, _ = w.Write([]byte(`{"properties":{"provisioningState":"Succeeded"}}`))
			case r.Method == "PUT":
				w.WriteHeader(200)
				_, _ = w.Write([]byte(`{"properties":{"provisioningState":"Succeeded"}}`))
			case r.Method == "GET":
				// pre-reads (refuseForeignUpsert + provisioningState poll) carry OUR tags.
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
	if !strings.Contains(cdBody, `"hostName":"api.acme.eu"`) || !strings.Contains(cdBody, `"certificateType":"ManagedCertificate"`) {
		t.Fatalf("customDomains body wrong: %s", cdBody)
	}
	if !strings.Contains(rtBody, "/customDomains/api-acme-eu") {
		t.Fatalf("route body missing custom domain association: %s", rtBody)
	}
	if strings.Contains(rtBody, "cacheConfiguration") {
		t.Fatalf("disabled route must omit cacheConfiguration: %s", rtBody)
	}
}

// azRouteJSON returns the route properties JSON fragment for a viewer.protocol.
func azRouteJSON(viewer string) string {
	switch viewer {
	case "allow-all":
		return `"supportedProtocols":["Http","Https"],"httpsRedirect":"Disabled"`
	case "redirect-to-https":
		return `"supportedProtocols":["Http","Https"],"httpsRedirect":"Enabled"`
	default: // https-only
		return `"supportedProtocols":["Https"],"httpsRedirect":"Disabled"`
	}
}

// azCDNServer is the AFD happy-path fake: every PUT succeeds; a GET on the route returns
// the viewer posture, on the origin the hostName, elsewhere the profile tags — all with
// provisioningState Succeeded so putAndPoll concludes; DELETE is a synchronous 200.
func azCDNServer(t *testing.T, capLabel, origin, viewer string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			switch r.Method {
			case "PUT":
				w.WriteHeader(200)
				_, _ = w.Write([]byte(`{"properties":{"provisioningState":"Succeeded"}}`))
			case "GET":
				switch {
				case strings.Contains(r.URL.Path, "/routes/"):
					_, _ = w.Write([]byte(`{"properties":{"provisioningState":"Succeeded",` + azRouteJSON(viewer) + `}}`))
				case strings.Contains(r.URL.Path, "/origins/"):
					_, _ = w.Write([]byte(`{"properties":{"provisioningState":"Succeeded","hostName":"` + origin + `"}}`))
				default:
					_, _ = w.Write([]byte(`{"tags":{"groundhold-capability":"` + capLabel + `","groundhold-environment":"prod"},` +
						`"properties":{"provisioningState":"Succeeded"}}`))
				}
			case "DELETE":
				w.WriteHeader(200)
			default:
				w.WriteHeader(404)
			}
		}))
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
	srv := azCDNServer(t, "edge", "origin.example.com", "https-only")
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
	srv := azCDNServer(t, "someone-else", "origin.example.com", "https-only")
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
		Name:            "azure/azurecdn",
		Classify:        armRole,
		OwnerTagValue:   "edge",
		AssertTransient: true, // D237
		DeterministicID: true,
		// F-LC3 (D518): migrated to the absence property.
		ObserveAbsent: func(pr provider.Provider) ([]provider.Observation, []string, error) {
			return pr.Observe("azurecdn", "edge", pid)
		},
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
				Happy: func() *httptest.Server { return azCDNServer(t, "edge", "origin.example.com", "https-only") },
				Run: func(pr provider.Provider) provider.CreateResult {
					return pr.Create("azurecdn", "edge", "prod", azCDNAttrs(), azCDNImpl(), "k", 1)
				},
			},
			{
				Name:  "delete",
				Happy: func() *httptest.Server { return azCDNServer(t, "edge", "origin.example.com", "https-only") },
				Run: func(pr provider.Provider) provider.CreateResult {
					return pr.Delete("azurecdn", "edge", "prod", pid, "k")
				},
			},
		},
	}
	certifynet.CertifyDriverNet(t, p)
}

// Weapon 2 (D87), the metamorphic write/read round-trip for capability.cdn.distribution
// on AFD: the fake captures the route PUT's supportedProtocols/httpsRedirect and echoes
// them on the route GET, so viewer.protocol must survive write -> read unchanged —
// including redirect-to-https, which classic CDN could not express.
func TestMetamorphicAzureCDNRoundTrip(t *testing.T) {
	cases := []struct{ name, viewer string }{
		{"https-only", "https-only"},
		{"allow-all", "allow-all"},
		{"redirect-to-https", "redirect-to-https"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var supported []any
			var httpsRedirect, origin string
			srv := httptest.NewServer(http.HandlerFunc(
				func(w http.ResponseWriter, r *http.Request) {
					switch r.Method {
					case "PUT":
						body, _ := io.ReadAll(r.Body)
						if strings.Contains(r.URL.Path, "/routes/") {
							var doc struct {
								Properties struct {
									SupportedProtocols []any  `json:"supportedProtocols"`
									HTTPSRedirect      string `json:"httpsRedirect"`
								} `json:"properties"`
							}
							_ = json.Unmarshal(body, &doc)
							supported = doc.Properties.SupportedProtocols
							httpsRedirect = doc.Properties.HTTPSRedirect
						} else if strings.Contains(r.URL.Path, "/origins/") {
							var doc struct {
								Properties struct {
									HostName string `json:"hostName"`
								} `json:"properties"`
							}
							_ = json.Unmarshal(body, &doc)
							origin = doc.Properties.HostName
						}
						w.WriteHeader(200)
						_, _ = w.Write([]byte(`{"properties":{"provisioningState":"Succeeded"}}`))
					case "GET":
						switch {
						case strings.Contains(r.URL.Path, "/routes/"):
							sp, _ := json.Marshal(supported)
							_, _ = w.Write([]byte(`{"properties":{"provisioningState":"Succeeded","supportedProtocols":` +
								string(sp) + `,"httpsRedirect":"` + httpsRedirect + `"}}`))
						case strings.Contains(r.URL.Path, "/origins/"):
							_, _ = w.Write([]byte(`{"properties":{"provisioningState":"Succeeded","hostName":"` + origin + `"}}`))
						default:
							_, _ = w.Write([]byte(`{"tags":{"groundhold-capability":"edge","groundhold-environment":"prod"},"properties":{"provisioningState":"Succeeded"}}`))
						}
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
			if got["viewer.protocol"] != c.viewer {
				t.Errorf("viewer round-trip: want %q got %v", c.viewer, got["viewer.protocol"])
			}
		})
	}
}
