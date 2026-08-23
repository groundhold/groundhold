package aws

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func cfAttrs() map[string]any {
	return map[string]any{
		"origin.domain":   "origin.example.com",
		"viewer.protocol": "https-only",
		"service.managed": true,
	}
}

func TestBuildCloudFrontHonors(t *testing.T) {
	p, err := BuildCloudFront("prod", "edge", cfAttrs(), nil, 1)
	if err != nil {
		t.Fatal(err)
	}
	if p.OriginDomain != "origin.example.com" || p.ViewerProtocol != "https-only" || !strings.HasPrefix(p.CallerReference, "pv") {
		t.Fatalf("plan = %+v", p)
	}
	xml := p.createXML("edge", "prod", "")
	if !strings.Contains(xml, "<DomainName>origin.example.com</DomainName>") ||
		!strings.Contains(xml, "<ViewerProtocolPolicy>https-only</ViewerProtocolPolicy>") {
		t.Fatalf("xml = %s", xml)
	}
}

func TestBuildCloudFrontRefusals(t *testing.T) {
	cases := map[string]map[string]any{
		"bad-domain":   {"origin.domain": "not a domain"},
		"bad-viewer":   {"viewer.protocol": "carrier-pigeon"},
		"unmanaged":    {"service.managed": false},
		"unknown-attr": {"cdn.tier": "x"},
	}
	for name, extra := range cases {
		a := cfAttrs()
		for k, v := range extra {
			a[k] = v
		}
		if _, err := BuildCloudFront("prod", "edge", a, nil, 1); err == nil {
			t.Errorf("%s: expected refusal, got none", name)
		}
	}
	a := cfAttrs()
	delete(a, "origin.domain")
	if _, err := BuildCloudFront("prod", "edge", a, nil, 1); err == nil {
		t.Error("missing origin.domain must refuse")
	}
	a = cfAttrs()
	delete(a, "viewer.protocol")
	if _, err := BuildCloudFront("prod", "edge", a, nil, 1); err == nil {
		t.Error("missing viewer.protocol must refuse")
	}
}

// TestBuildCloudFrontCachePolicy pins the SAFE-PER-ORIGIN-TYPE default and the
// cache_policy override. A dynamic Lambda Function URL origin (origin_access: oac,
// the D316 pattern) MUST default to CachingDisabled — CachingOptimized there caches
// dynamic per-user responses keyed by URL (stale / cross-user leak, the Acme
// finding). A static origin keeps CachingOptimized. The operand overrides either.
func TestBuildCloudFrontCachePolicy(t *testing.T) {
	tag := func(id string) string { return "<CachePolicyId>" + id + "</CachePolicyId>" }
	cases := []struct {
		name string
		impl map[string]any
		want string
	}{
		{"static-default-optimized", nil, cachePolicyOptimized},
		{"dynamic-oac-default-disabled", map[string]any{"origin_access": "oac"}, cachePolicyDisabled},
		{"override-static-to-disabled", map[string]any{"cache_policy": "disabled"}, cachePolicyDisabled},
		{"override-dynamic-to-optimized", map[string]any{"origin_access": "oac", "cache_policy": "optimized"}, cachePolicyOptimized},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p, err := BuildCloudFront("prod", "edge", cfAttrs(), c.impl, 1)
			if err != nil {
				t.Fatal(err)
			}
			if p.CachePolicyID != c.want {
				t.Fatalf("CachePolicyID = %q, want %q", p.CachePolicyID, c.want)
			}
			xml := p.createXML("edge", "prod", "")
			if !strings.Contains(xml, tag(c.want)) {
				t.Fatalf("xml missing %s: %s", tag(c.want), xml)
			}
			other := cachePolicyOptimized
			if c.want == cachePolicyOptimized {
				other = cachePolicyDisabled
			}
			if strings.Contains(xml, tag(other)) {
				t.Fatalf("xml carries the wrong policy %s: %s", tag(other), xml)
			}
		})
	}
	// A bogus cache_policy value refuses (closed vocabulary), never silently drops.
	if _, err := BuildCloudFront("prod", "edge", cfAttrs(), map[string]any{"cache_policy": "aggressive"}, 1); err == nil {
		t.Error("unsupported cache_policy must refuse")
	}
}

// TestCreateCloudFrontCachePolicyGolden is the httptest golden: the CreateDistribution
// body carries CachingDisabled for a dynamic OAC/Function-URL origin, CachingOptimized
// for a static one, and the cache_policy operand overrides both.
func TestCreateCloudFrontCachePolicyGolden(t *testing.T) {
	cases := []struct {
		name string
		impl map[string]any
		want string
	}{
		{"static-origin-optimized", nil, cachePolicyOptimized},
		{"dynamic-oac-disabled", map[string]any{"origin_access": "oac"}, cachePolicyDisabled},
		{"override-static-to-disabled", map[string]any{"cache_policy": "disabled"}, cachePolicyDisabled},
		{"override-dynamic-to-optimized", map[string]any{"origin_access": "oac", "cache_policy": "optimized"}, cachePolicyOptimized},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var distBody string
			srv := httptest.NewServer(http.HandlerFunc(
				func(w http.ResponseWriter, r *http.Request) {
					switch {
					case r.Method == "POST" && strings.HasPrefix(r.URL.Path, cloudFrontPath+"/origin-access-control"):
						w.WriteHeader(201)
						_, _ = w.Write([]byte(`<OriginAccessControl><Id>E2OACEXAMPLE</Id></OriginAccessControl>`))
					case r.Method == "POST" && strings.HasPrefix(r.URL.Path, cloudFrontPath+"/distribution"):
						b, _ := io.ReadAll(r.Body)
						distBody = string(b)
						w.Header().Set("ETag", "etag-1")
						w.WriteHeader(201)
						_, _ = w.Write([]byte(`<Distribution><Id>E1234567890ABC</Id><ARN>` + cfTestARN + `</ARN></Distribution>`))
					default:
						w.WriteHeader(404)
					}
				}))
			defer srv.Close()
			d := cfDriver(t, srv)
			res := d.createCloudFront("000000000000", "prod", "edge", cfAttrs(), c.impl, 1)
			if res.Status != "succeeded" {
				t.Fatalf("create: %+v", res)
			}
			if !strings.Contains(distBody, "<CachePolicyId>"+c.want+"</CachePolicyId>") {
				t.Fatalf("create body missing CachePolicyId %s: %s", c.want, distBody)
			}
		})
	}
}

const cfUSCertARN = "arn:aws:acm:us-east-1:000000000000:certificate/abc-123"

// TestBuildCloudFrontCustomDomain pins the aliases + certificate (ViewerCertificate)
// operands: aliases become CNAMEs, a us-east-1 ACM cert becomes an ACMCertificateArn
// ViewerCertificate (sni-only / TLSv1.2_2021), and with NO certificate the body keeps
// CloudFrontDefaultCertificate (no ViewerCertificate element — unchanged default).
func TestBuildCloudFrontCustomDomain(t *testing.T) {
	impl := map[string]any{
		"aliases":     []any{"api.acme.eu", "www.acme.eu"},
		"certificate": cfUSCertARN,
	}
	p, err := BuildCloudFront("prod", "edge", cfAttrs(), impl, 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Aliases) != 2 || p.Aliases[0] != "api.acme.eu" || p.CertACMArn != cfUSCertARN {
		t.Fatalf("plan = %+v", p)
	}
	xml := p.createXML("edge", "prod", "")
	for _, want := range []string{
		"<Aliases><Quantity>2</Quantity><Items><CNAME>api.acme.eu</CNAME><CNAME>www.acme.eu</CNAME></Items></Aliases>",
		"<ViewerCertificate><ACMCertificateArn>" + cfUSCertARN + "</ACMCertificateArn>",
		"<SSLSupportMethod>sni-only</SSLSupportMethod>",
		"<MinimumProtocolVersion>TLSv1.2_2021</MinimumProtocolVersion>",
	} {
		if !strings.Contains(xml, want) {
			t.Fatalf("xml missing %q: %s", want, xml)
		}
	}
	// The default (no certificate operand) keeps CloudFrontDefaultCertificate: no
	// Aliases, no ViewerCertificate element — the pre-existing body is unchanged.
	base, err := BuildCloudFront("prod", "edge", cfAttrs(), nil, 1)
	if err != nil {
		t.Fatal(err)
	}
	bx := base.createXML("edge", "prod", "")
	if strings.Contains(bx, "<ViewerCertificate>") || strings.Contains(bx, "<Aliases>") {
		t.Fatalf("default body must carry neither Aliases nor ViewerCertificate: %s", bx)
	}
}

// TestBuildCloudFrontCustomDomainRefusals pins the fail-closed edges: aliases without
// a certificate, a certificate without aliases, a non-us-east-1 cert (the honest
// infrastructural refusal), a malformed ARN, and a non-list aliases operand.
func TestBuildCloudFrontCustomDomainRefusals(t *testing.T) {
	cases := map[string]map[string]any{
		"alias-without-cert": {"aliases": []any{"api.acme.eu"}},
		"cert-without-alias": {"certificate": cfUSCertARN},
		"cert-wrong-region": {"aliases": []any{"api.acme.eu"},
			"certificate": "arn:aws:acm:eu-central-1:000000000000:certificate/abc-123"},
		"cert-bad-arn":   {"aliases": []any{"api.acme.eu"}, "certificate": "not-an-arn"},
		"alias-not-list": {"aliases": "api.acme.eu", "certificate": cfUSCertARN},
		"alias-bad-fqdn": {"aliases": []any{"not a domain"}, "certificate": cfUSCertARN},
	}
	for name, impl := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := BuildCloudFront("prod", "edge", cfAttrs(), impl, 1); err == nil {
				t.Errorf("%s: expected refusal, got none", name)
			}
		})
	}
}

// TestCreateCloudFrontCustomDomainGolden is the httptest golden: the CreateDistribution
// body carries the Aliases CNAMEs and an ACM ViewerCertificate; without a certificate
// operand it carries neither (CloudFrontDefaultCertificate, unchanged).
func TestCreateCloudFrontCustomDomainGolden(t *testing.T) {
	cases := []struct {
		name      string
		impl      map[string]any
		wantAlias bool
		wantCert  bool
	}{
		{"custom-domain", map[string]any{
			"aliases":     []any{"api.acme.eu"},
			"certificate": cfUSCertARN}, true, true},
		{"default-no-cert", nil, false, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var distBody string
			srv := httptest.NewServer(http.HandlerFunc(
				func(w http.ResponseWriter, r *http.Request) {
					if r.Method == "POST" && strings.HasPrefix(r.URL.Path, cloudFrontPath+"/distribution") {
						b, _ := io.ReadAll(r.Body)
						distBody = string(b)
						w.Header().Set("ETag", "etag-1")
						w.WriteHeader(201)
						_, _ = w.Write([]byte(`<Distribution><Id>E1234567890ABC</Id><ARN>` + cfTestARN + `</ARN></Distribution>`))
						return
					}
					w.WriteHeader(404)
				}))
			defer srv.Close()
			d := cfDriver(t, srv)
			res := d.createCloudFront("000000000000", "prod", "edge", cfAttrs(), c.impl, 1)
			if res.Status != "succeeded" {
				t.Fatalf("create: %+v", res)
			}
			hasAlias := strings.Contains(distBody, "<CNAME>api.acme.eu</CNAME>")
			hasCert := strings.Contains(distBody, "<ACMCertificateArn>"+cfUSCertARN+"</ACMCertificateArn>")
			if hasAlias != c.wantAlias || hasCert != c.wantCert {
				t.Fatalf("alias=%v(want %v) cert=%v(want %v): %s", hasAlias, c.wantAlias, hasCert, c.wantCert, distBody)
			}
		})
	}
}

const cfTestARN = "arn:aws:cloudfront::000000000000:distribution/E1234567890ABC"

// cfServer is a happy REST-XML server. enabled controls whether the distribution
// blocks deletion (CloudFront's disable-before-delete precondition).
func cfServer(t *testing.T, capLabel, origin, viewer string, enabled bool) *httptest.Server {
	t.Helper()
	dist := func() string {
		return `<Distribution><Id>E1234567890ABC</Id><ARN>` + cfTestARN + `</ARN><Status>Deployed</Status>` +
			`<DomainName>d111111abcdef8.cloudfront.net</DomainName>` +
			`<DistributionConfig><Enabled>` + boolStrAWS(enabled) + `</Enabled>` +
			`<Origins><Items><Origin><DomainName>` + origin + `</DomainName></Origin></Items></Origins>` +
			`<DefaultCacheBehavior><ViewerProtocolPolicy>` + viewer + `</ViewerProtocolPolicy></DefaultCacheBehavior>` +
			`</DistributionConfig></Distribution>`
	}
	return httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			switch {
			case r.Method == "POST" && strings.HasPrefix(r.URL.Path, cloudFrontPath+"/distribution"):
				w.Header().Set("ETag", "etag-1")
				w.WriteHeader(201)
				_, _ = w.Write([]byte(dist()))
			case r.Method == "GET" && strings.HasPrefix(r.URL.Path, cloudFrontPath+"/tagging"):
				_, _ = w.Write([]byte(`<Tags><Items>` +
					`<Tag><Key>groundhold-capability</Key><Value>` + capLabel + `</Value></Tag>` +
					`<Tag><Key>groundhold-environment</Key><Value>prod</Value></Tag>` +
					`</Items></Tags>`))
			case r.Method == "GET" && strings.Contains(r.URL.Path, "/distribution/"):
				w.Header().Set("ETag", "etag-1")
				_, _ = w.Write([]byte(dist()))
			case r.Method == "DELETE":
				w.WriteHeader(204)
			default:
				w.WriteHeader(404)
			}
		}))
}

func boolStrAWS(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

func cfDriver(t *testing.T, srv *httptest.Server) *Driver {
	t.Helper()
	t.Setenv("AWS_ACCESS_KEY_ID", "AKID")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "secret")
	d := NewDriver("us-east-1")
	d.Account = "000000000000"
	d.CloudFrontBaseURL = srv.URL
	d.Now = time.Now
	d.PollInterval = time.Millisecond
	d.PollTimeout = 2 * time.Second
	return d
}

// D1193: viewer.protocol is the WEAKEST posture across ALL cache behaviors. A default
// of https-only beside an additional (/api/*) behavior set to allow-all serves plaintext
// on that path — reading the default alone read it fully secure (a false-green). Observe
// must emit allow-all (the weakest).
func TestObserveCloudFront_WeakestAcrossCacheBehaviors(t *testing.T) {
	dist := `<Distribution><Id>E1234567890ABC</Id><ARN>` + cfTestARN + `</ARN><Status>Deployed</Status>` +
		`<DomainName>d111111abcdef8.cloudfront.net</DomainName>` +
		`<DistributionConfig><Enabled>true</Enabled>` +
		`<Origins><Items><Origin><DomainName>origin.example.com</DomainName></Origin></Items></Origins>` +
		`<DefaultCacheBehavior><ViewerProtocolPolicy>https-only</ViewerProtocolPolicy></DefaultCacheBehavior>` +
		`<CacheBehaviors><Items>` +
		`<CacheBehavior><PathPattern>/static/*</PathPattern><ViewerProtocolPolicy>redirect-to-https</ViewerProtocolPolicy></CacheBehavior>` +
		`<CacheBehavior><PathPattern>/api/*</PathPattern><ViewerProtocolPolicy>allow-all</ViewerProtocolPolicy></CacheBehavior>` +
		`</Items></CacheBehaviors>` +
		`</DistributionConfig></Distribution>`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" && strings.Contains(r.URL.Path, "/distribution/") {
			w.Header().Set("ETag", "etag-1")
			_, _ = w.Write([]byte(dist))
			return
		}
		w.WriteHeader(404)
	}))
	defer srv.Close()
	d := cfDriver(t, srv)

	obs, _, err := d.observeCloudFront("edge", cfProviderID("000000000000", "E1234567890ABC"))
	if err != nil {
		t.Fatal(err)
	}
	var got any
	for _, o := range obs {
		if o.Path == "viewer.protocol" {
			got = o.Value
		}
	}
	if got != "allow-all" {
		t.Fatalf("viewer.protocol = %v, want allow-all (the weakest across the default and the /api/* behavior)", got)
	}
}

func TestCreateObserveDeleteCloudFront(t *testing.T) {
	// disabled so the delete precondition passes.
	srv := cfServer(t, "edge", "origin.example.com", "https-only", false)
	defer srv.Close()
	d := cfDriver(t, srv)
	res := d.createCloudFront("000000000000", "prod", "edge", cfAttrs(), nil, 1)
	if res.Status != "succeeded" || res.ProviderID != "cf:000000000000:E1234567890ABC" {
		t.Fatalf("create: %+v", res)
	}
	obs, _, err := d.observeCloudFront("edge", res.ProviderID)
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
	if del := d.deleteCloudFront("edge", "prod", res.ProviderID); del.Status != "succeeded" {
		t.Fatalf("delete: %+v", del)
	}
}

func TestDeleteCloudFrontEnabledRefused(t *testing.T) {
	// an ENABLED distribution must refuse deletion (disable-before-delete).
	srv := cfServer(t, "edge", "origin.example.com", "https-only", true)
	defer srv.Close()
	d := cfDriver(t, srv)
	pid := cfProviderID("000000000000", "E1234567890ABC")
	res := d.deleteCloudFront("edge", "prod", pid)
	if res.Status != "failed" || !strings.Contains(res.Reason, "disabled") {
		t.Fatalf("enabled distribution must refuse delete, got %+v", res)
	}
}

func TestDeleteCloudFrontForeignRefused(t *testing.T) {
	srv := cfServer(t, "someone-else", "origin.example.com", "https-only", false)
	defer srv.Close()
	d := cfDriver(t, srv)
	pid := cfProviderID("000000000000", "E1234567890ABC")
	res := d.deleteCloudFront("edge", "prod", pid)
	if res.Status != "failed" || !strings.Contains(res.Reason, "not ours") {
		t.Fatalf("foreign distribution must refuse delete, got %+v", res)
	}
}

// Weapon 2 (D87), the metamorphic write/read round-trip for
// capability.cdn.distribution on AWS CloudFront. A STATEFUL fake records the origin
// and viewer protocol the create writes and reflects them on the get read.
func TestMetamorphicCloudFrontRoundTrip(t *testing.T) {
	cases := []struct {
		name   string
		origin string
		viewer string
	}{
		{"https-only", "a.example.com", "https-only"},
		{"redirect", "b.example.com", "redirect-to-https"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var origin, viewer string
			srv := httptest.NewServer(http.HandlerFunc(
				func(w http.ResponseWriter, r *http.Request) {
					dist := func() string {
						return `<Distribution><Id>E1234567890ABC</Id><ARN>` + cfTestARN + `</ARN>` +
							`<DistributionConfig><Enabled>false</Enabled>` +
							`<Origins><Items><Origin><DomainName>` + origin + `</DomainName></Origin></Items></Origins>` +
							`<DefaultCacheBehavior><ViewerProtocolPolicy>` + viewer + `</ViewerProtocolPolicy></DefaultCacheBehavior>` +
							`</DistributionConfig></Distribution>`
					}
					switch {
					case r.Method == "POST":
						body := readJSON5(r)
						origin, viewer = body.origin, body.viewer
						w.Header().Set("ETag", "etag-1")
						w.WriteHeader(201)
						_, _ = w.Write([]byte(dist()))
					case r.Method == "GET":
						w.Header().Set("ETag", "etag-1")
						_, _ = w.Write([]byte(dist()))
					default:
						w.WriteHeader(204)
					}
				}))
			defer srv.Close()
			d := cfDriver(t, srv)
			a := cfAttrs()
			a["origin.domain"] = c.origin
			a["viewer.protocol"] = c.viewer
			res := d.createCloudFront("000000000000", "prod", "edge", a, nil, 1)
			if res.Status != "succeeded" {
				t.Fatalf("create: %+v", res)
			}
			obs, _, err := d.observeCloudFront("edge", res.ProviderID)
			if err != nil {
				t.Fatal(err)
			}
			got := map[string]any{}
			for _, o := range obs {
				got[o.Path] = o.Value
			}
			if got["origin.domain"] != c.origin {
				t.Errorf("origin round-trip: want %q got %v", c.origin, got["origin.domain"])
			}
			if got["viewer.protocol"] != c.viewer {
				t.Errorf("viewer round-trip: want %q got %v", c.viewer, got["viewer.protocol"])
			}
		})
	}
}

// readJSON5 extracts the origin DomainName + ViewerProtocolPolicy from a CloudFront
// create XML body (a tiny substring parse — the config is XML, not JSON).
type cfCreateFields struct{ origin, viewer string }

func readJSON5(r *http.Request) cfCreateFields {
	b, _ := io.ReadAll(r.Body)
	s := string(b)
	return cfCreateFields{
		origin: betweenAWS(s, "<DomainName>", "</DomainName>"),
		viewer: betweenAWS(s, "<ViewerProtocolPolicy>", "</ViewerProtocolPolicy>"),
	}
}

func betweenAWS(s, a, b string) string {
	i := strings.Index(s, a)
	if i < 0 {
		return ""
	}
	i += len(a)
	j := strings.Index(s[i:], b)
	if j < 0 {
		return ""
	}
	return s[i : i+j]
}

// D1235. `viewer.protocol` is a CLOSED enum (https-only | redirect-to-https |
// allow-all) and it is the CDN's TLS posture — whether the edge will serve a viewer
// over plain HTTP. Two states used to be wrong, in opposite ways:
//
//   - a policy value outside the enum was emitted VERBATIM as measured, because the
//     "mapper" it went through returned its argument on every branch. An out-of-enum
//     value that looks like a measurement is worse than no value.
//   - no policy at all produced silence, though CloudFront REQUIRES the field on the
//     default cache behavior — so an empty read is a read that did not answer.
//
// Note what is deliberately NOT done: an unrecognised policy is not reported as
// `allow-all`. The ranking treats it as weakest for CHOOSING which behavior dominates,
// which is right; asserting the edge serves plain HTTP is a different claim and this
// read does not establish it.
func TestCloudFrontViewerProtocolOutsideTheEnumIsWithheld(t *testing.T) {
	srv := cfServer(t, "edge", "example.org", "https-strict-2027", true)
	defer srv.Close()
	d := cfDriver(t, srv)
	obs, diags, err := d.observeCloudFront("edge", cfProviderID("000000000000", "E1234567890ABC"))
	if err != nil {
		t.Fatal(err)
	}
	for _, o := range obs {
		if o.Path == "viewer.protocol" {
			t.Fatalf("a policy outside the vocabulary's enum must not be emitted as a "+
				"measurement, got %v", o.Value)
		}
	}
	var named bool
	for _, dg := range diags {
		if strings.Contains(dg, "viewer.protocol not observed") &&
			strings.Contains(dg, "https-strict-2027") {
			named = true
		}
	}
	if !named {
		t.Fatalf("the withholding must name the value it could not place in the enum, got %v", diags)
	}
}

// The in-enum path still measures, or the fix has simply stopped reporting.
func TestCloudFrontViewerProtocolInTheEnumIsStillMeasured(t *testing.T) {
	srv := cfServer(t, "edge", "example.org", "redirect-to-https", true)
	defer srv.Close()
	d := cfDriver(t, srv)
	obs, _, err := d.observeCloudFront("edge", cfProviderID("000000000000", "E1234567890ABC"))
	if err != nil {
		t.Fatal(err)
	}
	for _, o := range obs {
		if o.Path == "viewer.protocol" {
			if o.Value != "redirect-to-https" {
				t.Fatalf("viewer.protocol = %v, want redirect-to-https", o.Value)
			}
			return
		}
	}
	t.Fatalf("a policy inside the enum must still be measured")
}
