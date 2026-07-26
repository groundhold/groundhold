package aws

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func readJSON4(r *http.Request) map[string]any {
	b, _ := io.ReadAll(r.Body)
	m := map[string]any{}
	_ = json.Unmarshal(b, &m)
	return m
}

func acmAttrs() map[string]any {
	return map[string]any{
		"location.region":   "us-east-1",
		"domain":            "app.example.com",
		"validation.method": "dns",
		"auto.renew":        true,
		"service.managed":   true,
	}
}

func TestBuildACMHonors(t *testing.T) {
	p, err := BuildACM("prod", "web", acmAttrs(), nil, 1)
	if err != nil {
		t.Fatal(err)
	}
	if p.Domain != "app.example.com" || !p.ValidationDNS || !p.AutoRenew || !strings.HasPrefix(p.IdempotencyToken, "pv") {
		t.Fatalf("plan = %+v", p)
	}
	body := p.createBody("web", "prod")
	if body["ValidationMethod"] != "DNS" || body["DomainName"] != "app.example.com" {
		t.Fatalf("body = %+v", body)
	}
}

func TestBuildACMRefusals(t *testing.T) {
	cases := map[string]map[string]any{
		"bad-domain":     {"domain": "not a domain"},
		"bad-validation": {"validation.method": "carrier-pigeon"},
		"no-autorenew":   {"auto.renew": false},          // managed => auto-renew
		"email-renew":    {"validation.method": "email"}, // email can't auto-renew (with auto.renew true default)
		"unmanaged":      {"service.managed": false},
		"unknown-attr":   {"cert.tier": "x"},
	}
	for name, extra := range cases {
		a := acmAttrs()
		for k, v := range extra {
			a[k] = v
		}
		if _, err := BuildACM("prod", "web", a, nil, 1); err == nil {
			t.Errorf("%s: expected refusal, got none", name)
		}
	}
	// missing domain / validation.method must refuse.
	a := acmAttrs()
	delete(a, "domain")
	if _, err := BuildACM("prod", "web", a, nil, 1); err == nil {
		t.Error("missing domain must refuse")
	}
	a = acmAttrs()
	delete(a, "validation.method")
	if _, err := BuildACM("prod", "web", a, nil, 1); err == nil {
		t.Error("missing validation.method must refuse")
	}
}

func TestBuildACMEmailNoRenew(t *testing.T) {
	// email validation with auto.renew NOT set is allowed (a non-renewing cert).
	a := acmAttrs()
	a["validation.method"] = "email"
	delete(a, "auto.renew")
	p, err := BuildACM("prod", "web", a, nil, 1)
	if err != nil {
		t.Fatalf("email cert without auto.renew should build: %v", err)
	}
	if p.ValidationDNS {
		t.Fatalf("plan = %+v", p)
	}
}

func acmTarget2(r *http.Request) string {
	full := r.Header.Get("X-Amz-Target")
	return full[strings.LastIndex(full, ".")+1:]
}

const acmTestARN = "arn:aws:acm:us-east-1:000000000000:certificate/12345678-1234-1234-1234-123456789012"

func acmServer(t *testing.T, capLabel, domain, renewal string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			switch acmTarget2(r) {
			case "RequestCertificate":
				_, _ = w.Write([]byte(`{"CertificateArn":"` + acmTestARN + `"}`))
			case "DescribeCertificate":
				_, _ = w.Write([]byte(`{"Certificate":{"CertificateArn":"` + acmTestARN + `","DomainName":"` + domain +
					`","Status":"PENDING_VALIDATION","Type":"AMAZON_ISSUED","RenewalEligibility":"` + renewal +
					`","DomainValidationOptions":[{"ValidationMethod":"DNS"}]}}`))
			case "ListTagsForCertificate":
				_, _ = w.Write([]byte(`{"Tags":[{"Key":"groundhold-capability","Value":"` + capLabel + `"},{"Key":"groundhold-environment","Value":"prod"}]}`))
			case "ListCertificates":
				_, _ = w.Write([]byte(`{"CertificateSummaryList":[{"CertificateArn":"` + acmTestARN + `","DomainName":"` + domain + `"}]}`))
			case "DeleteCertificate":
				w.WriteHeader(200)
			default:
				w.WriteHeader(400)
			}
		}))
}

func acmDriver(t *testing.T, srv *httptest.Server) *Driver {
	t.Helper()
	t.Setenv("AWS_ACCESS_KEY_ID", "AKID")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "secret")
	d := NewDriver("us-east-1")
	d.Account = "000000000000"
	d.ACMBaseURL = srv.URL
	d.Now = time.Now
	d.PollInterval = time.Millisecond
	d.PollTimeout = 2 * time.Second
	return d
}

func TestCreateObserveDeleteACM(t *testing.T) {
	srv := acmServer(t, "web", "app.example.com", "ELIGIBLE")
	defer srv.Close()
	d := acmDriver(t, srv)
	res := d.createACM("us-east-1", "000000000000", "prod", "web", acmAttrs(), nil, 1)
	if res.Status != "succeeded" || !strings.HasPrefix(res.ProviderID, "acm:us-east-1:000000000000:") {
		t.Fatalf("create: %+v", res)
	}
	obs, _, err := d.observeACM("web", res.ProviderID)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]any{}
	for _, o := range obs {
		got[o.Path] = o.Value
	}
	if got["location.region"] != "us-east-1" || got["domain"] != "app.example.com" || got["auto.renew"] != true {
		t.Fatalf("observe: %+v", got)
	}
	if got["validation.method"] != "dns" { // F17: observe must emit it so a bound-cert reconcile confirms it
		t.Fatalf("observe must emit validation.method=dns, got %v", got["validation.method"])
	}
	if del := d.deleteACM("web", "prod", res.ProviderID); del.Status != "succeeded" {
		t.Fatalf("delete: %+v", del)
	}
}

func TestDeleteACMForeignRefused(t *testing.T) {
	srv := acmServer(t, "someone-else", "app.example.com", "INELIGIBLE")
	defer srv.Close()
	d := acmDriver(t, srv)
	pid := acmProviderID("us-east-1", "000000000000", "12345678-1234-1234-1234-123456789012")
	res := d.deleteACM("web", "prod", pid)
	if res.Status != "failed" || !strings.Contains(res.Reason, "not ours") {
		t.Fatalf("foreign certificate must refuse delete, got %+v", res)
	}
}

// Weapon 2 (D87), the metamorphic write/read round-trip for
// capability.certificate.tls on AWS ACM. A STATEFUL fake records the domain the
// create requests and reflects it (with an eligibility keyed on the domain) on the
// describe read.
func TestMetamorphicACMRoundTrip(t *testing.T) {
	cases := []struct {
		name    string
		domain  string
		renewal string
		wantRen bool
	}{
		// F16-A: a groundhold-created cert is AMAZON_ISSUED (managed) and auto-renews
		// regardless of the TRANSIENT RenewalEligibility — an unused cert is INELIGIBLE
		// but still auto-renews once in use.
		{"eligible", "a.example.com", "ELIGIBLE", true},
		{"ineligible", "b.example.com", "INELIGIBLE", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var domain string
			srv := httptest.NewServer(http.HandlerFunc(
				func(w http.ResponseWriter, r *http.Request) {
					switch acmTarget2(r) {
					case "RequestCertificate":
						domain = readJSON4(r)["DomainName"].(string)
						_, _ = w.Write([]byte(`{"CertificateArn":"` + acmTestARN + `"}`))
					case "DescribeCertificate":
						_, _ = w.Write([]byte(`{"Certificate":{"DomainName":"` + domain +
							`","Status":"ISSUED","Type":"AMAZON_ISSUED","RenewalEligibility":"` + c.renewal + `"}}`))
					default:
						w.WriteHeader(200)
					}
				}))
			defer srv.Close()
			d := acmDriver(t, srv)
			a := acmAttrs()
			a["domain"] = c.domain
			res := d.createACM("us-east-1", "000000000000", "prod", "web", a, nil, 1)
			if res.Status != "succeeded" {
				t.Fatalf("create: %+v", res)
			}
			obs, _, err := d.observeACM("web", res.ProviderID)
			if err != nil {
				t.Fatal(err)
			}
			got := map[string]any{}
			for _, o := range obs {
				got[o.Path] = o.Value
			}
			if got["domain"] != c.domain {
				t.Errorf("domain round-trip: want %q got %v", c.domain, got["domain"])
			}
			if got["auto.renew"] != c.wantRen {
				t.Errorf("renew round-trip: want %v got %v", c.wantRen, got["auto.renew"])
			}
		})
	}
}

// TestObserveACMManagedAutoRenew pins F16-A: a managed (AMAZON_ISSUED) certificate that
// is not yet in use reports RenewalEligibility=INELIGIBLE, but it STILL auto-renews
// (that is what "managed" means). Keying auto.renew on the transient eligibility made an
// unused cert observe false against a declared true → a perpetual no-op reconcile.
func TestObserveACMManagedAutoRenew(t *testing.T) {
	srv := acmServer(t, "web", "app.example.com", "INELIGIBLE")
	defer srv.Close()
	d := acmDriver(t, srv)
	pid := acmProviderID("us-east-1", "000000000000", "12345678-1234-1234-1234-123456789012")
	obs, _, err := d.observeACM("web", pid)
	if err != nil {
		t.Fatal(err)
	}
	var saw bool
	for _, o := range obs {
		if o.Path == "auto.renew" {
			saw = true
			if o.Value != true {
				t.Fatalf("a managed cert must observe auto.renew=true even when INELIGIBLE (F16-A), got %v", o.Value)
			}
		}
	}
	if !saw {
		t.Fatal("auto.renew must be observed")
	}
}
