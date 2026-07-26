package azure

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

func acsEmailAttrs() map[string]any {
	return map[string]any{
		"location.region":     "europe",
		"authentication.dkim": true,
		"service.managed":     true,
	}
}

func acsEmailImpl() map[string]any {
	return map[string]any{
		"resource_group":     "rg1",
		"email_service_name": "pvmailsvc",
		"domain_management":  "CustomerManaged",
		"domain":             "mail.example.com",
	}
}

func TestBuildACSEmailHonors(t *testing.T) {
	p, err := BuildACSEmail("prod", "email", acsEmailAttrs(), acsEmailImpl(), 1)
	if err != nil {
		t.Fatal(err)
	}
	if p.Name != "pvmailsvc" {
		t.Fatalf("name = %q", p.Name)
	}
	if p.DataLocation != "Europe" {
		t.Fatalf("dataLocation = %q (want canonical Europe for EU residency)", p.DataLocation)
	}
	if !p.DKIM || p.DomainName != "mail.example.com" || p.DomainManagement != "CustomerManaged" {
		t.Fatalf("dkim=%v domain=%q mgmt=%q", p.DKIM, p.DomainName, p.DomainManagement)
	}
}

func TestBuildACSEmailAzureManagedDefault(t *testing.T) {
	impl := map[string]any{"resource_group": "rg1"}
	p, err := BuildACSEmail("prod", "email", map[string]any{
		"location.region": "United States", "authentication.dkim": true, "service.managed": true,
	}, impl, 1)
	if err != nil {
		t.Fatal(err)
	}
	if p.DomainManagement != "AzureManaged" || p.DomainName != azureManagedDomainName {
		t.Fatalf("expected default azure-managed domain, got mgmt=%q name=%q", p.DomainManagement, p.DomainName)
	}
	if p.DataLocation != "United States" {
		t.Fatalf("dataLocation = %q", p.DataLocation)
	}
}

func TestBuildACSEmailRefusals(t *testing.T) {
	base := func() (map[string]any, map[string]any) { return acsEmailAttrs(), acsEmailImpl() }
	cases := map[string]func() (map[string]any, map[string]any){
		"bounce-tracked-true": func() (map[string]any, map[string]any) {
			a, i := base()
			a["bounce.tracked"] = true
			return a, i
		},
		"unknown-attr": func() (map[string]any, map[string]any) {
			a, i := base()
			a["throughput.tier"] = "premium"
			return a, i
		},
		"missing-rg": func() (map[string]any, map[string]any) {
			a, _ := base()
			return a, map[string]any{"email_service_name": "pvmailsvc", "domain_management": "CustomerManaged", "domain": "mail.example.com"}
		},
		"missing-region": func() (map[string]any, map[string]any) {
			a, i := base()
			delete(a, "location.region")
			return a, i
		},
		"unknown-region": func() (map[string]any, map[string]any) {
			a, i := base()
			a["location.region"] = "narnia"
			return a, i
		},
		"dkim-no-domain": func() (map[string]any, map[string]any) {
			a, _ := base()
			return a, map[string]any{"resource_group": "rg1", "domain_management": "CustomerManaged"}
		},
		"domain-without-dkim": func() (map[string]any, map[string]any) {
			a, i := base()
			a["authentication.dkim"] = false
			return a, i
		},
		"managed-false": func() (map[string]any, map[string]any) {
			a, i := base()
			a["service.managed"] = false
			return a, i
		},
		"bad-domain-management": func() (map[string]any, map[string]any) {
			a, i := base()
			i["domain_management"] = "Whatever"
			return a, i
		},
	}
	for name, mk := range cases {
		a, i := mk()
		if _, err := BuildACSEmail("prod", "email", a, i, 1); err == nil {
			t.Errorf("%s: expected refusal, got none", name)
		}
	}
}

func TestClassifyACSEmailChange(t *testing.T) {
	if verb, _ := classifyACSEmailChange("authentication.dkim"); verb != "mutable" {
		t.Errorf("dkim should be mutable, got %q", verb)
	}
	if verb, _ := classifyACSEmailChange("location.region"); verb != "immutable" {
		t.Errorf("dataLocation should be immutable, got %q", verb)
	}
	if verb, _ := classifyACSEmailChange("bounce.tracked"); verb != "unsupported" {
		t.Errorf("bounce.tracked should be unsupported, got %q", verb)
	}
}

// acsEmailArmFake is a stateful ARM fake for the emailService + domain composite:
// the emailService is 404 until its PUT, Succeeded after; likewise its domain, which
// reports DKIM Verified so observe derives authentication.dkim = true.
type acsEmailArmFake struct {
	mu       sync.Mutex
	svcThere bool
	domThere bool
	wantData string
	wantDom  string
	t        *testing.T
}

func (f *acsEmailArmFake) handler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer test-token" {
			f.t.Errorf("missing/wrong bearer: %q", got)
		}
		f.mu.Lock()
		defer f.mu.Unlock()
		p := r.URL.Path
		isDomain := strings.Contains(p, "/domains/")
		isDomainList := strings.HasSuffix(p, "/domains")
		switch {
		case isDomainList && r.Method == "GET":
			if f.domThere {
				_, _ = w.Write([]byte(`{"value":[{"name":"` + f.wantDom + `","properties":{` +
					`"provisioningState":"Succeeded","domainManagement":"CustomerManaged",` +
					`"verificationStates":{"DKIM":{"status":"Verified"}}}}]}`))
			} else {
				_, _ = w.Write([]byte(`{"value":[]}`))
			}
		case isDomain && r.Method == "PUT":
			raw, _ := io.ReadAll(r.Body)
			var body struct {
				Location   string `json:"location"`
				Properties struct {
					DomainManagement string `json:"domainManagement"`
				} `json:"properties"`
			}
			_ = json.Unmarshal(raw, &body)
			if body.Location != "global" || body.Properties.DomainManagement != "CustomerManaged" {
				f.t.Errorf("domain PUT body = %+v", body)
			}
			f.domThere = true
			w.WriteHeader(201)
			_, _ = w.Write([]byte(`{"properties":{"provisioningState":"Succeeded"}}`))
		case isDomain && r.Method == "GET":
			if f.domThere {
				_, _ = w.Write([]byte(`{"name":"` + f.wantDom + `","properties":{"provisioningState":"Succeeded",` +
					`"verificationStates":{"DKIM":{"status":"Verified"}}}}`))
			} else {
				w.WriteHeader(404)
			}
		case isDomain && r.Method == "DELETE":
			f.domThere = false
			w.WriteHeader(200)
		case r.Method == "PUT": // emailService
			raw, _ := io.ReadAll(r.Body)
			var body struct {
				Location   string            `json:"location"`
				Tags       map[string]string `json:"tags"`
				Properties struct {
					DataLocation string `json:"dataLocation"`
				} `json:"properties"`
			}
			_ = json.Unmarshal(raw, &body)
			if body.Location != "global" {
				f.t.Errorf("emailService location = %q (want global)", body.Location)
			}
			if body.Properties.DataLocation != f.wantData {
				f.t.Errorf("emailService dataLocation = %q (want %q)", body.Properties.DataLocation, f.wantData)
			}
			if body.Tags["groundhold-capability"] == "" {
				f.t.Errorf("emailService missing ownership tags: %+v", body.Tags)
			}
			f.svcThere = true
			w.WriteHeader(201)
			_, _ = w.Write([]byte(`{"properties":{"provisioningState":"Succeeded"}}`))
		case r.Method == "GET": // emailService
			if f.svcThere {
				_, _ = w.Write([]byte(`{"location":"global","tags":{"groundhold-capability":"email","groundhold-environment":"prod"},` +
					`"properties":{"provisioningState":"Succeeded","dataLocation":"` + f.wantData + `"}}`))
			} else {
				w.WriteHeader(404)
			}
		case r.Method == "DELETE": // emailService
			f.svcThere = false
			w.WriteHeader(200)
		default:
			w.WriteHeader(404)
		}
	}
}

func TestCreateObserveDeleteACSEmail(t *testing.T) {
	fake := &acsEmailArmFake{t: t, wantData: "Europe", wantDom: "mail.example.com"}
	srv := httptest.NewServer(fake.handler())
	defer srv.Close()
	d := vnetTestDriver(t, srv)

	res := d.createACSEmail("prod", "email", acsEmailAttrs(), acsEmailImpl(), 1)
	if res.Status != "succeeded" || res.ProviderID == "" {
		t.Fatalf("create: %+v", res)
	}
	if res.ProviderID != "acsemail:"+testSub+":rg1:pvmailsvc" {
		t.Fatalf("providerId = %q", res.ProviderID)
	}

	obs, diags, err := d.observeACSEmail("email", res.ProviderID)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]any{}
	for _, o := range obs {
		got[o.Path] = o.Value
	}
	if got["location.region"] != "europe" {
		t.Fatalf("observe location.region = %v (want europe residency)", got["location.region"])
	}
	if got["authentication.dkim"] != true {
		t.Fatalf("observe authentication.dkim = %v (want true, DKIM Verified)", got["authentication.dkim"])
	}
	if got["service.managed"] != true {
		t.Fatalf("observe service.managed = %v", got["service.managed"])
	}
	// bounce.tracked must NEVER be fabricated — omitted with a diagnostic.
	if _, present := got["bounce.tracked"]; present {
		t.Fatalf("bounce.tracked must not be observed on ACS Email")
	}
	var sawBounceDiag bool
	for _, dg := range diags {
		if strings.Contains(dg, "bounce.tracked not observed") {
			sawBounceDiag = true
		}
	}
	if !sawBounceDiag {
		t.Fatalf("expected an honest bounce.tracked diagnostic, got %v", diags)
	}

	if del := d.deleteACSEmail("email", "prod", res.ProviderID); del.Status != "succeeded" {
		t.Fatalf("delete: %+v", del)
	}
}

func TestDeleteACSEmailForeignSubscriptionRefused(t *testing.T) {
	fake := &acsEmailArmFake{t: t, wantData: "Europe", wantDom: "mail.example.com"}
	srv := httptest.NewServer(fake.handler())
	defer srv.Close()
	d := vnetTestDriver(t, srv)
	foreign := acsEmailProviderID("00000000-0000-0000-0000-0000000000ff", "rg1", "pvmailsvc")
	res := d.deleteACSEmail("email", "prod", foreign)
	if res.Status != "failed" || !strings.Contains(res.Reason, "across subscriptions") {
		t.Fatalf("foreign subscription must refuse delete, got %+v", res)
	}
}

func TestCreateACSEmailForeignServiceRefused(t *testing.T) {
	// emailService exists but with foreign tags — create must refuse to adopt it.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"location":"global","tags":{"owner":"someone-else"},` +
			`"properties":{"provisioningState":"Succeeded","dataLocation":"Europe"}}`))
	}))
	defer srv.Close()
	d := vnetTestDriver(t, srv)
	res := d.createACSEmail("prod", "email", acsEmailAttrs(), acsEmailImpl(), 1)
	if res.Status != "failed" || !strings.Contains(res.Reason, "not ours") {
		t.Fatalf("foreign emailService must refuse, got %+v", res)
	}
}
