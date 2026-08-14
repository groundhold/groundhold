package gcp

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"groundhold/internal/certifynet"
	"groundhold/internal/provider"
)

func arAttrs() map[string]any {
	return map[string]any{
		"location.region":                "europe-west1",
		"network.publicExposure":         false,
		"encryption.customerManagedKeys": true,
		"immutable.tags":                 true,
		"service.managed":                true,
	}
}

func arImpl() map[string]any {
	return map[string]any{"kms_key": "projects/acme-prod/locations/europe-west1/keyRings/r/cryptoKeys/k"}
}

func TestBuildARRepoHonors(t *testing.T) {
	p, err := BuildARRepo("acme-prod", "prod", "images", arAttrs(), arImpl(), 1)
	if err != nil {
		t.Fatal(err)
	}
	if p.Region != "europe-west1" || !p.ImmutableTags || p.KmsKey == "" || p.Public {
		t.Fatalf("plan = %+v", p)
	}
	body := p.createBody("images", "prod")
	if body["format"] != "DOCKER" || body["dockerConfig"].(map[string]any)["immutableTags"] != true ||
		body["kmsKeyName"] == nil {
		t.Fatalf("body = %+v", body)
	}
}

func TestBuildARRepoRefusals(t *testing.T) {
	cases := map[string]struct {
		extra map[string]any
		impl  map[string]any
	}{
		"cmek-no-key":  {map[string]any{"encryption.customerManagedKeys": true}, nil},
		"unmanaged":    {map[string]any{"service.managed": false}, arImpl()},
		"unknown-attr": {map[string]any{"registry.tier": "premium"}, arImpl()},
	}
	for name, c := range cases {
		a := arAttrs()
		for k, v := range c.extra {
			a[k] = v
		}
		if _, err := BuildARRepo("acme-prod", "prod", "images", a, c.impl, 1); err == nil {
			t.Errorf("%s: expected refusal, got none", name)
		}
	}
	a := arAttrs()
	delete(a, "location.region")
	if _, err := BuildARRepo("acme-prod", "prod", "images", a, arImpl(), 1); err == nil {
		t.Error("missing location.region must refuse")
	}
}

func arServer(t *testing.T, tagCap string, public bool) *httptest.Server {
	return arServerScan(t, tagCap, public, false)
}

// arServerScan also fakes Service Usage: GET .../services/<svc> returns the project's
// Container Scanning API state, and POST .../services/<svc>:enable returns an LRO. This
// is how the driver measures/enables security.scanOnPush — a PROJECT posture, not a repo
// field (the honest divergence from ECR).
func arServerScan(t *testing.T, tagCap string, public, scanEnabled bool) *httptest.Server {
	t.Helper()
	iamPub := ""
	if public {
		iamPub = `{"role":"roles/artifactregistry.reader","members":["allUsers"]}`
	}
	scanState := "DISABLED"
	if scanEnabled {
		scanState = "ENABLED"
	}
	return httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			switch {
			case strings.HasSuffix(r.URL.Path, ":enable"):
				_, _ = w.Write([]byte(`{"name":"operations/su-op1"}`))
			case r.Method == "GET" && strings.Contains(r.URL.Path, "/services/"):
				_, _ = w.Write([]byte(`{"state":"` + scanState + `"}`))
			case r.Method == "POST" && strings.HasSuffix(r.URL.Path, "/repositories"):
				_, _ = w.Write([]byte(`{"name":"projects/acme-prod/locations/europe-west1/operations/op1"}`))
			case r.Method == "GET" && strings.Contains(r.URL.Path, "/operations/"):
				_, _ = w.Write([]byte(`{"done":true}`))
			case strings.HasSuffix(r.URL.Path, ":getIamPolicy"):
				b := `{"bindings":[]}`
				if iamPub != "" {
					b = `{"bindings":[` + iamPub + `]}`
				}
				_, _ = w.Write([]byte(b))
			case strings.HasSuffix(r.URL.Path, ":setIamPolicy"):
				_, _ = w.Write([]byte(`{}`))
			case r.Method == "GET":
				_, _ = w.Write([]byte(`{"format":"DOCKER","kmsKeyName":"k","dockerConfig":{"immutableTags":true},` +
					`"labels":{"groundhold-capability":"` + tagCap + `","groundhold-environment":"prod"}}`))
			case r.Method == "DELETE":
				_, _ = w.Write([]byte(`{"name":"projects/acme-prod/locations/europe-west1/operations/op2"}`))
			default:
				w.WriteHeader(404)
			}
		}))
}

func arDriver(t *testing.T, srv *httptest.Server) *Driver {
	t.Helper()
	t.Setenv("GROUNDHOLD_GCP_ACCESS_TOKEN", "test-token")
	d := NewDriver("acme-prod")
	d.ARBaseURL = srv.URL
	d.PollInterval = 0
	suBaseOverride = srv.URL // Service Usage (Container Scanning) also fakes to this server
	t.Cleanup(func() { suBaseOverride = "" })
	return d
}

func TestCreateObserveDeleteARRepo(t *testing.T) {
	srv := arServer(t, "images", false)
	defer srv.Close()
	d := arDriver(t, srv)
	res := d.createARRepo("images", "prod", arAttrs(), arImpl(), 1)
	if res.Status != "succeeded" || !strings.HasPrefix(res.ProviderID, "gar:acme-prod:europe-west1:") {
		t.Fatalf("create: %+v", res)
	}
	obs, _, err := d.observeARRepo("images", res.ProviderID)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]any{}
	for _, o := range obs {
		got[o.Path] = o.Value
	}
	if got["location.region"] != "europe-west1" || got["immutable.tags"] != true ||
		got["encryption.customerManagedKeys"] != true || got["network.publicExposure"] != false {
		t.Fatalf("observe: %+v", got)
	}
	if del := d.deleteARRepo("images", "prod", res.ProviderID); del.Status != "succeeded" {
		t.Fatalf("delete: %+v", del)
	}
}

func TestCreatePublicARRepoSetsIAM(t *testing.T) {
	srv := arServer(t, "images", true)
	defer srv.Close()
	d := arDriver(t, srv)
	a := arAttrs()
	a["network.publicExposure"] = true
	res := d.createARRepo("images", "prod", a, arImpl(), 1)
	if res.Status != "succeeded" {
		t.Fatalf("public create: %+v", res)
	}
	obs, _, _ := d.observeARRepo("images", res.ProviderID)
	got := map[string]any{}
	for _, o := range obs {
		got[o.Path] = o.Value
	}
	if got["network.publicExposure"] != true {
		t.Fatalf("public registry must observe publicExposure=true: %+v", got)
	}
}

func TestDeleteARRepoForeignRefused(t *testing.T) {
	srv := arServer(t, "someone-else", false)
	defer srv.Close()
	d := arDriver(t, srv)
	res := d.deleteARRepo("images", "prod", "gar:acme-prod:europe-west1:pv-images-prod-abcd1234")
	if res.Status != "failed" || !strings.Contains(res.Reason, "not ours") {
		t.Fatalf("foreign registry must refuse delete, got %+v", res)
	}
}

// security.scanOnPush is a PROJECT posture in GCP, never a repository field: the plan
// records it but the createBody must NOT carry it (unlike ECR's imageScanningConfiguration).
func TestBuildARRepoScanOnPushIsNotARepoField(t *testing.T) {
	a := arAttrs()
	a["security.scanOnPush"] = true
	p, err := BuildARRepo("acme-prod", "prod", "images", a, arImpl(), 1)
	if err != nil {
		t.Fatal(err)
	}
	if !p.ScanOnPush {
		t.Fatalf("plan must record scanOnPush: %+v", p)
	}
	body := p.createBody("images", "prod")
	for k := range body {
		if strings.Contains(strings.ToLower(k), "scan") {
			t.Fatalf("createBody must not carry a scanning field (project API, not a repo field): %v", body)
		}
	}
}

// create with scanOnPush=true enables the project Container Scanning API; observe then
// measures it from that API state (state ENABLED => scanOnPush true), NOT from the repo.
func TestARScanOnPushEnableAndObserve(t *testing.T) {
	srv := arServerScan(t, "images", false, true)
	defer srv.Close()
	d := arDriver(t, srv)
	a := arAttrs()
	a["security.scanOnPush"] = true
	res := d.createARRepo("images", "prod", a, arImpl(), 1)
	if res.Status != "succeeded" {
		t.Fatalf("create with scanOnPush must succeed (enable API): %+v", res)
	}
	obs, diags, err := d.observeARRepo("images", res.ProviderID)
	if err != nil {
		t.Fatal(err)
	}
	var got any
	for _, o := range obs {
		if o.Path == "security.scanOnPush" {
			got = o.Value
		}
	}
	if got != true {
		t.Fatalf("observe must measure scanOnPush=true from the project API state, got %v", got)
	}
	joined := strings.Join(diags, " | ")
	if !strings.Contains(joined, "project-level Container Scanning API") {
		t.Fatalf("observe must diagnose scanOnPush as a project posture: %q", joined)
	}
}

// when the project API is DISABLED, observe reports scanOnPush=false honestly.
func TestARScanOnPushObserveDisabled(t *testing.T) {
	srv := arServerScan(t, "images", false, false)
	defer srv.Close()
	d := arDriver(t, srv)
	obs, _, err := d.observeARRepo("images", "gar:acme-prod:europe-west1:pv-images-prod-abcd1234")
	if err != nil {
		t.Fatal(err)
	}
	var seen bool
	for _, o := range obs {
		if o.Path == "security.scanOnPush" {
			seen = true
			if o.Value != false {
				t.Fatalf("disabled project API must observe scanOnPush=false, got %v", o.Value)
			}
		}
	}
	if !seen {
		t.Fatal("scanOnPush must be observed when the project API is readable")
	}
}

// scanOnPush is deliberately classified unsupported for in-place change (project-wide API,
// not a per-repo toggle) — honest, and NOT mutable-without-updater.
func TestClassifyARChangeScanOnPushUnsupported(t *testing.T) {
	cls, reason := classifyARChange("security.scanOnPush")
	if cls != "unsupported" {
		t.Fatalf("scanOnPush must classify unsupported (project-level API), got %q", cls)
	}
	if !strings.Contains(reason, "project-level Container Scanning API") {
		t.Fatalf("reason must explain the project-level nature: %q", reason)
	}
	if c, _ := classifyARChange("location.region"); c != "immutable" {
		t.Fatalf("region change must be immutable (replacement), got %q", c)
	}
}

// arAdoptServer is arExistingServer with the two adopt-critical controls made
// configurable (D1062): the repository GET reports the given kmsKeyName (CMEK iff
// non-empty) and immutableTags ("true"/"false"), so the control-completeness cases can
// serve a repository that lacks CMEK or tag immutability.
func arAdoptServer(tagCap, kmsKeyName, immutableTags string) func() *httptest.Server {
	return func() *httptest.Server {
		return httptest.NewServer(http.HandlerFunc(
			func(w http.ResponseWriter, r *http.Request) {
				switch {
				case r.Method == "POST" && strings.HasSuffix(r.URL.Path, "/repositories"):
					w.WriteHeader(http.StatusConflict)
					_, _ = w.Write([]byte(`{"error":{"code":409,"message":"already exists"}}`))
				case strings.HasSuffix(r.URL.Path, ":enable"):
					_, _ = w.Write([]byte(`{"name":"operations/su-op1"}`))
				case r.Method == "GET" && strings.Contains(r.URL.Path, "/services/"):
					_, _ = w.Write([]byte(`{"state":"ENABLED"}`))
				case r.Method == "GET" && strings.Contains(r.URL.Path, "/operations/"):
					_, _ = w.Write([]byte(`{"done":true}`))
				case strings.HasSuffix(r.URL.Path, ":getIamPolicy"):
					_, _ = w.Write([]byte(`{"bindings":[]}`))
				case strings.HasSuffix(r.URL.Path, ":setIamPolicy"):
					_, _ = w.Write([]byte(`{}`))
				case r.Method == "GET":
					_, _ = w.Write([]byte(`{"format":"DOCKER","kmsKeyName":"` + kmsKeyName + `",` +
						`"dockerConfig":{"immutableTags":` + immutableTags + `},` +
						`"labels":{"groundhold-capability":"` + tagCap + `","groundhold-environment":"prod"}}`))
				default:
					w.WriteHeader(404)
				}
			}))
	}
}

func arRole(req *http.Request, _ []byte) certifynet.Role {
	if req.Method == http.MethodGet || strings.HasSuffix(req.URL.Path, ":getIamPolicy") {
		return certifynet.RoleRead
	}
	return certifynet.RoleMutateOpaque
}

// arExistingServer: the repository already exists at our deterministic id and carries our
// labels, so the create is answered 409 and the driver must recognise and bind it.
func arExistingServer(t *testing.T, tagCap string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			switch {
			case r.Method == "POST" && strings.HasSuffix(r.URL.Path, "/repositories"):
				w.WriteHeader(http.StatusConflict)
				_, _ = w.Write([]byte(`{"error":{"code":409,"message":"already exists"}}`))
			case strings.HasSuffix(r.URL.Path, ":enable"):
				_, _ = w.Write([]byte(`{"name":"operations/su-op1"}`))
			case r.Method == "GET" && strings.Contains(r.URL.Path, "/services/"):
				_, _ = w.Write([]byte(`{"state":"ENABLED"}`))
			case r.Method == "GET" && strings.Contains(r.URL.Path, "/operations/"):
				_, _ = w.Write([]byte(`{"done":true}`))
			case strings.HasSuffix(r.URL.Path, ":getIamPolicy"):
				_, _ = w.Write([]byte(`{"bindings":[]}`))
			case strings.HasSuffix(r.URL.Path, ":setIamPolicy"):
				_, _ = w.Write([]byte(`{}`))
			case r.Method == "GET":
				_, _ = w.Write([]byte(`{"format":"DOCKER","kmsKeyName":"k","dockerConfig":{"immutableTags":true},` +
					`"labels":{"groundhold-capability":"` + tagCap + `","groundhold-environment":"prod"}}`))
			default:
				w.WriteHeader(404)
			}
		}))
}

// TestAdoptsExistingARRepo enrols artifactregistry as the FIRST GCP service in the D391
// class gate (D413). GCP resources are name-addressed, so the failure this prevents is
// not a duplicate but a converge that hard-fails against an estate already standing.
func TestAdoptsExistingARRepo(t *testing.T) {
	t.Setenv("GROUNDHOLD_GCP_ACCESS_TOKEN", "test-token")
	p := &certifynet.ExistingProbe{
		Name:           "gcp/artifactregistry",
		Classify:       arRole,
		ExistingServer: func() *httptest.Server { return arExistingServer(t, "images") },
		New: func(happyURL string, rt http.RoundTripper) provider.Provider {
			d := NewDriver("acme-prod")
			d.HTTP = &http.Client{Transport: rt}
			d.ARBaseURL = happyURL
			d.PollInterval = 0
			suBaseOverride = happyURL
			t.Cleanup(func() { suBaseOverride = "" })
			return d
		},
		Create: func(pr provider.Provider) provider.CreateResult {
			return pr.Create("artifactregistry", "images", "prod", arAttrs(), arImpl(), "images", 1)
		},
		AllowedMutations: 2, // the refused create + re-asserting the exposure posture
		// D1062: CMEK is fixed at creation and tag immutability has no wired update, so
		// adopting a repository that lacks either FAILS. The check runs before the
		// exposure re-assertion, so a rejected adopt sends only the refused create.
		AdoptControls: arAdoptControls,
		MissingControl: []certifynet.ControlCase{
			// live repository is on a Google-managed key though we declared CMEK.
			{Path: "encryption.customerManagedKeys", Server: arAdoptServer("images", "", "true"),
				WantStatus: "failed", WantMutations: 1},
			// live repository allows tag overwrites though we declared immutable tags.
			{Path: "immutable.tags", Server: arAdoptServer("images", "k", "false"),
				WantStatus: "failed", WantMutations: 1},
		},
		MoreSecure: arAdoptServer("images", "k", "true"), // both controls in place — adopts clean
	}
	certifynet.CertifyCreateAdoptsExisting(t, p)
}
