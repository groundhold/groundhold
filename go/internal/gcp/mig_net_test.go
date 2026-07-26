package gcp

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// migServer routes by path so a test states what the API does. It records paths
// because ZONAL AND REGIONAL GROUPS LIVE AT DIFFERENT URLS, and hitting the wrong
// one is a failure mode this driver has that a single-scope driver does not.
type migServer struct {
	insertStatus int
	autoStatus   int
	getStatus    int
	getBody      string
	autoListBody string
	autoListErr  int
	templateBody string
	templateErr  int
	deleteStatus int
	opBody       string
	paths        []string
	methods      []string
}

func (s *migServer) handler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p := r.URL.Path
		s.paths = append(s.paths, p)
		s.methods = append(s.methods, r.Method)
		switch {
		case strings.Contains(p, "/operations/"):
			_, _ = w.Write([]byte(s.opBody))
		case strings.Contains(p, "/instanceTemplates/"):
			if s.templateErr != 0 {
				w.WriteHeader(s.templateErr)
				_, _ = w.Write([]byte(`{}`))
				return
			}
			_, _ = w.Write([]byte(s.templateBody))
		case r.Method == http.MethodPost && strings.HasSuffix(p, "/autoscalers"):
			w.WriteHeader(s.autoStatus)
			_, _ = w.Write([]byte(`{"name":"op-1"}`))
		case r.Method == http.MethodGet && strings.HasSuffix(p, "/autoscalers"):
			if s.autoListErr != 0 {
				w.WriteHeader(s.autoListErr)
				_, _ = w.Write([]byte(`{}`))
				return
			}
			_, _ = w.Write([]byte(s.autoListBody))
		case r.Method == http.MethodPost && strings.HasSuffix(p, "/instanceGroupManagers"):
			w.WriteHeader(s.insertStatus)
			_, _ = w.Write([]byte(`{"name":"op-1"}`))
		case r.Method == http.MethodDelete:
			w.WriteHeader(s.deleteStatus)
			_, _ = w.Write([]byte(`{"name":"op-1"}`))
		default:
			w.WriteHeader(s.getStatus)
			_, _ = w.Write([]byte(s.getBody))
		}
	}
}

func migDriver(t *testing.T, s *migServer) (*Driver, func()) {
	t.Helper()
	t.Setenv("GROUNDHOLD_GCP_ACCESS_TOKEN", "test-token")
	srv := httptest.NewServer(s.handler())
	d := NewDriver("acme-prod")
	d.ComputeBaseURL = srv.URL
	d.PollInterval = time.Millisecond
	d.PollTimeout = 50 * time.Millisecond
	return d, srv.Close
}

const migSelfLink = "https://x/projects/acme-prod/regions/europe-west1/instanceGroupManagers/g1"

func migOwnedDoc() string {
	return `{"name":"g1","selfLink":"` + migSelfLink + `","targetSize":2,
"instanceTemplate":"projects/acme-prod/global/instanceTemplates/web-template",
"description":"` + vpcOwnerMarker("web-fleet", "production") + `"}`
}

const migPrivateTemplate = `{"properties":{"networkInterfaces":[{}]}}`
const migPublicTemplate = `{"properties":{"networkInterfaces":[{"accessConfigs":[{"type":"ONE_TO_ONE_NAT"}]}]}}`

func migAutoscalerList() string {
	return `{"items":[{"target":"` + migSelfLink + `","autoscalingPolicy":{"minNumReplicas":2,"maxNumReplicas":10}}]}`
}

func migHappyServer() *migServer {
	return &migServer{
		insertStatus: 200, autoStatus: 200, getStatus: 200, getBody: migOwnedDoc(),
		autoListBody: migAutoscalerList(), templateBody: migPrivateTemplate,
		deleteStatus: 200, opBody: `{"name":"op-1","status":"DONE"}`,
	}
}

func TestCreateMIGRegionalHitsTheRegionalEndpoint(t *testing.T) {
	s := migHappyServer()
	d, done := migDriver(t, s)
	defer done()

	res := d.createMIG("web-fleet", "production", migAttrs(), migImpl(), 0)
	if res.Status != "succeeded" {
		t.Fatalf("status = %q (%s)", res.Status, res.Reason)
	}
	if !strings.HasPrefix(res.ProviderID, "mig:acme-prod:europe-west1:") {
		t.Errorf("providerId = %q, want a region-scoped id", res.ProviderID)
	}
	var insertPath, autoPath string
	for i, p := range s.paths {
		if s.methods[i] == http.MethodPost && strings.HasSuffix(p, "/instanceGroupManagers") {
			insertPath = p
		}
		if s.methods[i] == http.MethodPost && strings.HasSuffix(p, "/autoscalers") {
			autoPath = p
		}
	}
	if !strings.Contains(insertPath, "/regions/europe-west1/") {
		t.Errorf("insert path = %q, want the REGIONAL collection", insertPath)
	}
	if !strings.Contains(autoPath, "/regions/europe-west1/") {
		t.Errorf("autoscaler path = %q, want the matching scope", autoPath)
	}
}

func TestCreateMIGZonalHitsTheZonalEndpoint(t *testing.T) {
	attrs := migAttrs()
	attrs["availability.class"] = "zonal"
	impl := migImpl()
	impl["zone"] = "europe-west1-b"

	s := migHappyServer()
	d, done := migDriver(t, s)
	defer done()

	res := d.createMIG("web-fleet", "production", attrs, impl, 0)
	if res.Status != "succeeded" {
		t.Fatalf("status = %q (%s)", res.Status, res.Reason)
	}
	if !strings.HasPrefix(res.ProviderID, "mig:acme-prod:europe-west1-b:") {
		t.Errorf("providerId = %q, want a zone-scoped id", res.ProviderID)
	}
}

// The group inherits the template's addressing and cannot override it.
func TestCreateMIGRefusesWhenTheTemplateContradictsExposure(t *testing.T) {
	s := migHappyServer()
	s.templateBody = migPublicTemplate // contract says publicExposure: false
	d, done := migDriver(t, s)
	defer done()

	res := d.createMIG("web-fleet", "production", migAttrs(), migImpl(), 0)
	if res.Status != "failed" {
		t.Fatalf("status = %q, want failed", res.Status)
	}
	if !strings.Contains(res.Reason, "cannot override it") {
		t.Errorf("reason = %q", res.Reason)
	}
	for i, p := range s.paths {
		if s.methods[i] == http.MethodPost && strings.HasSuffix(p, "/instanceGroupManagers") {
			t.Fatal("the group was created against a contradicting instance template")
		}
	}
}

func TestCreateMIGRefusesWhenTheTemplateIsUnreadable(t *testing.T) {
	s := migHappyServer()
	s.templateErr = 500
	d, done := migDriver(t, s)
	defer done()

	res := d.createMIG("web-fleet", "production", migAttrs(), migImpl(), 0)
	if res.Status != "failed" {
		t.Fatalf("status = %q, want failed", res.Status)
	}
	// D296: a read that produced nothing must name its cause.
	if !strings.Contains(res.Reason, "instanceTemplates.get") {
		t.Errorf("reason %q does not name the call that failed", res.Reason)
	}
	if !strings.Contains(res.Reason, "cannot set addressing itself") {
		t.Errorf("reason %q does not say why the create was refused", res.Reason)
	}
}

func TestCreateMIGMutationHonesty(t *testing.T) {
	// The group EXISTS and holds its floor; only the autoscaler is uncertain.
	t.Run("a lost autoscaler leaves the group unknown, not failed", func(t *testing.T) {
		s := migHappyServer()
		s.autoStatus = 503
		d, done := migDriver(t, s)
		defer done()
		res := d.createMIG("web-fleet", "production", migAttrs(), migImpl(), 0)
		if res.Status != "unknown" {
			t.Errorf("status = %q, want unknown", res.Status)
		}
		if !strings.Contains(res.Reason, "holds its floor") {
			t.Errorf("reason = %q does not say what state the fleet is in", res.Reason)
		}
	})
	t.Run("a name conflict with our marker is the create succeeding twice", func(t *testing.T) {
		s := migHappyServer()
		s.insertStatus = 409
		d, done := migDriver(t, s)
		defer done()
		res := d.createMIG("web-fleet", "production", migAttrs(), migImpl(), 0)
		if res.Status != "succeeded" {
			t.Errorf("status = %q (%s), want succeeded", res.Status, res.Reason)
		}
	})
	// Binding a stranger's fleet would put our delete over it.
	t.Run("a name conflict with a foreign marker refuses to bind", func(t *testing.T) {
		s := migHappyServer()
		s.insertStatus = 409
		s.getBody = strings.Replace(migOwnedDoc(),
			vpcOwnerMarker("web-fleet", "production"), "someone-elses-fleet", 1)
		d, done := migDriver(t, s)
		defer done()
		res := d.createMIG("web-fleet", "production", migAttrs(), migImpl(), 0)
		if res.Status != "failed" || res.ProviderID != "" {
			t.Errorf("status = %q providerId = %q", res.Status, res.ProviderID)
		}
	})
	t.Run("a create that never reaches the network is failed", func(t *testing.T) {
		s := migHappyServer()
		d, done := migDriver(t, s)
		defer done()
		impl := migImpl()
		delete(impl, "instance_template")
		res := d.createMIG("web-fleet", "production", migAttrs(), impl, 0)
		if res.Status != "failed" {
			t.Errorf("status = %q, want failed", res.Status)
		}
		if len(s.paths) != 0 {
			t.Errorf("the driver called %v before refusing", s.paths)
		}
	})
}

func TestObserveMIGWithAutoscaler(t *testing.T) {
	s := migHappyServer()
	d, done := migDriver(t, s)
	defer done()

	obs, unread, err := d.observeMIG("web-fleet", "mig:acme-prod:europe-west1:g1")
	if err != nil {
		t.Fatalf("observe: %v", err)
	}
	if len(unread) != 0 {
		t.Errorf("unread = %v on a fully readable group", unread)
	}
	got := map[string]any{}
	for _, o := range obs {
		got[o.Path] = o.Value
	}
	want := map[string]any{
		"location.region":        "europe-west1",
		"availability.class":     "regional",
		"replicas.minimum":       2,
		"replicas.maximum":       10,
		"autoscaling.enabled":    true,
		"network.publicExposure": false,
		"service.managed":        true,
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s = %v, want %v", k, got[k], v)
		}
	}
}

// Without an autoscaler the group has ONE size, and it is both bounds — the same
// asymmetry the create path honors, read back the same way.
func TestObserveMIGWithoutAutoscalerReadsBothBoundsFromTargetSize(t *testing.T) {
	s := migHappyServer()
	s.autoListBody = `{"items":[]}`
	d, done := migDriver(t, s)
	defer done()

	obs, _, err := d.observeMIG("web-fleet", "mig:acme-prod:europe-west1:g1")
	if err != nil {
		t.Fatalf("observe: %v", err)
	}
	got := map[string]any{}
	for _, o := range obs {
		got[o.Path] = o.Value
	}
	if got["autoscaling.enabled"] != false {
		t.Errorf("autoscaling.enabled = %v, want false", got["autoscaling.enabled"])
	}
	if got["replicas.minimum"] != 2 || got["replicas.maximum"] != 2 {
		t.Errorf("envelope = %v..%v, want the single targetSize on both bounds",
			got["replicas.minimum"], got["replicas.maximum"])
	}
}

// One unread call would otherwise produce TWO wrong answers: a scaling fleet
// reported fixed-size, and its bounds read off targetSize.
func TestObserveMIGUnreadableAutoscalerListIsUnreadNotFalse(t *testing.T) {
	s := migHappyServer()
	s.autoListErr = 500
	d, done := migDriver(t, s)
	defer done()

	obs, unread, err := d.observeMIG("web-fleet", "mig:acme-prod:europe-west1:g1")
	if err != nil {
		t.Fatalf("observe: %v", err)
	}
	for _, o := range obs {
		switch o.Path {
		case "autoscaling.enabled", "replicas.minimum", "replicas.maximum":
			t.Errorf("%s was observed as %v from an unreadable autoscaler list", o.Path, o.Value)
		}
	}
	var said bool
	for _, u := range unread {
		if strings.Contains(u, "capacity envelope unread") {
			said = true
		}
	}
	if !said {
		t.Errorf("diagnostics %v do not report the attributes unread", unread)
	}
}

func TestDeleteMIG(t *testing.T) {
	pid := "mig:acme-prod:europe-west1:g1"

	t.Run("retires the fleet it owns", func(t *testing.T) {
		s := migHappyServer()
		d, done := migDriver(t, s)
		defer done()
		if res := d.deleteMIG("web-fleet", "production", pid); res.Status != "succeeded" {
			t.Fatalf("status = %q (%s)", res.Status, res.Reason)
		}
	})
	t.Run("refuses a fleet that is not ours", func(t *testing.T) {
		s := migHappyServer()
		s.getBody = strings.Replace(migOwnedDoc(),
			vpcOwnerMarker("web-fleet", "production"), "someone-elses-fleet", 1)
		d, done := migDriver(t, s)
		defer done()
		if res := d.deleteMIG("web-fleet", "production", pid); res.Status != "failed" {
			t.Fatalf("status = %q, want failed", res.Status)
		}
		for _, m := range s.methods {
			if m == http.MethodDelete {
				t.Fatal("a foreign fleet was terminated")
			}
		}
	})
	t.Run("an absent group is already deleted", func(t *testing.T) {
		s := migHappyServer()
		s.getStatus, s.getBody = 404, `{}`
		d, done := migDriver(t, s)
		defer done()
		if res := d.deleteMIG("web-fleet", "production", pid); res.Status != "succeeded" {
			t.Errorf("status = %q, want succeeded (idempotent)", res.Status)
		}
	})
	t.Run("an unreadable pre-delete read is unknown, never a delete", func(t *testing.T) {
		s := migHappyServer()
		s.getStatus, s.getBody = 500, `{}`
		d, done := migDriver(t, s)
		defer done()
		if res := d.deleteMIG("web-fleet", "production", pid); res.Status != "unknown" {
			t.Errorf("status = %q, want unknown", res.Status)
		}
		for _, m := range s.methods {
			if m == http.MethodDelete {
				t.Fatal("a fleet was terminated without a successful ownership read")
			}
		}
	})
}

// A sweep that enumerated zones only would miss every regional group and report
// the account clean.
func TestDiscoverMIGsFindsBothScopes(t *testing.T) {
	s := migHappyServer()
	s.getBody = `{"items":{
"zones/europe-west1-b":{"instanceGroupManagers":[{"name":"zonal-one"}]},
"regions/europe-west1":{"instanceGroupManagers":[{"name":"regional-one"}]},
"zones/us-central1-a":{"instanceGroupManagers":[{"name":"elsewhere"}]}}}`
	d, done := migDriver(t, s)
	defer done()

	got, _, err := d.discoverMIGs("europe-west1")
	if err != nil {
		t.Fatalf("discover: %v", err)
	}
	ids := map[string]bool{}
	for _, g := range got {
		ids[g.ProviderID] = true
		if g.ResourceType != "capability.compute.autoscaling" {
			t.Errorf("resourceType = %q", g.ResourceType)
		}
	}
	if !ids["mig:acme-prod:europe-west1-b:zonal-one"] {
		t.Errorf("the zonal group was not discovered: %v", ids)
	}
	if !ids["mig:acme-prod:europe-west1:regional-one"] {
		t.Errorf("the REGIONAL group was not discovered: %v", ids)
	}
	if ids["mig:acme-prod:us-central1-a:elsewhere"] {
		t.Errorf("a group from another region was discovered: %v", ids)
	}
}

func TestSplitMIGProviderID(t *testing.T) {
	for _, tc := range []struct {
		pid, scope string
		regional   bool
	}{
		{"mig:acme-prod:europe-west1-b:g1", "europe-west1-b", false},
		{"mig:acme-prod:europe-west1:g1", "europe-west1", true},
	} {
		_, scope, _, err := splitMIGProviderID(tc.pid)
		if err != nil {
			t.Fatalf("%s: %v", tc.pid, err)
		}
		if scope != tc.scope || migScopeIsRegional(scope) != tc.regional {
			t.Errorf("%s: scope = %q regional = %v", tc.pid, scope, migScopeIsRegional(scope))
		}
	}
	for _, bad := range []string{
		"gce:acme-prod:europe-west1-b:g1",
		"mig:acme-prod:not a scope:g1",
		"mig:acme-prod:europe-west1-b:../../etc/passwd",
		"mig:acme-prod:europe-west1-b",
		"mig::europe-west1-b:g1",
	} {
		if _, _, _, err := splitMIGProviderID(bad); err == nil {
			t.Errorf("%q was accepted", bad)
		}
	}
}
