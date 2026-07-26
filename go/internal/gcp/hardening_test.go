package gcp

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Cloud Run v2 serviceId must be fewer than 50 chars (live discovery doc); a
// long capability + environment must still produce a valid name.
func TestServiceNameUnder50(t *testing.T) {
	n := ServiceName("acme-prod", "production-environment",
		"a-very-long-capability-identifier-for-a-service", 1)
	if len(n) >= 50 {
		t.Fatalf("ServiceName must be < 50 chars, got %d (%q)", len(n), n)
	}
}

func TestCloudRunFractionalRefused(t *testing.T) {
	base := map[string]any{"location.region": "europe-central2"}
	for _, tc := range []struct {
		name string
		impl map[string]any
		attr map[string]any
	}{
		{"port", map[string]any{"image": "x", "port": 8080.5}, base},
		{"replicas", map[string]any{"image": "x"},
			map[string]any{"location.region": "x", "replicas.minimum": 2.9}},
	} {
		if _, err := BuildCloudRunCreateRequest("p", "e", "c", tc.attr, tc.impl, 1); err == nil {
			t.Errorf("%s: a fractional value must be refused, not truncated", tc.name)
		}
	}
}

// retention.minimum is a floor — a sub-second remainder must round UP, never
// truncate below the declared minimum.
func TestGCSRetentionRoundsUp(t *testing.T) {
	a := gcsAttrs()
	a["retention.minimum"] = "90500ms"
	req, err := BuildGCSCreateRequest("p", "prod", "assets", a, nil, 1)
	if err != nil {
		t.Fatal(err)
	}
	rp := req.Body["retentionPolicy"].(map[string]any)
	if rp["retentionPeriod"] != "91" {
		t.Fatalf("90500ms must round up to 91s, got %v", rp["retentionPeriod"])
	}
}

// Cloud SQL labels must be sanitized identically to Cloud Run/GCS — a raw value
// with a dot/uppercase would 400 every Cloud SQL create.
func TestCloudSQLLabelsSanitized(t *testing.T) {
	req, err := BuildCreateRequest("p", "Prod.Env", "cap",
		map[string]any{"engine.protocol": "postgresql/16", "location.region": "x"},
		map[string]any{"tier": "t"}, 1)
	if err != nil {
		t.Fatal(err)
	}
	s := req.Body["settings"].(map[string]any)
	lbl := s["userLabels"].(map[string]any)
	if lbl["groundhold-environment"] != sanitizeLabel("Prod.Env") {
		t.Fatalf("label must be sanitized, got %v", lbl["groundhold-environment"])
	}
	if strings.ContainsAny(lbl["groundhold-environment"].(string), ".") {
		t.Fatalf("sanitized label must not contain a dot: %v", lbl["groundhold-environment"])
	}
}

// Cloud Run invokerIamDisabled=true is a public mode independent of any allUsers
// binding: observe must report publicExposure=true for an ALL-ingress service
// even with an empty IAM policy.
// An intrusive probe on an instance that is not ours (no/mismatched
// groundhold-capability label) must refuse BEFORE spending on a scratch restore.
func TestProbeIntrusiveRefusesForeignInstance(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			// a foreign instance sharing the name — no groundhold-capability label
			_, _ = w.Write([]byte(`{"databaseVersion":"POSTGRES_16","ipAddresses":[],` +
				`"settings":{"tier":"db-custom-2-8192","userLabels":{"team":"someone-else"}}}`))
		}))
	defer srv.Close()
	d := testDriver(t, srv)
	_, err := d.Probe("cloudsql", "db", "acme-prod:europe-central2:source-db", true)
	if err == nil || !strings.Contains(err.Error(), "not ours") {
		t.Fatalf("intrusive probe on a foreign instance must refuse, got %v", err)
	}
}

// A forged cross-project providerId must refuse before any probe read.
func TestProbeCrossProjectRefused(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(`{}`)) }))
	defer srv.Close()
	d := testDriver(t, srv) // pinned acme-prod
	if _, err := d.Probe("cloudsql", "db", "other-proj:region:db-1", false); err == nil {
		t.Fatal("a cross-project probe providerId must refuse")
	}
}

// A malformed pinned project must refuse before interpolation (confused deputy).
func TestProjectCharsetValidated(t *testing.T) {
	t.Setenv("GROUNDHOLD_GCP_ACCESS_TOKEN", "test-token")
	d := NewDriver("bad project/../x")
	if err := d.Validate("cloudsql", "db", "prod",
		map[string]any{"engine.protocol": "postgresql/16", "location.region": "x"},
		map[string]any{"tier": "t"}, 1); err == nil {
		t.Fatal("a malformed project must be refused")
	}
	// a valid project still passes
	d2 := NewDriver("example-project")
	if err := d2.Validate("cloudsql", "db", "prod",
		map[string]any{"engine.protocol": "postgresql/16", "location.region": "x"},
		map[string]any{"tier": "t"}, 1); err != nil {
		t.Fatalf("a valid project must pass, got %v", err)
	}
}

// A 409 on an ours-labeled instance in a DIFFERENT region must refuse (region
// is immutable) — never bind the wrong resource as succeeded.
func TestClassify409RegionMismatchRefused(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			if r.Method == "POST" {
				w.WriteHeader(http.StatusConflict)
				return
			}
			// GET: ours by labels, but in us-central1 while the request wants europe-west1
			_, _ = w.Write([]byte(`{"region":"us-central1","settings":{"userLabels":` +
				`{"groundhold-capability":"orders-db","groundhold-environment":"production"}}}`))
		}))
	defer srv.Close()
	cr := testDriver(t, srv).Create("cloudsql", "orders-db", "production", attrs, impl, "k1", 1)
	if cr.Status != "failed" || !strings.Contains(cr.Reason, "region is immutable") {
		t.Fatalf("region mismatch must refuse, got %+v", cr)
	}
}

func TestObserveCloudRunSignedProvenance(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			if strings.Contains(r.URL.Path, ":getIamPolicy") {
				_, _ = w.Write([]byte(`{"bindings":[]}`))
				return
			}
			_, _ = w.Write([]byte(`{"ingress":"INGRESS_TRAFFIC_INTERNAL_ONLY",` +
				`"binaryAuthorization":{"useDefault":true}}`))
		}))
	defer srv.Close()
	t.Setenv("GROUNDHOLD_GCP_ACCESS_TOKEN", "test-token")
	d := NewDriver("acme-prod")
	d.RunBaseURL = srv.URL
	obs, _, err := d.observeCloudRun("web", "cloudrun:acme-prod:europe-central2:web-1")
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, o := range obs {
		if o.Path == "image.signedProvenance" {
			found = true
			if o.Value != true || o.Derivation != "config-intent" {
				t.Fatalf("signedProvenance must be observed as config-intent true, got %+v", o)
			}
		}
	}
	if !found {
		t.Fatal("image.signedProvenance must be observable (else converge can't converge)")
	}
}

func TestObserveCloudRunInvokerIamDisabledPublic(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			// services.get returns the service; IAM getIamPolicy must NOT be
			// consulted when invokerIamDisabled decides publicness.
			if strings.Contains(r.URL.Path, ":getIamPolicy") {
				t.Errorf("IAM policy must not be read when invokerIamDisabled is set")
			}
			_, _ = w.Write([]byte(`{"ingress":"INGRESS_TRAFFIC_ALL","invokerIamDisabled":true}`))
		}))
	defer srv.Close()
	t.Setenv("GROUNDHOLD_GCP_ACCESS_TOKEN", "test-token")
	d := NewDriver("acme-prod")
	d.RunBaseURL = srv.URL
	obs, _, err := d.observeCloudRun("web", "cloudrun:acme-prod:europe-central2:web-1")
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, o := range obs {
		if o.Path == "network.publicExposure" {
			found = true
			if o.Value != true {
				t.Fatalf("invokerIamDisabled + ingress ALL must be public, got %v", o.Value)
			}
		}
	}
	if !found {
		t.Fatal("publicExposure must be observed (measured) for a public-mode service")
	}
}
