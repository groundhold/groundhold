package gcp

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"groundhold/internal/provider"
)

type gcpImageServer struct {
	getStatus    int
	getBody      string
	policyStatus int
	policyBody   string
	paths        []string
}

func (s *gcpImageServer) handler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		s.paths = append(s.paths, r.URL.Path)
		if strings.Contains(r.URL.Path, "getIamPolicy") {
			w.WriteHeader(s.policyStatus)
			_, _ = w.Write([]byte(s.policyBody))
			return
		}
		w.WriteHeader(s.getStatus)
		_, _ = w.Write([]byte(s.getBody))
	}
}

func gcpImageDriver(t *testing.T, s *gcpImageServer) (*Driver, func()) {
	t.Helper()
	t.Setenv("GROUNDHOLD_GCP_ACCESS_TOKEN", "test-token")
	srv := httptest.NewServer(s.handler())
	d := NewDriver("acme-prod")
	d.ComputeBaseURL = srv.URL
	d.PollInterval = time.Millisecond
	d.PollTimeout = 50 * time.Millisecond
	return d, srv.Close
}

const gcpImageJSON = `{"name":"base-2026-07","status":"READY",
"storageLocations":["eu"],
"imageEncryptionKey":{"kmsKeyName":"projects/acme-prod/locations/eu/keyRings/r/cryptoKeys/k"}}`

const gcpImagePID = "gcpimage:acme-prod:base-2026-07"

// The witness predicate is the design decision, and BOTH halves matter: too broad
// and groundhold silently creates nothing on GCP at all.
func TestGCPWitnessPredicateIsPerServiceAndNarrow(t *testing.T) {
	if provider.CanAuthor("gcp", "computeimage") {
		t.Error("gcp/computeimage reports as authorable — the compiler would emit a create " +
			"the driver refuses, the exact lie D177 exists to prevent")
	}
	for _, svc := range []string{"gce", "pd", "cloudsql", "gcs", "vpc", "gke"} {
		if !provider.CanAuthor("gcp", svc) {
			t.Errorf("gcp/%s stopped being authorable — the predicate is too broad", svc)
		}
	}
}

func TestObserveGCPImage(t *testing.T) {
	s := &gcpImageServer{getStatus: 200, getBody: gcpImageJSON,
		policyStatus: 200, policyBody: `{"bindings":[{"role":"roles/compute.imageUser","members":["user:a@b.c"]}]}`}
	d, done := gcpImageDriver(t, s)
	defer done()

	obs, unread, err := d.observeGCPImage("base-image", gcpImagePID)
	if err != nil {
		t.Fatalf("observe: %v", err)
	}
	got := map[string]any{}
	for _, o := range obs {
		got[o.Path] = o.Value
	}
	want := map[string]any{
		"location.region":                "eu",
		"network.publicExposure":         false,
		"encryption.atRest":              true,
		"encryption.customerManagedKeys": true,
		"service.managed":                true,
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s = %v, want %v", k, got[k], v)
		}
	}
	var saidProv bool
	for _, u := range unread {
		if strings.Contains(u, "sourceProvenance") {
			saidProv = true
		}
	}
	if !saidProv {
		t.Error("sourceProvenance is neither observed nor reported unread")
	}
	if _, ok := got["sourceProvenance"]; ok {
		t.Error("sourceProvenance was observed — a Compute image carries no readable attestation, " +
			"so any value here is invented")
	}
}

// A public image is the question the type exists to answer, and either binding
// answers it: allUsers or allAuthenticatedUsers both mean a stranger can boot it.
func TestObserveGCPImagePublicSharing(t *testing.T) {
	for _, member := range []string{"allUsers", "allAuthenticatedUsers"} {
		s := &gcpImageServer{getStatus: 200, getBody: gcpImageJSON, policyStatus: 200,
			policyBody: `{"bindings":[{"role":"roles/compute.imageUser","members":["` + member + `"]}]}`}
		d, done := gcpImageDriver(t, s)
		obs, _, err := d.observeGCPImage("base-image", gcpImagePID)
		done()
		if err != nil {
			t.Fatalf("%s: observe: %v", member, err)
		}
		var seen bool
		for _, o := range obs {
			if o.Path == "network.publicExposure" {
				seen = true
				if o.Value != true {
					t.Errorf("%s: publicExposure = %v, want true", member, o.Value)
				}
			}
		}
		if !seen {
			t.Errorf("%s: publicExposure was not observed", member)
		}
	}
}

// A silent false here passes an "is our base image private?" constraint on an
// image the whole internet can launch.
func TestObserveGCPImageUnreadablePolicyIsUnreadNotFalse(t *testing.T) {
	s := &gcpImageServer{getStatus: 200, getBody: gcpImageJSON, policyStatus: 403, policyBody: `{}`}
	d, done := gcpImageDriver(t, s)
	defer done()

	obs, unread, err := d.observeGCPImage("base-image", gcpImagePID)
	if err != nil {
		t.Fatalf("observe: %v", err)
	}
	for _, o := range obs {
		if o.Path == "network.publicExposure" {
			t.Errorf("publicExposure was observed as %v from an unreadable policy", o.Value)
		}
	}
	var said bool
	for _, u := range unread {
		if strings.Contains(u, "sharing unread") && strings.Contains(u, "getIamPolicy") {
			said = true
		}
	}
	if !said {
		t.Errorf("diagnostics %v do not name the failed call", unread)
	}
}

func TestObserveGCPImageMissingIsNotAnError(t *testing.T) {
	s := &gcpImageServer{getStatus: 404, getBody: `{}`}
	d, done := gcpImageDriver(t, s)
	defer done()
	obs, unread, err := d.observeGCPImage("base-image", gcpImagePID)
	if err != nil {
		t.Fatalf("an absent image produced an error: %v", err)
	}
	if len(obs) != 0 || len(unread) == 0 {
		t.Errorf("obs = %v, unread = %v", obs, unread)
	}
}

func TestObserveGCPImageUnreadableIsAnError(t *testing.T) {
	s := &gcpImageServer{getStatus: 500, getBody: `{}`}
	d, done := gcpImageDriver(t, s)
	defer done()
	obs, _, err := d.observeGCPImage("base-image", gcpImagePID)
	if err == nil {
		t.Fatal("a 500 produced no error")
	}
	if len(obs) != 0 {
		t.Errorf("observations %v despite the failed read", obs)
	}
	if !strings.Contains(err.Error(), "images.get") {
		t.Errorf("diagnostic %q does not name the call", err)
	}
}

func TestDiscoverGCPImages(t *testing.T) {
	s := &gcpImageServer{getStatus: 200, getBody: `{"items":[{"name":"base-2026-07"}]}`,
		policyStatus: 200, policyBody: `{"bindings":[]}`}
	d, done := gcpImageDriver(t, s)
	defer done()

	got, _, err := d.discoverGCPImages("europe-west1")
	if err != nil {
		t.Fatalf("discover: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("discovered %d images, want 1", len(got))
	}
	if got[0].ResourceType != "capability.compute.image" || got[0].ProviderID != gcpImagePID {
		t.Errorf("discovered %+v", got[0])
	}
}

func TestGCPImageRefusesEveryAuthoringPath(t *testing.T) {
	s := &gcpImageServer{getStatus: 200, getBody: gcpImageJSON, policyStatus: 200, policyBody: `{}`}
	d, done := gcpImageDriver(t, s)
	defer done()

	if err := d.Validate("computeimage", "base-image", "production", nil, nil, 1); err == nil {
		t.Error("Validate accepted a create for a witness service")
	} else if !strings.Contains(err.Error(), "WITNESS") {
		t.Errorf("Validate refusal = %q", err)
	}
	create := d.Create("computeimage", "base-image", "production", nil, nil, "k", 1)
	if create.Status != "failed" || !strings.Contains(create.Reason, "WITNESS") {
		t.Errorf("Create = %q/%q", create.Status, create.Reason)
	}
	del := d.Delete("computeimage", "base-image", "production", gcpImagePID, "k")
	if del.Status != "failed" || !strings.Contains(del.Reason, "WITNESS") {
		t.Errorf("Delete = %q/%q", del.Status, del.Reason)
	}
}

func TestClassifyComputeImageChange(t *testing.T) {
	for _, path := range []string{"location.region", "network.publicExposure",
		"encryption.atRest", "encryption.customerManagedKeys", "sourceProvenance", "service.managed"} {
		class, why := classifyComputeImageChange(path)
		if class != "unsupported" || !strings.Contains(why, "witnessed") {
			t.Errorf("%s classified %q/%q", path, class, why)
		}
	}
	if class, _ := classifyComputeImageChange("something.invented"); class != "" {
		t.Errorf("an unknown path classified %q", class)
	}
}

// The providerId carries NO region: an image is global, and inventing one would
// make two names for one image.
func TestSplitGCPImageProviderID(t *testing.T) {
	project, name, err := splitGCPImageProviderID(gcpImagePID)
	if err != nil {
		t.Fatalf("split: %v", err)
	}
	if project != "acme-prod" || name != "base-2026-07" {
		t.Errorf("split = %q/%q", project, name)
	}
	for _, bad := range []string{
		"gce:acme-prod:base-2026-07",
		"gcpimage:acme-prod",
		"gcpimage::base",
		"gcpimage:acme-prod:../../etc/passwd",
	} {
		if _, _, err := splitGCPImageProviderID(bad); err == nil {
			t.Errorf("%q was accepted", bad)
		}
	}
}
