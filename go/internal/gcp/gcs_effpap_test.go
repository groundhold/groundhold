package gcp

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// D238: GCS publicExposure must fold in the EFFECTIVE org-policy PAP. A bucket
// with PAP="inherited" + UBLA on + a stale allUsers binding is reported public
// ONLY when the effective org policy does not enforce PAP; a positively enforced
// org policy downgrades to private (measured), and an unreadable org policy keeps
// the conservative public verdict (never a fabricated private).

const effPapBucket = `{"location":"EUROPE-CENTRAL2","metageneration":"3","projectNumber":"111",` +
	`"iamConfiguration":{"publicAccessPrevention":"inherited",` +
	`"uniformBucketLevelAccess":{"enabled":true}}}`

// effPapServer routes buckets.get, the bucket IAM policy, and the org-policy
// getEffectivePolicy. orgStatus!=200 makes the org read unreadable; orgBody is
// the getEffectivePolicy JSON otherwise. iamHasAllUsers controls the binding;
// iamReadable=false makes the IAM policy read fail (the rescue path).
func effPapServer(t *testing.T, iamHasAllUsers, iamReadable bool, orgStatus int, orgBody string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := r.URL.Path
		switch {
		case strings.Contains(p, ":getEffectivePolicy"):
			if orgStatus != 0 && orgStatus != 200 {
				w.WriteHeader(orgStatus)
				return
			}
			_, _ = w.Write([]byte(orgBody))
		case strings.HasSuffix(p, "/iam") && r.Method == "GET":
			if !iamReadable {
				w.WriteHeader(403)
				return
			}
			if iamHasAllUsers {
				_, _ = w.Write([]byte(`{"etag":"e1","version":3,"bindings":[` +
					`{"role":"roles/storage.objectViewer","members":["allUsers"]}]}`))
			} else {
				_, _ = w.Write([]byte(`{"etag":"e1","version":3,"bindings":[]}`))
			}
		case r.Method == "GET": // buckets.get
			_, _ = w.Write([]byte(effPapBucket))
		default:
			w.WriteHeader(500)
		}
	}))
}

func effPapDriver(t *testing.T, srv *httptest.Server) *Driver {
	t.Helper()
	t.Setenv("GROUNDHOLD_GCP_ACCESS_TOKEN", "test-token")
	d := NewDriver("acme-prod")
	d.GcsBaseURL = srv.URL
	d.OrgPolicyBaseURL = srv.URL
	d.ProjNumber = "111"
	return d
}

// helper: find network.publicExposure in an observe result.
func findExposure(t *testing.T, d *Driver) (val any, present bool, diags []string) {
	t.Helper()
	o, dg, err := d.observeGCS("assets", "gcs:acme-prod:the-bucket")
	if err != nil {
		t.Fatal(err)
	}
	for _, ob := range o {
		if ob.Path == "network.publicExposure" {
			return ob.Value, true, dg
		}
	}
	return nil, false, dg
}

func TestEffPAPEnforcedDowngradesToPrivate(t *testing.T) {
	// allUsers binding present, but the org policy positively enforces PAP.
	srv := effPapServer(t, true, true, 200, `{"spec":{"rules":[{"enforce":true}]}}`)
	defer srv.Close()
	val, present, diags := findExposure(t, effPapDriver(t, srv))
	if !present || val != false {
		t.Fatalf("org-enforced PAP must downgrade publicExposure to false, got present=%v val=%v", present, val)
	}
	var masked bool
	for _, dg := range diags {
		if strings.Contains(dg, "masked") {
			masked = true
		}
	}
	if !masked {
		t.Errorf("a downgrade must warn that the allUsers binding is masked, got %v", diags)
	}
}

func TestEffPAPNotEnforcedStaysPublic(t *testing.T) {
	for _, body := range []string{
		`{"spec":{"rules":[{"enforce":false}]}}`, // explicit not-enforced
		`{"spec":{}}`,                            // empty spec = not enforced anywhere
		`{}`,                                     // no spec at all
	} {
		srv := effPapServer(t, true, true, 200, body)
		val, present, _ := findExposure(t, effPapDriver(t, srv))
		srv.Close()
		if !present || val != true {
			t.Errorf("not-enforced org policy (%s) must keep publicExposure=true, got present=%v val=%v", body, present, val)
		}
	}
}

func TestEffPAPUnreadableStaysConservativePublic(t *testing.T) {
	for _, st := range []int{403, 404, 500, 503} {
		srv := effPapServer(t, true, true, st, "")
		val, present, diags := findExposure(t, effPapDriver(t, srv))
		srv.Close()
		if !present || val != true {
			t.Errorf("unreadable org policy (HTTP %d) must keep conservative publicExposure=true, got present=%v val=%v", st, present, val)
		}
		var warned bool
		for _, dg := range diags {
			// the diagnostic must name the org-policy read AND why it gave no
			// answer (D296: a diagnosis, not the bare word "unreadable").
			if strings.Contains(dg, "effective org-policy") && strings.Contains(dg, "gave no answer") {
				warned = true
			}
		}
		if !warned {
			t.Errorf("HTTP %d: want an org-policy-gave-no-answer diagnostic, got %v", st, diags)
		}
	}
}

func TestEffPAPPrivateBucketMakesNoOrgCall(t *testing.T) {
	// no allUsers binding: publicExposure=false WITHOUT ever querying org policy.
	var orgCalls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := r.URL.Path
		switch {
		case strings.Contains(p, ":getEffectivePolicy"):
			orgCalls++
			_, _ = w.Write([]byte(`{"spec":{"rules":[{"enforce":true}]}}`))
		case strings.HasSuffix(p, "/iam") && r.Method == "GET":
			_, _ = w.Write([]byte(`{"etag":"e1","version":3,"bindings":[]}`))
		default:
			_, _ = w.Write([]byte(effPapBucket))
		}
	}))
	defer srv.Close()
	val, present, _ := findExposure(t, effPapDriver(t, srv))
	if !present || val != false {
		t.Fatalf("a non-public bucket must be publicExposure=false, got present=%v val=%v", present, val)
	}
	if orgCalls != 0 {
		t.Errorf("org policy must be queried lazily (never for a private bucket), got %d calls", orgCalls)
	}
}

func TestEffPAPRescueOnUnreadableIAM(t *testing.T) {
	// the bucket IAM policy is unreadable, but the org policy positively enforces
	// PAP: an honesty gain — publicExposure=false rather than no observation.
	srv := effPapServer(t, false, false, 200, `{"spec":{"rules":[{"enforce":true}]}}`)
	defer srv.Close()
	val, present, _ := findExposure(t, effPapDriver(t, srv))
	if !present || val != false {
		t.Fatalf("rescue: unreadable IAM + org-enforced PAP must yield publicExposure=false, got present=%v val=%v", present, val)
	}
}
