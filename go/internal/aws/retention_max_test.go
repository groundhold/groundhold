package aws

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// retention.maximum (D87 depth): S3 lifecycle expiration. Builder emits a
// whole-day Expiration rule (floored, since it is a ceiling); observe reverse-maps
// it; sub-day is refused (Expiration.Days is whole days).

func TestBuildS3RetentionMaximum(t *testing.T) {
	a := s3Attrs()
	a["retention.maximum"] = "90d"
	plan, err := BuildS3Requests("000000000000", "prod", "assets", a, nil, 1)
	if err != nil {
		t.Fatal(err)
	}
	if plan.Lifecycle == nil {
		t.Fatal("retention.maximum must emit a lifecycle rule")
	}
	if !strings.Contains(plan.Lifecycle.Body, "<Days>90</Days>") {
		t.Fatalf("lifecycle body missing 90-day expiry: %s", plan.Lifecycle.Body)
	}
	if plan.Lifecycle.Path != "/?lifecycle" {
		t.Fatalf("lifecycle path = %q", plan.Lifecycle.Path)
	}
}

func TestBuildS3RetentionMaximumFloorsToDays(t *testing.T) {
	a := s3Attrs()
	a["retention.maximum"] = "90.5d" // a ceiling rounds DOWN to whole days
	plan, err := BuildS3Requests("000000000000", "prod", "assets", a, nil, 1)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(plan.Lifecycle.Body, "<Days>90</Days>") {
		t.Fatalf("ceiling must floor 90d12h -> 90 days: %s", plan.Lifecycle.Body)
	}
}

func TestBuildS3RetentionMaximumSubDayRefused(t *testing.T) {
	a := s3Attrs()
	a["retention.maximum"] = "12h"
	if _, err := BuildS3Requests("000000000000", "prod", "assets", a, nil, 1); err == nil {
		t.Fatal("sub-day retention.maximum must be refused")
	}
}

func TestObserveS3RetentionMaximum(t *testing.T) {
	t.Setenv("AWS_ACCESS_KEY_ID", "AKID")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "secret")
	srv := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.RawQuery {
			case "versioning":
				_, _ = w.Write([]byte(`<VersioningConfiguration><Status>Suspended</Status></VersioningConfiguration>`))
			case "lifecycle":
				_, _ = w.Write([]byte(`<LifecycleConfiguration><Rule><ID>x</ID><Status>Enabled</Status>` +
					`<Expiration><Days>365</Days></Expiration></Rule></LifecycleConfiguration>`))
			case "policyStatus":
				w.WriteHeader(404)
				_, _ = w.Write([]byte("<Error><Code>NoSuchBucketPolicy</Code></Error>"))
			default:
				w.WriteHeader(404)
			}
		}))
	defer srv.Close()
	d := s3TestDriver(t, srv)
	obs, _, err := d.observeS3("assets", "s3:eu-central-1:pv-assets-abcd1234")
	if err != nil {
		t.Fatal(err)
	}
	got := ""
	for _, o := range obs {
		if o.Path == "retention.maximum" {
			got, _ = o.Value.(string)
		}
	}
	if got != "365d" {
		t.Fatalf("retention.maximum = %q, want 365d", got)
	}
}
