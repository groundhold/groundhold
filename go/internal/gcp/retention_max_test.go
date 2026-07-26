package gcp

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// retention.maximum (D87 depth): GCS lifecycle Delete-by-age. Builder emits a
// whole-day rule (floored ceiling); observe reverse-maps it.

func TestBuildGCSRetentionMaximum(t *testing.T) {
	attrs := map[string]any{
		"location.region":   "europe-central2",
		"retention.maximum": "180d",
		"service.managed":   true,
		"encryption.atRest": true,
	}
	req, err := BuildGCSCreateRequest("acme-prod", "prod", "assets", attrs, nil, 1)
	if err != nil {
		t.Fatal(err)
	}
	lc, ok := req.Body["lifecycle"].(map[string]any)
	if !ok {
		t.Fatalf("no lifecycle in body: %+v", req.Body)
	}
	rules := lc["rule"].([]any)
	rule := rules[0].(map[string]any)
	if rule["action"].(map[string]any)["type"] != "Delete" {
		t.Fatalf("lifecycle action not Delete: %+v", rule)
	}
	if age := rule["condition"].(map[string]any)["age"].(int64); age != 180 {
		t.Fatalf("lifecycle age = %d, want 180", age)
	}
}

func TestBuildGCSRetentionMaximumSubDayRefused(t *testing.T) {
	attrs := map[string]any{
		"location.region":   "europe-central2",
		"retention.maximum": "6h",
		"service.managed":   true,
		"encryption.atRest": true,
	}
	if _, err := BuildGCSCreateRequest("acme-prod", "prod", "assets", attrs, nil, 1); err == nil {
		t.Fatal("sub-day retention.maximum must be refused")
	}
}

func TestObserveGCSRetentionMaximum(t *testing.T) {
	t.Setenv("GROUNDHOLD_GCP_ACCESS_TOKEN", "test-token")
	srv := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte(`{"location":"EUROPE-CENTRAL2","labels":{"groundhold-capability":"assets"},` +
				`"iamConfiguration":{"publicAccessPrevention":"enforced","uniformBucketLevelAccess":{"enabled":true}},` +
				`"lifecycle":{"rule":[{"action":{"type":"Delete"},"condition":{"age":365}}]}}`))
		}))
	defer srv.Close()
	d := NewDriver("acme-prod")
	d.GcsBaseURL = srv.URL
	d.ProjNumber = "111"
	obs, _, err := d.observeGCS("assets", "gcs:acme-prod:pv-assets-abcd1234")
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
