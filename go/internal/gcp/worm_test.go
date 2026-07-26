package gcp

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// retention.locked (Slice B): GCS WORM via buckets.lockRetentionPolicy — a
// one-way lock of the SAME bucket, create-time. It presupposes
// retention.minimum (the floor being locked); the lock without a floor refuses.

func TestBuildGCSRetentionLockedRequiresMinimum(t *testing.T) {
	a := gcsAttrs()
	a["retention.locked"] = true
	if _, err := BuildGCSCreateRequest("p", "e", "assets", a, nil, 1); err == nil {
		t.Fatal("retention.locked without retention.minimum must be refused (cannot lock nothing)")
	}
}

func TestBuildGCSRetentionLockedWithMinimum(t *testing.T) {
	a := gcsAttrs()
	a["retention.locked"] = true
	a["retention.minimum"] = "3650d"
	req, err := BuildGCSCreateRequest("p", "e", "assets", a, nil, 1)
	if err != nil {
		t.Fatal(err)
	}
	rp, ok := req.Body["retentionPolicy"].(map[string]any)
	if !ok || rp["retentionPeriod"] == nil {
		t.Fatalf("a locked bucket must carry a retentionPolicy to lock: %+v", req.Body)
	}
}

func TestCreateGCSLocksRetention(t *testing.T) {
	locked := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := r.URL.Path
		switch {
		case r.Method == "POST" && strings.HasSuffix(p, "/lockRetentionPolicy"):
			locked = true
			_, _ = w.Write([]byte(`{"name":"the-bucket","metageneration":"2",` +
				`"retentionPolicy":{"retentionPeriod":"315360000000","isLocked":true}}`))
		case r.Method == "POST" && strings.HasSuffix(p, "/b"):
			_, _ = w.Write([]byte(`{"name":"the-bucket"}`))
		case r.Method == "GET":
			il := "false"
			if locked {
				il = "true"
			}
			_, _ = w.Write([]byte(`{"name":"the-bucket","metageneration":"1",` +
				`"retentionPolicy":{"retentionPeriod":"315360000000","isLocked":` + il + `}}`))
		default:
			w.WriteHeader(500)
		}
	}))
	defer srv.Close()
	d := gcsDriver(t, srv)
	a := map[string]any{"location.region": "europe-central2", "encryption.atRest": true,
		"service.managed": true, "retention.minimum": "3650d", "retention.locked": true}
	res := d.createGCS("assets", "prod", a, nil, 1)
	if res.Status != "succeeded" {
		t.Fatalf("locked create must succeed: %+v", res)
	}
	if !locked {
		t.Fatal("lockRetentionPolicy was never issued")
	}
}

func TestObserveGCSRetentionLocked(t *testing.T) {
	t.Setenv("GROUNDHOLD_GCP_ACCESS_TOKEN", "test-token")
	srv := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte(`{"location":"EUROPE-CENTRAL2","labels":{"groundhold-capability":"assets"},` +
				`"iamConfiguration":{"publicAccessPrevention":"enforced","uniformBucketLevelAccess":{"enabled":true}},` +
				`"retentionPolicy":{"retentionPeriod":"315360000000","isLocked":true}}`))
		}))
	defer srv.Close()
	d := NewDriver("acme-prod")
	d.GcsBaseURL = srv.URL
	d.ProjNumber = "111"
	obs, _, err := d.observeGCS("assets", "gcs:acme-prod:pv-assets-abcd1234")
	if err != nil {
		t.Fatal(err)
	}
	got, has := false, false
	for _, o := range obs {
		if o.Path == "retention.locked" {
			has = true
			got, _ = o.Value.(bool)
		}
	}
	if !has || !got {
		t.Fatalf("a locked retention policy must observe retention.locked=true (has=%v got=%v)", has, got)
	}
}
