package gcp

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func logBucketAttrs() map[string]any {
	return map[string]any{
		"location.region": "us-central1",
		"retention.days":  "90d",
		"service.managed": true,
	}
}

func TestBuildLogBucketHonors(t *testing.T) {
	p, err := BuildLogBucket("acme-prod", "prod", "flowlogs", logBucketAttrs(), nil, 1)
	if err != nil {
		t.Fatal(err)
	}
	if p.Location != "us-central1" || p.RetentionDays != 90 ||
		p.Description != "groundhold-managed flowlogs (prod)" {
		t.Fatalf("plan = %+v", p)
	}
	if !strings.HasPrefix(p.BucketID, "flowlogs-prod-") {
		t.Fatalf("bucket id = %q", p.BucketID)
	}
	body := p.createBody()
	if body["retentionDays"] != 90 || body["description"] != p.Description {
		t.Fatalf("create body = %+v", body)
	}
	if _, ok := body["cmekSettings"]; ok {
		t.Fatalf("no-CMEK body must not carry cmekSettings: %+v", body)
	}
}

func TestBuildLogBucketRetentionRoundsUp(t *testing.T) {
	// a retention FLOOR must never be under-delivered: 90.5 days rounds UP to 91.
	a := logBucketAttrs()
	a["retention.days"] = "2172h" // 90.5 days
	p, err := BuildLogBucket("acme-prod", "prod", "flowlogs", a, nil, 1)
	if err != nil {
		t.Fatal(err)
	}
	if p.RetentionDays != 91 {
		t.Fatalf("90.5d must round UP to 91, got %d", p.RetentionDays)
	}
}

func TestBuildLogBucketCMEK(t *testing.T) {
	a := logBucketAttrs()
	a["encryption.customerManagedKeys"] = true
	// CMEK=true without a key operand is a refusal (the default key does not satisfy it).
	if _, err := BuildLogBucket("acme-prod", "prod", "flowlogs", a, nil, 1); err == nil {
		t.Fatal("CMEK without implementation.kms_key_name must refuse")
	}
	key := "projects/acme-prod/locations/us-central1/keyRings/r/cryptoKeys/k"
	p, err := BuildLogBucket("acme-prod", "prod", "flowlogs", a,
		map[string]any{"kms_key_name": key}, 1)
	if err != nil {
		t.Fatal(err)
	}
	cmek, ok := p.createBody()["cmekSettings"].(map[string]any)
	if !ok || cmek["kmsKeyName"] != key {
		t.Fatalf("cmekSettings = %+v", p.createBody()["cmekSettings"])
	}
}

func TestBuildLogBucketPinnedID(t *testing.T) {
	p, err := BuildLogBucket("acme-prod", "prod", "flowlogs", logBucketAttrs(),
		map[string]any{"log_bucket_id": "eks-control-plane"}, 1)
	if err != nil {
		t.Fatal(err)
	}
	if p.BucketID != "eks-control-plane" {
		t.Fatalf("pinned operand id ignored: %q", p.BucketID)
	}
}

func TestBuildLogBucketRefusals(t *testing.T) {
	cases := map[string]map[string]any{
		"no-location":      {"location.region": ""},
		"bad-location":     {"location.region": "US Central!!"},
		"retention-number": {"retention.days": "90"}, // not a duration (bare number)
		"zero-retention":   {"retention.days": "0s"}, // rounds to zero whole days
		"unmanaged":        {"service.managed": false},
		"unknown-attr":     {"log.format": "json"},
	}
	for name, extra := range cases {
		a := logBucketAttrs()
		for k, v := range extra {
			a[k] = v
		}
		if _, err := BuildLogBucket("acme-prod", "prod", "flowlogs", a, nil, 1); err == nil {
			t.Errorf("%s: expected refusal, got none", name)
		}
	}
}

func TestClassifyLogBucketChange(t *testing.T) {
	for path, want := range map[string]string{
		"retention.days":                 "mutable",
		"encryption.customerManagedKeys": "mutable",
		"location.region":                "immutable",
		"service.managed":                "unsupported",
		"cost.monthly":                   "unsupported",
	} {
		if got, _ := classifyLogBucketChange(path); got != want {
			t.Errorf("classify %s = %q, want %q", path, got, want)
		}
	}
}

// logBucketDoc for the fake, controllable per field.
type fakeLogBucket struct {
	description   string
	retentionDays int
	locked        bool
	cmekKey       string
}

func logBucketServer(t *testing.T, b fakeLogBucket, patched *map[string]string) *httptest.Server {
	t.Helper()
	docJSON := func(loc, id string) string {
		cmek := ""
		if b.cmekKey != "" {
			cmek = `,"cmekSettings":{"kmsKeyName":"` + b.cmekKey + `"}`
		}
		return `{"name":"projects/acme-prod/locations/` + loc + `/buckets/` + id + `",` +
			`"description":"` + b.description + `","retentionDays":` +
			itoa(b.retentionDays) + `,"locked":` + btoa(b.locked) + cmek + `}`
	}
	return httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			switch {
			case r.Method == "POST" && strings.HasSuffix(r.URL.Path, "/buckets"):
				_, _ = w.Write([]byte(docJSON("us-central1", r.URL.Query().Get("bucketId"))))
			case r.Method == "PATCH":
				if patched != nil {
					*patched = map[string]string{"updateMask": r.URL.Query().Get("updateMask")}
				}
				_, _ = w.Write([]byte(`{"name":"x"}`))
			case r.Method == "DELETE":
				w.WriteHeader(200)
			case r.Method == "GET" && strings.HasSuffix(r.URL.Path, "/buckets"):
				// list (locations/-)
				_, _ = w.Write([]byte(`{"buckets":[` + docJSON("us-central1", "flowlogs-prod-abc") + `]}`))
			case r.Method == "GET":
				parts := strings.Split(r.URL.Path, "/")
				_, _ = w.Write([]byte(docJSON("us-central1", parts[len(parts)-1])))
			default:
				w.WriteHeader(404)
			}
		}))
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	if neg {
		b = append([]byte{'-'}, b...)
	}
	return string(b)
}

func btoa(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

func logBucketDriver(t *testing.T, srv *httptest.Server) *Driver {
	t.Helper()
	t.Setenv("GROUNDHOLD_GCP_ACCESS_TOKEN", "test-token")
	d := NewDriver("acme-prod")
	d.LoggingBaseURL = srv.URL
	return d
}

func TestCreateObserveDeleteLogBucket(t *testing.T) {
	srv := logBucketServer(t, fakeLogBucket{
		description: "groundhold-managed flowlogs (prod)", retentionDays: 90}, nil)
	defer srv.Close()
	d := logBucketDriver(t, srv)

	res := d.createLogBucket("flowlogs", "prod", logBucketAttrs(), nil, 1)
	if res.Status != "succeeded" || !strings.HasPrefix(res.ProviderID, "gcp-logbucket:acme-prod:us-central1:") {
		t.Fatalf("create: %+v", res)
	}
	obs, _, err := d.observeLogBucket("flowlogs", res.ProviderID)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]any{}
	for _, o := range obs {
		got[o.Path] = o.Value
	}
	if got["location.region"] != "us-central1" || got["retention.days"] != "90d" ||
		got["service.managed"] != true {
		t.Fatalf("observe: %+v", got)
	}
	if del := d.deleteLogBucket("flowlogs", "prod", res.ProviderID); del.Status != "succeeded" {
		t.Fatalf("delete: %+v", del)
	}
}

func TestObserveLogBucketCMEK(t *testing.T) {
	key := "projects/acme-prod/locations/us-central1/keyRings/r/cryptoKeys/k"
	srv := logBucketServer(t, fakeLogBucket{
		description: "groundhold-managed flowlogs (prod)", retentionDays: 90, cmekKey: key}, nil)
	defer srv.Close()
	d := logBucketDriver(t, srv)
	obs, _, err := d.observeLogBucket("flowlogs", "gcp-logbucket:acme-prod:us-central1:flowlogs-prod-abc")
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, o := range obs {
		if o.Path == "encryption.customerManagedKeys" && o.Value == true {
			found = true
		}
	}
	if !found {
		t.Fatalf("a CMEK bucket must observe customerManagedKeys=true: %+v", obs)
	}
}

func TestUpdateLogBucketRetentionAndCMEK(t *testing.T) {
	var patched map[string]string
	srv := logBucketServer(t, fakeLogBucket{
		description: "groundhold-managed flowlogs (prod)", retentionDays: 90}, &patched)
	defer srv.Close()
	d := logBucketDriver(t, srv)
	pid := "gcp-logbucket:acme-prod:us-central1:flowlogs-prod-abc"

	// retention.days patch -> updateMask=retentionDays
	res := d.updateLogBucket("flowlogs", "prod", pid,
		map[string]any{"retention.days": "365d"}, nil, []string{"retention.days"})
	if res.Status != "succeeded" || patched["updateMask"] != "retentionDays" {
		t.Fatalf("retention update: res=%+v mask=%q", res, patched["updateMask"])
	}

	// CMEK patch -> updateMask=cmekSettings.kmsKeyName
	key := "projects/acme-prod/locations/us-central1/keyRings/r/cryptoKeys/k"
	res = d.updateLogBucket("flowlogs", "prod", pid,
		map[string]any{"encryption.customerManagedKeys": true},
		map[string]any{"kms_key_name": key},
		[]string{"encryption.customerManagedKeys"})
	if res.Status != "succeeded" || patched["updateMask"] != "cmekSettings.kmsKeyName" {
		t.Fatalf("cmek update: res=%+v mask=%q", res, patched["updateMask"])
	}
}

func TestUpdateLogBucketForeignRefused(t *testing.T) {
	srv := logBucketServer(t, fakeLogBucket{description: "someone else's bucket", retentionDays: 30}, nil)
	defer srv.Close()
	d := logBucketDriver(t, srv)
	res := d.updateLogBucket("flowlogs", "prod",
		"gcp-logbucket:acme-prod:us-central1:flowlogs-prod-abc",
		map[string]any{"retention.days": "365d"}, nil, []string{"retention.days"})
	if res.Status != "failed" || !strings.Contains(res.Reason, "not ours") {
		t.Fatalf("foreign bucket must refuse update, got %+v", res)
	}
}

func TestDeleteLogBucketForeignRefused(t *testing.T) {
	srv := logBucketServer(t, fakeLogBucket{description: "someone else's bucket", retentionDays: 30}, nil)
	defer srv.Close()
	d := logBucketDriver(t, srv)
	res := d.deleteLogBucket("flowlogs", "prod", "gcp-logbucket:acme-prod:us-central1:flowlogs-prod-abc")
	if res.Status != "failed" || !strings.Contains(res.Reason, "not ours") {
		t.Fatalf("foreign bucket must refuse delete, got %+v", res)
	}
}

func TestDeleteLogBucketLockedRefused(t *testing.T) {
	srv := logBucketServer(t, fakeLogBucket{
		description: "groundhold-managed flowlogs (prod)", retentionDays: 90, locked: true}, nil)
	defer srv.Close()
	d := logBucketDriver(t, srv)
	res := d.deleteLogBucket("flowlogs", "prod", "gcp-logbucket:acme-prod:us-central1:flowlogs-prod-abc")
	if res.Status != "failed" || !strings.Contains(res.Reason, "LOCKED") {
		t.Fatalf("locked bucket must refuse delete, got %+v", res)
	}
}

func TestDiscoverLogBuckets(t *testing.T) {
	srv := logBucketServer(t, fakeLogBucket{
		description: "groundhold-managed flowlogs (prod)", retentionDays: 90}, nil)
	defer srv.Close()
	d := logBucketDriver(t, srv)
	found, _, err := d.discoverLogBuckets("")
	if err != nil {
		t.Fatal(err)
	}
	if len(found) != 1 || found[0].ResourceType != "capability.monitoring.logs" ||
		found[0].ProviderID != "gcp-logbucket:acme-prod:us-central1:flowlogs-prod-abc" {
		t.Fatalf("discover: %+v", found)
	}
}

func TestSplitLogBucketProviderIDRejectsMalformed(t *testing.T) {
	for _, bad := range []string{
		"logbucket:acme-prod:us-central1:x",              // wrong prefix
		"gcp-logbucket:acme-prod:us-central1",            // too few parts
		"gcp-logbucket:acme-prod:us central1:x",          // bad location
		"gcp-logbucket:acme-prod:us-central1:../../evil", // path injection
	} {
		if _, _, _, err := splitLogBucketProviderID(bad); err == nil {
			t.Errorf("malformed providerId %q must be rejected", bad)
		}
	}
}
