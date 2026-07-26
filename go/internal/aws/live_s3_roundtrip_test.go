package aws

import (
	"os"
	"testing"
	"time"
)

// TestLiveS3Roundtrip is a LIVE create->observe->delete against real S3, gated on
// GROUNDHOLD_LIVE_S3=1 (never runs in make check). It proves the refactored shells
// (groundholdTagsMatch rename, parseS3Tags signature) did not break the happy path,
// then cleans up the bucket it created.
func TestLiveS3Roundtrip(t *testing.T) {
	if os.Getenv("GROUNDHOLD_LIVE_S3") != "1" || os.Getenv("AWS_ACCESS_KEY_ID") == "" {
		t.Skip("live S3 roundtrip disabled (set GROUNDHOLD_LIVE_S3=1 with real creds)")
	}
	region := os.Getenv("AWS_DEFAULT_REGION")
	if region == "" {
		region = "eu-central-1"
	}
	d := NewDriver(region)
	d.Now = time.Now
	attrs := map[string]any{
		"location.region":        region,
		"durability.class":       "regional",
		"versioning.enabled":     true,
		"network.publicExposure": false,
		"encryption.atRest":      true,
		"service.managed":        true,
	}
	account, _, err := d.CallerIdentity()
	if err != nil {
		t.Fatalf("STS: %v", err)
	}

	res := d.createS3(account, "prod", "assets", attrs, nil, 99)
	t.Logf("create: %+v", res)
	if res.Status != "succeeded" {
		t.Fatalf("live create must succeed, got %+v", res)
	}
	pid := res.ProviderID

	// always clean up
	defer func() {
		del := d.deleteS3("assets", "prod", pid)
		t.Logf("delete: %+v", del)
		if del.Status != "succeeded" {
			t.Errorf("cleanup delete did not succeed: %+v", del)
		}
	}()

	obs, notes, err := d.observeS3("assets", pid)
	if err != nil {
		t.Fatalf("observe: %v (notes=%v)", err, notes)
	}
	got := map[string]any{}
	for _, o := range obs {
		got[o.Path] = o.Value
	}
	t.Logf("observe: %+v", got)
	if got["location.region"] != region {
		t.Errorf("region mismatch: %v", got["location.region"])
	}
	if got["versioning.enabled"] != true {
		t.Errorf("versioning should be enabled: %v", got["versioning.enabled"])
	}
	if got["network.publicExposure"] != false {
		t.Errorf("should not be public: %v", got["network.publicExposure"])
	}
}
