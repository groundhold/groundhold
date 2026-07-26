package aws

import (
	"os"
	"testing"
	"time"
)

// TestLiveSNSRoundtrip is a LIVE create->observe->delete against real SNS, gated
// on GROUNDHOLD_LIVE_SNS=1 (never runs in make check). SNS topics are free-tier and
// synchronous; the topic is always deleted, even on a mid-test failure.
func TestLiveSNSRoundtrip(t *testing.T) {
	if os.Getenv("GROUNDHOLD_LIVE_SNS") != "1" || os.Getenv("AWS_ACCESS_KEY_ID") == "" {
		t.Skip("live SNS roundtrip disabled (set GROUNDHOLD_LIVE_SNS=1 with real creds)")
	}
	region := os.Getenv("AWS_DEFAULT_REGION")
	if region == "" {
		region = "eu-central-1"
	}
	d := NewDriver(region)
	d.Now = time.Now
	account, _, err := d.CallerIdentity()
	if err != nil {
		t.Fatalf("STS: %v", err)
	}

	attrs := map[string]any{
		"location.region":        region,
		"network.publicExposure": false,
		"encryption.atRest":      true, // alias/aws/sns provider-default key
		"service.managed":        true,
	}
	res := d.createSNS(region, account, "livetest", "events", attrs, nil, 1)
	t.Logf("create: %+v", res)
	if res.Status != "succeeded" {
		t.Fatalf("live create must succeed, got %+v", res)
	}
	pid := res.ProviderID
	defer func() {
		del := d.deleteSNS("events", "livetest", pid)
		t.Logf("delete: %+v", del)
		if del.Status != "succeeded" {
			t.Errorf("cleanup delete did not succeed: %+v", del)
		}
	}()

	obs, notes, err := d.observeSNS("events", pid)
	if err != nil {
		t.Fatalf("observe: %v (notes=%v)", err, notes)
	}
	got := map[string]any{}
	for _, o := range obs {
		got[o.Path] = o.Value
	}
	t.Logf("observe: %+v", got)
	if got["network.publicExposure"] != false {
		t.Errorf("must not be public: %v", got["network.publicExposure"])
	}
	if got["encryption.atRest"] != true {
		t.Errorf("must be encrypted (alias/aws/sns): %v", got["encryption.atRest"])
	}
}
