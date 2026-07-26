package aws

import (
	"os"
	"testing"
	"time"
)

// TestLiveSQSRoundtrip is a LIVE create->observe->delete against real SQS, gated
// on GROUNDHOLD_LIVE_SQS=1 (never runs in make check). SQS queues are free-tier and
// synchronous; the queue is always deleted, even on a mid-test failure.
func TestLiveSQSRoundtrip(t *testing.T) {
	if os.Getenv("GROUNDHOLD_LIVE_SQS") != "1" || os.Getenv("AWS_ACCESS_KEY_ID") == "" {
		t.Skip("live SQS roundtrip disabled (set GROUNDHOLD_LIVE_SQS=1 with real creds)")
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
		"delivery.guarantee":     "exactly-once", // FIFO queue
		"ordering.enabled":       true,
		"retention.minimum":      "1d",
		"encryption.atRest":      true, // SSE-SQS managed
		"network.publicExposure": false,
		"service.managed":        true,
	}
	res := d.createSQS(region, account, "livetest", "orders", attrs, nil, 1)
	t.Logf("create: %+v", res)
	if res.Status != "succeeded" {
		t.Fatalf("live create must succeed, got %+v", res)
	}
	pid := res.ProviderID
	defer func() {
		del := d.deleteSQS("orders", "livetest", pid)
		t.Logf("delete: %+v", del)
		if del.Status != "succeeded" {
			t.Errorf("cleanup delete did not succeed: %+v", del)
		}
	}()

	obs, notes, err := d.observeSQS("orders", pid)
	if err != nil {
		t.Fatalf("observe: %v (notes=%v)", err, notes)
	}
	got := map[string]any{}
	for _, o := range obs {
		got[o.Path] = o.Value
	}
	t.Logf("observe: %+v", got)
	if got["ordering.enabled"] != true {
		t.Errorf("FIFO queue must observe ordering.enabled=true: %v", got["ordering.enabled"])
	}
	if got["network.publicExposure"] != false {
		t.Errorf("must not be public: %v", got["network.publicExposure"])
	}
}
