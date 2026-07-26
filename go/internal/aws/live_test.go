package aws

import (
	"os"
	"testing"
)

// TestLiveCallerIdentity is a LIVE recon test: it runs only when real AWS
// credentials are in the environment (skipped in make check). It proves the
// SigV4 signer works against real AWS and reports the acting identity.
func TestLiveCallerIdentity(t *testing.T) {
	if os.Getenv("AWS_ACCESS_KEY_ID") == "" {
		t.Skip("no live AWS credentials; skipping")
	}
	region := os.Getenv("AWS_DEFAULT_REGION")
	if region == "" {
		region = "eu-central-1"
	}
	d := NewDriver(region)
	account, arn, err := d.CallerIdentity()
	if err != nil {
		t.Fatalf("STS GetCallerIdentity failed: %v", err)
	}
	t.Logf("LIVE AWS identity: account=%s arn=%s", account, arn)
	if account == "" {
		t.Fatal("no account returned")
	}
}
