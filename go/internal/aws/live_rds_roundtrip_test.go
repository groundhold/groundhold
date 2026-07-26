package aws

import (
	"crypto/rand"
	"os"
	"testing"
	"time"
)

// livePassword returns an RDS-complaint master password with no forbidden chars
// (/, @, ", space). Generated at runtime so no secret is committed; the instance
// is deleted within the test.
func livePassword(t *testing.T) string {
	t.Helper()
	const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789"
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		t.Fatalf("rand: %v", err)
	}
	for i := range b {
		b[i] = alphabet[int(b[i])%len(alphabet)]
	}
	return "Pv" + string(b) // ensures upper+lower present
}

// TestLiveRDSRoundtrip is a LIVE create->observe->delete against real RDS, gated on
// GROUNDHOLD_LIVE_RDS=1 (never runs in make check). RDS create is ASYNC and slow
// (~5-10 min to "available"), so the poll timeout is generous. deletion_protection
// is opted OFF so the driver can clean up. The instance is ALWAYS deleted, even on
// a mid-test failure, via a deferred delete keyed on the deterministic pid.
//
// Env overrides: GROUNDHOLD_LIVE_RDS_ENGINE (default postgresql/16),
// GROUNDHOLD_LIVE_RDS_SUBNET_GROUP (default: RDS default subnets),
// GROUNDHOLD_LIVE_RDS_CLASS (default db.t3.micro).
func TestLiveRDSRoundtrip(t *testing.T) {
	if os.Getenv("GROUNDHOLD_LIVE_RDS") != "1" || os.Getenv("AWS_ACCESS_KEY_ID") == "" {
		t.Skip("live RDS roundtrip disabled (set GROUNDHOLD_LIVE_RDS=1 with real creds)")
	}
	region := os.Getenv("AWS_DEFAULT_REGION")
	if region == "" {
		region = "eu-central-1"
	}
	engine := os.Getenv("GROUNDHOLD_LIVE_RDS_ENGINE")
	if engine == "" {
		engine = "postgresql/16"
	}
	class := os.Getenv("GROUNDHOLD_LIVE_RDS_CLASS")
	if class == "" {
		class = "db.t3.micro"
	}

	d := NewDriver(region)
	d.Now = time.Now
	d.PollInterval = 20 * time.Second
	d.PollTimeout = 20 * time.Minute

	account, _, err := d.CallerIdentity()
	if err != nil {
		t.Fatalf("STS: %v", err)
	}

	attrs := map[string]any{
		"location.region":        region,
		"engine.protocol":        engine,
		"encryption.atRest":      true,
		"network.publicExposure": false,
		"availability.class":     "zonal",
		"service.managed":        true,
	}
	impl := map[string]any{
		"instance_class":      class,
		"allocated_storage":   "20",
		"master_username":     "groundholdadmin",
		"master_password":     livePassword(t),
		"deletion_protection": false,
	}
	if sg := os.Getenv("GROUNDHOLD_LIVE_RDS_SUBNET_GROUP"); sg != "" {
		impl["db_subnet_group"] = sg
	}

	// deterministic pid for the deferred cleanup, even if create returns unknown.
	pid := rdsProviderID(region, DBIdentifier(account, "test", "livedb", 1))
	defer func() {
		// retry delete a few times — a still-"creating" instance can't be deleted
		// until it reaches an eligible state.
		for i := 0; i < 30; i++ {
			del := d.deleteRDS("livedb", "test", pid)
			t.Logf("cleanup delete attempt %d: %+v", i, del)
			if del.Status == "succeeded" {
				return
			}
			time.Sleep(20 * time.Second)
		}
		t.Errorf("cleanup FAILED — delete %s manually", pid)
	}()

	res := d.createRDS(region, account, "test", "livedb", attrs, impl, 1)
	t.Logf("create: %+v", res)
	if res.Status != "succeeded" {
		t.Fatalf("live create must reach available/succeeded, got %+v", res)
	}
	if res.ProviderID != pid {
		t.Fatalf("pid drift: got %q want %q", res.ProviderID, pid)
	}

	obs, notes, err := d.observeRDS("livedb", pid)
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
	if got["encryption.atRest"] != true {
		t.Errorf("storage must be encrypted: %v", got["encryption.atRest"])
	}
	if got["network.publicExposure"] != false {
		t.Errorf("must not be publicly accessible: %v", got["network.publicExposure"])
	}
}
