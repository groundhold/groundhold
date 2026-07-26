package aws

import (
	"regexp"
	"strings"
	"testing"
)

func s3Attrs() map[string]any {
	return map[string]any{
		"location.region":        "eu-central-1",
		"durability.class":       "regional",
		"versioning.enabled":     true,
		"network.publicExposure": false,
		"encryption.atRest":      true,
		"service.managed":        true,
	}
}

func TestBucketNameDeterministicAndDNS(t *testing.T) {
	n := BucketName("000000000000", "prod", "assets", 1)
	if !regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$`).MatchString(n) {
		t.Fatalf("bucket name not DNS-compatible: %q", n)
	}
	if n != BucketName("000000000000", "prod", "assets", 1) {
		t.Fatal("bucket name must be deterministic")
	}
}

func TestBuildS3Golden(t *testing.T) {
	plan, err := BuildS3Requests("000000000000", "prod", "assets", s3Attrs(), nil, 1)
	if err != nil {
		t.Fatal(err)
	}
	// eu-central-1 requires a LocationConstraint in the create body
	if !strings.Contains(plan.Create.Body, "<LocationConstraint>eu-central-1</LocationConstraint>") {
		t.Fatalf("create must carry LocationConstraint: %q", plan.Create.Body)
	}
	// ownership tags
	if !strings.Contains(plan.Tagging.Body, "groundhold-capability") ||
		!strings.Contains(plan.Tagging.Body, "assets") {
		t.Fatalf("tagging must carry ownership: %q", plan.Tagging.Body)
	}
	// private baseline: policy fully blocked
	if !strings.Contains(plan.PublicAccessBlk.Body, "<BlockPublicPolicy>true</BlockPublicPolicy>") {
		t.Fatalf("private bucket must block public policy: %q", plan.PublicAccessBlk.Body)
	}
	if plan.Public {
		t.Fatal("this bucket is private")
	}
	if plan.Versioning == nil || !strings.Contains(plan.Versioning.Body, "Enabled") {
		t.Fatal("versioning must be requested")
	}
}

func TestBuildS3PublicRelaxesBlock(t *testing.T) {
	a := s3Attrs()
	a["network.publicExposure"] = true
	plan, err := BuildS3Requests("acct", "prod", "assets", a, nil, 1)
	if err != nil {
		t.Fatal(err)
	}
	if !plan.Public {
		t.Fatal("plan must be marked public")
	}
	if !strings.Contains(plan.PublicAccessBlk.Body, "<BlockPublicPolicy>false</BlockPublicPolicy>") {
		t.Fatalf("public bucket must relax the policy block: %q", plan.PublicAccessBlk.Body)
	}
	if !strings.Contains(PublicReadPolicy(plan.Bucket), `"Principal":"*"`) {
		t.Fatal("public read policy must grant anonymous access")
	}
}

func TestUsEast1NoLocationConstraint(t *testing.T) {
	a := s3Attrs()
	a["location.region"] = "us-east-1"
	plan, err := BuildS3Requests("acct", "prod", "assets", a, nil, 1)
	if err != nil {
		t.Fatal(err)
	}
	if plan.Create.Body != "" {
		t.Fatalf("us-east-1 must NOT carry a LocationConstraint, got %q", plan.Create.Body)
	}
}

func s3ReplImpl() map[string]any {
	return map[string]any{
		"replication_destination_bucket_arn": "arn:aws:s3:::pv-assets-replica-abcd1234",
		"replication_role_arn":               "arn:aws:iam::000000000000:role/groundhold-crr",
	}
}

func TestBuildS3ReplicationGolden(t *testing.T) {
	a := s3Attrs()
	a["replication.enabled"] = true
	a["replication.destinationRegion"] = "eu-west-3" // OBSERVED, not built — accepted
	plan, err := BuildS3Requests("000000000000", "prod", "assets", a, s3ReplImpl(), 1)
	if err != nil {
		t.Fatal(err)
	}
	if plan.Replication == nil {
		t.Fatal("replication must be requested")
	}
	b := plan.Replication.Body
	for _, want := range []string{
		"<Status>Enabled</Status>",
		"<Role>arn:aws:iam::000000000000:role/groundhold-crr</Role>",
		"<Bucket>arn:aws:s3:::pv-assets-replica-abcd1234</Bucket>",
	} {
		if !strings.Contains(b, want) {
			t.Fatalf("replication body missing %q: %s", want, b)
		}
	}
	// the destination REGION must NOT leak into the built request (it is observed)
	if strings.Contains(b, "eu-west-3") {
		t.Fatalf("destinationRegion must not be built into the rule: %s", b)
	}
	if plan.Replication.Path != "/?replication" {
		t.Fatalf("replication path = %q", plan.Replication.Path)
	}
}

func TestBuildS3ReplicationRefusals(t *testing.T) {
	cases := map[string]func(map[string]any, map[string]any){
		"no versioning": func(a, i map[string]any) {
			a["replication.enabled"] = true
			a["versioning.enabled"] = false
		},
		"missing operands": func(a, i map[string]any) {
			a["replication.enabled"] = true
			delete(i, "replication_destination_bucket_arn")
			delete(i, "replication_role_arn")
		},
		"missing role": func(a, i map[string]any) {
			a["replication.enabled"] = true
			delete(i, "replication_role_arn")
		},
		"bad dest arn": func(a, i map[string]any) {
			a["replication.enabled"] = true
			i["replication_destination_bucket_arn"] = "not-an-arn"
		},
		"bad role arn": func(a, i map[string]any) {
			a["replication.enabled"] = true
			i["replication_role_arn"] = "arn:aws:iam::x:role/y"
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			a := s3Attrs()
			i := s3ReplImpl()
			mutate(a, i)
			if _, err := BuildS3Requests("acct", "prod", "assets", a, i, 1); err == nil {
				t.Fatalf("expected refusal for %q", name)
			}
		})
	}
}

// A contract with no replication.* behaves exactly as before (backward compat).
func TestBuildS3NoReplicationByDefault(t *testing.T) {
	plan, err := BuildS3Requests("acct", "prod", "assets", s3Attrs(), nil, 1)
	if err != nil {
		t.Fatal(err)
	}
	if plan.Replication != nil {
		t.Fatal("no replication.enabled => no replication request")
	}
}

// WORM at birth: retention.minimum + retention.locked (+ versioning) => the
// bucket is born object-lock-enabled (create header) with a COMPLIANCE default
// retention. This USED to be a hard refusal (create-time-only, "use GCS"); the
// driver now owns create from zero, so it honors it — semantics changed from
// refusal to support (a new capability, no case weakened).
func TestBuildS3ObjectLockCompliance(t *testing.T) {
	a := s3Attrs()
	a["retention.minimum"] = "3650d"
	a["retention.locked"] = true
	plan, err := BuildS3Requests("000000000000", "prod", "vault", a, nil, 1)
	if err != nil {
		t.Fatal(err)
	}
	if !plan.ObjectLockEnabled || plan.ObjectLockMode != "COMPLIANCE" || plan.ObjectLockDays != 3650 {
		t.Fatalf("expected COMPLIANCE/3650d object lock, got enabled=%v mode=%q days=%d",
			plan.ObjectLockEnabled, plan.ObjectLockMode, plan.ObjectLockDays)
	}
	if plan.Create.Headers["x-amz-bucket-object-lock-enabled"] != "true" {
		t.Fatalf("create must carry the object-lock-enable header, got %v", plan.Create.Headers)
	}
	if plan.ObjectLock == nil || plan.ObjectLock.Path != "/?object-lock" {
		t.Fatalf("object-lock request missing or wrong path: %+v", plan.ObjectLock)
	}
	for _, want := range []string{
		"<ObjectLockEnabled>Enabled</ObjectLockEnabled>",
		"<Mode>COMPLIANCE</Mode>", "<Days>3650</Days>",
	} {
		if !strings.Contains(plan.ObjectLock.Body, want) {
			t.Fatalf("object-lock body missing %q: %s", want, plan.ObjectLock.Body)
		}
	}
}

// retention.minimum WITHOUT a lock => GOVERNANCE (a soft, bypassable floor).
func TestBuildS3ObjectLockGovernance(t *testing.T) {
	a := s3Attrs()
	a["retention.minimum"] = "168h" // 7 days
	plan, err := BuildS3Requests("acct", "prod", "vault", a, nil, 1)
	if err != nil {
		t.Fatal(err)
	}
	if !plan.ObjectLockEnabled || plan.ObjectLockMode != "GOVERNANCE" || plan.ObjectLockDays != 7 {
		t.Fatalf("expected GOVERNANCE/7d, got enabled=%v mode=%q days=%d",
			plan.ObjectLockEnabled, plan.ObjectLockMode, plan.ObjectLockDays)
	}
}

// No retention.* => no object lock (backward compat: create carries no header).
func TestBuildS3NoObjectLockByDefault(t *testing.T) {
	plan, err := BuildS3Requests("acct", "prod", "assets", s3Attrs(), nil, 1)
	if err != nil {
		t.Fatal(err)
	}
	if plan.ObjectLockEnabled || plan.ObjectLock != nil || plan.Create.Headers["x-amz-bucket-object-lock-enabled"] != "" {
		t.Fatal("no retention.* => no object lock and no create header")
	}
}

func TestBuildS3ObjectLockRefusals(t *testing.T) {
	cases := map[string]func(map[string]any){
		"locked without minimum": func(a map[string]any) {
			a["retention.locked"] = true // no retention.minimum -> lock nothing
		},
		"object lock without versioning": func(a map[string]any) {
			a["retention.minimum"] = "3650d"
			a["versioning.enabled"] = false
		},
		"sub-day minimum": func(a map[string]any) {
			a["retention.minimum"] = "1h"
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			a := s3Attrs()
			mutate(a)
			if _, err := BuildS3Requests("acct", "prod", "vault", a, nil, 1); err == nil {
				t.Fatalf("expected refusal for %q", name)
			}
		})
	}
}

func TestBuildS3Refusals(t *testing.T) {
	cases := map[string]func(map[string]any){
		"single-zone":   func(a map[string]any) { a["durability.class"] = "single-zone" },
		"no encryption": func(a map[string]any) { a["encryption.atRest"] = false },
		"unmanaged":     func(a map[string]any) { a["service.managed"] = false },
		"no region":     func(a map[string]any) { delete(a, "location.region") },
		"unknown attr":  func(a map[string]any) { a["engine.protocol"] = "x" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			a := s3Attrs()
			mutate(a)
			if _, err := BuildS3Requests("acct", "prod", "assets", a, nil, 1); err == nil {
				t.Fatalf("expected refusal for %q", name)
			}
		})
	}
}
