package aws

import (
	"strings"
	"testing"
)

// ebsVolAttrs/ebsVolImpl are the minimum a create needs: the four facts the contract
// governs, and the operands the driver refuses to invent.
func ebsVolAttrs() map[string]any {
	return map[string]any{
		"location.region":                "eu-central-1",
		"availability.class":             "zonal",
		"encryption.atRest":              true,
		"encryption.customerManagedKeys": false,
		"service.managed":                true,
	}
}

func ebsVolImpl() map[string]any {
	return map[string]any{
		"availability_zone": "eu-central-1a",
		"size_gb":           100,
		"volume_type":       "gp3",
	}
}

func TestBuildEBSVolumeCreateGolden(t *testing.T) {
	p, err := BuildEBSVolumeCreate("production", "orders-data", ebsVolAttrs(), ebsVolImpl(), 0)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	got := ec2RunForm(t, p.createBody())

	want := map[string]string{
		"Action":                          "CreateVolume",
		"AvailabilityZone":                "eu-central-1a",
		"Size":                            "100",
		"VolumeType":                      "gp3",
		"Encrypted":                       "true",
		"TagSpecification.1.ResourceType": "volume",
	}
	for k, v := range want {
		if got.Get(k) != v {
			t.Errorf("%s = %q, want %q", k, got.Get(k), v)
		}
	}
	// Not requested is not sent: an unset IOPS/throughput must not become a
	// number the operator never chose (and would be billed for on io2).
	for _, k := range []string{"Iops", "Throughput", "SnapshotId", "KmsKeyId"} {
		if got.Has(k) {
			t.Errorf("%s = %q, but the operand was not supplied", k, got.Get(k))
		}
	}
	if p.ClientToken == "" || got.Get("ClientToken") != p.ClientToken {
		t.Errorf("ClientToken missing from the body: plan %q, body %q",
			p.ClientToken, got.Get("ClientToken"))
	}
}

// The idempotency key must be a pure function of the identity a lost create has
// to be recovered by — otherwise a retry makes a SECOND volume, and for a
// stateful capability a duplicate is worse than a failure.
func TestEBSClientTokenIsDeterministicAndScoped(t *testing.T) {
	a, err := BuildEBSVolumeCreate("production", "orders-data", ebsVolAttrs(), ebsVolImpl(), 0)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	b, err := BuildEBSVolumeCreate("production", "orders-data", ebsVolAttrs(), ebsVolImpl(), 0)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if a.ClientToken != b.ClientToken {
		t.Errorf("two builds of the same volume gave different tokens: %q vs %q",
			a.ClientToken, b.ClientToken)
	}
	for _, other := range []struct {
		name       string
		env, cap   string
		generation int
	}{
		{"another environment", "staging", "orders-data", 0},
		{"another capability", "production", "audit-data", 0},
		{"a replacement generation", "production", "orders-data", 2},
	} {
		o, err := BuildEBSVolumeCreate(other.env, other.cap, ebsVolAttrs(), ebsVolImpl(), other.generation)
		if err != nil {
			t.Fatalf("%s: build: %v", other.name, err)
		}
		if o.ClientToken == a.ClientToken {
			t.Errorf("%s shares the token %q — a distinct volume would be silently "+
				"deduplicated into the first one", other.name, a.ClientToken)
		}
	}
}

// Encryption defaults ON. A volume created unencrypted cannot be encrypted later
// (the data has to be copied through a snapshot), so the default is the one the
// operator cannot cheaply undo being wrong about.
func TestEBSEncryptionDefaultsOn(t *testing.T) {
	attrs := ebsVolAttrs()
	delete(attrs, "encryption.atRest")
	p, err := BuildEBSVolumeCreate("production", "orders-data", attrs, ebsVolImpl(), 0)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if !p.Encrypted {
		t.Error("a volume with no declared encryption.atRest was built unencrypted")
	}
	if ec2RunForm(t, p.createBody()).Get("Encrypted") != "true" {
		t.Error("Encrypted is not true in the request body")
	}
}

func TestEBSCustomerManagedKeyRidesInTheBody(t *testing.T) {
	attrs := ebsVolAttrs()
	attrs["encryption.customerManagedKeys"] = true
	impl := ebsVolImpl()
	impl["kms_key_id"] = "arn:aws:kms:eu-central-1:000000000000:key/abc-123"

	p, err := BuildEBSVolumeCreate("production", "orders-data", attrs, impl, 0)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if got := ec2RunForm(t, p.createBody()).Get("KmsKeyId"); got != impl["kms_key_id"] {
		t.Errorf("KmsKeyId = %q, want the declared key", got)
	}
}

// A snapshot carries its own size, so it is the ONE case where the driver has a
// capacity it did not invent.
func TestEBSSizeMayComeFromASnapshot(t *testing.T) {
	impl := map[string]any{
		"availability_zone": "eu-central-1a",
		"snapshot_id":       "snap-0123456789abcdef0",
	}
	p, err := BuildEBSVolumeCreate("production", "orders-data", ebsVolAttrs(), impl, 0)
	if err != nil {
		t.Fatalf("a restore with no explicit size was refused: %v", err)
	}
	body := ec2RunForm(t, p.createBody())
	if body.Get("SnapshotId") != "snap-0123456789abcdef0" {
		t.Errorf("SnapshotId = %q", body.Get("SnapshotId"))
	}
	if body.Has("Size") {
		t.Errorf("Size = %q was sent for a restore that declared none", body.Get("Size"))
	}
}

// Every refusal below is a create that must NOT reach AWS. Each names the
// specific thing that would otherwise be provisioned wrongly.
func TestBuildEBSVolumeCreateRefusals(t *testing.T) {
	cases := []struct {
		name  string
		mutA  func(map[string]any)
		mutI  func(map[string]any)
		wants string
	}{
		{
			name:  "regional is not a thing EBS sells",
			mutA:  func(a map[string]any) { a["availability.class"] = "regional" },
			wants: "there is no regional EBS",
		},
		{
			name:  "an unknown availability class",
			mutA:  func(a map[string]any) { a["availability.class"] = "multi-regional" },
			wants: "has no EBS mapping",
		},
		{
			name:  "an attribute the driver cannot map",
			mutA:  func(a map[string]any) { a["network.publicExposure"] = false },
			wants: "refusing rather than silently dropping it",
		},
		{
			name:  "a customer key with nowhere to get it",
			mutA:  func(a map[string]any) { a["encryption.customerManagedKeys"] = true },
			wants: "requires implementation.kms_key_id",
		},
		{
			name: "a key on an unencrypted volume",
			mutA: func(a map[string]any) {
				a["encryption.customerManagedKeys"] = true
				a["encryption.atRest"] = false
			},
			mutI:  func(i map[string]any) { i["kms_key_id"] = "arn:aws:kms:eu-central-1:0:key/k" },
			wants: "contradictory",
		},
		{
			name:  "an unmanaged volume is an adoption, not a create",
			mutA:  func(a map[string]any) { a["service.managed"] = false },
			wants: "adoption, not a create",
		},
		{
			name:  "no zone",
			mutI:  func(i map[string]any) { delete(i, "availability_zone") },
			wants: "implementation.availability_zone is required",
		},
		{
			name:  "a zone that is not one",
			mutI:  func(i map[string]any) { i["availability_zone"] = "eu-central-1" },
			wants: "is not an availability zone",
		},
		{
			// The residency check: without it the create succeeds in the wrong
			// jurisdiction and the contract reports satisfied.
			name:  "a zone outside the contract's region",
			mutI:  func(i map[string]any) { i["availability_zone"] = "us-east-1a" },
			wants: "contradicts implementation.availability_zone",
		},
		{
			name:  "no size and nothing to restore",
			mutI:  func(i map[string]any) { delete(i, "size_gb") },
			wants: "implementation.size_gb is required",
		},
		{
			name:  "a size that is not a size",
			mutI:  func(i map[string]any) { i["size_gb"] = 0 },
			wants: "positive whole number of GiB",
		},
		{
			name:  "a volume type that is not one",
			mutI:  func(i map[string]any) { i["volume_type"] = "extremely-fast" },
			wants: "is not an EBS volume type",
		},
		{
			name:  "a snapshot id that is not one",
			mutI:  func(i map[string]any) { i["snapshot_id"] = "vol-0123456789abcdef0" },
			wants: "is not a snapshot id",
		},
		{
			name:  "negative iops",
			mutI:  func(i map[string]any) { i["iops"] = -1 },
			wants: "implementation.iops must be a positive whole number",
		},
		{
			name:  "encryption.atRest as a string",
			mutA:  func(a map[string]any) { a["encryption.atRest"] = "yes" },
			wants: "must be a bool",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			attrs, impl := ebsVolAttrs(), ebsVolImpl()
			if tc.mutA != nil {
				tc.mutA(attrs)
			}
			if tc.mutI != nil {
				tc.mutI(impl)
			}
			_, err := BuildEBSVolumeCreate("production", "orders-data", attrs, impl, 0)
			if err == nil {
				t.Fatalf("build succeeded; want a refusal mentioning %q", tc.wants)
			}
			if !strings.Contains(err.Error(), tc.wants) {
				t.Errorf("refusal = %q, want it to mention %q", err, tc.wants)
			}
		})
	}
}

// ModifyVolume exists, but everything it can change is an OPERAND here. The four
// attributes this vocabulary governs are all fixed at creation, and saying so is
// the honest answer rather than a gap — a stateful replacement then needs consent
// instead of happening quietly.
func TestClassifyEBSVolumeChange(t *testing.T) {
	for _, path := range []string{
		"location.region", "availability.class",
		"encryption.atRest", "encryption.customerManagedKeys",
	} {
		class, why := classifyEBSVolumeChange(path)
		if class != "immutable" {
			t.Errorf("%s classified %q, want immutable", path, class)
		}
		if why == "" {
			t.Errorf("%s gave no reason — a refusal without one cannot be acted on", path)
		}
	}
	if class, _ := classifyEBSVolumeChange("service.managed"); class != "unsupported" {
		t.Errorf("service.managed classified %q, want unsupported", class)
	}
	if class, why := classifyEBSVolumeChange("something.invented"); class != "" || why != "" {
		t.Errorf("an unknown path classified %q/%q, want the empty (unhandled) answer", class, why)
	}
}
