package gcp

import (
	"strings"
	"testing"
)

// pdAttrs/pdImpl are the minimum a create needs: the facts the contract governs,
// and the operands the driver refuses to invent.
func pdAttrs() map[string]any {
	return map[string]any{
		"location.region":                "europe-west1",
		"availability.class":             "zonal",
		"encryption.atRest":              true,
		"encryption.customerManagedKeys": false,
		"service.managed":                true,
	}
}

func pdImpl() map[string]any {
	return map[string]any{
		"zone":      "europe-west1-b",
		"size_gb":   100,
		"disk_type": "pd-balanced",
	}
}

func TestBuildPDCreateGoldenZonal(t *testing.T) {
	p, err := BuildPDCreate("acme-prod", "production", "orders-data", pdAttrs(), pdImpl(), 0)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if p.Regional {
		t.Error("a zonal contract produced a regional plan")
	}
	if p.Zone != "europe-west1-b" || p.Region != "europe-west1" {
		t.Errorf("placement = %q/%q", p.Zone, p.Region)
	}
	body := p.createBody("orders-data", "production")
	if body["sizeGb"] != "100" {
		t.Errorf("sizeGb = %v", body["sizeGb"])
	}
	// The type is scope-qualified: a bare token would be rejected by the API.
	if body["type"] != "zones/europe-west1-b/diskTypes/pd-balanced" {
		t.Errorf("type = %v, want the zone-qualified form", body["type"])
	}
	if _, ok := body["replicaZones"]; ok {
		t.Error("a zonal disk carried replicaZones")
	}
	if _, ok := body["diskEncryptionKey"]; ok {
		t.Error("a disk with no declared CMEK carried an encryption key")
	}
	labels, _ := body["labels"].(map[string]any)
	if labels["groundhold-capability"] != "orders-data" {
		t.Errorf("ownership labels = %v — the 409 continuation depends on them", labels)
	}
}

// The regional path is the substance of this driver: a DIFFERENT resource with a
// different durability guarantee, which is why the vocabulary carries the
// attribute at all (the EBS twin refuses it — AWS does not sell one).
func TestBuildPDCreateGoldenRegional(t *testing.T) {
	attrs := pdAttrs()
	attrs["availability.class"] = "regional"
	impl := map[string]any{
		"size_gb":       200,
		"disk_type":     "pd-ssd",
		"replica_zones": []any{"europe-west1-b", "europe-west1-c"},
	}
	p, err := BuildPDCreate("acme-prod", "production", "orders-data", attrs, impl, 0)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if !p.Regional {
		t.Fatal("a regional contract produced a zonal plan — the durability guarantee was silently downgraded")
	}
	if p.Region != "europe-west1" {
		t.Errorf("region = %q", p.Region)
	}
	body := p.createBody("orders-data", "production")
	zones, _ := body["replicaZones"].([]any)
	if len(zones) != 2 || zones[0] != "zones/europe-west1-b" || zones[1] != "zones/europe-west1-c" {
		t.Errorf("replicaZones = %v, want both zones in the qualified form", body["replicaZones"])
	}
	if body["type"] != "regions/europe-west1/diskTypes/pd-ssd" {
		t.Errorf("type = %v, want the region-qualified form", body["type"])
	}
}

// The name IS the idempotency mechanism (D43): disks.insert takes no idempotency
// key, so a name that varied between builds would make a retry create a SECOND
// disk — and on a stateful capability a duplicate is worse than a failure.
func TestPDNameIsDeterministicAndScoped(t *testing.T) {
	a, err := BuildPDCreate("acme-prod", "production", "orders-data", pdAttrs(), pdImpl(), 0)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	b, err := BuildPDCreate("acme-prod", "production", "orders-data", pdAttrs(), pdImpl(), 0)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if a.Name != b.Name {
		t.Errorf("two builds gave different names: %q vs %q", a.Name, b.Name)
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
		o, err := BuildPDCreate("acme-prod", other.env, other.cap, pdAttrs(), pdImpl(), other.generation)
		if err != nil {
			t.Fatalf("%s: build: %v", other.name, err)
		}
		if o.Name == a.Name {
			t.Errorf("%s shares the name %q — a distinct disk would collide with the first", other.name, a.Name)
		}
	}
}

func TestBuildPDCreateCustomerManagedKey(t *testing.T) {
	attrs := pdAttrs()
	attrs["encryption.customerManagedKeys"] = true
	impl := pdImpl()
	impl["kms_key_name"] = "projects/acme-prod/locations/europe-west1/keyRings/r/cryptoKeys/k"

	p, err := BuildPDCreate("acme-prod", "production", "orders-data", attrs, impl, 0)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	key, _ := p.createBody("orders-data", "production")["diskEncryptionKey"].(map[string]any)
	if key["kmsKeyName"] != impl["kms_key_name"] {
		t.Errorf("diskEncryptionKey = %v, want the declared key", key)
	}
}

func TestPDSizeMayComeFromASnapshot(t *testing.T) {
	impl := map[string]any{"zone": "europe-west1-b", "source_snapshot": "orders-nightly"}
	p, err := BuildPDCreate("acme-prod", "production", "orders-data", pdAttrs(), impl, 0)
	if err != nil {
		t.Fatalf("a restore with no explicit size was refused: %v", err)
	}
	body := p.createBody("orders-data", "production")
	if body["sourceSnapshot"] != "orders-nightly" {
		t.Errorf("sourceSnapshot = %v", body["sourceSnapshot"])
	}
	if _, ok := body["sizeGb"]; ok {
		t.Errorf("sizeGb = %v was sent for a restore that declared none", body["sizeGb"])
	}
}

// Every refusal below is a create that must NOT reach GCP.
func TestBuildPDCreateRefusals(t *testing.T) {
	cases := []struct {
		name  string
		mutA  func(map[string]any)
		impl  map[string]any
		wants string
	}{
		{
			// Accepting it and silently getting an encrypted disk is not honoring the
			// contract, it is overruling it — and reporting satisfied would hide that.
			name:  "unencrypted is not something GCP can do",
			mutA:  func(a map[string]any) { a["encryption.atRest"] = false },
			wants: "offers no way to disable it",
		},
		{
			name:  "an unknown availability class",
			mutA:  func(a map[string]any) { a["availability.class"] = "multi-regional" },
			wants: "has no persistent-disk mapping (zonal or regional)",
		},
		{
			name:  "an attribute the driver cannot map",
			mutA:  func(a map[string]any) { a["network.publicExposure"] = false },
			wants: "refusing rather than silently dropping it",
		},
		{
			name:  "a customer key with nowhere to get it",
			mutA:  func(a map[string]any) { a["encryption.customerManagedKeys"] = true },
			wants: "requires implementation.kms_key_name",
		},
		{
			name:  "an unmanaged disk is an adoption, not a create",
			mutA:  func(a map[string]any) { a["service.managed"] = false },
			wants: "adoption, not a create",
		},
		{
			name:  "no zone",
			impl:  map[string]any{"size_gb": 100},
			wants: "implementation.zone is required",
		},
		{
			name:  "a zone that is not one",
			impl:  map[string]any{"zone": "europe-west1", "size_gb": 100},
			wants: "is not a valid zone",
		},
		{
			// The residency check: without it the create succeeds in the wrong
			// jurisdiction and the contract reports satisfied.
			name:  "a zone outside the contract's region",
			impl:  map[string]any{"zone": "us-central1-a", "size_gb": 100},
			wants: "refusing rather than storing the data somewhere the contract did not ask for",
		},
		{
			name:  "no size and nothing to restore",
			impl:  map[string]any{"zone": "europe-west1-b"},
			wants: "implementation.size_gb is required",
		},
		{
			name:  "a size that is not a size",
			impl:  map[string]any{"zone": "europe-west1-b", "size_gb": 1.5},
			wants: "positive whole number of GiB",
		},
		{
			name:  "a disk type that is not one",
			impl:  map[string]any{"zone": "europe-west1-b", "size_gb": 100, "disk_type": "Extremely Fast"},
			wants: "is not a disk type",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			attrs := pdAttrs()
			if tc.mutA != nil {
				tc.mutA(attrs)
			}
			impl := tc.impl
			if impl == nil {
				impl = pdImpl()
			}
			_, err := BuildPDCreate("acme-prod", "production", "orders-data", attrs, impl, 0)
			if err == nil {
				t.Fatalf("build succeeded; want a refusal mentioning %q", tc.wants)
			}
			if !strings.Contains(err.Error(), tc.wants) {
				t.Errorf("refusal = %q, want it to mention %q", err, tc.wants)
			}
		})
	}
}

// The regional operands have their own failure modes, and each one silently
// tolerated would misreport how many failures the disk survives.
func TestBuildPDCreateRegionalRefusals(t *testing.T) {
	cases := []struct {
		name  string
		impl  map[string]any
		wants string
	}{
		{
			name:  "regional with no replica zones",
			impl:  map[string]any{"size_gb": 100},
			wants: "requires implementation.replica_zones",
		},
		{
			name:  "one zone is not a replica set",
			impl:  map[string]any{"size_gb": 100, "replica_zones": []any{"europe-west1-b"}},
			wants: "exactly two zones",
		},
		{
			name: "three zones would be silently truncated",
			impl: map[string]any{"size_gb": 100,
				"replica_zones": []any{"europe-west1-b", "europe-west1-c", "europe-west1-d"}},
			wants: "exactly two zones",
		},
		{
			// Two copies in one zone survive nothing a single copy does not — and the
			// contract would report `regional` for it.
			name: "the same zone twice",
			impl: map[string]any{"size_gb": 100,
				"replica_zones": []any{"europe-west1-b", "europe-west1-b"}},
			wants: "twice",
		},
		{
			name: "replicas in two different regions",
			impl: map[string]any{"size_gb": 100,
				"replica_zones": []any{"europe-west1-b", "europe-west4-a"}},
			wants: "span two different regions",
		},
		{
			name: "a replica that is not a zone",
			impl: map[string]any{"size_gb": 100,
				"replica_zones": []any{"europe-west1-b", "europe-west1"}},
			wants: "which is not a zone",
		},
		{
			name:  "replica zones that are not a list",
			impl:  map[string]any{"size_gb": 100, "replica_zones": "europe-west1-b"},
			wants: "must be a list",
		},
		{
			name: "replicas outside the contract's region",
			impl: map[string]any{"size_gb": 100,
				"replica_zones": []any{"us-central1-a", "us-central1-b"}},
			wants: "refusing rather than storing the data somewhere the contract did not ask for",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			attrs := pdAttrs()
			attrs["availability.class"] = "regional"
			_, err := BuildPDCreate("acme-prod", "production", "orders-data", attrs, tc.impl, 0)
			if err == nil {
				t.Fatalf("build succeeded; want a refusal mentioning %q", tc.wants)
			}
			if !strings.Contains(err.Error(), tc.wants) {
				t.Errorf("refusal = %q, want it to mention %q", err, tc.wants)
			}
		})
	}
}

// Zonal and regional disks are different RESOURCES, not two settings of one, so
// changing the class is a new disk and the data must be copied — which on a
// stateful capability means it needs consent rather than happening quietly.
func TestClassifyPDChange(t *testing.T) {
	// D823: encryption.atRest was pinned "immutable" here. Compute Engine encrypts every
	// persistent disk and the setting cannot be changed, so a replacement reaches the same
	// state — the honest answer is that =false cannot be honoured, not that it needs a new
	// disk. customerManagedKeys stays immutable: disks.updateKmsKey rotates the key's
	// VERSION, which is not the same as attaching a key to a disk created without one.
	if class, why := classifyPDChange("encryption.atRest"); class != "unsupported" || why == "" {
		t.Errorf("encryption.atRest classified %q/%q, want unsupported with a reason", class, why)
	}
	for _, path := range []string{
		"location.region", "availability.class", "encryption.customerManagedKeys",
	} {
		class, why := classifyPDChange(path)
		if class != "immutable" {
			t.Errorf("%s classified %q, want immutable", path, class)
		}
		if why == "" {
			t.Errorf("%s gave no reason — a refusal without one cannot be acted on", path)
		}
	}
	if class, _ := classifyPDChange("service.managed"); class != "unsupported" {
		t.Errorf("service.managed classified %q, want unsupported", class)
	}
	if class, why := classifyPDChange("something.invented"); class != "" || why != "" {
		t.Errorf("an unknown path classified %q/%q, want the empty (unhandled) answer", class, why)
	}
}
