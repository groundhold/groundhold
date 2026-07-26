package gcp

import (
	"strings"
	"testing"
)

func gceAttrs() map[string]any {
	return map[string]any{
		"location.region":                "europe-west1",
		"availability.class":             "zonal",
		"network.publicExposure":         false,
		"encryption.atRest":              true,
		"encryption.customerManagedKeys": false,
		"service.managed":                true,
	}
}

func gceImpl() map[string]any {
	return map[string]any{
		"zone":         "europe-west1-b",
		"machine_type": "e2-standard-2",
		"source_image": "projects/debian-cloud/global/images/debian-12",
	}
}

func TestBuildGCEInstanceCreateGolden(t *testing.T) {
	p, err := BuildGCEInstanceCreate("acme-prod", "production", "web", gceAttrs(), gceImpl(), 0)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	body := p.createBody("web", "production")

	if got := body["machineType"]; got != "zones/europe-west1-b/machineTypes/e2-standard-2" {
		t.Errorf("machineType = %v", got)
	}
	disks := body["disks"].([]any)
	boot := disks[0].(map[string]any)
	if boot["boot"] != true || boot["autoDelete"] != true {
		t.Errorf("boot disk flags wrong: %v", boot)
	}
	if got := boot["initializeParams"].(map[string]any)["sourceImage"]; got != "projects/debian-cloud/global/images/debian-12" {
		t.Errorf("sourceImage = %v", got)
	}
	if _, present := boot["diskEncryptionKey"]; present {
		t.Error("a CMEK block appeared although customerManagedKeys is false")
	}
	labels := body["labels"].(map[string]any)
	if labels["groundhold-capability"] != "web" || labels["groundhold-environment"] != "production" {
		t.Errorf("ownership labels wrong: %v", labels)
	}
	// A private instance has NO accessConfigs block at all — GCP has no "false"
	// to set, and an empty block would still request an address.
	nic := body["networkInterfaces"].([]any)[0].(map[string]any)
	if _, present := nic["accessConfigs"]; present {
		t.Error("a private instance carries an accessConfigs block — that requests a public address")
	}
	// No disk size was supplied, so none may be invented.
	if _, present := boot["initializeParams"].(map[string]any)["diskSizeGb"]; present {
		t.Error("diskSizeGb appeared uninvited")
	}
}

// The deterministic NAME is GCP's idempotency mechanism: instances.insert takes no
// idempotency key, so a lost create must be recoverable by name rather than
// duplicated.
func TestGCEInstanceNameIsDeterministic(t *testing.T) {
	a, err := BuildGCEInstanceCreate("acme-prod", "production", "web", gceAttrs(), gceImpl(), 0)
	if err != nil {
		t.Fatal(err)
	}
	b, err := BuildGCEInstanceCreate("acme-prod", "production", "web", gceAttrs(), gceImpl(), 0)
	if err != nil {
		t.Fatal(err)
	}
	if a.Name != b.Name {
		t.Errorf("name is not deterministic: %q vs %q", a.Name, b.Name)
	}
	c, err := BuildGCEInstanceCreate("acme-prod", "production", "web", gceAttrs(), gceImpl(), 2)
	if err != nil {
		t.Fatal(err)
	}
	if a.Name == c.Name {
		t.Error("generation 2 reused the original's name — a replacement would collide with " +
			"the instance it replaces instead of coexisting with it (D48)")
	}
	if len(a.Name) > 63 {
		t.Errorf("name %q exceeds the 63-character instance limit", a.Name)
	}
}

// The GCP-specific refusal: a contract that says one region and an operand that
// says another must not both "pass". Provisioning in the operand's region while
// reporting the contract's would make a residency verdict a lie.
func TestGCEInstanceRegionMustMatchTheZone(t *testing.T) {
	attrs := gceAttrs()
	attrs["location.region"] = "us-central1"
	_, err := BuildGCEInstanceCreate("acme-prod", "production", "web", attrs, gceImpl(), 0)
	if err == nil {
		t.Fatal("a us-central1 contract accepted a europe-west1-b zone — residency became unprovable")
	}
	if !strings.Contains(err.Error(), "contradicts") {
		t.Errorf("refusal does not explain the contradiction: %v", err)
	}
}

func TestBuildGCEInstanceCreateRefusals(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(attrs, impl map[string]any)
		want   string
	}{
		// GCP encrypts every persistent disk and cannot be told not to, so
		// accepting false would report a state the platform cannot produce.
		{"unencrypted disks", func(a, _ map[string]any) {
			a["encryption.atRest"] = false
		}, "offers no way to disable it"},
		{"regional placement", func(a, _ map[string]any) {
			a["availability.class"] = "regional"
		}, "managed instance group"},
		{"unknown availability class", func(a, _ map[string]any) {
			a["availability.class"] = "planet-scale"
		}, "has no Compute Engine mapping"},
		{"unmapped attribute", func(a, _ map[string]any) {
			a["replicas.minimum"] = 3
		}, "has no Compute Engine mapping"},
		{"cmk without a key", func(a, i map[string]any) {
			a["encryption.customerManagedKeys"] = true
			delete(i, "kms_key_name")
		}, "requires implementation.kms_key_name"},
		{"self-operated", func(a, _ map[string]any) {
			a["service.managed"] = false
		}, "cannot be honored"},
		{"no zone", func(_, i map[string]any) {
			delete(i, "zone")
		}, "zone is required"},
		{"bogus zone", func(_, i map[string]any) {
			i["zone"] = "europe-west1"
		}, "not a valid zone"},
		{"no machine type", func(_, i map[string]any) {
			delete(i, "machine_type")
		}, "machine_type is required"},
		{"no image", func(_, i map[string]any) {
			delete(i, "source_image")
		}, "source_image is required"},
		{"bogus image", func(_, i map[string]any) {
			i["source_image"] = "debian:latest"
		}, "not a valid image reference"},
		{"bogus subnetwork", func(_, i map[string]any) {
			i["subnetwork"] = "my-network"
		}, "not a valid subnetwork reference"},
		{"fractional disk", func(_, i map[string]any) {
			i["disk_size_gb"] = 10.5
		}, "positive whole number"},
		{"exposure is not a bool", func(a, _ map[string]any) {
			a["network.publicExposure"] = "yes"
		}, "must be a bool"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			attrs, impl := gceAttrs(), gceImpl()
			tc.mutate(attrs, impl)
			_, err := BuildGCEInstanceCreate("acme-prod", "production", "web", attrs, impl, 0)
			if err == nil {
				t.Fatal("expected a refusal, got a plan — a silently dropped attribute is the one unforgivable bug")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("refusal does not explain itself:\n got: %v\nwant substring: %q", err, tc.want)
			}
		})
	}
}

func TestGCEInstancePublicExposureIsThePresenceOfAnAccessConfig(t *testing.T) {
	attrs := gceAttrs()
	attrs["network.publicExposure"] = true
	p, err := BuildGCEInstanceCreate("acme-prod", "production", "web", attrs, gceImpl(), 0)
	if err != nil {
		t.Fatal(err)
	}
	nic := p.createBody("web", "production")["networkInterfaces"].([]any)[0].(map[string]any)
	cfgs, present := nic["accessConfigs"]
	if !present {
		t.Fatal("a public instance has no accessConfigs block — it would get no address")
	}
	if got := cfgs.([]any)[0].(map[string]any)["type"]; got != "ONE_TO_ONE_NAT" {
		t.Errorf("accessConfig type = %v", got)
	}
}

func TestGCEInstanceOptionalOperands(t *testing.T) {
	attrs, impl := gceAttrs(), gceImpl()
	attrs["encryption.customerManagedKeys"] = true
	impl["kms_key_name"] = "projects/acme-prod/locations/europe-west1/keyRings/r/cryptoKeys/k"
	impl["disk_size_gb"] = 100
	impl["subnetwork"] = "projects/acme-prod/regions/europe-west1/subnetworks/private"

	p, err := BuildGCEInstanceCreate("acme-prod", "production", "web", attrs, impl, 0)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	body := p.createBody("web", "production")
	boot := body["disks"].([]any)[0].(map[string]any)
	if got := boot["diskEncryptionKey"].(map[string]any)["kmsKeyName"]; got != impl["kms_key_name"] {
		t.Errorf("kmsKeyName = %v", got)
	}
	if got := boot["initializeParams"].(map[string]any)["diskSizeGb"]; got != "100" {
		t.Errorf("diskSizeGb = %v", got)
	}
	nic := body["networkInterfaces"].([]any)[0].(map[string]any)
	if got := nic["subnetwork"]; got != impl["subnetwork"] {
		t.Errorf("subnetwork = %v", got)
	}
}

// The classifier's verdicts must match the EC2 twin's where the reason is the
// same, and differ only where the platform genuinely differs.
func TestClassifyGCEInstanceChange(t *testing.T) {
	for path, want := range map[string]string{
		"location.region":                "immutable",
		"availability.class":             "immutable",
		"network.publicExposure":         "immutable",
		"encryption.customerManagedKeys": "immutable",
		// GCP cannot disable encryption at all, so there is nothing to patch —
		// "unsupported" rather than "immutable" is the honest distinction.
		"encryption.atRest": "unsupported",
		"service.managed":   "unsupported",
	} {
		got, reason := classifyGCEInstanceChange(path)
		if got != want {
			t.Errorf("%s classified %q, want %q", path, got, want)
		}
		if reason == "" {
			t.Errorf("%s carries no reason — a classification without one cannot be reviewed", path)
		}
	}
	if got, _ := classifyGCEInstanceChange("nonsense.path"); got != "" {
		t.Errorf("an unknown path classified as %q instead of falling through", got)
	}
}
