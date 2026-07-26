package gcp

import (
	"strings"
	"testing"
)

func migAttrs() map[string]any {
	return map[string]any{
		"location.region":        "europe-west1",
		"availability.class":     "regional",
		"replicas.minimum":       2,
		"replicas.maximum":       10,
		"autoscaling.enabled":    true,
		"network.publicExposure": false,
		"service.managed":        true,
	}
}

func migImpl() map[string]any {
	return map[string]any{
		"instance_template":      "web-template",
		"target_cpu_utilization": 60,
	}
}

func TestBuildMIGCreateGoldenRegional(t *testing.T) {
	p, err := BuildMIGCreate("acme-prod", "production", "web-fleet", migAttrs(), migImpl(), 0)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if !p.Regional || p.Region != "europe-west1" {
		t.Errorf("placement = regional:%v region:%q", p.Regional, p.Region)
	}
	body := p.createBody("web-fleet", "production")
	// targetSize starts the group at its FLOOR: the contract's minimum is the
	// capacity it declared it needs, and starting above it bills for machines
	// nobody asked for.
	if body["targetSize"] != 2 {
		t.Errorf("targetSize = %v, want the declared floor 2", body["targetSize"])
	}
	if body["instanceTemplate"] != "web-template" {
		t.Errorf("instanceTemplate = %v", body["instanceTemplate"])
	}
	// A MIG has no labels, so ownership rides in the description marker — the
	// established pattern in this package for exactly this situation.
	if body["description"] != vpcOwnerMarker("web-fleet", "production") {
		t.Errorf("description = %v, want the ownership marker", body["description"])
	}

	auto := p.autoscalerBody("https://x/projects/acme-prod/regions/europe-west1/instanceGroupManagers/g")
	pol, _ := auto["autoscalingPolicy"].(map[string]any)
	if pol["minNumReplicas"] != 2 || pol["maxNumReplicas"] != 10 {
		t.Errorf("autoscaler envelope = %v..%v", pol["minNumReplicas"], pol["maxNumReplicas"])
	}
	cpu, _ := pol["cpuUtilization"].(map[string]any)
	if cpu["utilizationTarget"] != 0.6 {
		t.Errorf("utilizationTarget = %v, want the operator's 0.6", cpu["utilizationTarget"])
	}
}

func TestBuildMIGCreateZonal(t *testing.T) {
	attrs := migAttrs()
	attrs["availability.class"] = "zonal"
	impl := migImpl()
	impl["zone"] = "europe-west1-b"

	p, err := BuildMIGCreate("acme-prod", "production", "web-fleet", attrs, impl, 0)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if p.Regional || p.Zone != "europe-west1-b" || p.Region != "europe-west1" {
		t.Errorf("placement = regional:%v zone:%q region:%q", p.Regional, p.Zone, p.Region)
	}
}

// Without an autoscaler a MIG has ONE size, not an envelope. Accepting a range
// would report bounds the resource cannot hold.
func TestBuildMIGCreateFixedSizeNeedsEqualBounds(t *testing.T) {
	attrs := migAttrs()
	attrs["autoscaling.enabled"] = false
	impl := migImpl()
	delete(impl, "target_cpu_utilization")

	if _, err := BuildMIGCreate("acme-prod", "production", "web-fleet", attrs, impl, 0); err == nil {
		t.Fatal("a fixed-size group with a 2..10 range was accepted")
	} else if !strings.Contains(err.Error(), "could never be satisfied") {
		t.Errorf("refusal = %q", err)
	}

	attrs["replicas.minimum"] = 3
	attrs["replicas.maximum"] = 3
	p, err := BuildMIGCreate("acme-prod", "production", "web-fleet", attrs, impl, 0)
	if err != nil {
		t.Fatalf("a legitimate fixed-size fleet was refused: %v", err)
	}
	if p.createBody("web-fleet", "production")["targetSize"] != 3 {
		t.Errorf("targetSize = %v", p.createBody("web-fleet", "production")["targetSize"])
	}
}

func TestMIGNameIsDeterministicAndScoped(t *testing.T) {
	a, _ := BuildMIGCreate("acme-prod", "production", "web-fleet", migAttrs(), migImpl(), 0)
	b, _ := BuildMIGCreate("acme-prod", "production", "web-fleet", migAttrs(), migImpl(), 0)
	if a.Name == "" || a.Name != b.Name {
		t.Errorf("name is not deterministic: %q vs %q", a.Name, b.Name)
	}
	for _, o := range []struct {
		env, cap string
		gen      int
	}{{"staging", "web-fleet", 0}, {"production", "batch-fleet", 0}, {"production", "web-fleet", 2}} {
		got, _ := BuildMIGCreate("acme-prod", o.env, o.cap, migAttrs(), migImpl(), o.gen)
		if got.Name == a.Name {
			t.Errorf("%s/%s/g%d shares the name %q", o.env, o.cap, o.gen, a.Name)
		}
	}
}

func TestBuildMIGCreateRefusals(t *testing.T) {
	cases := []struct {
		name  string
		mutA  func(map[string]any)
		mutI  func(map[string]any)
		wants string
	}{
		{"no capacity envelope", func(a map[string]any) { delete(a, "replicas.maximum") }, nil, "both required"},
		{"a floor above the ceiling", func(a map[string]any) {
			a["replicas.minimum"] = 10
			a["replicas.maximum"] = 2
		}, nil, "exceeds replicas.maximum"},
		{"a fractional replica count", func(a map[string]any) { a["replicas.minimum"] = 1.5 }, nil, "whole number of machines"},
		{"an unknown availability class", func(a map[string]any) { a["availability.class"] = "multi-regional" }, nil, "has no managed-instance-group mapping"},
		{"an attribute the driver cannot map", func(a map[string]any) { a["encryption.atRest"] = true }, nil, "refusing rather than silently dropping it"},
		{"an unmanaged group is an adoption", func(a map[string]any) { a["service.managed"] = false }, nil, "adoption, not a create"},
		{"no instance template", nil, func(i map[string]any) { delete(i, "instance_template") }, "implementation.instance_template is required"},
		{"a template reference that is not one", nil, func(i map[string]any) { i["instance_template"] = "Not A Template" }, "is not an instance-template reference"},
		{"autoscaling wanted with no target", nil, func(i map[string]any) { delete(i, "target_cpu_utilization") }, "the driver does not invent one"},
		{"a target that is not a percentage", nil, func(i map[string]any) { i["target_cpu_utilization"] = 0 }, "between 1 and 100"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			attrs, impl := migAttrs(), migImpl()
			if tc.mutA != nil {
				tc.mutA(attrs)
			}
			if tc.mutI != nil {
				tc.mutI(impl)
			}
			_, err := BuildMIGCreate("acme-prod", "production", "web-fleet", attrs, impl, 0)
			if err == nil {
				t.Fatalf("build succeeded; want a refusal mentioning %q", tc.wants)
			}
			if !strings.Contains(err.Error(), tc.wants) {
				t.Errorf("refusal = %q, want it to mention %q", err, tc.wants)
			}
		})
	}
}

// The residency check: without it the fleet runs in the wrong jurisdiction and
// the contract reports satisfied.
func TestBuildMIGCreateZoneMustSitInsideTheRegion(t *testing.T) {
	attrs := migAttrs()
	attrs["availability.class"] = "zonal"
	impl := migImpl()
	impl["zone"] = "us-central1-a"

	_, err := BuildMIGCreate("acme-prod", "production", "web-fleet", attrs, impl, 0)
	if err == nil {
		t.Fatal("a zone outside the contract's region was accepted")
	}
	if !strings.Contains(err.Error(), "the contract did not ask for") {
		t.Errorf("refusal = %q", err)
	}
}

func TestBuildMIGCreateZonalNeedsAZone(t *testing.T) {
	attrs := migAttrs()
	attrs["availability.class"] = "zonal"
	_, err := BuildMIGCreate("acme-prod", "production", "web-fleet", attrs, migImpl(), 0)
	if err == nil || !strings.Contains(err.Error(), "implementation.zone is required") {
		t.Errorf("refusal = %v", err)
	}
}

func TestClassifyMIGChange(t *testing.T) {
	for _, path := range []string{"replicas.minimum", "replicas.maximum", "autoscaling.enabled"} {
		if class, why := classifyMIGChange(path); class != "mutable" || why == "" {
			t.Errorf("%s classified %q/%q, want mutable with a reason", path, class, why)
		}
	}
	for _, path := range []string{"location.region", "availability.class", "network.publicExposure"} {
		if class, why := classifyMIGChange(path); class != "immutable" || why == "" {
			t.Errorf("%s classified %q/%q, want immutable with a reason", path, class, why)
		}
	}
	if class, _ := classifyMIGChange("service.managed"); class != "unsupported" {
		t.Errorf("service.managed classified %q", class)
	}
	if class, why := classifyMIGChange("something.invented"); class != "" || why != "" {
		t.Errorf("an unknown path classified %q/%q", class, why)
	}
}
