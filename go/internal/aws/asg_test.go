package aws

import (
	"strconv"
	"strings"
	"testing"
)

func asgAttrs() map[string]any {
	return map[string]any{
		"location.region":        "eu-central-1",
		"availability.class":     "regional",
		"replicas.minimum":       2,
		"replicas.maximum":       10,
		"autoscaling.enabled":    true,
		"network.publicExposure": false,
		"service.managed":        true,
	}
}

func asgImpl() map[string]any {
	return map[string]any{
		"subnet_ids":             []any{"subnet-0abc123456789def0", "subnet-0fed987654321cba0"},
		"launch_template_id":     "lt-0123456789abcdef0",
		"target_cpu_utilization": 60,
	}
}

func TestBuildASGCreateGolden(t *testing.T) {
	p, err := BuildASGCreate("production", "web-fleet", asgAttrs(), asgImpl(), 0)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	got := ec2RunForm(t, p.createBody())
	want := map[string]string{
		"Action":                          "CreateAutoScalingGroup",
		"MinSize":                         "2",
		"MaxSize":                         "10",
		"VPCZoneIdentifier":               "subnet-0abc123456789def0,subnet-0fed987654321cba0",
		"LaunchTemplate.LaunchTemplateId": "lt-0123456789abcdef0",
	}
	for k, v := range want {
		if got.Get(k) != v {
			t.Errorf("%s = %q, want %q", k, got.Get(k), v)
		}
	}
	// AWS starts a group at MinSize. Sending a desired size the contract never
	// mentioned would provision machines nobody asked for.
	if got.Has("DesiredCapacity") {
		t.Errorf("DesiredCapacity = %q was sent, but the contract declares only an envelope",
			got.Get("DesiredCapacity"))
	}
	// Ownership tags must reach the MACHINES, not only the group — a fleet whose
	// members are untagged is a fleet nothing else can attribute.
	var propagated bool
	for i := 1; i <= 4; i++ {
		if got.Get("Tags.member."+strconv.Itoa(i)+".PropagateAtLaunch") == "true" {
			propagated = true
		}
	}
	if !propagated {
		t.Error("ownership tags do not propagate at launch")
	}
}

func TestASGPolicyBodyCarriesOnlyTheOperatorsTarget(t *testing.T) {
	p, err := BuildASGCreate("production", "web-fleet", asgAttrs(), asgImpl(), 0)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	got := ec2RunForm(t, p.policyBody())
	if got.Get("Action") != "PutScalingPolicy" || got.Get("PolicyType") != "TargetTrackingScaling" {
		t.Errorf("policy = %q/%q", got.Get("Action"), got.Get("PolicyType"))
	}
	if got.Get("TargetTrackingConfiguration.TargetValue") != "60" {
		t.Errorf("target = %q, want the operator's 60", got.Get("TargetTrackingConfiguration.TargetValue"))
	}
}

// The name IS the idempotency mechanism: CreateAutoScalingGroup takes no client
// token, so a name that varied between builds would make a retry create a SECOND
// fleet — and pay for it.
func TestASGNameIsDeterministicAndScoped(t *testing.T) {
	a, _ := BuildASGCreate("production", "web-fleet", asgAttrs(), asgImpl(), 0)
	b, _ := BuildASGCreate("production", "web-fleet", asgAttrs(), asgImpl(), 0)
	if a.Name == "" || a.Name != b.Name {
		t.Errorf("name is not deterministic: %q vs %q", a.Name, b.Name)
	}
	for _, o := range []struct {
		env, cap string
		gen      int
	}{{"staging", "web-fleet", 0}, {"production", "batch-fleet", 0}, {"production", "web-fleet", 2}} {
		got, _ := BuildASGCreate(o.env, o.cap, asgAttrs(), asgImpl(), o.gen)
		if got.Name == a.Name {
			t.Errorf("%s/%s/g%d shares the name %q", o.env, o.cap, o.gen, a.Name)
		}
	}
}

func TestBuildASGCreateRefusals(t *testing.T) {
	cases := []struct {
		name  string
		mutA  func(map[string]any)
		mutI  func(map[string]any)
		wants string
	}{
		{
			name:  "no capacity envelope",
			mutA:  func(a map[string]any) { delete(a, "replicas.minimum") },
			wants: "both required",
		},
		{
			// An envelope with no interior cannot be satisfied by any fleet size.
			name: "a floor above the ceiling",
			mutA: func(a map[string]any) {
				a["replicas.minimum"] = 10
				a["replicas.maximum"] = 2
			},
			wants: "exceeds replicas.maximum",
		},
		{
			name:  "a fractional replica count",
			mutA:  func(a map[string]any) { a["replicas.minimum"] = 1.5 },
			wants: "whole number of machines",
		},
		{
			// The class is a consequence of the subnets, so a regional claim over one
			// subnet is a durability guarantee that does not exist.
			name:  "regional over a single subnet",
			mutI:  func(i map[string]any) { i["subnet_ids"] = []any{"subnet-0abc123456789def0"} },
			wants: "does not survive losing it",
		},
		{
			// And the reverse: the group would observe back as regional and the
			// contract would report a violation it can never resolve.
			name:  "zonal over several subnets",
			mutA:  func(a map[string]any) { a["availability.class"] = "zonal" },
			wants: "can never resolve",
		},
		{
			name:  "an unknown availability class",
			mutA:  func(a map[string]any) { a["availability.class"] = "multi-regional" },
			wants: "has no Auto Scaling mapping",
		},
		{
			name:  "no subnets",
			mutI:  func(i map[string]any) { delete(i, "subnet_ids") },
			wants: "implementation.subnet_ids is required",
		},
		{
			name:  "a subnet that is not one",
			mutI:  func(i map[string]any) { i["subnet_ids"] = []any{"vpc-0abc123456789def0", "subnet-0fed987654321cba0"} },
			wants: "which is not a subnet id",
		},
		{
			name:  "no launch template",
			mutI:  func(i map[string]any) { delete(i, "launch_template_id") },
			wants: "implementation.launch_template_id is required",
		},
		{
			name:  "a launch template that is not one",
			mutI:  func(i map[string]any) { i["launch_template_id"] = "ami-0123456789abcdef0" },
			wants: "is not a launch-template id",
		},
		{
			name:  "a version selector that is not one",
			mutI:  func(i map[string]any) { i["launch_template_version"] = "newest" },
			wants: "is not a version selector",
		},
		{
			// The policy's tuning is deliberately outside the vocabulary (D363), so
			// inventing a target would attach a control loop nobody reviewed.
			name:  "autoscaling wanted with no target",
			mutI:  func(i map[string]any) { delete(i, "target_cpu_utilization") },
			wants: "the driver does not invent one",
		},
		{
			// Silence here would leave the operator believing the fleet scales.
			name:  "a target with no policy to carry it",
			mutA:  func(a map[string]any) { a["autoscaling.enabled"] = false },
			wants: "the fleet would stay fixed-size",
		},
		{
			name:  "a target that is not a percentage",
			mutI:  func(i map[string]any) { i["target_cpu_utilization"] = 140 },
			wants: "between 1 and 100",
		},
		{
			name:  "an unmanaged group is an adoption, not a create",
			mutA:  func(a map[string]any) { a["service.managed"] = false },
			wants: "adoption, not a create",
		},
		{
			name:  "an attribute the driver cannot map",
			mutA:  func(a map[string]any) { a["encryption.atRest"] = true },
			wants: "refusing rather than silently dropping it",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			attrs, impl := asgAttrs(), asgImpl()
			if tc.mutA != nil {
				tc.mutA(attrs)
			}
			if tc.mutI != nil {
				tc.mutI(impl)
			}
			_, err := BuildASGCreate("production", "web-fleet", attrs, impl, 0)
			if err == nil {
				t.Fatalf("build succeeded; want a refusal mentioning %q", tc.wants)
			}
			if !strings.Contains(err.Error(), tc.wants) {
				t.Errorf("refusal = %q, want it to mention %q", err, tc.wants)
			}
		})
	}
}

// A fixed-size fleet is a legitimate group: floor == ceiling, no policy.
func TestBuildASGCreateFixedSizeFleet(t *testing.T) {
	attrs := asgAttrs()
	attrs["autoscaling.enabled"] = false
	attrs["replicas.minimum"] = 3
	attrs["replicas.maximum"] = 3
	impl := asgImpl()
	delete(impl, "target_cpu_utilization")

	p, err := BuildASGCreate("production", "web-fleet", attrs, impl, 0)
	if err != nil {
		t.Fatalf("a fixed-size fleet was refused: %v", err)
	}
	if p.AutoscalingWanted {
		t.Error("a fleet with no policy was planned as autoscaling")
	}
	body := ec2RunForm(t, p.createBody())
	if body.Get("MinSize") != "3" || body.Get("MaxSize") != "3" {
		t.Errorf("envelope = %q..%q", body.Get("MinSize"), body.Get("MaxSize"))
	}
}

// The first member of the compute family where most of the vocabulary IS mutable
// — resizing the envelope is what a group is FOR.
func TestClassifyASGChange(t *testing.T) {
	for _, path := range []string{"replicas.minimum", "replicas.maximum", "autoscaling.enabled"} {
		if class, why := classifyASGChange(path); class != "mutable" || why == "" {
			t.Errorf("%s classified %q/%q, want mutable with a reason", path, class, why)
		}
	}
	if class, why := classifyASGChange("location.region"); class != "immutable" || why == "" {
		t.Errorf("location.region classified %q/%q, want immutable with a reason", class, why)
	}
	// D822: availability.class and network.publicExposure were pinned "immutable" here.
	// Both were claims about AWS, and AWS contradicts both — UpdateAutoScalingGroup accepts
	// VPCZoneIdentifier/AvailabilityZones, and public addressing lives in a launch template
	// this tool does not author (a statement about groundhold, not a replacement AWS needs).
	for _, path := range []string{"availability.class", "network.publicExposure"} {
		if class, why := classifyASGChange(path); class != "unsupported" || why == "" {
			t.Errorf("%s classified %q/%q, want unsupported with a reason", path, class, why)
		}
	}
	if class, _ := classifyASGChange("service.managed"); class != "unsupported" {
		t.Errorf("service.managed classified %q", class)
	}
	if class, why := classifyASGChange("something.invented"); class != "" || why != "" {
		t.Errorf("an unknown path classified %q/%q", class, why)
	}
}
