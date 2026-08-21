package aws

import "testing"

// memImpl is a minimal valid lambda create impl with a declared memory_size.
func memImpl(mem any) map[string]any {
	m := map[string]any{
		"image_uri": "000000000000.dkr.ecr.eu-central-1.amazonaws.com/fn:latest",
		"role_arn":  "arn:aws:iam::000000000000:role/fn-exec",
	}
	if mem != nil {
		m["memory_size"] = mem
	}
	return m
}

func memAttrs() map[string]any { return map[string]any{"location.region": "eu-central-1"} }

// TestLambdaMemorySizeOperandBuildsAndPatches pins memory_size end to end on the pure
// paths: it reaches the CreateFunction body AND the UpdateFunctionConfiguration body (so
// it survives recreation AND corrects drift — the family complaint), it is declared-only
// in OperandTargets (an adopted function whose contract is silent must not drift to AWS's
// 128 MB default), and it classifies as an in-place patch, never a replacement.
func TestLambdaMemorySizeOperandBuildsAndPatches(t *testing.T) {
	p, err := BuildLambda("000000000000", "prod", "api", memAttrs(), memImpl(1024), 1)
	if err != nil {
		t.Fatal(err)
	}
	if !p.MemorySizeSet || p.MemorySize != 1024 {
		t.Fatalf("memory_size not read into the plan: set=%v val=%d", p.MemorySizeSet, p.MemorySize)
	}
	if got := p.createBody("api", "prod")["MemorySize"]; got != 1024 {
		t.Fatalf("createBody must carry MemorySize, got %v", got)
	}
	if got := p.updateConfigBody()["MemorySize"]; got != 1024 {
		t.Fatalf("updateConfigBody must carry MemorySize so drift patches online, got %v", got)
	}
	if class, _ := classifyLambdaChange(lambdaMemOperand); class != "mutable" {
		t.Fatalf("a memory_size change must be an in-place patch, got %q", class)
	}

	// declared-only target
	targets, err := (&Driver{}).OperandTargets("lambda", memAttrs(), memImpl(2048))
	if err != nil {
		t.Fatal(err)
	}
	found := ""
	for _, tg := range targets {
		if tg.Path == lambdaMemOperand {
			found, _ = tg.Desired.(string)
		}
	}
	if found != "2048" {
		t.Fatalf("a declared memory_size must yield a target, got %q", found)
	}
	// no memory_size declared -> NO target (must not drift an adopted function to 128)
	silent, _ := (&Driver{}).OperandTargets("lambda", memAttrs(), memImpl(nil))
	for _, tg := range silent {
		if tg.Path == lambdaMemOperand {
			t.Fatalf("a silent contract must NOT emit a memory target, got %v", tg.Desired)
		}
	}

	// an absent operand leaves the plan unset (AWS default 128, not a forged 0)
	p0, _ := BuildLambda("000000000000", "prod", "api", memAttrs(), memImpl(nil), 1)
	if p0.MemorySizeSet {
		t.Fatal("no memory_size declared must leave MemorySizeSet false")
	}
	if p0.createBody("api", "prod")["MemorySize"] != nil {
		t.Fatal("an absent memory_size must not appear in the create body")
	}
}

// TestLambdaMemorySizeRangeRefused pins the preflight range check: memory on Lambda is
// the CPU allocation, so a value AWS would reject is refused BEFORE the apply, not
// clamped and not left to fail mid-mutation.
func TestLambdaMemorySizeRangeRefused(t *testing.T) {
	for _, bad := range []int{127, 0, -1, 10241, 20000} {
		if _, err := BuildLambda("000000000000", "prod", "api", memAttrs(), memImpl(bad), 1); err == nil {
			t.Errorf("memory_size %d is out of range and must refuse in preflight", bad)
		}
	}
	for _, ok := range []int{128, 512, 1769, 10240} {
		if _, err := BuildLambda("000000000000", "prod", "api", memAttrs(), memImpl(ok), 1); err != nil {
			t.Errorf("memory_size %d is in range and must build, got %v", ok, err)
		}
	}
	// a non-integer memory_size is refused (never silently defaulted)
	if _, err := BuildLambda("000000000000", "prod", "api", memAttrs(), memImpl("lots"), 1); err == nil {
		t.Error("a non-integer memory_size must refuse")
	}
}

// TestObserveLambdaMemorySize pins the observe side: the live memory is read back and
// rendered exactly as OperandTargets renders the declared value, so a drift is comparable.
func TestObserveLambdaMemorySize(t *testing.T) {
	d, done := operandDriver(t, "ok")
	defer done()
	obs, _, err := d.observeLambda("api", operandPID)
	if err != nil {
		t.Fatal(err)
	}
	var got string
	for _, o := range obs {
		if o.Path == lambdaMemOperand {
			got, _ = o.Value.(string)
		}
	}
	if got != "1024" {
		t.Fatalf("observe must read back MemorySize as the operand value, got %q", got)
	}
	// and it compares like-for-like against a declared 1024 (no spurious drift)
	targets, _ := d.OperandTargets("lambda", memAttrs(), memImpl(1024))
	var desired string
	for _, tg := range targets {
		if tg.Path == lambdaMemOperand {
			desired, _ = tg.Desired.(string)
		}
	}
	if desired != got {
		t.Fatalf("declared 1024 must match observed 1024 byte-for-byte: desired %q observed %q", desired, got)
	}
}
