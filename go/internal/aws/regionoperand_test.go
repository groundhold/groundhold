package aws

import (
	"strings"
	"testing"
)

// D279: capabilities whose VOCAB declares no location.region cannot satisfy an
// attrs-side region gate — their region is an implementation operand
// (typically {$ref: eks.region} / {$ref: <vpc-cap>.region}).

func TestRegionOperandResolution(t *testing.T) {
	if r := regionOperand(map[string]any{"location.region": "eu-west-1"},
		map[string]any{"region": "eu-central-1"}); r != "eu-central-1" {
		t.Fatalf("the implementation operand must win, got %q", r)
	}
	if r := regionOperand(map[string]any{"location.region": "eu-west-1"},
		map[string]any{}); r != "eu-west-1" {
		t.Fatalf("attrs fallback = %q", r)
	}
	if r := regionOperand(map[string]any{}, map[string]any{}); r != "" {
		t.Fatalf("no source must yield empty, got %q", r)
	}
}

func TestVocabRegionFreeServicesAreExemptFromAttrsGate(t *testing.T) {
	for _, svc := range []string{"eks-addon", "eks-podidentity", "loadbalancer"} {
		if !isGlobalService(svc) {
			t.Fatalf("%s has a region-free vocab and must be exempt from the "+
				"attrs location.region gate (D279)", svc)
		}
	}
}

func TestCreateRefusalNamesImplementationRegion(t *testing.T) {
	t.Setenv("AWS_ACCESS_KEY_ID", "AKID")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "secret")
	d := NewDriver("")
	for _, svc := range []string{"eks-addon", "eks-podidentity", "loadbalancer"} {
		res := d.Create(svc, "cap", "prod", map[string]any{}, map[string]any{}, "k", 1)
		if res.Status != "failed" || !strings.Contains(res.Reason, "implementation.region") {
			t.Fatalf("%s create without a region must refuse naming "+
				"implementation.region, got %+v", svc, res)
		}
	}
}
