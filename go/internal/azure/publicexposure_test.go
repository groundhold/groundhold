package azure

import "testing"

// D822. The scale set said its zone list was "fixed when the scale set is created". Microsoft
// documents the opposite for the direction that matters: "You can modify a scale set to
// expand the set of zones over which to spread VM instances", limited by "You can't remove
// or replace zones, only add zones".
//
// So RAISING availability is an in-place update. The old classification told an operator to
// destroy a running fleet in order to make it safer, which is the worst shape a false claim
// can take: it punishes the change you want people to make.
func TestScaleSetDoesNotClaimAReplacementAzureDoesNotRequire(t *testing.T) {
	class, reason := classifyVMSSChange("availability.class")
	if class == "immutable" {
		t.Fatalf("classified immutable (%q), so widening a scale set's zones destroys and "+
			"recreates the fleet — but Azure supports adding zones on a live scale set", reason)
	}
	if reason == "" {
		t.Fatal("a refusal with no reason sends nobody anywhere")
	}
}
