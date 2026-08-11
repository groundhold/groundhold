package gcp

import "testing"

// D821. The twin of the AWS case, and the clearer one: Compute Engine publishes THREE
// methods for exactly this change — instances.addAccessConfig, deleteAccessConfig and
// updateAccessConfig, all against an existing instance's network interface — while the
// driver told the compiler the change was impossible in place, which makes the plan
// destroy and recreate the machine.
//
// `unsupported` is the honest answer while no updater is wired: the capability is blocked
// with a reason that names what Google does support, instead of a replacement nobody needs.
func TestComputeInstanceDoesNotClaimAReplacementGoogleDoesNotRequire(t *testing.T) {
	class, reason := classifyGCEInstanceChange("network.publicExposure")
	if class == "immutable" {
		t.Fatalf("classified immutable (%q), so the plan destroys and recreates the machine "+
			"— but GCE changes it in place with instances.addAccessConfig / "+
			"deleteAccessConfig / updateAccessConfig (compute/v1 discovery document)", reason)
	}
	if reason == "" {
		t.Fatal("a refusal with no reason sends nobody anywhere")
	}
}
