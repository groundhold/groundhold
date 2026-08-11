package compiler

import "testing"

// D837. `deleteRisk` hardcoded SecurityExposure "none" for every delete of every
// capability — including the ones the vocabulary marks `protection: true`, whose whole
// purpose is to BE a security control (a WAF, threat detection). Removing one is the
// clearest security exposure a plan can carry, and the plan said there was none.
//
// The standard is this file's own, stated three lines above updateRisk: "Where the
// direction is not derivable, the answer is 'possible', never 'none': the compiler has
// established nothing about it, and `none` is a claim." Here the direction IS derivable —
// D698 put the marker in the vocabulary for exactly this question.
func TestDeletingAProtectionIsAnExposure(t *testing.T) {
	if got := deleteRisk(true, true).SecurityExposure; got != "certain" {
		t.Fatalf("deleting a protection capability reported SecurityExposure %q — a plan "+
			"that removes a WAF and calls the exposure %q tells an operator the control "+
			"costs nothing to drop", got, got)
	}
	if got := deleteRisk(true, false).SecurityExposure; got != "none" {
		t.Fatalf("deleting an ordinary capability reported SecurityExposure %q, want none — "+
			"removing a resource is not an exposure by itself", got)
	}
}
