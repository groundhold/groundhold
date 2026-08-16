package provider_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// D1135. The release workflow skips two gates on the mirror — the mutation meter and
// the standalone export gate — because both are private tooling that does not cross
// the boundary. The comment explaining that skip does not merely note it; it makes a
// claim of fact: they "gate the PRIVATE source before the sync ... so the shipping
// code has already passed them".
//
// Half of it was true. This script runs the export gate, so an export that cannot
// stand alone never reaches a branch. Nothing ran the meter. Its only automated caller
// is a CI job that this repository's way of working does not trigger, so the 639
// re-injected bugs it re-checks were guarded on no automated path at all — while a
// sentence in the release workflow said the shipping code had passed them.
//
// A skip justified by a step somebody else performs is only as good as that step. The
// repair is not to soften the sentence: it is to perform it, which is what the receipt
// check does. This gate ties the two together, so the justification cannot outlive the
// thing justifying it.
func TestTheSkippedReleaseGatesAreActuallyPerformedBeforeTheSync(t *testing.T) {
	skipIfExported(t, "the release workflow and the publication script")
	root := repoRoot(t)

	rel, err := os.ReadFile(filepath.Join(root, ".github", "workflows", "release.yml"))
	if err != nil {
		t.Fatal(err)
	}
	sync, err := os.ReadFile(filepath.Join(root, "scripts", "sync-public.sh"))
	if err != nil {
		t.Fatal(err)
	}
	release, publish := string(rel), string(sync)

	// The premise: the release itself does NOT run these. If that ever stops being
	// true the justification is moot, but so is this gate — say so rather than
	// silently checking a claim nobody is making any more.
	const claim = "gate the PRIVATE source before the sync"
	if !strings.Contains(release, claim) {
		t.Fatalf("the release workflow no longer claims to %q — either the skip was "+
			"removed or the sentence was reworded, and this gate is now measuring "+
			"something nobody asserts (D328)", claim)
	}

	// What the claim promises, each backed by the step that performs it.
	for _, must := range []struct{ what, needle, why string }{
		{
			what:   "the standalone export gate",
			needle: "scripts/export-public.sh",
			why:    "an export that cannot build and pass its own suite must not reach a branch",
		},
		{
			what:   "the mutation meter",
			needle: ".mutation-pass",
			why: "the release skips the meter on the mirror because this side already ran it; " +
				"without a receipt naming the commit being published, that is a claim about " +
				"a run nobody made",
		},
	} {
		if !strings.Contains(publish, must.needle) {
			t.Errorf("the release workflow says %s ran before the sync, and the publication "+
				"script does not perform it (%s missing) — %s", must.what, must.needle, must.why)
		}
	}

	// A receipt that is not compared to the commit being published would pass a run
	// from any earlier state, which is the failure the receipt exists to prevent.
	if !strings.Contains(publish, "rev-parse HEAD") {
		t.Error("the mutation receipt is not compared against HEAD — a receipt from an " +
			"earlier commit says nothing about the one being published")
	}
}
