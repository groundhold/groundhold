package main

import (
	"strings"
	"testing"
)

// D691. Three capability types are declared in the vocabulary and realised by no
// shipped driver: capability.ai.speech, capability.identity.sso and
// capability.identity.oauth-client — the last carrying no `mappings:` anywhere at
// all. A contract can declare one and nothing can ever implement it.
//
// `parity` already knew: it prints `unbuilt` for exactly these, per cloud. `explain
// <type>` — the rung of the discovery ladder an author reads BEFORE writing the
// contract — printed the attribute list and said nothing, so the author learned at
// the bottom (verify reporting it unimplemented, plan blocking) what the top could
// have said.
func TestExplainSaysWhenNoDriverRealisesACapability(t *testing.T) {
	if svcs := servingServices("capability.database.relational"); len(svcs) == 0 {
		t.Fatal("no driver serves the relational database — the probe is broken " +
			"and this gate would call everything unbuilt")
	}
	for _, unbuilt := range []string{
		"capability.ai.speech",
		"capability.identity.sso",
		"capability.identity.oauth-client",
	} {
		if svcs := servingServices(unbuilt); len(svcs) != 0 {
			t.Errorf("%s is now served by %v — remove it from this list and from "+
				"D691's claim rather than leaving the record wrong", unbuilt, svcs)
		}
	}

	out := captureStdout(t, func() {
		run([]string{"explain", "capability.identity.sso", "--vocab",
			repoRootFromCmd(t) + "/spec/vocab"})
	})
	if !strings.Contains(out, "UNBUILT") {
		t.Errorf("explain does not say a capability nothing can build is "+
			"unbuildable:\n%s", out)
	}
	if !strings.Contains(out, "cannot be implemented by any candidate") {
		t.Errorf("the warning does not say what it costs the reader:\n%s", out)
	}

	// The control: a capability four drivers serve must not carry the warning, or
	// it stops meaning anything.
	ok := captureStdout(t, func() {
		run([]string{"explain", "capability.database.relational", "--vocab",
			repoRootFromCmd(t) + "/spec/vocab"})
	})
	if strings.Contains(ok, "UNBUILT") {
		t.Error("a served capability is reported unbuilt")
	}
}
