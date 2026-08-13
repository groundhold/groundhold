package state

import (
	"regexp"
	"testing"
)

// ActorTypes is the closed set of event actor types, validated on load in BOTH
// implementations (ValidateEvent here; state.py's ACTOR_TYPES in the reference).
// EVENT_TYPES already carries a Go/Python/spec registry gate; this is the sibling
// set that did not, and D25 makes it the same contract — an actor type accepted by
// one implementation and refused by the other is a ledger one writes and the other
// cannot replay (the D338 failure mode, on a smaller set).
func TestActorTypesMatchThePythonReference(t *testing.T) {
	raw := readRepoFile(t, "ref", "groundholdlib", "state.py")
	m := regexp.MustCompile(`ACTOR_TYPES\s*=\s*\{([^}]*)\}`).FindStringSubmatch(raw)
	if m == nil {
		t.Fatal("could not find ACTOR_TYPES in ref/groundholdlib/state.py — a gate that " +
			"loses its subject must fail, not pass (D565)")
	}
	py := map[string]bool{}
	for _, q := range regexp.MustCompile(`"([^"]+)"`).FindAllStringSubmatch(m[1], -1) {
		py[q[1]] = true
	}
	if len(py) == 0 || len(ActorTypes) == 0 {
		t.Fatal("an actor-type set is empty — the gate would be vacuous (D328)")
	}
	for k := range ActorTypes {
		if !py[k] {
			t.Errorf("Go accepts actor type %q but the Python reference does not — a ledger "+
				"the runtime writes is refused by the reference (D25 divergence)", k)
		}
	}
	for k := range py {
		if !ActorTypes[k] {
			t.Errorf("the Python reference accepts actor type %q but Go does not — a ledger "+
				"the reference writes is refused by the runtime (D25 divergence)", k)
		}
	}
}
