package ledger

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"testing"

	"groundhold/internal/state"
)

// D338: `MutationTypes[etype]` is what makes an append require an active lease and
// a matching fencing token (D29). Membership is hand-maintained, and the default is
// silent: a mutating event type omitted from the map is appended with no lease and
// no token at all. That is the fail-open shape D330 found in perrnext's `next`
// coverage, except here the thing left undecided is a concurrency control.
//
// The fix is the same one that package already uses: force an explicit decision.
// Every event type must be in MutationTypes or in NonMutatingTypes, never both and
// never neither.
func TestEveryEventTypeIsClassified(t *testing.T) {
	if len(state.EventTypes) == 0 || len(MutationTypes) == 0 || len(NonMutatingTypes) == 0 {
		t.Fatal("an input set is empty — the gate would be vacuous (D328)")
	}

	var undecided, both []string
	for etype := range state.EventTypes {
		m, n := MutationTypes[etype], NonMutatingTypes[etype]
		switch {
		case m && n:
			both = append(both, etype)
		case !m && !n:
			undecided = append(undecided, etype)
		}
	}
	sort.Strings(undecided)
	sort.Strings(both)

	if len(undecided) > 0 {
		t.Errorf("event types classified neither mutating nor non-mutating: %v\n"+
			"They append with NO lease and NO fencing token — if any of them changes "+
			"the world, D29's concurrency control is silently off for it.", undecided)
	}
	if len(both) > 0 {
		t.Errorf("event types in BOTH MutationTypes and NonMutatingTypes: %v", both)
	}

	// The reverse direction: a classification naming a type the registry does not
	// know is dead weight that reads like coverage.
	for _, set := range []struct {
		name string
		m    map[string]bool
	}{{"MutationTypes", MutationTypes}, {"NonMutatingTypes", NonMutatingTypes}} {
		var unknown []string
		for etype := range set.m {
			if !state.EventTypes[etype] {
				unknown = append(unknown, etype)
			}
		}
		sort.Strings(unknown)
		if len(unknown) > 0 {
			t.Errorf("%s classifies types absent from the closed registry: %v",
				set.name, unknown)
		}
	}
}

// D599. The gate above forces a decision; it does not check the decision is the SAME
// one on both sides of the dual implementation. It was not. The runtime carried
// `ownership.claimed` in MutationTypes; the reference implementation and
// spec/state-model.md §2 did not. So an authorship stamp appended with no lease —
// exactly what §1 says the event is — was accepted by the reference and REFUSED by
// the runtime with "mutation requires a fencing token (D29)".
//
// This is D338's interop failure one layer in: the two agreed on the event-type
// REGISTRY and disagreed on the RULE attached to one member. It survived because the
// differential fuzzer drew its event types from a hand-copied list of eleven that
// never contained this one; with the alphabet derived from the schema instead (D598's
// sibling), the same seeds that had been silent found it inside 40 documents.
func TestEventClassificationAgreesAcrossImplementations(t *testing.T) {
	root := classRepoRoot(t)

	for _, c := range []struct {
		what string
		runtime,
		reference map[string]bool
	}{
		{"mutation set (active lease + matching fencing token required, D29)",
			MutationTypes, pyClassSet(t, root, "MUTATION_TYPES")},
		{"decision set (advances the heads a sealed plan pins, D41)",
			DecisionTypes, pyDecisionSet(t, root)},
	} {
		if len(c.runtime) == 0 || len(c.reference) == 0 {
			t.Fatalf("%s: a side parsed to ZERO types — the gate would be vacuous "+
				"(D328): runtime=%d reference=%d",
				c.what, len(c.runtime), len(c.reference))
		}
		if d := setDiff(c.runtime, c.reference); len(d) > 0 {
			t.Errorf("%s DIFFERS between the runtime and the reference: %v\n"+
				"A type one side calls a mutation and the other does not makes a ledger "+
				"one side writes unappendable on the other.", c.what, d)
		}
	}

	// The spec publishes the same set, and it is all a third implementation has.
	if d := setDiff(MutationTypes, specMutationTypes(t, root)); len(d) > 0 {
		t.Errorf("the runtime's mutation set differs from the registry published in "+
			"spec/state-model.md §2: %v", d)
	}
}

func setDiff(runtime, reference map[string]bool) []string {
	var out []string
	for k := range runtime {
		if !reference[k] {
			out = append(out, "only in runtime: "+k)
		}
	}
	for k := range reference {
		if !runtime[k] {
			out = append(out, "only in reference: "+k)
		}
	}
	sort.Strings(out)
	return out
}

func classRepoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 8; i++ {
		if _, err := os.Stat(filepath.Join(dir, "spec", "state-model.md")); err == nil {
			return dir
		}
		dir = filepath.Dir(dir)
	}
	t.Skip("no spec/ above this directory — an exported tree has nothing to compare")
	return ""
}

func classRead(t *testing.T, root string, parts ...string) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(append([]string{root}, parts...)...))
	if err != nil {
		t.Fatalf("cannot read the artefact this gate compares against — a gate that "+
			"loses its subject must fail, not pass (D565): %v", err)
	}
	return string(raw)
}

func dottedSet(s string) map[string]bool {
	out := map[string]bool{}
	for _, m := range regexp.MustCompile(`[a-z][a-z0-9]*(?:\.[a-z0-9]+)+`).
		FindAllString(s, -1) {
		out[m] = true
	}
	return out
}

func pyClassSet(t *testing.T, root, name string) map[string]bool {
	t.Helper()
	raw := classRead(t, root, "ref", "groundholdlib", "scenario.py")
	m := regexp.MustCompile(`(?s)` + name + `\s*=\s*\{(.*?)\}`).FindStringSubmatch(raw)
	if m == nil {
		t.Fatalf("could not find %s in ref/groundholdlib/scenario.py — if its shape "+
			"changed, this gate must be re-taught, never silently skipped", name)
	}
	return dottedSet(m[1])
}

// DECISION_TYPES is written as MUTATION_TYPES | {...}; read it as that union.
func pyDecisionSet(t *testing.T, root string) map[string]bool {
	t.Helper()
	raw := classRead(t, root, "ref", "groundholdlib", "scenario.py")
	m := regexp.MustCompile(`(?s)DECISION_TYPES\s*=\s*MUTATION_TYPES\s*\|\s*\{(.*?)\}`).
		FindStringSubmatch(raw)
	if m == nil {
		t.Fatal("DECISION_TYPES in ref/groundholdlib/scenario.py is no longer a union " +
			"over MUTATION_TYPES — re-teach this gate rather than dropping it")
	}
	out := pyClassSet(t, root, "MUTATION_TYPES")
	for k := range dottedSet(m[1]) {
		out[k] = true
	}
	return out
}

func specMutationTypes(t *testing.T, root string) map[string]bool {
	t.Helper()
	m := regexp.MustCompile("(?s)### Mutation type registry.*?```\\n(.*?)```").
		FindStringSubmatch(classRead(t, root, "spec", "state-model.md"))
	if m == nil {
		t.Fatal("spec/state-model.md no longer publishes a mutation type registry " +
			"block — a third implementation would have only prose to build against")
	}
	set := dottedSet(m[1])
	if len(set) == 0 {
		t.Fatal("the published mutation registry block parsed to nothing (D328)")
	}
	return set
}
