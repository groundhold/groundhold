package state

import (
	"encoding/json"
	"errors"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// D1159. `source` is the ledger's OTHER closed set, and it had none of what the event
// types have. D338 reconciles those across four artefacts because drift there makes a
// ledger written by one implementation unreadable to the other. Nothing did the same for
// sources, and by the time anyone looked the four copies said three different things:
//
//	the runtime              five values, as string literals across 29 emission sites,
//	                         collected nowhere — so there was nothing to compare
//	spec/state.schema.json   five (D1151 had just corrected it, in a definition that
//	                         nothing referenced — see D1158)
//	spec/state-model.md      THREE: `provider-api | probe | manual`. D1151 fixed the
//	                         enum and left the prose registry beside it untouched.
//	the reference            no set at all
//
// This is not bookkeeping. The compiler BRANCHES on the field: an observation sourced
// `candidate-declared` is adopt-recorded intent, so its path is carried as unverifiable
// — never drift, never a staleness freeze. A source a build does not recognize misses
// that branch and the value is compared as measured reality, which turns "this cannot be
// verified" into "verified by the candidate's own word".
func TestObservationSourceRegistryAgreesEverywhere(t *testing.T) {
	sets := map[string]map[string]bool{
		"go/internal/state/state.go (ObservationSources)": ObservationSources,
		"ref/groundholdlib/state.py (OBSERVATION_SOURCES)": pySet(t,
			"OBSERVATION_SOURCES"),
		"spec/state-model.md (the observation example's comment)": specSources(t),
		"spec/state.schema.json (observation.source enum)":        schemaSources(t),
	}

	names := make([]string, 0, len(sets))
	for n, s := range sets {
		if len(s) == 0 {
			t.Fatalf("%s parsed to ZERO sources — the gate would be vacuous (D328)", n)
		}
		names = append(names, n)
	}
	sort.Strings(names)

	// Compare every artefact against the runtime's set: it is the one that decides
	// what a ledger may hold, so a disagreement is always measured against it.
	want := keys(ObservationSources)
	for _, n := range names {
		got := keys(sets[n])
		if strings.Join(got, " ") != strings.Join(want, " ") {
			t.Errorf("%s publishes\n  %v\nthe runtime accepts\n  %v\n"+
				"A source in one and not the other is a value one side writes and "+
				"the other refuses to load — in the substrate every piece of "+
				"evidence lives in.", n, got, want)
		}
	}

	// The floor that makes the comparison mean something: naming the members is not
	// enough if the set could quietly become a set of one.
	if len(ObservationSources) < 5 {
		t.Errorf("the source set holds %d values; five are published. A shrunken set "+
			"refuses evidence the runtime is right to record.", len(ObservationSources))
	}
}

func keys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// pySet reads a `NAME = { "a", "b" }` literal out of the reference implementation.
func pySet(t *testing.T, name string) map[string]bool {
	t.Helper()
	raw := readRepoFile(t, "ref", "groundholdlib", "state.py")
	m := regexp.MustCompile("(?s)" + name + " = \\{(.*?)\\}").FindStringSubmatch(raw)
	if m == nil {
		t.Fatalf("could not find %s in the reference implementation", name)
	}
	out := map[string]bool{}
	for _, v := range regexp.MustCompile(`"([^"]+)"`).FindAllStringSubmatch(m[1], -1) {
		out[v[1]] = true
	}
	return out
}

// specSources reads the values the published observation example lists in its comment.
// The prose is where a reader learns the set, and it is the copy that drifted.
func specSources(t *testing.T) map[string]bool {
	t.Helper()
	raw := readRepoFile(t, "spec", "state-model.md")
	m := regexp.MustCompile(`(?m)^source: \S+\s+#(.*(?:\n\s*#.*)*)`).FindStringSubmatch(raw)
	if m == nil {
		t.Fatal("could not find the observation example's `source:` line in " +
			"spec/state-model.md — it moved, and this gate is reading nothing (D328)")
	}
	// The list ends at the parenthetical that describes the set — "(closed set,
	// fail-closed)" is prose ABOUT the registry, not a member of it. Parsed by
	// position rather than by filtering words: the first draft skipped anything with
	// a bracket in it and duly read `set` out of `(closed set, ...)`.
	text := strings.ReplaceAll(m[1], "#", " ")
	if i := strings.Index(text, "("); i >= 0 {
		text = text[:i]
	}
	out := map[string]bool{}
	for _, w := range strings.Fields(text) {
		if w := strings.Trim(w, "|,"); w != "" {
			out[w] = true
		}
	}
	return out
}

func schemaSources(t *testing.T) map[string]bool {
	t.Helper()
	raw := readRepoFile(t, "spec", "state.schema.json")
	var doc struct {
		Defs struct {
			Observation struct {
				Properties struct {
					Source struct {
						Enum []string `json:"enum"`
					} `json:"source"`
				} `json:"properties"`
			} `json:"observation"`
		} `json:"$defs"`
	}
	if err := json.Unmarshal([]byte(raw), &doc); err != nil {
		t.Fatalf("state schema does not parse: %v", err)
	}
	out := map[string]bool{}
	for _, s := range doc.Defs.Observation.Properties.Source.Enum {
		out[s] = true
	}
	return out
}

// D1159: the enforcement itself, on the write path. The registry gate above proves the
// four copies agree; this proves the set is CONSULTED — a set everyone agrees on and
// nobody checks is the arrangement that let a typo promote intent into evidence.
func TestAnUnknownObservationSourceIsRefusedAtWrite(t *testing.T) {
	event := func(source string) map[string]any {
		return map[string]any{
			"apiVersion": "state/v0", "kind": "LedgerEvent",
			"event": map[string]any{
				"type": "observation.recorded", "environment": "test",
				"capabilities": []any{"db"},
				"occurredAt":   "2026-07-11T09:00:00Z",
				"actor":        map[string]any{"id": "r", "type": "runtime"},
				"body": map[string]any{"observations": []any{map[string]any{
					"kind": "Observation", "capability": "db", "path": "service.managed",
					"value": true, "source": source, "derivation": "measured",
					"observedAt": "2026-07-11T09:00:00Z", "ttlSeconds": 900,
				}}},
			},
		}
	}

	// Every published source must load, or the refusal is a bug rather than a boundary.
	for src := range ObservationSources {
		if _, err := ValidateEvent(event(src)); err != nil {
			t.Errorf("published source %q was REFUSED: %v — a closed set enforced from "+
				"the wrong side turns evidence away", src, err)
		}
	}

	for _, bad := range []string{"overheard", "collector", "", "Provider-API"} {
		_, err := ValidateEvent(event(bad))
		if err == nil {
			t.Errorf("source %q was ACCEPTED. The compiler reads this field to tell "+
				"adopt-recorded INTENT from a measurement, so an unrecognized value "+
				"is carried as measured reality — `cannot be verified` becomes "+
				"`verified by the candidate's own word`.", bad)
			continue
		}
		// It must route through the version-gap channel, not the corruption one: an
		// additive registry means a newer build may legitimately write a source this
		// one does not know, and calling that ledger corrupt is D1154's defect.
		var unknown *UnknownTypeError
		if !errors.As(err, &unknown) {
			t.Errorf("source %q was refused as %T, not as an unknown-value error. A "+
				"build meeting a NEWER source must report a version gap and leave the "+
				"file alone, never call an intact ledger corrupt (D1154).", bad, err)
			continue
		}
		if !strings.Contains(err.Error(), "observation source") {
			t.Errorf("the refusal for %q says %q — it must name WHICH set the value "+
				"is outside, or a reader cannot tell it from an unknown event type",
				bad, err.Error())
		}
	}
}
