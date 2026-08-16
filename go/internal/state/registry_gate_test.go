package state

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// D338: the event type registry (D19, "closed set, fail-closed") is the ORIGINAL
// registry — spec/errors.md says its own rules mirror this one. It is the ledger's
// alphabet: capsule, export, restore, audit and replay all route on it, and both
// implementations REFUSE an unknown type by design.
//
// Four artefacts publish it and all four are load-bearing:
//
//	go/internal/state/state.go     EventTypes — the production runtime's set
//	ref/groundholdlib/state.py     EVENT_TYPES — the reference implementation's
//	spec/state-model.md            the published registry block
//	spec/state.schema.json         the closed enum consumers validate ledgers against
//
// Drift here is not a documentation gap. Because both sides are fail-closed, a type
// one implementation writes and the other does not know makes a ledger written by
// the runtime UNREADABLE to the reference — the dual-implementation guarantee (D25)
// silently inverted, in the substrate every piece of evidence lives in.
func TestEventTypeRegistryAgreesEverywhere(t *testing.T) {
	sets := map[string]map[string]bool{
		"go/internal/state/state.go (EventTypes)":  EventTypes,
		"ref/groundholdlib/state.py (EVENT_TYPES)": pyEventTypes(t),
		"spec/state-model.md (registry block)":     specEventTypes(t),
		"spec/state.schema.json (closed enum)":     schemaEventTypes(t),
	}

	names := make([]string, 0, len(sets))
	for n, s := range sets {
		if len(s) == 0 {
			t.Fatalf("%s parsed to ZERO event types — the gate would be vacuous (D328)", n)
		}
		names = append(names, n)
	}
	sort.Strings(names)

	// Union first, so a type missing from three artefacts is reported once per
	// artefact rather than as six pairwise diffs.
	union := map[string]bool{}
	for _, s := range sets {
		for k := range s {
			union[k] = true
		}
	}
	for _, n := range names {
		var missing []string
		for k := range union {
			if !sets[n][k] {
				missing = append(missing, k)
			}
		}
		sort.Strings(missing)
		if len(missing) > 0 {
			t.Errorf("%s does not know these event types: %v\n"+
				"The set is fail-closed in both implementations: whoever does not know a "+
				"type REFUSES a ledger containing it.", n, missing)
		}
	}
}

func repoRoot(t *testing.T) string {
	t.Helper()
	// internal/state -> internal -> go -> repo
	abs, err := filepath.Abs(filepath.Join("..", "..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	return abs
}

func pyEventTypes(t *testing.T) map[string]bool {
	t.Helper()
	raw := readRepoFile(t, "ref", "groundholdlib", "state.py")
	m := regexp.MustCompile(`(?s)EVENT_TYPES\s*=\s*\{(.*?)\n\}`).FindStringSubmatch(raw)
	if m == nil {
		t.Fatal("could not find EVENT_TYPES in ref/groundholdlib/state.py")
	}
	return dotted(m[1])
}

// specEventTypes reads the fenced block under the registry heading — the thing a
// reader implementing from the spec would copy.
func specEventTypes(t *testing.T) map[string]bool {
	t.Helper()
	raw := readRepoFile(t, "spec", "state-model.md")
	m := regexp.MustCompile("(?s)### Event type registry.*?```\\n(.*?)```").FindStringSubmatch(raw)
	if m == nil {
		t.Fatal("could not find the Event type registry block in spec/state-model.md")
	}
	out := map[string]bool{}
	for _, w := range strings.Fields(m[1]) {
		out[w] = true
	}
	return out
}

// schemaEventTypes reads $defs.ledgerEvent.event.type.enum — parsed as JSON, since
// it is machine-consumed and a text match would not notice the def moving.
func schemaEventTypes(t *testing.T) map[string]bool {
	t.Helper()
	raw := readRepoFile(t, "spec", "state.schema.json")
	var doc struct {
		Defs struct {
			LedgerEvent struct {
				Properties struct {
					Event struct {
						Properties struct {
							Type struct {
								Enum []string `json:"enum"`
							} `json:"type"`
						} `json:"properties"`
					} `json:"event"`
				} `json:"properties"`
			} `json:"ledgerEvent"`
		} `json:"$defs"`
	}
	if err := json.Unmarshal([]byte(raw), &doc); err != nil {
		t.Fatalf("parse spec/state.schema.json: %v", err)
	}
	out := map[string]bool{}
	for _, c := range doc.Defs.LedgerEvent.Properties.Event.Properties.Type.Enum {
		out[c] = true
	}
	return out
}

func readRepoFile(t *testing.T, parts ...string) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(append([]string{repoRoot(t)}, parts...)...))
	if err != nil {
		t.Fatalf("read %v: %v", parts, err)
	}
	return string(raw)
}

func dotted(s string) map[string]bool {
	out := map[string]bool{}
	for _, m := range regexp.MustCompile(`"([a-z][a-z0-9.]+)"`).FindAllStringSubmatch(s, -1) {
		out[m[1]] = true
	}
	return out
}

// D1151. The neighbouring gate holds the EVENT-TYPE registry across all four copies,
// including the schema, and that is the shape this one is missing next door: the
// observation SOURCE enum in `spec/state.schema.json` listed three values while the
// runtime writes four, two of which it does not list.
//
//	provider-api        internal/observe        — a driver read this from the resource
//	probe               internal/probe          — an outcome probe measured it
//	candidate-declared  internal/adopt          — adopted, and the provider emitted NO
//	                                              value for it, so it is intent (D555)
//	reachability        internal/reach          — the post-apply reach recording
//
// The schema listed the first two and `manual`, which nothing here emits. So a ledger
// produced by `adopt` over an attribute the provider cannot read, or by any reachability
// recording, does not validate against the file the registry gate above calls "the
// closed enum consumers validate ledgers against". Nothing noticed because nothing
// validates a real ledger against it — the schema is compared to other registries and
// never to output.
//
// The set is NAMED. Derived from the emitting sites it would agree with itself whatever
// they did (D1130), and derived from the schema it would agree with the file this exists
// to hold.
func TestObservationSourceEnumCoversWhatTheRuntimeWrites(t *testing.T) {
	want := []string{"candidate-declared", "manual", "probe", "provider-api", "reachability"}

	got := schemaObservationSources(t)
	if len(got) == 0 {
		t.Fatal("no observation-source enum found in spec/state.schema.json — the scan " +
			"broke and this gate would pass on anything (D328)")
	}
	sort.Strings(got)
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("the schema publishes sources %v; the runtime writes %v.\nA value the "+
			"runtime writes and the schema omits makes our own ledger fail the validation "+
			"we tell consumers to run; a value the schema promises and nothing writes is "+
			"an offer nobody can take.", got, want)
	}

	// The emitting sites must stay inside it. Matched as an ASSIGNMENT, not anywhere in
	// the file: every one of these files says its own source in prose too, and a check
	// that accepts the word accepts the paragraph explaining the word — which is how
	// D1142 kept a gate green on a comment denying the very thing it checked. A mutant
	// that renamed the emitted literal walked straight through the first draft of this.
	for _, site := range []struct{ file, literal string }{
		{filepath.Join("..", "observe", "observe.go"), "provider-api"},
		{filepath.Join("..", "probe", "probe.go"), "probe"},
		{filepath.Join("..", "reach", "record.go"), "reachability"},
		{filepath.Join("..", "provider", "provider.go"), "candidate-declared"},
	} {
		raw, err := os.ReadFile(site.file)
		if err != nil {
			t.Skipf("cannot read %s: %v", site.file, err)
		}
		// Either the value is assigned to a source field at the emitting site, or it is
		// the named constant the emitting site uses. Both are assignments; neither is
		// prose about one.
		assigned := regexp.MustCompile(
			`(?:"source":|Source:|=)\s*"` + regexp.QuoteMeta(site.literal) + `"`)
		if !assigned.MatchString(string(raw)) {
			t.Errorf("%s no longer ASSIGNS the source %q — either it moved or the value "+
				"changed, and the schema still promises it to consumers", site.file, site.literal)
		}
	}
}

// schemaObservationSources reads $defs.observation.properties.source.enum.
func schemaObservationSources(t *testing.T) []string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "spec", "state.schema.json"))
	if err != nil {
		t.Skipf("no state schema in this tree: %v", err)
	}
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
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("state schema does not parse: %v", err)
	}
	return doc.Defs.Observation.Properties.Source.Enum
}
