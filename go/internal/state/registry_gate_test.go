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
