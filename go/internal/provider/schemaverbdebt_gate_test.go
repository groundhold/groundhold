package provider_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// verbsWithoutASchemaDef are verbs VERIFIED to print a JSON document that
// spec/outputs.schema.json does not describe. It may only SHRINK.
//
// D845. The schema's own description said "One $def per verb." It has twenty defs, and
// running the binary settles the rest: `parity` prints a capability map, `apiver` prints
// its pin catalogue, and `posture` prints `{at, summary, rows, postureHash}` — the document
// whose `shadowLowerBound` field D777 flagged for the owner. A consumer generating types
// from the schema is told the coverage is total and finds three documents it cannot type.
//
// The existing schema gate (D559) cannot see this: it walks FROM the defs TO the structs,
// asking whether a described field exists. This asks the other direction — whether a
// published document is described at all — and nothing did.
//
// Only verbs whose document was OBSERVED are listed. Several more (`cost`, `diff`,
// `suggest`, `runs`, `status`) need arguments this test cannot supply, so whether they
// publish a document is unmeasured here, and unmeasured is not the same as absent.
var verbsWithoutASchemaDef = map[string]string{
	"posture": "prints {at, summary, rows, postureHash}; summary.shadowLowerBound is the field D777 flagged",
	"parity":  "prints the capability map keyed by capability type",
	"apiver":  "prints {apiVersion: apiver/v0, pins} — an envelope VERSION no spec file describes",
	"cost":    "prints {specVersion, contract, environment, currency, weekly}",
	"diff":    "prints {specVersion, contract, environmentA, environmentB, hardOnlyInA, ...}",
	"suggest": "prints {specVersion, contract, environment, suggested, alreadyEnforced}",
	"runs":    "prints {byState, runs, total}",
	"status":  "prints {handle, kind, state, code, lease}",
}

// TestVerbsPublishingWithoutASchemaDef holds the register two ways: a verb here must be a
// real verb that still has no def, and the count may only fall.
func TestVerbsPublishingWithoutASchemaDef(t *testing.T) {
	root := repoRoot(t)

	blob, err := os.ReadFile(filepath.Join(root, "spec", "outputs.schema.json"))
	if err != nil {
		t.Fatalf("read schema: %v", err)
	}
	var doc struct {
		Description string                     `json:"description"`
		Defs        map[string]json.RawMessage `json:"$defs"`
	}
	if err := json.Unmarshal(blob, &doc); err != nil {
		t.Fatalf("schema is not JSON: %v", err)
	}
	// D328: assert the subject. A schema that lost its defs would make every check below
	// pass by having nothing to disagree with.
	if len(doc.Defs) < 15 {
		t.Fatalf("the schema carries %d defs — too few to be the real one", len(doc.Defs))
	}

	// The corrected description must not re-assert total coverage while the register is
	// non-empty; that sentence is the thing this entry fixed.
	if len(verbsWithoutASchemaDef) > 0 && strings.Contains(doc.Description, "One $def per verb") {
		t.Errorf("the schema says \"One $def per verb\" while %d verb(s) publish without one: %v",
			len(verbsWithoutASchemaDef), sortedKeys(verbsWithoutASchemaDef))
	}

	help, err := os.ReadFile(filepath.Join(root, "go", "cmd", "groundhold", "main.go"))
	if err != nil {
		t.Fatalf("read main.go: %v", err)
	}
	for verb, why := range verbsWithoutASchemaDef {
		if !strings.Contains(string(help), "groundhold "+verb+" ") {
			t.Errorf("register names %q (%s) but the CLI help has no such verb — drop it or "+
				"fix the name", verb, why)
		}
		for def := range doc.Defs {
			if strings.EqualFold(def, verb) || strings.EqualFold(def, verb+"Result") {
				t.Errorf("register names %q as undescribed, but the schema now has a %q def "+
					"— drop the register entry, the debt is paid", verb, def)
			}
		}
	}
}

func sortedKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
