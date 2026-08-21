package provider_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// D1158. Ask the question this repository asks of every other gate — what would it print
// if it were switched off — of a published SCHEMA, and one of the four answered: exactly
// what it prints now.
//
// `spec/state.schema.json` carried no `type`, no `$ref` and no `properties` at its root.
// Every document was a valid State Model v0: a ledger event, a bare object, the number
// 42. Four of its definitions were unreachable, so the shapes the file exists to describe
// — bindings, observations, operation receipts — were the one part of it nothing could
// check, and `spec/state-model.md` called it "fail-closed on every side".
//
// Two things had quietly drifted in that shelter, and both are the reason this is a gate
// and not a one-line fix. `$defs/operationReceipt` required three fields the runtime has
// never written and named none of the five it always does. And `prev` demanded a
// `sha256:` hash, which rejects the `genesis` sentinel — that is, the opening event of
// every ledger ever written. An artefact nobody runs anything through does not stay
// correct; it stays unexamined.
//
// The rules below are deliberately escapable, but only in writing. A schema may leave its
// root open if it declares itself a CATALOGUE, and a definition may go unreferenced if it
// declares itself descriptive-only. Both declarations live in the schema, not here: an
// exception a gate carries is an exception nobody reviews.
func TestNoPublishedSchemaAcceptsEverything(t *testing.T) {
	root := repoRoot(t)
	files, err := filepath.Glob(filepath.Join(root, "spec", "*.schema.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(files) < 4 {
		t.Fatalf("found %d published schemas — the scan broke, or they moved somewhere "+
			"this gate cannot see them (D328)", len(files))
	}

	for _, f := range files {
		name := filepath.Base(f)
		t.Run(name, func(t *testing.T) {
			raw, err := os.ReadFile(f)
			if err != nil {
				t.Fatal(err)
			}
			var doc map[string]any
			if err := json.Unmarshal(raw, &doc); err != nil {
				t.Fatalf("does not parse: %v", err)
			}

			// (1) The root must constrain something, or say why it does not. These are
			// the keywords that can reject a document; metadata cannot.
			constrains := false
			for _, k := range []string{"type", "$ref", "properties", "required",
				"enum", "const", "anyOf", "allOf", "oneOf", "items"} {
				if _, ok := doc[k]; ok {
					constrains = true
					break
				}
			}
			// A PREFIX, not a mention. The declaration must be the first thing the
			// comment says, because the comment goes on to use the word "catalogue"
			// in a sentence explaining what a non-catalogue would mean — and a
			// check that accepts the word accepts the paragraph about the word.
			// Found by mutating this gate: renaming the marker left it passing.
			cat := strings.HasPrefix(strings.ToLower(strings.TrimSpace(str(doc["$comment"]))), "catalogue:")
			if !constrains && !cat {
				t.Errorf("the root constrains NOTHING and does not declare itself a "+
					"catalogue, so every document validates — including ones that are "+
					"not of this kind at all. This is what %s did while the spec called "+
					"it fail-closed. Either give the root a `$ref`/`type`, or declare "+
					"the catalogue in a root `$comment` so a reader knows to select a "+
					"$defs entry.", name)
			}

			// (2) Every definition must be reachable, or declare that it is not meant
			// to be. An unreferenced definition is published prose: it looks like a
			// contract, nothing holds it to the runtime, and it drifts.
			defs, _ := doc["$defs"].(map[string]any)
			if len(defs) == 0 {
				return
			}
			body := string(raw)
			var dead []string
			for d := range defs {
				if strings.Contains(body, `"#/$defs/`+d+`"`) {
					continue
				}
				if cat {
					continue // a catalogue's shapes ARE the entry points
				}
				sub, _ := defs[d].(map[string]any)
				if strings.HasPrefix(strings.ToLower(strings.TrimSpace(str(sub["$comment"]))), "descriptive-only:") {
					continue
				}
				dead = append(dead, d)
			}
			sort.Strings(dead)
			if len(dead) > 0 {
				t.Errorf("definitions nothing references: %v.\nA published definition "+
					"no path reaches cannot be wrong in any way a test would notice — "+
					"%s's operationReceipt required three fields the runtime never "+
					"wrote and named none of the five it always did. Reference it, or "+
					"declare it descriptive-only in its own `$comment` and say why.",
					dead, name)
			}
		})
	}
}

func str(v any) string { s, _ := v.(string); return s }
