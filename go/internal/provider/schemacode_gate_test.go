package provider_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// D515's class, checked where it IS mechanical. The record claiming code that does
// not exist cannot be gated in general — DESIGN.md is append-only history, so an
// old entry naming a since-deleted function is correct history, not a broken
// citation. What CAN be gated is the other published contract: the output schema
// promises field names to every consumer, and a promise nothing emits is the same
// failure with none of the prose.
//
// This walks every property name in every `$defs` shape of spec/outputs.schema.json
// and requires the Go tree to carry it as a json tag — or to hold a re-derived
// exemption below. It does not verify the field lives on the RIGHT struct (that
// would need a schema-to-struct table, which is its own thing to rot); it catches
// the class that actually bites, which is a published field name nothing produces.
//
// Today it finds nothing, and that is the point of writing it down: the day it
// finds something, someone will have shipped a schema field with no code.
func TestEveryPublishedOutputFieldHasCodeBehindIt(t *testing.T) {
	root := repoRoot(t)

	raw, err := os.ReadFile(filepath.Join(root, "spec", "outputs.schema.json"))
	if err != nil {
		t.Fatalf("the output schema is the published contract: %v", err)
	}
	var doc struct {
		Defs map[string]json.RawMessage `json:"$defs"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Defs) == 0 {
		t.Fatal("no $defs read from the schema — this gate would be vacuous")
	}

	// property name -> the shapes that promise it
	promised := map[string][]string{}
	for name, rawDef := range doc.Defs {
		for _, p := range propertyNames(t, rawDef) {
			promised[p] = append(promised[p], name)
		}
	}
	if len(promised) < 50 {
		t.Fatalf("only %d property names collected; the walk is not reaching the schema's "+
			"shapes and would pass on anything", len(promised))
	}

	tags, sources := goJSONTags(t, filepath.Join(root, "go"))
	if len(tags) < 200 {
		t.Fatalf("only %d json tags found in the Go tree — the scan is broken", len(tags))
	}

	for name, shapes := range promised {
		if tags[name] {
			continue
		}
		reason, exempt := dynamicOutputFields[name]
		if !exempt {
			sort.Strings(shapes)
			t.Errorf("the schema promises %q (in %v) and no Go struct emits it: a consumer "+
				"routing on that field gets nothing, and nothing said so", name, shapes)
			continue
		}
		// The exemption RE-DERIVES its evidence rather than being trusted: the
		// field must actually be assigned somewhere, or the exemption is stale and
		// hiding exactly the defect it claims to explain.
		if !strings.Contains(sources, reason) {
			t.Errorf("%q is exempt because it is injected dynamically, but %q no longer "+
				"appears in the Go tree — the exemption outlived its reason", name, reason)
		}
	}
}

// dynamicOutputFields are published fields a struct tag cannot carry because the
// value is written into the result map at the point of emission. The value is the
// literal that must still be found in the source, so the exemption cannot rot.
var dynamicOutputFields = map[string]string{
	// --explain (D64) attaches the error registry entry to whatever result is
	// being emitted, across every verb, so it belongs to no single struct.
	"explain": `m["explain"] = ex`,
}

// propertyNames collects every `properties` key reachable in a schema node,
// descending items/additionalProperties and the combinators.
func propertyNames(t *testing.T, raw json.RawMessage) []string {
	t.Helper()
	var node map[string]any
	if json.Unmarshal(raw, &node) != nil {
		return nil
	}
	var out []string
	var walk func(any)
	walk = func(n any) {
		m, ok := n.(map[string]any)
		if !ok {
			if arr, ok := n.([]any); ok {
				for _, x := range arr {
					walk(x)
				}
			}
			return
		}
		if props, ok := m["properties"].(map[string]any); ok {
			for k, v := range props {
				out = append(out, k)
				walk(v)
			}
		}
		for _, k := range []string{"items", "additionalProperties", "oneOf", "anyOf", "allOf"} {
			if v, ok := m[k]; ok {
				walk(v)
			}
		}
	}
	walk(node)
	return out
}

// goJSONTags returns the set of json tag names in the tree, and the concatenated
// source the exemptions re-derive their evidence from.
func goJSONTags(t *testing.T, dir string) (map[string]bool, string) {
	t.Helper()
	tags := map[string]bool{}
	var all strings.Builder
	err := filepath.Walk(dir, func(p string, info os.FileInfo, err error) error {
		// Non-test sources ONLY, for two reasons the first draft got wrong. A
		// json tag in a _test.go file must not satisfy a field the schema
		// publishes to real consumers. And the exemption evidence below is a
		// literal stored in THIS file — scanning test files made the check find
		// its own declaration and pass unconditionally, which is the harness
		// reporting success without exercising the thing it measures.
		if err != nil || info.IsDir() || !strings.HasSuffix(p, ".go") ||
			strings.HasSuffix(p, "_test.go") {
			return err
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		src := string(b)
		all.WriteString(src)
		for _, seg := range strings.Split(src, `json:"`)[1:] {
			name := seg
			if i := strings.IndexAny(name, `",`); i >= 0 {
				name = name[:i]
			}
			if name != "" && name != "-" {
				tags[name] = true
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return tags, all.String()
}
