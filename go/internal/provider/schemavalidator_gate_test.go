package provider_test

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// D1156/D1157. The four published schemas are what a stranger validates against — the
// runtime's JSON output on the way out, a contract or candidate on the way in — and
// nothing had ever run a real artefact through any of them. One check came close: it
// asked whether every property marked `required` was PRESENT in five of the twenty-one
// output shapes. Types, enums, `const`, `$ref` and open-map values went unread, and the
// input side had nothing at all.
//
// Both directions produced a live defect. `repair` shipped a `version-ahead` status and
// finding-kind outside their published enums (D1154, merged before this found it), and
// a shipped example carried two assumptions with no `statement` — published as required
// beside `id` and `status`, and read by neither implementation.
//
// `examples/schemacheck.py` is the one checker both directions use. This gate RUNS it
// rather than describing it (D1143/D1144/D1145): a check whose logic nothing executes is
// a comment. It also holds the property that makes the checker worth trusting — that it
// refuses loudly on a keyword it does not implement, which is how the three keywords the
// input schemas needed announced themselves instead of passing silently.
func TestTheSchemaCheckerActuallyValidates(t *testing.T) {
	skipIfExported(t, "the example harness")
	root := repoRoot(t)
	mod := filepath.Join(root, "examples", "schemacheck.py")
	if _, err := os.Stat(mod); err != nil {
		t.Skipf("no schema checker here: %v", err)
	}

	// run asks the checker about one document and returns what it says.
	run := func(t *testing.T, doc any, schema any) string {
		t.Helper()
		d, err := json.Marshal(doc)
		if err != nil {
			t.Fatal(err)
		}
		s, err := json.Marshal(schema)
		if err != nil {
			t.Fatal(err)
		}
		const prog = `
import json, sys
sys.path.insert(0, "examples")
from schemacheck import errors, selftest
doc, schema = json.loads(sys.argv[1]), json.loads(sys.argv[2])
for p, m in errors(doc, schema, schema.get("$defs", {})):
    print("%s: %s" % (p or "(root)", m))
for line in selftest():
    print(line)
`
		cmd := exec.Command("python3", "-c", prog, string(d), string(s))
		cmd.Dir = root
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("running the checker: %v\n%s", err, out)
		}
		return string(out)
	}

	schema := map[string]any{
		"type":     "object",
		"required": []any{"status", "count"},
		"properties": map[string]any{
			"status": map[string]any{"enum": []any{"healthy", "corrupt"}},
			"count":  map[string]any{"type": "integer"},
			"name":   map[string]any{"maxLength": 4},
			"items":  map[string]any{"type": "array", "minItems": 2},
			"map": map[string]any{"type": "object",
				"propertyNames": map[string]any{"pattern": "^[a-z]+$"}},
		},
	}
	good := map[string]any{"status": "healthy", "count": 1, "name": "abc",
		"items": []any{1, 2}, "map": map[string]any{"ok": 1}}

	t.Run("accepts a document that satisfies the schema", func(t *testing.T) {
		if out := run(t, good, schema); strings.TrimSpace(out) != "" {
			t.Errorf("the checker complained about a valid document. A checker that "+
				"rejects what is right is switched off within a week, and then the "+
				"schema is unchecked again:\n%s", out)
		}
	})

	// One case per keyword the OLD check could not read. Each is a way the runtime and
	// the published contract can disagree while every `required` property is present.
	for _, tc := range []struct {
		name  string
		mutic func(map[string]any)
		want  string
		why   string
	}{
		{"a value outside its enum", func(d map[string]any) { d["status"] = "fine" },
			"is not one of",
			"this is D1154 exactly: `repair` printed a status its own published enum " +
				"does not list, and a consumer validating against the schema rejects " +
				"output the runtime is right to produce"},
		{"a string where an integer is published", func(d map[string]any) { d["count"] = "1" },
			"schema says",
			"the old check read only whether a property was PRESENT, so a type change " +
				"— the thing that actually breaks a consumer's parser — went unread"},
		{"a required property that left", func(d map[string]any) { delete(d, "count") },
			"required property 'count' is absent",
			"a departed required property is the one thing the OLD check did catch, so " +
				"losing it would be a regression. Matched by NAME on purpose: the " +
				"checker's own self-witness prints the words `required property` when " +
				"it is broken, and a bare substring is satisfied by that sentence"},
		{"a string past its published maximum", func(d map[string]any) { d["name"] = "toolong" },
			"published maximum",
			"maxLength is how the schemas bound an identifier; unread, a document the " +
				"schema rejects passes here"},
		{"an array below its published minimum", func(d map[string]any) { d["items"] = []any{1} },
			"published minimum",
			"minItems is how the contract schema says a contract has at least one " +
				"capability"},
		{"a property NAME the schema forbids", func(d map[string]any) {
			d["map"] = map[string]any{"NOT-OK": 1}
		},
			"property name",
			"propertyNames is the only rule an open map carries — it is how the " +
				"schemas say every capability id is an identifier"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			bad := map[string]any{}
			for k, v := range good {
				bad[k] = v
			}
			tc.mutic(bad)
			out := run(t, bad, schema)
			if !strings.Contains(out, tc.want) {
				t.Errorf("ACCEPTED %s — %s\n%s", tc.name, tc.why, out)
			}
		})
	}

	// The property that makes the rest trustworthy. A checker covering a subset of JSON
	// Schema is honest only if it says so when it meets the rest; one that ignored an
	// unknown keyword would be weaker than the document it checks and its silence would
	// read as a pass. This is not hypothetical — extending the checker to the input
	// schemas met three keywords it did not have, and they announced themselves here.
	t.Run("refuses a keyword it does not implement", func(t *testing.T) {
		out := run(t, map[string]any{"a": 1},
			map[string]any{"type": "object", "uniqueItems": true})
		if !strings.Contains(out, "does not implement") {
			t.Errorf("a keyword outside the checker's set was passed over in silence. "+
				"Every PASS it prints is then a claim about rules it never read:\n%s", out)
		}
	})

	// Neither block may pass on nothing. The output side validates only the shapes the
	// harness managed to produce, so a harness that quietly stopped producing them would
	// validate almost nothing and still print PASS (D328) — the floors are what stop
	// that, and they are asserted here because a floor nobody checks is a comment.
	t.Run("neither block can pass on nothing", func(t *testing.T) {
		raw, err := os.ReadFile(filepath.Join(root, "examples", "check.sh"))
		if err != nil {
			t.Fatal(err)
		}
		body := string(raw)
		if !strings.Contains(body, "published shapes were produced") {
			t.Error("the output-schema check has no floor on how many shapes it saw — " +
				"ask what it would print with the harness producing nothing, and the " +
				"answer must not be the same thing it prints now")
		}
		if !strings.Contains(body, "documents were found") {
			t.Error("the shipped-document check has no floor on how many documents it " +
				"found — a broken `find` would leave it green over an empty list")
		}
		if !regexp.MustCompile(`if checked < \d+:`).MatchString(body) {
			t.Error("the output-schema floor is not a number any more — a token floor " +
				"is satisfied by anything")
		}
	})

	// D1158: the sentinel case, against the REAL state schema rather than a synthetic
	// one. `prev` used to demand a `sha256:` hash, which rejects `genesis` — the value
	// every capability's FIRST event carries, so the published schema refused the
	// opening event of every ledger ever written. Nothing noticed for as long as the
	// file existed, because its root constrained nothing and no ledger was ever handed
	// to it.
	t.Run("the genesis sentinel is a valid prev", func(t *testing.T) {
		raw, err := os.ReadFile(filepath.Join(root, "spec", "state.schema.json"))
		if err != nil {
			t.Fatal(err)
		}
		var st any
		if err := json.Unmarshal(raw, &st); err != nil {
			t.Fatalf("the state schema does not parse: %v", err)
		}
		event := map[string]any{
			"apiVersion": "state/v0", "kind": "LedgerEvent",
			"event": map[string]any{
				"type": "apply.started", "environment": "test",
				"capabilities": []any{"db"},
				"occurredAt":   "2026-01-01T00:00:00Z",
				"actor":        map[string]any{"id": "r", "type": "runtime"},
				"prev":         map[string]any{"db": "genesis"},
				"body":         map[string]any{},
			},
		}
		if out := run(t, event, st); strings.TrimSpace(out) != "" {
			t.Errorf("the published state schema rejects a capability's FIRST event. "+
				"`genesis` is the sentinel the chain opens with — every ledger in "+
				"existence starts this way, so a schema that refuses it refuses all "+
				"of them:\n%s", out)
		}
		// The sibling: a prev that is neither a hash nor the sentinel must still fail,
		// or the fix widened the field into anything-goes.
		bad := map[string]any{}
		for k, v := range event {
			bad[k] = v
		}
		ev := map[string]any{}
		for k, v := range event["event"].(map[string]any) {
			ev[k] = v
		}
		ev["prev"] = map[string]any{"db": "whatever"}
		bad["event"] = ev
		if out := run(t, bad, st); strings.TrimSpace(out) == "" {
			t.Error("a prev that is neither a hash nor `genesis` was ACCEPTED — the " +
				"chain's one structural field would then constrain nothing")
		}
	})

	// Both directions must use the SAME checker. Two copies would be free to agree with
	// each other by luck and diverge on the case that matters — the shape half this
	// record is about.
	t.Run("one checker, both directions", func(t *testing.T) {
		raw, err := os.ReadFile(filepath.Join(root, "examples", "check.sh"))
		if err != nil {
			t.Fatal(err)
		}
		if n := strings.Count(string(raw), "from schemacheck import"); n < 2 {
			t.Errorf("the harness imports the checker %d times; the output side and "+
				"the input side must both use it. A second, inlined copy is how two "+
				"implementations end up agreeing by luck", n)
		}
		if strings.Contains(string(raw), "def errors(doc, schema") {
			t.Error("examples/check.sh defines its own `errors` again — the checker " +
				"was extracted to examples/schemacheck.py precisely so there is one")
		}
	})
}
