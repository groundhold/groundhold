package provider_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// D559, the direction D516 declined. D516 walks the published output schema and
// requires the Go tree to carry every property name it promises — a promised field
// nothing emits. The reverse leaks the other way: a field the CLI PUBLISHES that the
// schema never describes. A consumer generating types from the schema does not know
// it exists, and nothing complains, because the schema shapes are open.
//
// Measured: `adoptResult` has published `notes` since D322 and the schema never
// mentioned it — three more note kinds were added on top of it (D555, D556) before
// anyone looked. It reads exactly like the D552 overstatement in reverse: two
// published artefacts describing one thing, neither checked against the other.
//
// D516's comment declined this direction because it needs a def→struct table, "which
// is its own thing to rot". A table that is ITSELF gated does not rot silently: every
// entry below must resolve to a live def AND a live struct, or this fails. The defs
// not yet in the table are counted on a ratchet that may only fall, so the gap is a
// number rather than an implication.
var schemaStructs = map[string]struct{ file, name string }{
	"adoptResult":     {"internal/adopt/adopt.go", "Result"},
	"observeResult":   {"internal/observe/observe.go", "Result"},
	"verifyReport":    {"internal/verify/verify.go", "Report"},
	"applyResult":     {"internal/apply/apply.go", "Result"},
	"discoverResult":  {"internal/discover/discover.go", "Result"},
	"probeResult":     {"internal/probe/probe.go", "Result"},
	"auditResult":     {"internal/audit/audit.go", "Result"},
	"resumeResult":    {"internal/resume/resume.go", "Result"},
	"publishResult":   {"internal/publish/publish.go", "Result"},
	"anchorCheck":     {"internal/ledger/anchor.go", "AnchorCheck"},
	"anchorDocument":  {"internal/ledger/anchor.go", "Anchor"},
	"exportRecord":    {"internal/export/export.go", "Record"},
	"hintsResult":     {"internal/importer/importer.go", "Result"},
	"repairDiagnosis": {"internal/ledger/repair.go", "Diagnosis"},
	"repairResult":    {"internal/ledger/repair.go", "RepairResult"},
	// converge's result type is unexported; the gate reads source text, so it
	// pins just as well — and this is the verb an operator runs unattended.
	"convergeResult": {"internal/converge/converge.go", "result"},
}

// Fields a struct publishes that the schema deliberately does not describe. Each
// needs a reason that survives re-reading, like D516's exemptions.
var publishedNotInSchema = map[string]string{}

const unmappedSchemaDefsBaseline = 4 // defs with no struct pinned yet; may only fall

func TestPublishedFieldsAreInTheOutputSchema(t *testing.T) {
	root := repoRoot(t)
	raw, err := os.ReadFile(filepath.Join(root, "spec", "outputs.schema.json"))
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Defs map[string]struct {
			Properties map[string]any `json:"properties"`
		} `json:"$defs"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("outputs.schema.json is unparseable: %v", err) // never read as "no defs"
	}
	if len(doc.Defs) < 5 {
		t.Fatalf("only %d schema defs read — this gate would be vacuous", len(doc.Defs))
	}

	unmapped := 0
	for def := range doc.Defs {
		if _, ok := schemaStructs[def]; !ok {
			unmapped++
		}
	}
	if unmapped > unmappedSchemaDefsBaseline {
		t.Errorf("debt GREW: %d schema defs have no struct pinned, baseline is %d",
			unmapped, unmappedSchemaDefsBaseline)
	}
	if unmapped < unmappedSchemaDefsBaseline {
		t.Errorf("debt SHRANK to %d but the baseline still says %d — lower it, or the "+
			"ratchet stops being one", unmapped, unmappedSchemaDefsBaseline)
	}

	tagRe := regexp.MustCompile(`json:"([a-zA-Z0-9_]+)`)
	for def, loc := range schemaStructs {
		spec, ok := doc.Defs[def]
		if !ok {
			t.Errorf("the table pins %q, which the schema no longer defines", def)
			continue
		}
		src, err := os.ReadFile(filepath.Join(root, "go", loc.file))
		if err != nil {
			t.Errorf("%s: %v", def, err)
			continue
		}
		body := structBody(string(src), loc.name)
		if body == "" {
			t.Errorf("the table pins %s.%s, which no longer exists", loc.file, loc.name)
			continue
		}
		var missing []string
		if len(tagRe.FindAllStringSubmatch("Field string `json:\"fieldName,omitempty\"`",
			-1)) == 0 {
			t.Fatal("D603: the json-tag extractor does not match an ordinary struct " +
				"tag — it is not running, and this gate then reports that the schema " +
				"describes every field it never looked for")
		}
		for _, m := range tagRe.FindAllStringSubmatch(body, -1) {
			field := m[1]
			if _, ok := spec.Properties[field]; ok {
				continue
			}
			if _, ok := publishedNotInSchema[def+"."+field]; ok {
				continue
			}
			missing = append(missing, field)
		}
		if len(missing) > 0 {
			sort.Strings(missing)
			t.Errorf("%s publishes %s — the output schema describes none of them.\n"+
				"A consumer generating types from the schema cannot see a field the CLI "+
				"emits, and the shapes are open so nothing rejects it.",
				def, strings.Join(missing, ", "))
		}
	}
}

// structBody returns the body of `type <name> struct { ... }`, or "".
func structBody(src, name string) string {
	i := strings.Index(src, "type "+name+" struct {")
	if i < 0 {
		return ""
	}
	rest := src[i:]
	j := strings.Index(rest, "\n}")
	if j < 0 {
		return ""
	}
	return rest[:j]
}
