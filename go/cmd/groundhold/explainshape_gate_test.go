package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	"groundhold/internal/perr"
)

// TestExplainDocumentIsFullyDescribedByTheSchema asks the direction nothing asked (D867).
//
// `TestEveryPublishedOutputFieldHasCodeBehindIt` (D515) walks the SCHEMA and requires code
// behind each field. Nothing walked the DOCUMENT and required a schema entry for each key —
// and `explain` emitted three keys against a def describing two. The missing one was `code`,
// which `spec/errors.md` calls the contract ("scripts and agents route on it") and the CLI's
// own help repeats. The def matched the `perr.Explanation` STRUCT exactly; the CLI marshals
// `perr.RegistryEntry`, which carries the code as well, so schema and struct agreed with each
// other while the document said more than both.
//
// Only `explain` is checked here, because it is the verb whose document needs no ledger, no
// provider and no fixture. The general form — run every verb, diff every key — is recorded as
// debt in D867 rather than half-built.
func TestExplainDocumentIsFullyDescribedByTheSchema(t *testing.T) {
	root := repoRootFromCmd(t)
	raw, err := os.ReadFile(filepath.Join(root, "spec", "outputs.schema.json"))
	if err != nil {
		t.Fatalf("read the output schema: %v", err)
	}
	var schema struct {
		Defs map[string]struct {
			Properties map[string]json.RawMessage `json:"properties"`
		} `json:"$defs"`
	}
	if err := json.Unmarshal(raw, &schema); err != nil {
		t.Fatalf("parse the output schema: %v", err)
	}
	def, ok := schema.Defs["explain"]
	if !ok {
		t.Fatal("the output schema has no `explain` def — a verb that publishes a document " +
			"with no def at all is D845's register, not this gate's silence")
	}
	if len(def.Properties) == 0 {
		t.Fatal("the explain def describes no properties — this gate would pass over nothing (D328)")
	}

	// The document the CLI actually marshals for `explain <code>`.
	var emitted map[string]any
	blob, err := json.Marshal(perr.RegistryEntry{
		Code: "observation-required", Summary: "s", Remediation: "r"})
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(blob, &emitted); err != nil {
		t.Fatal(err)
	}
	if len(emitted) == 0 {
		t.Fatal("the explain document marshalled to nothing — the subject is empty")
	}

	var undescribed []string
	for k := range emitted {
		if _, ok := def.Properties[k]; !ok {
			undescribed = append(undescribed, k)
		}
	}
	sort.Strings(undescribed)
	if len(undescribed) > 0 {
		t.Errorf("`explain` emits %v, which spec/outputs.schema.json does not describe.\n\n"+
			"A consumer reads the schema to learn the shape; a key that is emitted and "+
			"undescribed is a field they will not know to read — and `code` is the one this "+
			"project tells agents to route on (spec/errors.md). Describe it, or stop "+
			"emitting it (D867).", undescribed)
	}

	// The reverse leg, cheap here: a described property the document never carries would be
	// the D515 defect in this one def, and D515's gate only sees json tags anywhere in the
	// tree — a name that exists on some other struct passes it.
	var missing []string
	for k := range def.Properties {
		if _, ok := emitted[k]; !ok {
			missing = append(missing, k)
		}
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		t.Errorf("the explain def describes %v, which the document does not carry", missing)
	}

	// Guard the guard: if RegistryEntry ever stops being what the CLI marshals, this test
	// checks a shape nobody ships. The field names are the anchor.
	if got := reflect.TypeOf(perr.RegistryEntry{}).NumField(); got < 3 {
		t.Fatalf("perr.RegistryEntry has %d fields — this gate assumes it is the explain "+
			"document (code, summary, remediation)", got)
	}
	if !strings.Contains(string(blob), `"code"`) {
		t.Fatal("the marshalled explain document carries no `code` key — the CLI no longer " +
			"emits what this gate is written about")
	}
}
