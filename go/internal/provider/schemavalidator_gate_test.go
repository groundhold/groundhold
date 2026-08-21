package provider_test

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// D1156. `spec/outputs.schema.json` is what a machine consumer validates against, and
// the only thing that ever compared it to real output asked one question: is every
// property marked `required` PRESENT. Types, enums, `const`, `$ref` and open-map values
// went unread, and five of the twenty-one published shapes were the only ones a real
// output ever reached.
//
// So a verb could print a status outside its own published enum and the harness said
// PASS. It did: D1154 gave `repair` a `version-ahead` status and finding-kind, both
// outside the enums here, and that shipped. A consumer validating against the published
// schema would have rejected output the runtime is right to produce — which is the
// failure the four-artefact registry gate (D330) was built to prevent, arriving through
// the one artefact that gate does not read.
//
// The replacement is a real validator, in shell-embedded Python, and this gate runs it
// rather than describing it — the rule this record has now applied to the DCO check
// (D1143), the README-tag check (D1144) and the action-pin check (D1145). A check whose
// logic nothing executes is a comment.
func TestTheSchemaCheckActuallyValidates(t *testing.T) {
	skipIfExported(t, "the example harness")
	root := repoRoot(t)
	raw, err := os.ReadFile(filepath.Join(root, "examples", "check.sh"))
	if err != nil {
		t.Skipf("no example harness here: %v", err)
	}
	src := string(raw)

	// Extract the validator exactly as it runs: the heredoc body, nothing rewritten.
	const open = "missing=\"$(python3 - \"$SCH\" <<'PYEOF' || true\n"
	i := strings.Index(src, open)
	if i < 0 {
		t.Fatal("examples/check.sh no longer embeds the output-schema validator — it " +
			"was renamed or removed, and this gate is measuring nothing (D328)")
	}
	body := src[i+len(open):]
	j := strings.Index(body, "\nPYEOF")
	if j < 0 {
		t.Fatal("the validator heredoc is unterminated — the extraction is wrong")
	}
	script := body[:j]
	for _, need := range []string{"enum", "required", "$ref", "additionalProperties"} {
		if !strings.Contains(script, need) {
			t.Fatalf("the extracted script never mentions %q, so it cannot be reading "+
				"that keyword — the extraction grabbed the wrong block", need)
		}
	}

	// run drops one shape's document into a temp dir and returns what the validator
	// says about it. The vacuity floor will also complain (one shape is not twelve);
	// that line is expected here and the assertions below are about the enum.
	run := func(t *testing.T, name string, doc any) string {
		t.Helper()
		dir := t.TempDir()
		b, err := json.Marshal(doc)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, name+".json"), b, 0o644); err != nil {
			t.Fatal(err)
		}
		cmd := exec.Command("python3", "-", dir)
		cmd.Stdin = strings.NewReader(script)
		cmd.Dir = root // the script opens spec/outputs.schema.json relative to here
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("running the extracted validator: %v\n%s", err, out)
		}
		return string(out)
	}

	// A diagnosis the runtime really produces, in the shape it really produces it.
	good := map[string]any{
		"status": "version-ahead", "totalEvents": 1, "tailEvents": 1, "tailLines": 1,
		"validPrefixLines": 0, "fingerprint": "sha256:" + strings.Repeat("a", 64),
		"code": "ledger-version-ahead",
		"findings": []any{map[string]any{
			"line": 1, "kind": "version-ahead", "detail": "unknown event type",
			"remediation": "do NOT quarantine",
		}},
	}

	t.Run("accepts what the runtime prints", func(t *testing.T) {
		out := run(t, "repairDiagnosis", good)
		if strings.Contains(out, "is not one of") {
			t.Errorf("the validator rejected output the runtime is right to produce. "+
				"That is the same defect from the other side: the schema and the "+
				"runtime disagree, and here the SCHEMA is the one that is behind.\n%s",
				out)
		}
	})

	t.Run("catches a status outside the published enum", func(t *testing.T) {
		bad := map[string]any{}
		for k, v := range good {
			bad[k] = v
		}
		bad["status"] = "perfectly-fine-actually"
		out := run(t, "repairDiagnosis", bad)
		if !strings.Contains(out, "is not one of") {
			t.Errorf("a status outside the published enum was ACCEPTED. This is the "+
				"D1154 defect exactly: a consumer validating against the schema "+
				"rejects what the runtime prints, and nothing here notices.\n%s", out)
		}
	})

	t.Run("catches a type the schema does not publish", func(t *testing.T) {
		bad := map[string]any{}
		for k, v := range good {
			bad[k] = v
		}
		bad["tailEvents"] = "one" // published as an integer
		out := run(t, "repairDiagnosis", bad)
		if !strings.Contains(out, "schema says") {
			t.Errorf("a string where the schema publishes an integer was ACCEPTED — "+
				"the old check read only whether the property was PRESENT, which is "+
				"how this class survived:\n%s", out)
		}
	})

	t.Run("catches a required property that left", func(t *testing.T) {
		bad := map[string]any{}
		for k, v := range good {
			bad[k] = v
		}
		delete(bad, "fingerprint")
		out := run(t, "repairDiagnosis", bad)
		// NAMED, not merely "required property": the validator's own self-witness
		// prints "it accepted a missing required property" when it is broken, and a
		// bare substring match is satisfied by that sentence — so the assertion
		// passed while the detection was gone. Found by mutating this gate before
		// committing it; a check that accepts a WORD accepts a paragraph about the
		// word, and the fix is to match what only real detection can say.
		if !strings.Contains(out, "required property 'fingerprint' is absent") {
			t.Errorf("a departed required property was ACCEPTED — this is the one "+
				"thing the OLD check did catch, so losing it would be a "+
				"regression:\n%s", out)
		}
	})

	// The floor and the self-witness: both exist so that a broken or idle checker
	// cannot read as a clean one.
	t.Run("the check cannot pass on nothing", func(t *testing.T) {
		out := run(t, "repairDiagnosis", good)
		if !strings.Contains(out, "published shapes were produced") {
			t.Errorf("one shape did not trip the vacuity floor. A harness that "+
				"stopped exercising the verbs would validate almost nothing and "+
				"still print PASS (D328):\n%s", out)
		}
		if !strings.Contains(script, "the checker itself is broken") {
			t.Error("the validator no longer probes ITSELF with documents that must " +
				"fail. Every result it prints is a negative one, and a negative " +
				"result that cannot be told from a broken checker is worth nothing")
		}
	})
}
