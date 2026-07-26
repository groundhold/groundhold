package perr

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// D330: spec/errors.md is a PUBLISHED REGISTRY carrying the strongest promise in
// the repo about a machine-readable field — "the `code` field is the CONTRACT:
// scripts and agents route on it", additive-only, never reused. It had no gate,
// and the same rules bind FOUR artefacts that must agree:
//
//	the constants the runtime EMITS   (this file's const block)
//	the remediations `explain` PRINTS (the Explain map, projected by Registry())
//	the codes the spec PUBLISHES      (spec/errors.md)
//	the closed enum CONSUMERS VALIDATE AGAINST (spec/outputs.schema.json)
//
// When they drift the failure is not cosmetic: `groundhold explain <code>` answers
// "not an error code" for a code the runtime just emitted, the console — which
// projects Registry() verbatim under a one-glossary rule — shows a blocked figure
// with no way to fix it, and a consumer validating against the published schema
// rejects output the runtime is right to produce.
//
// The gate compares all four. Sibling of the D329 banner-vocabulary gate; this is
// the registry that one's rules were written to mirror.
func TestErrorCodeRegistryAgreesEverywhere(t *testing.T) {
	declared := declaredCodes(t)
	explained := map[string]bool{}
	for c := range Explain {
		explained[string(c)] = true
	}
	published, reserved := publishedCodes(t)
	schema := schemaCodes(t)

	if len(declared) == 0 || len(explained) == 0 || len(published) == 0 || len(schema) == 0 {
		t.Fatal("one of the four sets is empty — the gate would be vacuous (D328)")
	}

	diff := func(a, b map[string]bool) []string {
		var out []string
		for k := range a {
			if !b[k] {
				out = append(out, k)
			}
		}
		sort.Strings(out)
		return out
	}

	if miss := diff(declared, explained); len(miss) > 0 {
		t.Errorf("codes the runtime can emit with no entry in Explain: %v\n"+
			"`groundhold explain <code>` answers \"not an error code\" for these, and "+
			"the console's Registry() projection shows no remediation.", miss)
	}
	if extra := diff(explained, declared); len(extra) > 0 {
		t.Errorf("codes explained but never declared as constants: %v\n"+
			"the registry promises a remediation for something nothing emits.", extra)
	}
	if miss := diff(declared, published); len(miss) > 0 {
		t.Errorf("codes the runtime emits that spec/errors.md never published: %v\n"+
			"the registry is additive-only and calls itself the routing contract; a "+
			"consumer built from it meets a code it never learned.", miss)
	}
	// The schema enum is the sharpest of the four: it is CLOSED and referenced by
	// every verb's output shape, so a missing member does not merely under-document
	// — a consumer validating groundhold's own output against groundhold's own
	// published schema REJECTS a valid refusal.
	if miss := diff(declared, schema); len(miss) > 0 {
		t.Errorf("codes the runtime emits that are absent from the closed enum in "+
			"spec/outputs.schema.json: %v\na consumer validating output against the "+
			"published schema rejects a legitimate refusal carrying one of these.", miss)
	}
	if extra := diff(schema, declared); len(extra) > 0 {
		t.Errorf("schema enum admits codes nothing emits: %v", extra)
	}

	for _, c := range diff(published, declared) {
		if reserved[c] {
			continue // published, superseded, deliberately unimplemented
		}
		t.Errorf("spec/errors.md publishes %q but no constant emits it — "+
			"either implement it or mark the row reserved (the registry rule for a "+
			"superseded code).", c)
	}
}

// declaredCodes reads the const block in this package. Parsing source is normally
// the wrong instrument (D317), but the subject here IS a flat const block of string
// literals in one file — not dispatch logic — and the count guard below catches the
// shape change that would make the read vacuous.
func declaredCodes(t *testing.T) map[string]bool {
	t.Helper()
	raw, err := os.ReadFile("perr.go")
	if err != nil {
		t.Fatalf("read perr.go: %v", err)
	}
	out := map[string]bool{}
	re := regexp.MustCompile(`^\s*[A-Z]\w*\s+Code\s*=\s*"([a-z][a-z0-9-]*)"`)
	for _, line := range strings.Split(string(raw), "\n") {
		if m := re.FindStringSubmatch(line); m != nil {
			out[m[1]] = true
		}
	}
	if len(out) < 20 {
		t.Fatalf("found only %d code constants — the const block's shape changed and "+
			"this gate stopped measuring the thing it guards", len(out))
	}
	return out
}

// publishedCodes reads the registry table out of spec/errors.md, returning the
// published set and the subset marked reserved (the rule for a superseded code:
// it stays published forever, but nothing emits it).
func publishedCodes(t *testing.T) (published, reserved map[string]bool) {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", "..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(root, "spec", "errors.md"))
	if err != nil {
		t.Fatalf("read spec/errors.md: %v", err)
	}
	published, reserved = map[string]bool{}, map[string]bool{}
	row := regexp.MustCompile("^\\|\\s*`([a-z][a-z0-9-]*)`\\s*\\|(.*)$")
	for _, line := range strings.Split(string(raw), "\n") {
		m := row.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		published[m[1]] = true
		if strings.Contains(strings.ToLower(m[2]), "reserved") {
			reserved[m[1]] = true
		}
	}
	return published, reserved
}

// schemaCodes reads $defs.code.enum out of spec/outputs.schema.json — parsed as
// JSON, not scraped, because the enum is machine-consumed and a text match would
// not notice the def moving.
func schemaCodes(t *testing.T) map[string]bool {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", "..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(root, "spec", "outputs.schema.json"))
	if err != nil {
		t.Fatalf("read spec/outputs.schema.json: %v", err)
	}
	var doc struct {
		Defs struct {
			Code struct {
				Enum []string `json:"enum"`
			} `json:"code"`
		} `json:"$defs"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("parse spec/outputs.schema.json: %v", err)
	}
	out := map[string]bool{}
	for _, c := range doc.Defs.Code.Enum {
		out[c] = true
	}
	return out
}
