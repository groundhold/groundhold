package contract

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"groundhold/internal/scalars"
	"groundhold/internal/vocab"
)

func contains(s, sub string) bool { return strings.Contains(s, sub) }

// mustParse is a test helper: scalar Parse that fails the test on error.
func mustParse(t *testing.T, v any) *scalars.Scalar {
	t.Helper()
	s, err := scalars.Parse(v)
	if err != nil {
		t.Fatalf("Parse(%v): %v", v, err)
	}
	return s
}

// --- idIsClean: control characters are rejected in stable ids (D179) ---

func TestIdIsClean(t *testing.T) {
	cases := []struct {
		name string
		id   string
		want bool
	}{
		{"ordinary", "db-primary_1.eu", true},
		{"empty", "", true}, // empty has no chars; emptiness is caught elsewhere
		{"nul", "a\x00b", false},
		{"del", "a\x7fb", false},
		{"tab", "a\tb", false},
		{"newline", "a\nb", false},
		{"unit-separator", "a\x1fb", false},
		{"space-ok", "a b", true}, // 0x20 is the first allowed rune
		{"high-unicode-ok", "café", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := idIsClean(c.id); got != c.want {
				t.Errorf("idIsClean(%q)=%v want %v", c.id, got, c.want)
			}
		})
	}
}

// --- toFloat: only int/int64/float64 are numbers; strings/bools are not ---

func TestToFloat(t *testing.T) {
	cases := []struct {
		name  string
		in    any
		want  float64
		wantK bool
	}{
		{"int", 7, 7, true},
		{"float", 1.5, 1.5, true},
		{"string", "3", 0, false},
		{"bool", true, 0, false},
		{"nil", nil, 0, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, ok := toFloat(c.in)
			if got != c.want || ok != c.wantK {
				t.Errorf("toFloat(%v)=(%v,%v) want (%v,%v)", c.in, got, ok, c.want, c.wantK)
			}
		})
	}
}

// --- newConstraint: the richest validator in the package ---

func TestNewConstraintErrors(t *testing.T) {
	cases := []struct {
		name     string
		raw      map[string]any
		severity string
		errSub   string // substring expected in the error
	}{
		{"missing id", map[string]any{"op": "equals", "value": 1}, "hard",
			"constraint missing id"},
		{"control-char id", map[string]any{"id": "a\x00b", "op": "equals", "value": 1}, "hard",
			"control character"},
		{"invalid severity", map[string]any{"id": "c", "op": "equals", "value": 1}, "critical",
			"invalid severity"},
		{"unknown op", map[string]any{"id": "c", "op": "matches", "value": 1}, "hard",
			"unknown operator"},
		{"op requires value", map[string]any{"id": "c", "op": "equals"}, "hard",
			"requires a value"},
		{"unknown verify method", map[string]any{"id": "c", "op": "equals", "value": 1,
			"verify": map[string]any{"method": "guess"}}, "hard", "unknown verify method"},
		{"ill-typed value (nil)", map[string]any{"id": "c", "op": "equals", "value": nil}, "hard",
			"ill-typed value"},
		{"in requires list", map[string]any{"id": "c", "op": "in", "value": "eu"}, "hard",
			"requires a list value"},
		{"compatible-with requires protocol", map[string]any{"id": "c",
			"op": "compatible-with", "value": "eu"}, "hard", "requires a protocol value"},
		{"lte non-orderable", map[string]any{"id": "c", "op": "lte", "value": "eu"}, "hard",
			"not orderable"},
		// objective rules
		{"invalid objective", map[string]any{"id": "c", "objective": "flatten"}, "soft",
			"invalid objective"},
		{"objective on hard", map[string]any{"id": "c", "objective": "minimize"}, "hard",
			"only valid on soft"},
		{"objective + op mutually exclusive", map[string]any{"id": "c",
			"objective": "minimize", "op": "equals", "value": 1}, "soft",
			"mutually exclusive"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := newConstraint(c.raw, c.severity)
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", c.errSub)
			}
			if !contains(err.Error(), c.errSub) {
				t.Errorf("error %q does not contain %q", err.Error(), c.errSub)
			}
		})
	}
}

func TestNewConstraintOK(t *testing.T) {
	t.Run("equals parses expected eagerly (D19)", func(t *testing.T) {
		c, err := newConstraint(map[string]any{"id": "rpo", "op": "lte", "value": "5m"}, "hard")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if c.Expected == nil || c.Expected.Kind != scalars.Duration {
			t.Fatalf("expected duration scalar, got %+v", c.Expected)
		}
		if c.Severity != "hard" || c.Op != "lte" || c.ID != "rpo" {
			t.Errorf("field mismatch: %+v", c)
		}
	})

	t.Run("presence op leaves Expected nil and ignores value", func(t *testing.T) {
		// SURPRISING: an "exists" op with a spurious value is accepted, and the
		// value is silently ignored (Expected stays nil). Pinned to document it.
		c, err := newConstraint(map[string]any{"id": "e", "op": "exists",
			"value": "ignored"}, "hard")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if c.Expected != nil {
			t.Errorf("presence op should not parse an expected scalar, got %+v", c.Expected)
		}
	})

	t.Run("soft objective is valid without op/value", func(t *testing.T) {
		c, err := newConstraint(map[string]any{"id": "cost", "objective": "minimize"}, "soft")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if c.Objective != "minimize" || c.Expected != nil {
			t.Errorf("unexpected constraint: %+v", c)
		}
	})

	t.Run("default verify method is static", func(t *testing.T) {
		c, err := newConstraint(map[string]any{"id": "x", "op": "equals", "value": 1}, "hard")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if c.VerifyMethod != "static" {
			t.Errorf("default method=%q want static", c.VerifyMethod)
		}
	})
}

// --- provenanced: provenance survives (invariant #3), unknown may be valueless ---

func TestProvenanced(t *testing.T) {
	t.Run("bare scalar defaults to declared", func(t *testing.T) {
		p, err := provenanced("5m")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if p.Status != "declared" || p.Scalar == nil || p.Scalar.Kind != scalars.Duration {
			t.Errorf("unexpected provenanced: %+v", p)
		}
	})

	t.Run("unknown status may omit value", func(t *testing.T) {
		p, err := provenanced(map[string]any{"status": "unknown"})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if p.Status != "unknown" || p.Scalar != nil {
			t.Errorf("unknown must carry nil scalar, got %+v", p)
		}
	})

	t.Run("non-unknown status requires a value", func(t *testing.T) {
		_, err := provenanced(map[string]any{"status": "assumed"})
		if err == nil || !contains(err.Error(), "requires a value") {
			t.Fatalf("want requires-a-value error, got %v", err)
		}
	})

	t.Run("invalid status refused", func(t *testing.T) {
		_, err := provenanced(map[string]any{"status": "guessed", "value": 1})
		if err == nil || !contains(err.Error(), "invalid provenance status") {
			t.Fatalf("want invalid-status error, got %v", err)
		}
	})

	t.Run("confidence out of range refused", func(t *testing.T) {
		_, err := provenanced(map[string]any{"status": "assumed", "value": 1,
			"confidence": 1.5})
		if err == nil || !contains(err.Error(), "confidence") {
			t.Fatalf("want confidence error, got %v", err)
		}
	})

	t.Run("confidence and source survive", func(t *testing.T) {
		p, err := provenanced(map[string]any{"status": "inferred", "value": "5m",
			"confidence": 0.75, "source": "code:db.go"})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if p.Confidence == nil || *p.Confidence != 0.75 || p.Source != "code:db.go" {
			t.Errorf("provenance fields lost: %+v", p)
		}
	})

	t.Run("map with value but no status is treated as a scalar object, not provenance",
		func(t *testing.T) {
			// SURPRISING but by-design: the provenance branch requires a "status"
			// key. A {value, source} map without status falls through to scalar
			// parsing, which cannot type it -> error. Pinned.
			_, err := provenanced(map[string]any{"value": "5m", "source": "x"})
			if err == nil || !contains(err.Error(), "cannot type object value") {
				t.Fatalf("want cannot-type error, got %v", err)
			}
		})
}

// --- LoadContractDoc: structural validation, fail-closed (D19) ---

// baseContract returns a minimal valid contract document; tests mutate a clone.
func baseContract() map[string]any {
	return map[string]any{
		"kind":       "InfrastructureContract",
		"apiVersion": "contract/v0.1",
		"meta":       map[string]any{"id": "ctr-1", "environment": "prod", "version": 2},
		"capabilities": []any{
			map[string]any{"id": "db", "type": "capability.database.relational"},
		},
	}
}

// hardConstraint builds one hard constraint on a real vocabulary path, with `extra`
// merged in — so a case says only what it is ABOUT and the rest of the document stays
// valid. A fixture that is invalid in a second way does not test what its name says.
func hardConstraint(extra map[string]any) map[string]any {
	c := map[string]any{"id": "c-region", "subject": "db",
		"path": "location.region", "op": "equals", "value": "eu-central-1"}
	for k, v := range extra {
		c[k] = v
	}
	return map[string]any{"hard": []any{c}}
}

func TestLoadContractDocErrors(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(map[string]any)
		errSub string
	}{
		{"wrong kind", func(d map[string]any) { d["kind"] = "Nope" }, "kind must be"},
		{"wrong apiVersion", func(d map[string]any) { d["apiVersion"] = "contract/v9" },
			"apiVersion must be"},
		{"missing meta id", func(d map[string]any) { d["meta"] = map[string]any{} },
			"meta.id is required"},
		// D1166: a bar written in the short form was DROPPED, no typo needed. The
		// refusal must name where the bar belongs, or an author who wrote something
		// reasonable is told only that it is wrong.
		{"a verification bar in the requirements sugar", func(d map[string]any) {
			caps, _ := d["capabilities"].([]any)
			c, _ := caps[0].(map[string]any)
			c["requirements"] = map[string]any{"location.region": map[string]any{
				"op": "equals", "value": "eu-central-1",
				"verify": map[string]any{"method": "provider-api"}}}
		}, "constraints.hard"},
		{"the short form itself still loads", func(d map[string]any) {
			caps, _ := d["capabilities"].([]any)
			c, _ := caps[0].(map[string]any)
			c["requirements"] = map[string]any{"service.managed": map[string]any{
				"op": "equals", "value": true}}
		}, ""},
		// An assumption is a record; a key the loader drops is a part of it that
		// will not be there when someone reads the audit back.
		{"a misspelled assumption key", func(d map[string]any) {
			d["assumptions"] = []any{map[string]any{
				"id": "a-guess", "statement": "x", "status": "assumed",
				"confidance": 0.9}}
		}, "confidance"},
		// D1164: the consent block. A misspelled key here is not a refusal later — it
		// is a gate nobody armed, and `forbidden` is the one where that is fail-OPEN.
		{"a misspelled autonomy key", func(d map[string]any) {
			d["autonomy"] = map[string]any{
				"forbiden": []any{map[string]any{"delete_stateful": true}}}
		}, "a gate nobody armed"},
		// Every consent list must be reference-checked, from ONE list of keys. The
		// reference implementation carried a hand-typed tuple of three while the
		// runtime read five, so this document was refused by one and accepted by the
		// other — measured, and live until D1164.
		{"an unknown capability under a later consent list", func(d map[string]any) {
			d["autonomy"] = map[string]any{"allow_field_reclaim": []any{"ghost"}}
			// Matched on the phrase only the CAPABILITY check says: drop the key from
			// the list and it becomes an unknown-KEY refusal, which still contains the
			// key's name and would satisfy a looser assertion (the same not-unique
			// marker trap as D1160 and D1162).
		}, "allow_field_reclaim references unknown capability"},
		{"an unknown capability under the newest consent list", func(d map[string]any) {
			d["autonomy"] = map[string]any{"allow_emission_adopt": []any{"ghost"}}
		}, "allow_emission_adopt references unknown capability"},
		// D1162: the two that trade evidence for a claim. Both must NAME the key —
		// a reader who typed `vrify:` and is told only "invalid contract" reads the
		// block, sees a plausible `verify`, and looks elsewhere.
		{"a misspelled verify block", func(d map[string]any) {
			d["constraints"] = hardConstraint(map[string]any{
				"vrify": map[string]any{"method": "provider-api"}})
		}, "vrify"},
		{"a misspelled method inside verify", func(d map[string]any) {
			d["constraints"] = hardConstraint(map[string]any{
				"verify": map[string]any{"methdo": "provider-api"}})
		}, "methdo"},
		// The refusal must say what is at stake, or it reads as pedantry about a typo
		// rather than as a bar quietly dropping to the weakest evidence there is.
		// Matched on a phrase only THIS refusal uses: "weakest evidence there is" also
		// appears in D627's message two screens up, so a mutant on one left the other
		// satisfying the assertion — the same not-unique-marker trap as D1160's.
		{"the verify refusal says what it costs", func(d map[string]any) {
			d["constraints"] = hardConstraint(map[string]any{
				"verify": map[string]any{"methdo": "provider-api"}})
		}, "a bar nobody set"},
		// D1161: the levels INSIDE the document. The top level has been closed since
		// D673; these three were not, so a stray key was read by nothing while the
		// contract validated. One case PER LEVEL on purpose — one guard serving three
		// call sites passes easily on two of them.
		{"a stray key in meta", func(d map[string]any) {
			m, _ := d["meta"].(map[string]any)
			m["ownr"] = "someone"
		}, "ownr"},
		{"a stray key in a capability", func(d map[string]any) {
			caps, _ := d["capabilities"].([]any)
			c, _ := caps[0].(map[string]any)
			c["retention"] = "30d"
		}, "a requirement that never existed"},
		// The escape the top level has advertised since D673 must work here too, or a
		// document using the published hatch is refused one indentation further in.
		{"an x- key in a capability is NOT an error", func(d map[string]any) {
			caps, _ := d["capabilities"].([]any)
			c, _ := caps[0].(map[string]any)
			c["x-notes"] = "deliberately not runtime data"
		}, ""},
		{"capability missing id", func(d map[string]any) {
			d["capabilities"] = []any{map[string]any{"type": "capability.database.relational"}}
		}, "capability missing id"},
		{"control-char cap id", func(d map[string]any) {
			d["capabilities"] = []any{map[string]any{"id": "a\x00b",
				"type": "capability.database.relational"}}
		}, "control character"},
		{"unknown cap type", func(d map[string]any) {
			d["capabilities"] = []any{map[string]any{"id": "db", "type": "capability.bogus"}}
		}, "unknown capability type"},
		{"duplicate cap id", func(d map[string]any) {
			d["capabilities"] = []any{
				map[string]any{"id": "db", "type": "capability.database.relational"},
				map[string]any{"id": "db", "type": "capability.storage.object"},
			}
		}, "duplicate capability id"},
		{"invalid cap state", func(d map[string]any) {
			d["capabilities"] = []any{map[string]any{"id": "db",
				"type": "capability.database.relational", "state": "paused"}}
		}, "invalid state"},
		{"retired cap with requirements", func(d map[string]any) {
			d["capabilities"] = []any{map[string]any{"id": "db",
				"type": "capability.database.relational", "state": "retired",
				"requirements": map[string]any{"engine": map[string]any{"value": "x"}}}}
		}, "retired capability cannot carry requirements"},
		{"duplicate constraint id", func(d map[string]any) {
			d["constraints"] = map[string]any{"hard": []any{
				map[string]any{"id": "c1", "subject": "db", "op": "equals", "value": 1},
				map[string]any{"id": "c1", "subject": "db", "op": "equals", "value": 2},
			}}
		}, "duplicate constraint ids"},
		{"unknown subject", func(d map[string]any) {
			d["constraints"] = map[string]any{"hard": []any{
				map[string]any{"id": "c1", "subject": "ghost", "op": "equals", "value": 1},
			}}
		}, "unknown subject"},
		{"constraint targets retired cap", func(d map[string]any) {
			d["capabilities"] = []any{
				map[string]any{"id": "db", "type": "capability.database.relational",
					"state": "retired"},
			}
			d["constraints"] = map[string]any{"hard": []any{
				map[string]any{"id": "c1", "subject": "db", "op": "equals", "value": 1},
			}}
		}, "targets retired capability"},
		{"assumption unknown affects", func(d map[string]any) {
			d["assumptions"] = []any{map[string]any{"id": "a1", "status": "assumed",
				"statement": "the disk is fast", "affects": []any{"nope"}}}
		}, "affects unknown constraint"},
		{"assumption bad status", func(d map[string]any) {
			d["assumptions"] = []any{map[string]any{"id": "a1", "status": "hunch",
				"statement": "the disk is fast"}}
		}, "invalid status"},
		{"autonomy forbidden unknown constraint", func(d map[string]any) {
			d["autonomy"] = map[string]any{"forbidden": []any{
				map[string]any{"disable": "ghost"}}}
		}, "unknown constraint"},
		{"autonomy allow_replace unknown cap", func(d map[string]any) {
			d["autonomy"] = map[string]any{"allow_replace_stateful": []any{"ghost"}}
		}, "unknown capability"},
		{"autonomy no_assumed_hard_basis non-bool", func(d map[string]any) {
			d["autonomy"] = map[string]any{"no_assumed_hard_basis": "yes"}
		}, "must be a boolean"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			doc := baseContract()
			c.mutate(doc)
			_, err := LoadContractDoc(doc)
			// D1161: an empty errSub means the mutation must be ACCEPTED. The `x-`
			// escape has been published since D673 and the guard now runs at four
			// levels; a hatch that works only at the top is a hatch that surprises.
			if c.errSub == "" {
				if err != nil {
					t.Fatalf("want no error, got %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", c.errSub)
			}
			if !contains(err.Error(), c.errSub) {
				t.Errorf("error %q does not contain %q", err.Error(), c.errSub)
			}
		})
	}
}

func TestLoadContractDocOK(t *testing.T) {
	t.Run("minimal valid contract, version parsed", func(t *testing.T) {
		c, err := LoadContractDoc(baseContract())
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if c.ID != "ctr-1" || c.Environment != "prod" || c.Version != 2 {
			t.Errorf("meta not carried: %+v", c)
		}
	})

	t.Run("version defaults to 1 when absent", func(t *testing.T) {
		doc := baseContract()
		doc["meta"] = map[string]any{"id": "ctr-1"}
		c, err := LoadContractDoc(doc)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if c.Version != 1 {
			t.Errorf("version=%d want default 1", c.Version)
		}
	})

	t.Run("requirements desugar into deterministic hard constraints (D8)", func(t *testing.T) {
		doc := baseContract()
		doc["capabilities"] = []any{map[string]any{"id": "db",
			"type": "capability.database.relational",
			"requirements": map[string]any{
				"engine": map[string]any{"op": "compatible-with", "value": "postgresql/16"},
				"region": map[string]any{"value": "eu-west1"}, // op defaults to equals
			}}}
		c, err := LoadContractDoc(doc)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		got := map[string]bool{}
		for _, ct := range c.Constraints {
			got[ct.ID] = true
			if ct.Subject != "db" || ct.Severity != "hard" {
				t.Errorf("desugared constraint wrong shape: %+v", ct)
			}
		}
		for _, want := range []string{"req-db-engine", "req-db-region"} {
			if !got[want] {
				t.Errorf("missing desugared constraint %q; have %v", want, got)
			}
		}
	})

	t.Run("budget block defaults to hard severity", func(t *testing.T) {
		doc := baseContract()
		doc["budget"] = []any{
			map[string]any{"id": "b1", "subject": "db", "op": "lte", "value": "100 USD"},
			map[string]any{"id": "b2", "subject": "db", "op": "lte", "value": "50 USD",
				"severity": "soft"},
		}
		c, err := LoadContractDoc(doc)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		sev := map[string]string{}
		for _, ct := range c.Constraints {
			sev[ct.ID] = ct.Severity
		}
		if sev["b1"] != "hard" {
			t.Errorf("budget default severity=%q want hard", sev["b1"])
		}
		if sev["b2"] != "soft" {
			t.Errorf("budget explicit severity=%q want soft", sev["b2"])
		}
	})
}

// --- vocabCheck: D23 kind/enum gating, numeric 3.0==3 canonical equality ---

func TestVocabCheck(t *testing.T) {
	newContract := func() *Contract {
		return &Contract{Capabilities: map[string]map[string]any{
			"db": {"type": "capability.database.relational"}}}
	}
	vocabs := map[string]vocab.Vocabulary{
		"capability.database.relational": {
			Attributes: map[string]map[string]any{
				"engine":   {"kind": "protocol"},
				"replicas": {"kind": "number", "enum": []any{1, 3, 5}},
				"tier":     {"kind": "string", "enum": []any{"gp2", "gp3"}},
			},
		},
	}
	check := func(attr string, v any) error {
		cand := &Candidate{Capabilities: map[string]map[string]Provenanced{
			"db": {attr: {Scalar: mustParse(t, v), Status: "declared"}}}}
		return vocabCheck(cand, newContract(), vocabs)
	}

	t.Run("kind mismatch refused", func(t *testing.T) {
		// engine declared as a duration, vocab says protocol
		err := check("engine", "5m")
		if err == nil || !contains(err.Error(), "vocabulary defines kind protocol") {
			t.Fatalf("want kind-mismatch error, got %v", err)
		}
	})

	t.Run("matching protocol passes", func(t *testing.T) {
		if err := check("engine", "postgresql/16"); err != nil {
			t.Errorf("unexpected error: %v", err)
		}
	})

	t.Run("numeric enum: 3.0 matches int enum member 3", func(t *testing.T) {
		if err := check("replicas", 3.0); err != nil {
			t.Errorf("3.0 should match enum [1 3 5]: %v", err)
		}
	})

	t.Run("numeric enum miss refused", func(t *testing.T) {
		err := check("replicas", 4)
		if err == nil || !contains(err.Error(), "not in vocabulary enum") {
			t.Fatalf("want enum-miss error, got %v", err)
		}
	})

	t.Run("string enum hit passes", func(t *testing.T) {
		if err := check("tier", "gp3"); err != nil {
			t.Errorf("unexpected error: %v", err)
		}
	})

	t.Run("string enum miss refused", func(t *testing.T) {
		err := check("tier", "gp99")
		if err == nil || !contains(err.Error(), "not in vocabulary enum") {
			t.Fatalf("want enum-miss error, got %v", err)
		}
	})

	t.Run("attribute outside the vocabulary is legal", func(t *testing.T) {
		if err := check("some_provider_flag", "whatever"); err != nil {
			t.Errorf("non-vocabulary path should be allowed: %v", err)
		}
	})
}

// --- LoadContract / LoadCandidate: file paths, extras, provenance survival ---

func writeFile(t *testing.T, dir, name, body string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatalf("write %s: %v", p, err)
	}
	return p
}

func TestLoadContractAndCandidateRoundtrip(t *testing.T) {
	dir := t.TempDir()
	contractYAML := `
kind: InfrastructureContract
apiVersion: contract/v0.1
meta:
  id: ctr-db
  environment: prod
capabilities:
  - id: db
    type: capability.database.relational
constraints:
  hard:
    - id: c-rpo
      subject: db
      op: lte
      value: "5m"
`
	cpath := writeFile(t, dir, "contract.yaml", contractYAML)
	c, err := LoadContract(cpath)
	if err != nil {
		t.Fatalf("LoadContract: %v", err)
	}
	if c.ID != "ctr-db" || len(c.Constraints) != 1 {
		t.Fatalf("unexpected contract: %+v", c)
	}

	candidateYAML := `
kind: ImplementationCandidate
apiVersion: candidate/v0.1
contract: ctr-db
capabilities:
  db:
    provider: gcp
    service: cloudsql
    attributes:
      engine:
        status: inferred
        value: "postgresql/16"
        source: "code:db.go"
      rpo: "5m"
`
	candPath := writeFile(t, dir, "candidate.yaml", candidateYAML)
	cand, err := LoadCandidate(candPath, nil, nil)
	if err != nil {
		t.Fatalf("LoadCandidate: %v", err)
	}
	if cand.ContractID != "ctr-db" {
		t.Errorf("contract id=%q", cand.ContractID)
	}
	// Provenance survives (invariant #3): inferred status + source preserved.
	eng := cand.Capabilities["db"]["engine"]
	if eng.Status != "inferred" || eng.Source != "code:db.go" {
		t.Errorf("provenance lost: %+v", eng)
	}
	// A bare scalar attribute defaults to declared.
	if cand.Capabilities["db"]["rpo"].Status != "declared" {
		t.Errorf("bare scalar should default to declared: %+v", cand.Capabilities["db"]["rpo"])
	}
	// Extras: non-attribute keys are captured for identity, not verified.
	extra := cand.Extras["db"]
	if extra["provider"] != "gcp" || extra["service"] != "cloudsql" {
		t.Errorf("extras not captured: %+v", extra)
	}
	if _, leaked := extra["attributes"]; leaked {
		t.Errorf("attributes must not leak into extras: %+v", extra)
	}
}

func TestLoadCandidateErrors(t *testing.T) {
	dir := t.TempDir()
	cases := []struct {
		name, body, errSub string
	}{
		{"wrong kind", "kind: Nope\napiVersion: candidate/v0.1\ncontract: x\n",
			"kind must be"},
		{"wrong apiVersion",
			"kind: ImplementationCandidate\napiVersion: candidate/v9\ncontract: x\n",
			"apiVersion must be"},
		{"missing contract",
			"kind: ImplementationCandidate\napiVersion: candidate/v0.1\n",
			"must name its contract"},
		{"bad provenance status",
			"kind: ImplementationCandidate\napiVersion: candidate/v0.1\ncontract: x\n" +
				"capabilities:\n  db:\n    attributes:\n      e:\n        status: hunch\n        value: 1\n",
			"invalid provenance status"},
		// D1160, from the field: an operand written one level too high. The block
		// takes four keys; a fifth was collected and dropped, so `plan` sealed at
		// exit 0 and the resource kept the default the author thought they changed.
		// The refusal must NAME the key and say where an operand belongs, or the
		// reader is told only that something is wrong.
		// D1161, one indentation further in than the case below: a typo in a
		// provenance block dropped the confidence and the document passed at exit 0,
		// so an assumption's strength vanished with nothing said.
		{"a typo in a provenance block",
			"kind: ImplementationCandidate\napiVersion: candidate/v0.1\ncontract: x\n" +
				"capabilities:\n  db:\n    attributes:\n      service.managed:\n" +
				"        status: declared\n        value: true\n        confidance: 0.9\n",
			"confidance"},
		{"a key above the operands",
			"kind: ImplementationCandidate\napiVersion: candidate/v0.1\ncontract: x\n" +
				"capabilities:\n  db:\n    attributes:\n      service.managed: true\n" +
				"    memory_mb: 512\n",
			"memory_mb"},
		{"the refusal points at the free-form block",
			"kind: ImplementationCandidate\napiVersion: candidate/v0.1\ncontract: x\n" +
				"capabilities:\n  db:\n    attributes:\n      service.managed: true\n" +
				"    role_arn: arn:aws:iam::1:role/r\n",
			"belongs under `implementation:`"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p := writeFile(t, dir, "cand.yaml", c.body)
			_, err := LoadCandidate(p, nil, nil)
			if err == nil || !contains(err.Error(), c.errSub) {
				t.Fatalf("want error containing %q, got %v", c.errSub, err)
			}
		})
	}
}

func TestLoadContractRejectsNonMapping(t *testing.T) {
	dir := t.TempDir()
	p := writeFile(t, dir, "list.yaml", "- just\n- a\n- list\n")
	if _, err := LoadContract(p); err == nil ||
		!contains(err.Error(), "empty or not a mapping") {
		t.Fatalf("want not-a-mapping error, got %v", err)
	}
}

// D719. Acme's first field report: a contract with two unknown capability types
// cost one run per mistake, because the loader refused at the first — and the
// refusal named what was wrong without naming what is right, over a vocabulary it
// was holding. The conformance suite pins this cross-implementation; this pins it
// where `go test` can see it, which is where the mutation meter looks.
func TestUnknownCapabilityTypesAreAllNamedWithSuggestions(t *testing.T) {
	doc := map[string]any{
		"apiVersion": "contract/v0.1",
		"kind":       "InfrastructureContract",
		"meta":       map[string]any{"id": "e719", "environment": "production", "version": 1},
		"capabilities": []any{
			map[string]any{"id": "fw", "type": "capability.network.firewall"},
			map[string]any{"id": "det", "type": "capability.security.detection"},
			map[string]any{"id": "db", "type": "capability.database.relational"},
		},
	}
	_, err := LoadContractDoc(doc)
	if err == nil {
		t.Fatal("a contract with unknown capability types must be refused")
	}
	got := err.Error()
	for _, want := range []string{
		"2 unknown capability types",
		"capability.network.firewall",
		"capability.security.detection",
		"closest known types: capability.security.threatdetection",
		"the vocabulary is closed and has 57 types",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("refusal does not say %q; it said:\n%s", want, got)
		}
	}
	// A refusal that stops at the first mistake reads the same as one that found
	// only one. The count is what tells the two apart.
	if strings.Contains(got, "unknown capability type:") {
		t.Errorf("the refusal is in the single-type form, so it stopped at the first "+
			"of two; it said:\n%s", got)
	}
}

// D728: the two-bar verify form, and the three ways it is refused rather than allowed
// to become the defect it fixes. The conformance suite pins these cross-implementation;
// this pins them where the mutation meter looks.
func TestVerifyTwoBarFormRefusals(t *testing.T) {
	base := func(v map[string]any) map[string]any {
		return map[string]any{
			"apiVersion": "contract/v0.1",
			"kind":       "InfrastructureContract",
			"meta":       map[string]any{"id": "d728", "environment": "test", "version": 1},
			"capabilities": []any{
				map[string]any{"id": "net", "type": "capability.network.private"}},
			"constraints": map[string]any{"hard": []any{map[string]any{
				"id": "c", "subject": "net", "path": "egress.restricted",
				"op": "equals", "value": true, "verify": v}}},
		}
	}
	cases := []struct {
		name   string
		verify map[string]any
		want   string
	}{
		{"design stronger than runtime",
			map[string]any{"design": "probe", "runtime": "static"},
			"stronger than verify.runtime"},
		{"both spellings of the same bar",
			map[string]any{"method": "static", "design": "static", "runtime": "provider-api"},
			"one bar or two, never both spellings"},
		{"half the two-bar form",
			map[string]any{"design": "static"},
			"needs BOTH `design` and `runtime`"},
		{"a bar the loader cannot read",
			map[string]any{"design": nil, "runtime": "provider-api"},
			"must be strings"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := LoadContractDoc(base(c.verify))
			if err == nil {
				t.Fatalf("accepted; this is the shape that made the fix into its own defect")
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Fatalf("refusal does not say %q; it said %q", c.want, err)
			}
		})
	}
	// The coherent pair loads, and both bars survive.
	c, err := LoadContractDoc(base(map[string]any{"design": "static", "runtime": "provider-api"}))
	if err != nil {
		t.Fatalf("the two-bar form must load: %v", err)
	}
	if c.Constraints[0].VerifyMethod != "static" || c.Constraints[0].RuntimeMethod != "provider-api" {
		t.Fatalf("bars did not survive: %+v", c.Constraints[0])
	}
}

// D1160. The capability block's four keys live in three places — this loader, the
// reference implementation, and `spec/candidate.schema.json`, which is what a stranger
// validates a document against before the runtime ever sees it. A key one accepts and
// another drops is a document that loads here and is rejected there, or worse: read by
// nobody and silently discarded, which is the defect this set was closed to stop.
//
// Derived from the schema rather than restated: a hand-typed copy in a test is a fourth
// place to drift.
func TestCandidateCapabilityKeysMatchThePublishedShape(t *testing.T) {
	root := vocabParityRoot(t)
	raw, err := os.ReadFile(filepath.Join(root, "spec", "candidate.schema.json"))
	if err != nil {
		t.Skipf("no candidate schema in this tree: %v", err)
	}
	var doc struct {
		Properties struct {
			Capabilities struct {
				AdditionalProperties struct {
					AdditionalProperties *bool          `json:"additionalProperties"`
					Properties           map[string]any `json:"properties"`
				} `json:"additionalProperties"`
			} `json:"capabilities"`
		} `json:"properties"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("candidate schema does not parse: %v", err)
	}
	block := doc.Properties.Capabilities.AdditionalProperties

	published := make([]string, 0, len(block.Properties))
	for k := range block.Properties {
		published = append(published, k)
	}
	sort.Strings(published)
	if len(published) == 0 {
		t.Fatal("the schema publishes no capability-block keys — the scan lost its " +
			"subject and this gate would pass over anything (D328)")
	}

	accepted := make([]string, 0, len(candidateCapabilityKeys))
	for k := range candidateCapabilityKeys {
		accepted = append(accepted, k)
	}
	sort.Strings(accepted)

	if strings.Join(published, ",") != strings.Join(accepted, ",") {
		t.Errorf("the schema publishes %v; this loader accepts %v.\nA document valid "+
			"against the published shape must load, and one this loader accepts must "+
			"validate — otherwise the two disagree about what a candidate IS.",
			published, accepted)
	}

	// The schema must also CLOSE the block. Published with growth allowed, a stray key
	// validates cleanly for a consumer while the runtime refuses it — the same
	// disagreement from the other side.
	if block.AdditionalProperties == nil || *block.AdditionalProperties {
		t.Error("the capability block does not set `additionalProperties: false`. " +
			"`implementation` is the free-form half (D26); this level is structure, " +
			"and a schema that accepts any key here publishes a promise the loader " +
			"does not keep")
	}
}

// D1161. Three more levels closed, and the same reconciliation D1160 built for the
// candidate's capability block: what the loader accepts must be what the published
// document says, or a contract valid for a consumer is refused here — or worse, one this
// loader accepts is dropped by a consumer that validates.
//
// Derived from the schema, never restated: a hand-typed copy in a test is one more place
// to drift, which is the defect this whole family is about.
func TestContractInnerKeysMatchThePublishedShape(t *testing.T) {
	root := vocabParityRoot(t)
	read := func(name string) map[string]any {
		raw, err := os.ReadFile(filepath.Join(root, "spec", name))
		if err != nil {
			t.Skipf("no %s in this tree: %v", name, err)
		}
		var d map[string]any
		if err := json.Unmarshal(raw, &d); err != nil {
			t.Fatalf("%s does not parse: %v", name, err)
		}
		return d
	}
	dig := func(m map[string]any, path ...string) map[string]any {
		for _, p := range path {
			next, _ := m[p].(map[string]any)
			if next == nil {
				t.Fatalf("the published shape has no %q — the scan lost its subject "+
					"and this gate would pass over anything (D328)", p)
			}
			m = next
		}
		return m
	}
	published := func(block map[string]any) ([]string, bool, bool) {
		props, _ := block["properties"].(map[string]any)
		out := make([]string, 0, len(props))
		for k := range props {
			out = append(out, k)
		}
		sort.Strings(out)
		closed, _ := block["additionalProperties"].(bool)
		_, escape := block["patternProperties"]
		return out, block["additionalProperties"] != nil && !closed, escape
	}
	accepted := func(m map[string]bool) []string {
		out := make([]string, 0, len(m))
		for k := range m {
			out = append(out, k)
		}
		sort.Strings(out)
		return out
	}

	contract := read("contract.schema.json")
	candidate := read("candidate.schema.json")
	for _, tc := range []struct {
		name  string
		block map[string]any
		set   map[string]bool
	}{
		{"contract capability",
			dig(contract, "properties", "capabilities", "items"), contractCapabilityKeys},
		// D1162. The verify block is the sharpest of these: it published ONE spelling
		// of a bar while the loader has read two since D728, so a contract using the
		// two-bar form was valid for the runtime and invalid against this document.
		{"verify", dig(contract, "$defs", "verify"), verifyKeys},
		{"constraint", dig(contract, "$defs", "constraint"), constraintKeys},
		{"soft constraint", dig(contract, "$defs", "softConstraint"), softConstraintKeys},
		{"budget constraint",
			dig(contract, "$defs", "budgetConstraint"), budgetConstraintKeys},
		// D1166: the short form. Published `op`+`value`; the loader hardcodes a static
		// bar and reads nothing else, so anything more written here is dropped.
		{"requirement", dig(contract, "properties", "capabilities", "items",
			"properties", "requirements", "additionalProperties"), requirementKeys},
		{"assumption", dig(contract, "properties", "assumptions", "items"), assumptionKeys},
		{"contract meta",
			dig(contract, "properties", "meta"), contractMetaKeys},
		{"provenanced attribute",
			dig(candidate, "$defs", "provenanced"), provenancedKeys},
		// D1170. Eight nesting levels were closed and compared here, and the level
		// EVERY document has was not among them — the only one a reader meets before
		// they have written anything. It hid two of exactly the defect this table
		// exists to catch: the candidate's root published four keys while the loader
		// accepted five (`meta`, read by nobody — measured, a candidate carrying it
		// hashed IDENTICALLY to one without), and the contract's root accepted a
		// `requirements` block the schema has never published and nothing has ever
		// read at that depth. Both roots were also OPEN, so a contract spelled
		// `constraint:` — the D673 defect verbatim — validated against the published
		// document without a word.
		{"contract root", contract, knownTopLevel["InfrastructureContract"]},
		{"candidate root", candidate, knownTopLevel["ImplementationCandidate"]},
	} {
		t.Run(tc.name, func(t *testing.T) {
			keys, closed, escape := published(tc.block)
			if len(keys) == 0 {
				t.Fatal("the schema publishes no keys for this block (D328)")
			}
			if got := accepted(tc.set); strings.Join(got, ",") != strings.Join(keys, ",") {
				t.Errorf("the schema publishes %v; this loader accepts %v.\nA document "+
					"valid against the published shape must load, and one this loader "+
					"accepts must validate.", keys, got)
			}
			if !closed {
				t.Error("the block does not set `additionalProperties: false`. Published " +
					"with growth allowed, a stray key validates cleanly for a consumer " +
					"while the runtime refuses it — the same disagreement from the " +
					"other side")
			}
			// The loader honours `x-` at every level it guards; a schema that closed the
			// block without the escape would reject documents the runtime accepts.
			if !escape {
				t.Error("the block is closed but publishes no `x-` escape, which the " +
					"loader honours — the two disagree about a document that uses the " +
					"hatch this project has advertised since D673")
			}
		})
	}
}
