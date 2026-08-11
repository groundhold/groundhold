package verify

import (
	"os"
	"path/filepath"
	"testing"

	"groundhold/internal/contract"
	"groundhold/internal/vocab"
)

// setVocab is the shape of the only `unordered: true` attribute shipped today,
// `inference.destinationRegions` — the EU data-residency surface.
var setVocab = map[string]vocab.Vocabulary{
	"capability.ai.inference": {Attributes: map[string]map[string]any{
		"inference.destinationRegions": {"kind": "list", "unordered": true},
		"routing.order":                {"kind": "list"},
	}},
}

// load builds the pair through the REAL loaders, from files, because the
// candidate-side canonicalization this defect is about happens at load.
func load(t *testing.T, op string, operand, candValue []string, path string) (
	*contract.Contract, *contract.Candidate) {
	t.Helper()
	dir := t.TempDir()
	list := func(xs []string) string {
		out := ""
		for _, x := range xs {
			out += "\n      - " + x
		}
		return out
	}
	cpath := filepath.Join(dir, "c.yaml")
	if err := os.WriteFile(cpath, []byte(`apiVersion: contract/v0.1
kind: InfrastructureContract
meta: { id: p, owner: o@e.test, environment: test, version: 1 }
capabilities:
  - id: ai
    type: capability.ai.inference
constraints:
  hard:
    - id: c-set
      subject: ai
      path: `+path+`
      op: `+op+`
      value:`+list(operand)+`
      verify: { method: static }
`), 0o600); err != nil {
		t.Fatal(err)
	}
	kpath := filepath.Join(dir, "k.yaml")
	kl := ""
	for _, x := range candValue {
		kl += "\n        - " + x
	}
	if err := os.WriteFile(kpath, []byte(`apiVersion: candidate/v0.1
kind: ImplementationCandidate
contract: p
capabilities:
  ai:
    provider: fake
    service: sql
    attributes:
      `+path+`:`+kl+`
`), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := contract.LoadContract(cpath)
	if err != nil {
		t.Fatal(err)
	}
	cand, err := contract.LoadCandidate(kpath, c, setVocab)
	if err != nil {
		t.Fatal(err)
	}
	return c, cand
}

// D660. `unordered: true` says the attribute is a SET. The candidate's value was
// canonicalized (sorted) at load, where the vocabulary is known; the CONSTRAINT's
// operand never was. List equality is positional, so the verdict depended on the
// order the contract author happened to type:
//
//	contract not-equals [eu-west-1, eu-central-1]  vs  candidate [eu-central-1, eu-west-1]
//	  → PROVEN   exit 0      (the forbidden set, allowed)
//	contract not-equals [eu-central-1, eu-west-1]  vs  the same candidate
//	  → VIOLATED exit 2
//
// The candidate HASH is order-invariant, so the evidence looks canonical while the
// verdict is not. The only `unordered` attribute today is
// `inference.destinationRegions` — the EU data-residency surface.
func TestASetConstraintIgnoresTheOrderItWasTypedIn(t *testing.T) {
	for _, tc := range []struct {
		name    string
		op      string
		operand []string
		want    string
	}{
		{"equals, same order", "equals",
			[]string{"eu-central-1", "eu-west-1"}, "satisfied"},
		{"equals, other order", "equals",
			[]string{"eu-west-1", "eu-central-1"}, "satisfied"},
		{"not-equals, same order", "not-equals",
			[]string{"eu-central-1", "eu-west-1"}, "violated"},
		{"not-equals, other order", "not-equals",
			[]string{"eu-west-1", "eu-central-1"}, "violated"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, cand := load(t, tc.op, tc.operand,
				[]string{"eu-central-1", "eu-west-1"}, "inference.destinationRegions")
			rep, err := Verify(c, cand, setVocab)
			if err != nil {
				t.Fatal(err)
			}
			if got := rep.Verdicts[0].Verdict; got != tc.want {
				t.Errorf("verdict = %q, want %q — the same SET, written in a "+
					"different order, gets a different answer", got, tc.want)
			}
		})
	}
}

// The control: an ORDERED list (no `unordered:` marker) keeps positional equality.
// D21 says a plain `kind: list` is a sequence, and canonicalizing it would silently
// change what a contract means.
func TestAnOrderedListStaysOrdered(t *testing.T) {
	c, cand := load(t, "equals", []string{"b", "a"}, []string{"a", "b"},
		"routing.order")
	rep, err := Verify(c, cand, setVocab)
	if err != nil {
		t.Fatal(err)
	}
	if got := rep.Verdicts[0].Verdict; got != "violated" {
		t.Errorf("verdict = %q, want violated — [b,a] is not [a,b] for an ordered "+
			"list, and sorting it would change what the contract means", got)
	}
}
