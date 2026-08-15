// Package vocab loads attribute vocabularies — the per-capability type
// system (D10). A vocabulary is an OPTIONAL, strengthening input (D23):
// without one, loading and verification behave exactly as before.
package vocab

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"gopkg.in/yaml.v3"

	"groundhold/internal/docio"
)

type Vocabulary struct {
	Capability string
	Version    string
	Attributes map[string]map[string]any // path -> {kind, enum?, ...}
	Stateful   bool                      // D47
	// Protection (D698): deleting this capability removes a CONTROL rather than a
	// resource — threat detection, a WAF. Statefulness asks whether a delete loses
	// DATA; this asks whether it lowers a guard, and the answer is different for a
	// posture switch that holds no data at all.
	Protection bool
}

// LoadDir loads every vocabulary document in a directory, indexed by
// capability type.
func LoadDir(dir string) (map[string]Vocabulary, error) {
	paths, err := filepath.Glob(filepath.Join(dir, "*.yaml"))
	if err != nil {
		return nil, err
	}
	// D1091: a caller naming a directory is ASKING for it. `filepath.Glob` reports
	// no error for a path that does not exist and none for one holding no
	// vocabularies, so both used to return an empty map and no error — the operator
	// supplied `--vocab`, nothing loaded, nothing said so, and every custom
	// attribute silently lost the load-time kind/enum check (D19) it was there to
	// get. "I found nothing" and "there is nothing to find" arrived as one value.
	if len(paths) == 0 {
		if _, statErr := os.Stat(dir); statErr != nil {
			return nil, fmt.Errorf("vocabulary directory %s: %w", dir, statErr)
		}
		return nil, fmt.Errorf(
			"vocabulary directory %s holds no *.yaml vocabularies — it was named, so "+
				"it must supply something; use --no-vocab for the empty set", dir)
	}
	sort.Strings(paths)
	out := map[string]Vocabulary{}
	for _, p := range paths {
		raw, err := docio.ReadDoc(p)
		if err != nil {
			return nil, err
		}
		v, err := parseDoc(raw, p)
		if err != nil {
			return nil, err
		}
		// D668: the refusal existed and nothing called it. Its only caller was a
		// gate test over the EMBEDDED set, so a `--vocab` directory an operator
		// supplies was unvalidated: a typo'd `evidence:` fell back to `resource`,
		// the plan SEALED, and the refusal arrived at `apply` — past the gate, at
		// the mutation boundary, which is exactly the harm the function's own
		// docstring describes.
		if err := v.ValidateEvidence(); err != nil {
			return nil, fmt.Errorf("%s: %w", p, err)
		}
		out[v.Capability] = v
	}
	return out, nil
}

// parseDoc parses a single vocabulary document. name is used only for
// error messages (a file path or an embedded asset name). Shared by
// LoadDir (disk) and Embedded (compiled-in) so both parse identically.
func parseDoc(raw []byte, name string) (Vocabulary, error) {
	var docAny any
	if err := yaml.Unmarshal(raw, &docAny); err != nil {
		return Vocabulary{}, err
	}
	doc, ok := docAny.(map[string]any)
	capName, _ := doc["capability"].(string)
	if !ok || capName == "" {
		return Vocabulary{}, fmt.Errorf("%s: not a vocabulary document", name)
	}
	if err := checkVocabKeys(name, doc); err != nil {
		return Vocabulary{}, err
	}
	attrs := map[string]map[string]any{}
	if am, ok := doc["attributes"].(map[string]any); ok {
		for k, v := range am {
			if vm, ok := v.(map[string]any); ok {
				attrs[k] = vm
			}
		}
	}
	stateful, _ := doc["stateful"].(bool)
	protection, _ := doc["protection"].(bool)
	return Vocabulary{
		Capability: capName,
		Version:    fmt.Sprintf("%v", doc["version"]),
		Attributes: attrs,
		Stateful:   stateful,
		Protection: protection,
	}, nil
}

// ---- evidence class (D311) --------------------------------------------------
//
// An attribute's `evidence:` says HOW its value becomes true, from a closed set:
//
//	resource   (default, omitted) — the driver sets it and observe reads it back
//	projection — a forecast/derivation, never resource state (cost.monthly)
//	probe      — proven only by an outcome probe (recovery.rto)
//
// This was knowledge the vocabulary already carried in PROSE (`verification:`)
// and that the engine re-encoded by hand: a two-item switch in the compiler plus
// a no-op `case` in ~50 driver builders. Declaring it makes the type system the
// single source, so a new attribute of this class needs zero engine changes
// (D23/D55) — which is the whole point of a declarative vocabulary.
const (
	EvidenceResource   = "resource"
	EvidenceProjection = "projection"
	EvidenceProbe      = "probe"
)

// EvidenceOf returns the declared evidence class of an attribute, defaulting to
// EvidenceResource — an attribute that says nothing is ordinary resource state,
// so every existing vocabulary keeps its meaning unchanged.
func (v Vocabulary) EvidenceOf(path string) string {
	attr, ok := v.Attributes[path]
	if !ok {
		return EvidenceResource
	}
	switch e, _ := attr["evidence"].(string); e {
	case EvidenceProjection:
		return EvidenceProjection
	case EvidenceProbe:
		return EvidenceProbe
	default:
		// An unrecognised value is NOT silently treated as a projection: that
		// would make a typo weaken a reconcile. Unknown means ordinary state,
		// and ValidateEvidence is what refuses the typo out loud.
		return EvidenceResource
	}
}

// NotResourceState reports whether an attribute is something a driver can never
// read back — a projection or a probe outcome. Callers use it to keep such an
// attribute out of the change-set and out of a driver's builder entirely.
func (v Vocabulary) NotResourceState(path string) bool {
	return v.EvidenceOf(path) != EvidenceResource
}

// ValidateEvidence refuses an unrecognised `evidence:` value. A closed set that
// silently tolerates a typo is not closed — and here the typo's consequence is a
// reconcile that gates on an observation which will never arrive.
func (v Vocabulary) ValidateEvidence() error {
	paths := make([]string, 0, len(v.Attributes))
	for p := range v.Attributes {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	for _, p := range paths {
		e, present := v.Attributes[p]["evidence"]
		if !present {
			continue
		}
		s, _ := e.(string)
		switch s {
		case EvidenceResource, EvidenceProjection, EvidenceProbe:
		default:
			return fmt.Errorf("%s: attribute %s declares evidence %q — must be one of "+
				"resource | projection | probe", v.Capability, p, s)
		}
	}
	return nil
}

// The CLOSED key sets a vocabulary document may use, at the document level and per
// attribute (D701).
//
// There was no such set: every key not on the short list the parser read was silently
// dropped. `note:` rode on twelve attributes across nine files — genuinely useful
// prose, saying what static verification proves versus what an outcome probe proves —
// and no reader ever saw a word of it. This project refuses an operand no driver reads
// (D530) and an unknown top-level key in a contract (D673) for exactly this reason: a
// key that loads and does nothing is indistinguishable, to its author, from one that
// works.
//
// Only the KEY SET is enforced at load. "Every attribute is documented" is a rule
// about the vocabularies THIS project ships, not about anyone's extension document
// (`--vocab` extends the built-in set with a reader's own types), so it lives in a
// gate over spec/vocab rather than in a loader that would refuse a third party's
// undocumented-but-valid file.
//
// Each key here has a consumer, and that is the entry condition: `kind`/`enum` type
// candidate values, `description`/`verification`/`note`/`mappings` are published by
// `explain`, `evidence` classifies at the boundary (D311), `recommended` drives
// `suggest`, `unordered` makes a list a set, `stateful` and `protection` gate deletes.
var vocabDocKeys = map[string]bool{
	"capability": true, "version": true, "stateful": true, "protection": true,
	"attributes": true,
}

var vocabAttrKeys = map[string]bool{
	"kind": true, "description": true, "mappings": true, "evidence": true,
	"verification": true, "enum": true, "recommended": true, "note": true,
	"unordered": true,
}

func checkVocabKeys(name string, doc map[string]any) error {
	for _, k := range sortedKeys(doc) {
		if !vocabDocKeys[k] {
			return fmt.Errorf("%s: unknown vocabulary key %q — a key nothing reads is "+
				"silently dropped, so it is refused instead", name, k)
		}
	}
	am, _ := doc["attributes"].(map[string]any)
	for _, path := range sortedKeys(am) {
		spec, ok := am[path].(map[string]any)
		if !ok {
			return fmt.Errorf("%s: attribute %q is not a mapping", name, path)
		}
		for _, k := range sortedKeys(spec) {
			if !vocabAttrKeys[k] {
				return fmt.Errorf("%s: attribute %q has unknown key %q — a key nothing "+
					"reads is silently dropped, so it is refused instead", name, path, k)
			}
		}
	}
	return nil
}

func sortedKeys(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
