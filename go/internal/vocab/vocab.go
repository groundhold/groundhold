// Package vocab loads attribute vocabularies — the per-capability type
// system (D10). A vocabulary is an OPTIONAL, strengthening input (D23):
// without one, loading and verification behave exactly as before.
package vocab

import (
	"fmt"
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
}

// LoadDir loads every vocabulary document in a directory, indexed by
// capability type.
func LoadDir(dir string) (map[string]Vocabulary, error) {
	paths, err := filepath.Glob(filepath.Join(dir, "*.yaml"))
	if err != nil {
		return nil, err
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
	attrs := map[string]map[string]any{}
	if am, ok := doc["attributes"].(map[string]any); ok {
		for k, v := range am {
			if vm, ok := v.(map[string]any); ok {
				attrs[k] = vm
			}
		}
	}
	stateful, _ := doc["stateful"].(bool)
	return Vocabulary{
		Capability: capName,
		Version:    fmt.Sprintf("%v", doc["version"]),
		Attributes: attrs,
		Stateful:   stateful,
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
