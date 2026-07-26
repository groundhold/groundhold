// Package compose composes a base InfrastructureContract with ordered overlays
// (D199): environment DRY (dev/staging/prod) WITHOUT inheritance or
// interpolation in the contract language — invariant #4 stays intact because the
// output is a FLAT, complete contract (just "more constraints"), not a template.
// Composition is an authoring transform; the verifier, hashing and legibility of
// the sealed contract are untouched. Diff reports the constraint delta between
// two contracts and whether one's invariants are a subset of the other's — the
// deterministic promotion proof (dev ⊆ staging ⊆ prod) Terragrunt cannot give.
package compose

import (
	"fmt"
	"sort"
)

// idKeyedLists are the top-level list sections whose items carry a unique "id"
// and merge by union-over-id: an overlay item replaces the base item with the
// same id, otherwise it is appended.
var idKeyedLists = []string{"capabilities", "budget", "assumptions", "outcomes"}

// Merge composes base with overlays in order (later overlays win). meta keys are
// shallow-overridden; capabilities/budget/assumptions/outcomes and
// constraints.hard/.soft union by id; autonomy and any other scalar/map section
// is replaced whole. The result is deterministic: id-keyed lists are sorted by
// id so a given (base, overlays) always yields a byte-identical document.
func Merge(base map[string]any, overlays ...map[string]any) (map[string]any, error) {
	if base == nil {
		return nil, fmt.Errorf("base contract is empty")
	}
	out := deepCopyMap(base)
	for i, ov := range overlays {
		if ov == nil {
			return nil, fmt.Errorf("overlay %d is empty", i+1)
		}
		if err := mergeInto(out, ov); err != nil {
			return nil, fmt.Errorf("overlay %d: %w", i+1, err)
		}
	}
	sortContract(out)
	return out, nil
}

func mergeInto(out, ov map[string]any) error {
	for k, v := range ov {
		switch {
		case k == "meta":
			om, _ := out["meta"].(map[string]any)
			if om == nil {
				om = map[string]any{}
			}
			vm, ok := v.(map[string]any)
			if !ok {
				return fmt.Errorf("meta must be a mapping")
			}
			for mk, mv := range vm {
				om[mk] = deepCopy(mv)
			}
			out["meta"] = om
		case k == "constraints":
			ob, _ := out["constraints"].(map[string]any)
			if ob == nil {
				ob = map[string]any{}
			}
			vb, ok := v.(map[string]any)
			if !ok {
				return fmt.Errorf("constraints must be a mapping")
			}
			for _, sev := range []string{"hard", "soft"} {
				merged, err := mergeListByID(ob[sev], vb[sev], "constraints."+sev)
				if err != nil {
					return err
				}
				if merged != nil {
					ob[sev] = merged
				}
			}
			out["constraints"] = ob
		case contains(idKeyedLists, k):
			merged, err := mergeListByID(out[k], v, k)
			if err != nil {
				return err
			}
			out[k] = merged
		default:
			out[k] = deepCopy(v) // apiVersion, kind, autonomy, ... replaced whole
		}
	}
	return nil
}

// mergeListByID unions two id-keyed lists: overlay items replace base items with
// the same id (in place), new ids append. A nil overlay list leaves base as-is.
func mergeListByID(baseAny, ovAny any, what string) ([]any, error) {
	base := toList(baseAny)
	ov := toList(ovAny)
	if ovAny == nil {
		if baseAny == nil {
			return nil, nil
		}
		return base, nil
	}
	idx := map[string]int{}
	out := make([]any, len(base))
	copy(out, base)
	for i, it := range out {
		if id, ok := itemID(it); ok {
			idx[id] = i
		}
	}
	for _, it := range ov {
		id, ok := itemID(it)
		if !ok {
			return nil, fmt.Errorf("%s: overlay item without an id", what)
		}
		if pos, exists := idx[id]; exists {
			out[pos] = deepCopy(it)
		} else {
			idx[id] = len(out)
			out = append(out, deepCopy(it))
		}
	}
	return out, nil
}

// sortContract orders every id-keyed list by id so output is stable.
func sortContract(doc map[string]any) {
	for _, k := range idKeyedLists {
		if l, ok := doc[k].([]any); ok {
			sortByID(l)
		}
	}
	if cb, ok := doc["constraints"].(map[string]any); ok {
		for _, sev := range []string{"hard", "soft"} {
			if l, ok := cb[sev].([]any); ok {
				sortByID(l)
			}
		}
	}
}

func sortByID(l []any) {
	sort.SliceStable(l, func(i, j int) bool {
		a, _ := itemID(l[i])
		b, _ := itemID(l[j])
		return a < b
	})
}

// ---- Diff ---------------------------------------------------------------

// DiffResult is the constraint/capability delta between two contracts A and B.
type DiffResult struct {
	HardOnlyInA []string `json:"hardOnlyInA"`
	HardOnlyInB []string `json:"hardOnlyInB"`
	CapsOnlyInA []string `json:"capsOnlyInA"`
	CapsOnlyInB []string `json:"capsOnlyInB"`
	// ASubsetOfB is true when every hard-constraint id in A is also in B — B is
	// at least as strict as A (the dev ⊆ prod promotion proof).
	ASubsetOfB bool `json:"aSubsetOfB"`
}

// Diff compares two contract documents by hard-constraint id and capability id.
func Diff(a, b map[string]any) DiffResult {
	ah, bh := hardIDs(a), hardIDs(b)
	ac, bc := capIDs(a), capIDs(b)
	r := DiffResult{
		HardOnlyInA: minus(ah, bh),
		HardOnlyInB: minus(bh, ah),
		CapsOnlyInA: minus(ac, bc),
		CapsOnlyInB: minus(bc, ac),
	}
	r.ASubsetOfB = len(r.HardOnlyInA) == 0
	return r
}

func hardIDs(doc map[string]any) map[string]bool {
	out := map[string]bool{}
	cb, _ := doc["constraints"].(map[string]any)
	for _, it := range toList(cb["hard"]) {
		if id, ok := itemID(it); ok {
			out[id] = true
		}
	}
	return out
}

func capIDs(doc map[string]any) map[string]bool {
	out := map[string]bool{}
	for _, it := range toList(doc["capabilities"]) {
		if id, ok := itemID(it); ok {
			out[id] = true
		}
	}
	return out
}

func minus(a, b map[string]bool) []string {
	var out []string
	for k := range a {
		if !b[k] {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}

// ---- helpers ------------------------------------------------------------

func itemID(it any) (string, bool) {
	m, ok := it.(map[string]any)
	if !ok {
		return "", false
	}
	id, ok := m["id"].(string)
	return id, ok && id != ""
}

func toList(v any) []any {
	l, _ := v.([]any)
	return l
}

func contains(ss []string, s string) bool {
	for _, x := range ss {
		if x == s {
			return true
		}
	}
	return false
}

func deepCopy(v any) any {
	switch t := v.(type) {
	case map[string]any:
		return deepCopyMap(t)
	case []any:
		out := make([]any, len(t))
		for i, e := range t {
			out[i] = deepCopy(e)
		}
		return out
	default:
		return v
	}
}

func deepCopyMap(m map[string]any) map[string]any {
	out := make(map[string]any, len(m))
	for k, v := range m {
		out[k] = deepCopy(v)
	}
	return out
}
