// Package mapping is the provider-agnostic mapping algebra — the universal layer
// factored out of the k8s shell so future providers (clouds, SaaS) reuse it. It
// holds ONLY the pieces that carry no provider surface and no pinned hash in their
// signature: the fieldpath/v1 grammar (parse/resolve/set over map[string]any) and
// the pure OpenAPI drift-walker (ref resolution, path walking, type signatures).
// The k8s shell keeps everything welded to Kubernetes — the GVK identity format,
// REST paths, server-side apply/ownership, the fingerprint MODEL and its canon
// domain, and the lens registry's k8s semantics. When a second provider lands and
// the true shared seam is visible, more can move here; until then this is the
// honest boundary (D10 vertical-slice discipline).
package mapping

import "fmt"

// ParseFieldPath splits a fieldpath/v1 expression into segments. The grammar is
// deliberately tiny: dot-separated identifiers and bracket-quoted keys
// (`spec.hard["limits.cpu"]`). No wildcards, no indices, no predicates — a richer
// path is a richer language (invariant #4).
func ParseFieldPath(p string) ([]string, error) {
	var segs []string
	i := 0
	for i < len(p) {
		switch p[i] {
		case '[':
			if i+1 >= len(p) || p[i+1] != '"' {
				return nil, fmt.Errorf("fieldpath %q: expected [\" at %d", p, i)
			}
			end := -1
			for j := i + 2; j < len(p); j++ {
				if p[j] == '"' {
					end = j
					break
				}
			}
			if end < 0 || end+1 >= len(p) || p[end+1] != ']' {
				return nil, fmt.Errorf("fieldpath %q: unterminated quoted key", p)
			}
			segs = append(segs, p[i+2:end])
			i = end + 2
			if i < len(p) && p[i] == '.' {
				i++
			}
		case '.':
			return nil, fmt.Errorf("fieldpath %q: empty segment at %d", p, i)
		default:
			j := i
			for j < len(p) && p[j] != '.' && p[j] != '[' {
				j++
			}
			segs = append(segs, p[i:j])
			i = j
			if i < len(p) && p[i] == '.' {
				i++
			}
		}
	}
	if len(segs) == 0 {
		return nil, fmt.Errorf("fieldpath %q is empty", p)
	}
	return segs, nil
}

// ResolveField navigates a JSON object by a fieldpath/v1 expression and returns the
// value + whether it was present.
func ResolveField(obj map[string]any, path string) (any, bool, error) {
	segs, err := ParseFieldPath(path)
	if err != nil {
		return nil, false, err
	}
	var cur any = obj
	for _, s := range segs {
		mp, ok := cur.(map[string]any)
		if !ok {
			return nil, false, nil
		}
		v, ok := mp[s]
		if !ok {
			return nil, false, nil
		}
		cur = v
	}
	return cur, true, nil
}

// SetField sets a value at a fieldpath, creating intermediate maps and DESCENDING
// into existing ones (so a copy into metadata.labels[...] merges with the ownership
// labels already there rather than clobbering them).
func SetField(obj map[string]any, path string, value any) error {
	segs, err := ParseFieldPath(path)
	if err != nil {
		return err
	}
	cur := obj
	for i, seg := range segs {
		if i == len(segs)-1 {
			cur[seg] = value
			return nil
		}
		next, ok := cur[seg].(map[string]any)
		if !ok {
			next = map[string]any{}
			cur[seg] = next
		}
		cur = next
	}
	return nil
}
