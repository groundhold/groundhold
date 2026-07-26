// Package canonical implements canonicalization and hashing (D34,
// spec/canonicalization.md). Identity is the sha256 of domain-separated
// canonical JSON of the parsed semantic model — never of source bytes.
// All numbers render as strings (NUMSTR) so that two implementations
// produce byte-identical hashes.
package canonical

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math"
	"reflect"
	"sort"
	"strconv"
	"strings"

	"groundhold/internal/contract"
	"groundhold/internal/scalars"
)

const (
	domainContract  = "groundhold/canon/v1:contract"
	domainCandidate = "groundhold/canon/v1:candidate"
	domainEvent     = "groundhold/canon/v1:event"
	domainPlan      = "groundhold/canon/v1:plan"
	domainDiscovery = "groundhold/canon/v1:discovery"
)

// maxSafeInteger is the largest integer a IEEE-754 double represents
// exactly (2^53). Beyond it a JSON round-trip is lossy, so a canonical
// document may not carry such an integer as a NUMBER — the hash would
// depend on whether the value passed through JSON (D66). Both
// implementations refuse it identically; callers needing bigger
// integers must encode them as strings.
const maxSafeInteger = 1 << 53

// numStrFloat is the shared NUMSTR rule (D66): identical output in Go
// and Python, stable across a JSON replay round-trip.
//   - non-finite: error;
//   - integral in the JSON-safe range: the plain integer (no point,
//     no exponent);
//   - integral beyond the safe range: error (lossy through JSON);
//   - fractional: the SHORTEST fixed-point decimal that round-trips —
//     the same p in [1,17] loop the Python reference runs, never
//     exponent form.
func numStrFloat(f float64) (string, error) {
	if math.IsNaN(f) || math.IsInf(f, 0) {
		return "", fmt.Errorf("cannot canonicalize non-finite number")
	}
	if f == math.Trunc(f) {
		if math.Abs(f) >= maxSafeInteger {
			return "", fmt.Errorf(
				"integer %.0f exceeds the JSON-safe range (2^53); "+
					"encode it as a string to canonicalize", f)
		}
		return strconv.FormatInt(int64(f), 10), nil
	}
	for p := 1; p <= 17; p++ {
		s := strconv.FormatFloat(f, 'f', p, 64)
		if v, err := strconv.ParseFloat(s, 64); err == nil && v == f {
			return s, nil
		}
	}
	// A non-integral magnitude too small to round-trip in fixed-point (|f| below
	// ~1e-17) would otherwise fall to a lossy "0.000…0" — which is a FALSE
	// canonical form AND collides every such value onto one string (e.g. 1e-18
	// and 1e-20 hash identically), forging a shared identity. Refuse, exactly as
	// the >2^53 magnitude does: the canonicalizer must stay injective, never emit
	// a canonical form the value does not have. Encode tiny values as strings.
	return "", fmt.Errorf(
		"number %s is too small to canonicalize as a fixed-point decimal without "+
			"loss (magnitude below ~1e-17); encode it as a string",
		strconv.FormatFloat(f, 'g', -1, 64))
}

// numStrInt canonicalizes an integer that arrived AS an integer (YAML
// int, not a JSON float) — same safe-range refusal (D66).
func numStrInt(n int64) (string, error) {
	if n >= maxSafeInteger || n <= -maxSafeInteger {
		return "", fmt.Errorf(
			"integer %d exceeds the JSON-safe range (2^53); "+
				"encode it as a string to canonicalize", n)
	}
	return strconv.FormatInt(n, 10), nil
}

func quote(s string) string {
	var b strings.Builder
	b.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			b.WriteString(`\"`)
		case '\\':
			b.WriteString(`\\`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		default:
			if r < 0x20 {
				b.WriteString(fmt.Sprintf(`\u%04x`, r))
			} else {
				b.WriteRune(r)
			}
		}
	}
	b.WriteByte('"')
	return b.String()
}

// Canon renders canonical JSON: sorted keys, no whitespace, numbers as
// NUMSTR strings, minimal escaping.
func Canon(v any) (string, error) {
	switch x := v.(type) {
	case nil:
		return "null", nil
	case bool:
		if x {
			return "true", nil
		}
		return "false", nil
	case string:
		return quote(x), nil
	case int:
		s, err := numStrInt(int64(x))
		if err != nil {
			return "", err
		}
		return `"` + s + `"`, nil
	case int64:
		s, err := numStrInt(x)
		if err != nil {
			return "", err
		}
		return `"` + s + `"`, nil
	case float64:
		s, err := numStrFloat(x)
		if err != nil {
			return "", err
		}
		return `"` + s + `"`, nil
	case []any:
		parts := make([]string, len(x))
		for i, it := range x {
			c, err := Canon(it)
			if err != nil {
				return "", err
			}
			parts[i] = c
		}
		return "[" + strings.Join(parts, ",") + "]", nil
	case map[string]any:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		parts := make([]string, len(keys))
		for i, k := range keys {
			c, err := Canon(x[k])
			if err != nil {
				return "", err
			}
			parts[i] = quote(k) + ":" + c
		}
		return "{" + strings.Join(parts, ",") + "}", nil
	}
	// A driver may hand us a CONCRETE Go type — []string (cert SANs, security-
	// group rules, Bedrock destinationRegions), []int, map[string]string — rather
	// than the []any/map[string]any that YAML decoding yields. Normalize it via
	// reflection and recurse so the canonical form (and therefore the hash) is
	// identical to the equivalent generic value, and to the Python reference,
	// which sees every list the same way. Pure and deterministic (#6): no
	// heuristics, just a shape conversion the YAML path already implies.
	rv := reflect.ValueOf(v)
	switch rv.Kind() {
	case reflect.Slice, reflect.Array:
		items := make([]any, rv.Len())
		for i := range items {
			items[i] = rv.Index(i).Interface()
		}
		return Canon(items)
	case reflect.Map:
		m := make(map[string]any, rv.Len())
		for _, mk := range rv.MapKeys() {
			ks, ok := mk.Interface().(string)
			if !ok {
				return "", fmt.Errorf(
					"cannot canonicalize map with non-string key of type %T",
					mk.Interface())
			}
			m[ks] = rv.MapIndex(mk).Interface()
		}
		return Canon(m)
	case reflect.Ptr, reflect.Interface:
		if rv.IsNil() {
			return Canon(nil)
		}
		return Canon(rv.Elem().Interface())
	case reflect.String:
		return Canon(rv.String())
	case reflect.Bool:
		return Canon(rv.Bool())
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return Canon(rv.Int())
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32:
		return Canon(int64(rv.Uint()))
	}
	return "", fmt.Errorf("cannot canonicalize value of type %T", v)
}

func scalarModel(s *scalars.Scalar) map[string]any {
	switch s.Kind {
	case scalars.Duration:
		return map[string]any{"kind": "duration", "ms": s.Value}
	case scalars.Money:
		mv := s.Value.(scalars.MoneyValue)
		return map[string]any{"kind": "money",
			"amount": mv.Amount, "currency": mv.Currency}
	case scalars.Percent:
		return map[string]any{"kind": "percent", "value": s.Value}
	case scalars.Bytes:
		return map[string]any{"kind": "bytes", "bytes": s.Value}
	case scalars.Protocol:
		pv := s.Value.(scalars.ProtoValue)
		return map[string]any{"kind": "protocol", "name": pv.Name,
			"major": pv.Major, "minor": pv.Minor, "patch": pv.Patch}
	case scalars.List:
		items := []any{}
		for _, x := range s.Value.([]*scalars.Scalar) {
			items = append(items, scalarModel(x))
		}
		return map[string]any{"kind": "list", "items": items}
	}
	return map[string]any{"kind": string(s.Kind), "value": s.Value}
}

func constraintModel(c contract.Constraint) map[string]any {
	m := map[string]any{
		"id": c.ID, "severity": c.Severity, "verify": c.VerifyMethod}
	if c.Subject != "" {
		m["subject"] = c.Subject
	}
	if c.Path != "" {
		m["path"] = c.Path
	}
	if c.Op != "" {
		m["op"] = c.Op
	}
	if c.Objective != "" {
		m["objective"] = c.Objective
	}
	if c.Expected != nil {
		m["value"] = scalarModel(c.Expected)
	}
	return m
}

func sortByID(items []any) []any {
	out := append([]any{}, items...)
	sort.SliceStable(out, func(i, j int) bool {
		mi, _ := out[i].(map[string]any)
		mj, _ := out[j].(map[string]any)
		si, _ := mi["id"].(string)
		sj, _ := mj["id"].(string)
		return si < sj
	})
	return out
}

func ContractModel(c *contract.Contract) map[string]any {
	capIDs := make([]string, 0, len(c.Capabilities))
	for id := range c.Capabilities {
		capIDs = append(capIDs, id)
	}
	sort.Strings(capIDs)
	caps := []any{}
	for _, id := range capIDs {
		entry := map[string]any{
			"id": id, "type": c.Capabilities[id]["type"]}
		// retirement is semantic (D47); active stays absent so existing
		// contract hashes are unchanged
		if s, _ := c.Capabilities[id]["state"].(string); s == "retired" {
			entry["state"] = "retired"
		}
		caps = append(caps, entry)
	}
	cons := append([]contract.Constraint{}, c.Constraints...)
	sort.SliceStable(cons, func(i, j int) bool { return cons[i].ID < cons[j].ID })
	conModels := []any{}
	for _, cn := range cons {
		conModels = append(conModels, constraintModel(cn))
	}
	m := map[string]any{
		"apiVersion":   "contract/v0.1",
		"kind":         "InfrastructureContract",
		"id":           c.ID,
		"version":      c.Version,
		"capabilities": caps,
		"constraints":  conModels,
	}
	if c.Environment != "" {
		m["environment"] = c.Environment
	}
	if len(c.Assumptions) > 0 {
		fixed := []any{}
		for _, it := range c.Assumptions {
			a, _ := it.(map[string]any)
			a2 := map[string]any{}
			for k, v := range a {
				a2[k] = v
			}
			if af, ok := a2["affects"].([]any); ok && len(af) > 0 {
				ss := make([]string, 0, len(af))
				for _, r := range af {
					s, _ := r.(string)
					ss = append(ss, s)
				}
				sort.Strings(ss)
				sorted := make([]any, len(ss))
				for i, s := range ss {
					sorted[i] = s
				}
				a2["affects"] = sorted
			}
			fixed = append(fixed, a2)
		}
		m["assumptions"] = sortByID(fixed)
	}
	if len(c.Outcomes) > 0 {
		m["outcomes"] = sortByID(c.Outcomes)
	}
	if len(c.Autonomy) > 0 {
		m["autonomy"] = c.Autonomy
	}
	return m
}

func CandidateModel(cand *contract.Candidate) map[string]any {
	capIDs := make([]string, 0, len(cand.Capabilities))
	for id := range cand.Capabilities {
		capIDs = append(capIDs, id)
	}
	sort.Strings(capIDs)
	caps := []any{}
	for _, cid := range capIDs {
		attrs := cand.Capabilities[cid]
		paths := make([]string, 0, len(attrs))
		for p := range attrs {
			paths = append(paths, p)
		}
		sort.Strings(paths)
		attrModels := []any{}
		for _, p := range paths {
			pv := attrs[p]
			am := map[string]any{"path": p, "status": pv.Status}
			if pv.Scalar != nil {
				am["value"] = scalarModel(pv.Scalar)
			}
			if pv.Source != "" {
				am["source"] = pv.Source
			}
			if pv.Confidence != nil {
				am["confidence"] = *pv.Confidence
			}
			attrModels = append(attrModels, am)
		}
		entry := map[string]any{"id": cid, "attributes": attrModels}
		for k, v := range cand.Extras[cid] {
			entry[k] = v
		}
		caps = append(caps, entry)
	}
	return map[string]any{
		"apiVersion":   "candidate/v0.1",
		"kind":         "ImplementationCandidate",
		"contract":     cand.ContractID,
		"capabilities": caps,
	}
}

// Hash exposes domain-separated canonical hashing for documents whose
// domain lives outside this package's registry (snapshots, D137).
func Hash(domain string, model any) (string, error) {
	return hash(domain, model)
}

func hash(domain string, model any) (string, error) {
	c, err := Canon(model)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256([]byte(domain + "\n" + c))
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

func HashContract(c *contract.Contract) (string, error) {
	return hash(domainContract, ContractModel(c))
}

func HashCandidate(cand *contract.Candidate) (string, error) {
	return hash(domainCandidate, CandidateModel(cand))
}

// HashEvent: D35 — event identity is the raw canonical tree; an event
// records what was said, and normalizing history would falsify it.
// D102: the top-level `sig` key is EXCLUDED — a signature attests the
// identity, it is not part of it (detached-signature rule), so signed
// and unsigned copies of the same event share one hash.
func HashEvent(doc map[string]any) (string, error) {
	if _, ok := doc["sig"]; ok {
		stripped := make(map[string]any, len(doc)-1)
		for k, v := range doc {
			if k != "sig" {
				stripped[k] = v
			}
		}
		doc = stripped
	}
	return hash(domainEvent, doc)
}

// HashPlan: D36 — a sealed plan records a decision (raw tree, like
// events); normalizing it would re-open it.
func HashPlan(doc map[string]any) (string, error) {
	return hash(domainPlan, doc)
}

// HashDiscovery (D52): a discovery document records what enumeration
// SAW — raw tree, like events; drafts cite it as their provenance root.
func HashDiscovery(doc map[string]any) (string, error) {
	return hash(domainDiscovery, doc)
}
