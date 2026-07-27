// Package scalars implements typed scalars with units (D3, D15).
// Comparisons across incompatible kinds are refused, never coerced —
// the refusal surfaces as an unverifiable verdict upstream (D14).
package scalars

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

type Kind string

const (
	Duration Kind = "duration"
	Money    Kind = "money"
	Percent  Kind = "percent"
	Bytes    Kind = "bytes"
	Protocol Kind = "protocol"
	Bool     Kind = "bool"
	Number   Kind = "number"
	String   Kind = "string"
	List     Kind = "list"
)

// OrderableKinds are the kinds lte/gte accept (D19 shape checks).
var OrderableKinds = map[Kind]bool{
	Duration: true, Money: true, Percent: true, Bytes: true, Number: true,
}

// MoneyValue and ProtoValue are the canonical (comparable) value forms.
type MoneyValue struct {
	Amount   float64
	Currency string
}

type ProtoValue struct {
	Name                string
	Major, Minor, Patch int
}

// Scalar is a parsed, canonicalized value. Canonical forms mirror the
// reference: duration→ms (float64), money→MoneyValue, percent→float64,
// bytes→int64, protocol→ProtoValue, list→[]*Scalar.
type Scalar struct {
	Kind  Kind
	Value any
	Raw   any
}

func (s *Scalar) String() string {
	r := s.Raw
	if r == nil {
		r = s.Value
	}
	return fmt.Sprintf("<%s:%v>", s.Kind, r)
}

// TypeMismatch is refusal, not failure: it becomes unverifiable upstream.
type TypeMismatch struct{ Msg string }

func (e *TypeMismatch) Error() string { return e.Msg }

func mismatch(format string, args ...any) error {
	return &TypeMismatch{Msg: fmt.Sprintf(format, args...)}
}

var (
	durationRE = regexp.MustCompile(`^(\d+(?:\.\d+)?)(ms|s|m|h|d)$`)
	moneyRE    = regexp.MustCompile(`^(\d+(?:\.\d+)?)\s*([A-Z]{3})$`)
	percentRE  = regexp.MustCompile(`^(\d+(?:\.\d+)?)%$`)
	// D15: KiB/MiB/GiB/TiB are 1024-based (IEC), KB/MB/GB/TB are 1000-based
	bytesRE = regexp.MustCompile(`^(\d+(?:\.\d+)?)(B|KB|MB|GB|TB|KiB|MiB|GiB|TiB)$`)
	protoRE = regexp.MustCompile(`^([a-z][a-z0-9\-]*)/(\d+)(?:\.(\d+))?(?:\.(\d+))?$`)
)

var durationMS = map[string]float64{
	"ms": 1, "s": 1000, "m": 60_000, "h": 3_600_000, "d": 86_400_000}
var bytesMul = map[string]int64{
	"B":  1,
	"KB": 1000, "MB": 1000 * 1000, "GB": 1000 * 1000 * 1000, "TB": 1000 * 1000 * 1000 * 1000,
	"KiB": 1024, "MiB": 1024 * 1024, "GiB": 1024 * 1024 * 1024, "TiB": 1024 * 1024 * 1024 * 1024,
}

// Parse turns a plain YAML/JSON value into a typed scalar.
// safeNum refuses a scalar value whose numeric magnitude exceeds the
// JSON-safe integer range (D66): a duration or byte count that big
// cannot canonicalize deterministically. v0 limit — encode as needed.
func safeNum(f float64) error {
	if f >= float64(int64(1)<<53) || f <= -float64(int64(1)<<53) {
		return mismatch("value exceeds the JSON-safe range (2^53): %.0f", f)
	}
	// Lower bound, mirroring the canonicalizer (D179): a non-integral magnitude
	// too small to round-trip as a fixed-point decimal (~<1e-17) has no lossless
	// canonical form — it would canonicalize to a false "0.000…0" and collide with
	// every other such value. Refuse it at parse, exactly as the upper bound, so a
	// tiny scalar VALUE is a LOAD error in both impls — never a canonicalization
	// that succeeds in verify's verdict path but errors in the hash path.
	if f != float64(int64(f)) && !fixedPointRoundTrips(f) {
		return mismatch("value %s is too small to canonicalize as a fixed-point "+
			"decimal without loss; encode it as a string",
			strconv.FormatFloat(f, 'g', -1, 64))
	}
	return nil
}

// fixedPointRoundTrips reports whether f has a lossless fixed-point decimal form
// in the p∈[1,17] scheme the canonicalizer uses (the same loop as numStrFloat).
func fixedPointRoundTrips(f float64) bool {
	for p := 1; p <= 17; p++ {
		s := strconv.FormatFloat(f, 'f', p, 64)
		if v, err := strconv.ParseFloat(s, 64); err == nil && v == f {
			return true
		}
	}
	return false
}

func Parse(v any) (*Scalar, error) {
	switch x := v.(type) {
	case bool:
		return &Scalar{Bool, x, x}, nil
	case int:
		if err := safeNum(float64(x)); err != nil {
			return nil, err
		}
		return &Scalar{Number, float64(x), x}, nil
	case int64:
		if err := safeNum(float64(x)); err != nil {
			return nil, err
		}
		return &Scalar{Number, float64(x), x}, nil
	case float64:
		if err := safeNum(x); err != nil {
			return nil, err
		}
		return &Scalar{Number, x, x}, nil
	case []any:
		items := make([]*Scalar, 0, len(x))
		for _, it := range x {
			s, err := Parse(it)
			if err != nil {
				return nil, err
			}
			items = append(items, s)
		}
		return &Scalar{List, items, x}, nil
	case []string:
		// D376. A DRIVER produces Go values, not decoded YAML, and the natural Go
		// type for a set of regions or metric names is []string. Refusing it here
		// made every `adopt` of such an attribute fail with "observation
		// unparseable" — reported from the field on capability.ai.inference, and
		// true of six observations across four capability types.
		//
		// The seam is why nothing caught it: the conformance suite supplies
		// observations as YAML, which decodes to []any, so the values a test sees
		// are never the values a driver emits. Widening here rather than boxing in
		// each driver keeps the boundary honest — a list of strings IS a list, and
		// the next driver should not have to know that.
		items := make([]*Scalar, 0, len(x))
		boxed := make([]any, 0, len(x))
		for _, it := range x {
			s, err := Parse(it)
			if err != nil {
				return nil, err
			}
			items = append(items, s)
			boxed = append(boxed, it)
		}
		return &Scalar{List, items, boxed}, nil
	case map[string]any:
		// money object form: {amount, currency}
		if _, hasA := x["amount"]; hasA {
			if _, hasC := x["currency"]; hasC {
				amt, ok := toFloat(x["amount"])
				if !ok {
					return nil, mismatch("cannot type object value: %v", x)
				}
				if err := safeNum(amt); err != nil {
					return nil, err
				}
				cur := fmt.Sprintf("%v", x["currency"])
				return &Scalar{Money, MoneyValue{amt, cur}, x}, nil
			}
		}
		return nil, mismatch("cannot type object value: %v", x)
	case string:
		s := strings.TrimSpace(x)
		if m := durationRE.FindStringSubmatch(s); m != nil {
			f, _ := strconv.ParseFloat(m[1], 64)
			ms := f * durationMS[m[2]]
			if err := safeNum(ms); err != nil {
				return nil, err
			}
			return &Scalar{Duration, ms, x}, nil
		}
		if m := moneyRE.FindStringSubmatch(s); m != nil {
			f, _ := strconv.ParseFloat(m[1], 64)
			if err := safeNum(f); err != nil {
				return nil, err
			}
			return &Scalar{Money, MoneyValue{f, m[2]}, x}, nil
		}
		if m := percentRE.FindStringSubmatch(s); m != nil {
			f, _ := strconv.ParseFloat(m[1], 64)
			if err := safeNum(f); err != nil {
				return nil, err
			}
			return &Scalar{Percent, f, x}, nil
		}
		if m := bytesRE.FindStringSubmatch(s); m != nil {
			f, _ := strconv.ParseFloat(m[1], 64)
			b := f * float64(bytesMul[m[2]])
			if err := safeNum(b); err != nil {
				return nil, err
			}
			return &Scalar{Bytes, int64(b), x}, nil
		}
		if m := protoRE.FindStringSubmatch(s); m != nil {
			return &Scalar{Protocol, ProtoValue{
				Name: m[1], Major: atoi(m[2]),
				Minor: atoi(m[3]), Patch: atoi(m[4]),
			}, x}, nil
		}
		return &Scalar{String, x, x}, nil
	}
	return nil, mismatch("unsupported value: %v", v)
}

func atoi(s string) int {
	if s == "" {
		return 0
	}
	n, _ := strconv.Atoi(s)
	return n
}

func toFloat(v any) (float64, bool) {
	switch x := v.(type) {
	case int:
		return float64(x), true
	case int64:
		return float64(x), true
	case float64:
		return x, true
	}
	return 0, false
}

// ---- comparison helpers ----------------------------------------------------

func requireSameKind(a, b *Scalar) error {
	if a.Kind != b.Kind {
		return mismatch("cannot compare %s with %s (%s vs %s)", a.Kind, b.Kind, a, b)
	}
	if a.Kind == Money {
		am, bm := a.Value.(MoneyValue), b.Value.(MoneyValue)
		if am.Currency != bm.Currency {
			return mismatch("currency mismatch: %s vs %s", am.Currency, bm.Currency)
		}
	}
	return nil
}

func ordinal(s *Scalar) (float64, error) {
	switch s.Kind {
	case Money:
		return s.Value.(MoneyValue).Amount, nil
	case Duration, Percent, Number:
		return s.Value.(float64), nil
	case Bytes:
		return float64(s.Value.(int64)), nil
	}
	return 0, mismatch("%s is not orderable", s.Kind)
}

// valueEqual compares canonical values; lists positionally (D21).
func valueEqual(a, b *Scalar) bool {
	if a.Kind != b.Kind {
		return false
	}
	if a.Kind == List {
		al, bl := a.Value.([]*Scalar), b.Value.([]*Scalar)
		if len(al) != len(bl) {
			return false
		}
		for i := range al {
			if !valueEqual(al[i], bl[i]) {
				return false
			}
		}
		return true
	}
	return a.Value == b.Value
}

// ---- operators -------------------------------------------------------------

type Op func(a, b *Scalar) (bool, error)

func opEquals(a, b *Scalar) (bool, error) {
	if err := requireSameKind(a, b); err != nil {
		return false, err
	}
	if a.Kind == List {
		return listEqual(a, b)
	}
	return valueEqual(a, b), nil
}

// listEqual is strong-Kleene equality over positional element equality plus the
// structural length fact (D21). List equality is a CONJUNCTION: "same length AND
// every position equal". In three-valued logic a definite F dominates ⊥, so a
// length mismatch (a definite structural inequality — no element compared) or any
// single position that is a well-typed, definite mismatch proves the lists
// unequal regardless of ill-typed positions elsewhere. Equality is undecidable
// (unverifiable) only when every compared position is equal-or-ill-typed AND at
// least one is ill-typed. This yields a definite verdict whenever one is entailed
// by structure + well-typed comparisons alone, and refuses only when the truth
// genuinely rests on comparing incomparable kinds/currencies. Order-independent:
// a definite F anywhere wins, so the scan order never changes the verdict.
func listEqual(a, b *Scalar) (bool, error) {
	al, bl := a.Value.([]*Scalar), b.Value.([]*Scalar)
	if len(al) != len(bl) {
		return false, nil // length alone proves inequality; no element compared
	}
	var unver error
	for i := range al {
		eq, err := opEquals(al[i], bl[i]) // three-valued; recurses for nested lists
		if err != nil {
			unver = err // ⊥ at this position — remember, keep scanning for a definite F
			continue
		}
		if !eq {
			return false, nil // a well-typed mismatch proves inequality (F dominates ⊥)
		}
	}
	if unver != nil {
		return false, unver // some position ⊥, none definitely unequal → undecidable
	}
	return true, nil
}

func opLte(a, b *Scalar) (bool, error) {
	if err := requireSameKind(a, b); err != nil {
		return false, err
	}
	av, err := ordinal(a)
	if err != nil {
		return false, err
	}
	bv, err := ordinal(b)
	if err != nil {
		return false, err
	}
	return av <= bv, nil
}

func opGte(a, b *Scalar) (bool, error) {
	if err := requireSameKind(a, b); err != nil {
		return false, err
	}
	av, err := ordinal(a)
	if err != nil {
		return false, err
	}
	bv, err := ordinal(b)
	if err != nil {
		return false, err
	}
	return av >= bv, nil
}

// opIn is strong-Kleene membership: a DISJUNCTION of `a == x` over x in the list.
// A definite match (T) dominates ⊥, so it proves membership regardless of
// ill-typed elements elsewhere. With no definite match: if some element pair was
// ill-typed (⊥) the disjunction is undecidable (unverifiable) — the skipped
// incomparable element COULD have been the match, so calling it "not in" would be
// a fail-open (and `not-in` would falsely satisfy). Only when EVERY element is
// well-typed and none matched is `a` definitely not in the list. The D14 stance
// that a list with NO comparable element (incl. the empty list) is unverifiable
// is preserved — it falls out of "no definite match and nothing well-typed".
func opIn(a, b *Scalar) (bool, error) {
	if b.Kind != List {
		return false, mismatch("`in` requires a list on the right side")
	}
	anyComparable := false
	var unver error
	for _, x := range b.Value.([]*Scalar) {
		eq, err := opEquals(a, x)
		if err != nil {
			unver = err // ⊥ — this element could be the match; remember it
			continue
		}
		anyComparable = true
		if eq {
			return true, nil // a definite match proves membership (T dominates ⊥)
		}
	}
	if !anyComparable {
		// no well-typed element at all (incl. empty list) — undecidable (D14)
		return false, mismatch(
			"no element of the list is comparable with %s (D14)", a)
	}
	if unver != nil {
		return false, unver // some well-typed non-match, but an ill-typed pair could match → ⊥
	}
	return false, nil // every element well-typed and none matched → definitely not in
}

// opSubsetOf is strong-Kleene universal membership: ∀ x∈A: (x in B), each `in`
// evaluated three-valued via opIn. A definite non-member (F) proves A is not a
// subset; if no element is a definite non-member but some membership is
// undecidable (⊥), the subset relation is unverifiable — never coerced to a
// definite verdict that rests on an incomparable comparison.
func opSubsetOf(a, b *Scalar) (bool, error) {
	if a.Kind != List || b.Kind != List {
		return false, mismatch("`subset-of` requires lists on both sides")
	}
	var unver error
	for _, x := range a.Value.([]*Scalar) {
		in, err := opIn(x, b)
		if err != nil {
			unver = err // membership of x is ⊥ — remember, keep scanning for a definite F
			continue
		}
		if !in {
			return false, nil // x is definitely not in B → A is not a subset (F dominates)
		}
	}
	if unver != nil {
		return false, unver // some membership ⊥, none definitely false → undecidable
	}
	return true, nil
}

// candidate `a` compatible-with required `b`: same protocol name, same
// major, candidate version >= required version.
func opCompatibleWith(a, b *Scalar) (bool, error) {
	if a.Kind != Protocol || b.Kind != Protocol {
		return false, mismatch("`compatible-with` requires protocol values")
	}
	ap, bp := a.Value.(ProtoValue), b.Value.(ProtoValue)
	return ap.Name == bp.Name && ap.Major == bp.Major &&
		(ap.Minor > bp.Minor ||
			(ap.Minor == bp.Minor && ap.Patch >= bp.Patch)), nil
}

// ProtocolSatisfiedBy reports whether OBSERVED satisfies the DESIRED protocol
// declaration — i.e. whether a reconcile of a bound resource needs NO change. A desired
// value that pins only the MAJOR (postgresql/16) is satisfied by any observed minor of
// that same major (postgresql/16.11); a desired value that pins a minor (postgresql/
// 16.11) requires it to match. This is the precision-aware sibling of the `>=`
// compatible-with OPERATOR: "declare the major" means "accept any minor" WITHOUT
// discarding the observed minor's precision — the observer still reports 16.11, only the
// reconcile comparison's semantics change (F16-B). A different family or major is not
// satisfied (a real change). It is a TYPED comparison over the protocol kind, not an
// expression language — invariant #4 holds.
func ProtocolSatisfiedBy(desired, observed *Scalar) (bool, error) {
	if desired.Kind != Protocol || observed.Kind != Protocol {
		return false, mismatch("protocol satisfied-by requires protocol values")
	}
	dp, op := desired.Value.(ProtoValue), observed.Value.(ProtoValue)
	if dp.Name != op.Name || dp.Major != op.Major {
		return false, nil
	}
	switch protoDots(desired.Raw) {
	case 0: // major only -> any minor of the same major
		return true, nil
	case 1: // minor pinned -> minor must match
		return dp.Minor == op.Minor, nil
	default: // minor+patch pinned -> both must match
		return dp.Minor == op.Minor && dp.Patch == op.Patch, nil
	}
}

// protoDots counts the dots in a protocol value's version part (after "/"), so the
// declaration's PRECISION survives parse: "postgresql/16" -> 0 (major only),
// "postgresql/16.11" -> 1 (minor pinned). The parser fills a missing minor with 0, so
// the raw string is the only witness of what the operator actually wrote.
func protoDots(raw any) int {
	s, _ := raw.(string)
	i := strings.IndexByte(s, '/')
	if i < 0 {
		return 0
	}
	return strings.Count(s[i+1:], ".")
}

func negate(op Op) Op {
	return func(a, b *Scalar) (bool, error) {
		ok, err := op(a, b)
		if err != nil {
			return false, err
		}
		return !ok, nil
	}
}

// Operators is the closed operator set (D4). exists/absent act on
// presence, not value, and are handled by the verifier.
var Operators = map[string]Op{
	"equals":          opEquals,
	"not-equals":      negate(opEquals),
	"lte":             opLte,
	"gte":             opGte,
	"in":              opIn,
	"not-in":          negate(opIn),
	"subset-of":       opSubsetOf,
	"compatible-with": opCompatibleWith,
}
