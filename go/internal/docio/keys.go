package docio

import (
	"fmt"
	"sort"
	"strings"
)

// CheckKnownKeys refuses a mapping that carries a key nothing reads.
//
// D673 established the rule for the contract document and D1170 finished it at the
// root: a block this runtime does not read is silently non-gating, so a misspelling
// is not a typo — it is a requirement that quietly stops being one, at exit 0. The
// `x-` prefix is the escape, and it says by its name that the runtime does not read
// what lives under it.
//
// It moved here from the contract package in D1171, unchanged, because the SEALED
// PLAN needs the identical rule and a second copy would be free to drift from this
// one on the case that matters (D1156's lesson about two checkers agreeing by luck).
// `contract.checkKnownKeys` remains as a thin wrapper over this: the meter's mutants
// aim at that name at seven call sites, and a rename would silently re-aim them.
//
// A nil `known` disables the check. That is deliberate and it is what several mutants
// substitute in, so the caller-side gates prove each call site is doing real work.
func CheckKnownKeys(doc map[string]any, known map[string]bool, where, why string) error {
	if known == nil {
		return nil
	}
	unknown := UnknownKeys(doc, known)
	if len(unknown) == 0 {
		return nil
	}
	return fmt.Errorf("%s declares unknown key(s) %s — %s. Rename it, or prefix it "+
		"with `x-` if it is deliberately not runtime data",
		where, strings.Join(unknown, ", "), why)
}

// UnknownKeys is the scan, separated from the message so there is exactly ONE
// implementation of the `x-` escape. There used to be two — this one and the
// contract's top-level check, which duplicated the whole loop only to word its
// error differently — and the meter proved why that matters: moving this body out
// of `contract.go` in D1171 silently re-aimed the mutant that breaks the escape
// (a first-match substitution) onto the OTHER copy, which no test covered. The
// mutant survived. A second copy of a rule is a second place for a gate to point
// at while the first goes unwatched.
func UnknownKeys(doc map[string]any, known map[string]bool) []string {
	unknown := make([]string, 0, 2)
	for k := range doc {
		if known[k] || strings.HasPrefix(k, "x-") {
			continue
		}
		unknown = append(unknown, k)
	}
	sort.Strings(unknown)
	return unknown
}
