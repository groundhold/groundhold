// Package adoptcheck is the shared adopt-time control comparator (D1062). When a
// driver's create finds the resource ALREADY EXISTS and is ours, it ADOPTS it —
// but the controls its create body sets INLINE (encryption, deletion protection,
// TLS, residency, retention floors, immutable tags) never applied to the
// pre-existing resource. Reporting `succeeded` there is a false success in the
// dangerous direction: a candidate declaring a security control is told it is in
// place over a resource that LACKS it (the class fixed per-driver in D1047/D1048/
// D1058, generalised here so it is one enforced invariant, not 23 conventions).
//
// The comparator does NOT re-implement verify's comparison (D963/D964: every verb
// that re-implemented it produced a false-clean) and does NOT mutate the adopted
// resource (mutable remediation stays in the consent-gated converge loop). It reads
// the driver's OWN observations and, crucially, consumes ONLY `measured` ones: an
// observation that is config-intent, inferred, or absent proves nothing about the
// live resource's own setting (a public-access read derived from an org policy, an
// "encryption enabled" that does not prove the DECLARED key is attached), so it is
// unverifiable — never silently treated as satisfying the control. That constraint
// is what keeps the shared path from institutionalising the same false-clean one
// layer down.
package adoptcheck

import (
	"fmt"
	"sort"

	"groundhold/internal/provider"
)

// Direction is the SAFE comparison for an adopt-critical control — the direction in
// which the live resource may exceed the declaration without lying.
type Direction int

const (
	// SecureTrue: a declared `true` requires a measured `true` (CMEK, encryption at
	// rest, deletion protection, TLS enforced). Declared `false` requires nothing.
	SecureTrue Direction = iota
	// SecureFalse: a declared `false` requires a measured `false` — the secure state
	// is the false one (network.publicExposure=false means private; a measured `true`
	// is the dangerous direction). Declared `true` requires nothing.
	SecureFalse
	// Floor: the measured value must be >= the declared (retention.minimum). Compared
	// as integers; a non-integer on either side is unverifiable.
	Floor
	// Exact: the measured value must equal the declared (residency / location.region).
	Exact
	// Set: the measured value must equal the declared as an UNORDERED SET of strings —
	// an IAM role's `trust.principals` (who may assume it) is a set, and a live role
	// trusting a DIFFERENT or BROADER set than declared is the dangerous direction
	// (confused-deputy). Both sides are normalised to sorted string slices before
	// comparing, so element order never causes a false mismatch; a value that is not a
	// list of strings on either side is unverifiable.
	Set
)

// Control is one adopt-critical control a driver declares for a capability. The set
// is data (per-driver table), so it is diffable and gate-able rather than ad-hoc
// branch logic — a new driver cannot silently skip the convention.
type Control struct {
	Path              string
	Direction         Direction
	ImmutableAtCreate bool // cannot be changed after create → converge can never fix it
	UpdateWired       bool // a consent-gated, tested in-place update exists for this path
}

// Verdict is the adopt-check outcome. Status is one of clean|failed|unknown.
type Verdict struct {
	Status       string
	Missing      []string // controls the live resource LACKS (dangerous direction)
	Unverifiable []string // declared controls with no measured observation
	Reason       string
}

// Compare checks every adopt-critical control the candidate DECLARES against the
// driver's own MEASURED observations. Precedence (Codex review): an immutable
// control the resource lacks, or a mutable one with no in-place update, DOMINATES —
// the whole adopt is `failed` (binding an unusable/unfixable resource would hide
// that a replacement is needed, and `unknown` would spin the reconciler forever). A
// mutable control the resource lacks but that a wired update can patch is `unknown`
// (bind the handle; converge patches it through the consented path). A declared
// control with no measured observation is unverifiable → `unknown` (fail-closed:
// we did not witness it, so we do not claim it). Everything satisfied → `clean`.
func Compare(declared map[string]any, obs []provider.Observation, controls []Control) Verdict {
	measured := map[string]any{}
	for _, o := range obs {
		if o.Derivation == "measured" {
			measured[o.Path] = o.Value
		}
	}
	var failed, drift, unverifiable []string
	for _, c := range controls {
		want, declaredHere := declared[c.Path]
		if !declaredHere || !requiresControl(c.Direction, want) {
			continue // the candidate does not require this control — nothing to check
		}
		got, isMeasured := measured[c.Path]
		if !isMeasured {
			unverifiable = append(unverifiable, c.Path)
			continue
		}
		ok, comparable := satisfies(c.Direction, want, got)
		if !comparable {
			// a kind mismatch between declared and measured is unverifiable, never a
			// silent pass or a false miss (invariant #2: no coercion).
			unverifiable = append(unverifiable, c.Path)
			continue
		}
		if ok {
			continue
		}
		// the live resource LACKS a declared control — the dangerous direction.
		if c.ImmutableAtCreate || !c.UpdateWired {
			failed = append(failed, c.Path)
		} else {
			drift = append(drift, c.Path)
		}
	}
	sort.Strings(failed)
	sort.Strings(drift)
	sort.Strings(unverifiable)
	switch {
	case len(failed) > 0:
		return Verdict{Status: "failed", Missing: failed,
			Reason: fmt.Sprintf("adopted a resource missing a declared control that create "+
				"cannot fix in place: %v — reconcile (a replacement may be required)", failed)}
	case len(drift) > 0 || len(unverifiable) > 0:
		miss := append(append([]string{}, drift...), unverifiable...)
		sort.Strings(miss)
		return Verdict{Status: "unknown", Missing: drift, Unverifiable: unverifiable,
			Reason: fmt.Sprintf("adopt-pending-reconcile: declared controls not confirmed on the "+
				"live resource: %v — bound; converge reconciles them", miss)}
	default:
		return Verdict{Status: "clean"}
	}
}

// requiresControl reports whether a declared value actually ASKS for the secure
// state, so the safe direction (the candidate does not require it) is skipped rather
// than compared.
func requiresControl(dir Direction, want any) bool {
	switch dir {
	case SecureTrue:
		b, ok := want.(bool)
		return ok && b // only a declared true requires the control
	case SecureFalse:
		b, ok := want.(bool)
		return ok && !b // only a declared false (the secure state) requires it
	default:
		return true // Floor/Exact always compare when declared
	}
}

// satisfies reports (ok, comparable): ok = the measured value meets the declared in
// the safe direction; comparable = the kinds could be compared at all.
func satisfies(dir Direction, want, got any) (ok, comparable bool) {
	switch dir {
	case SecureTrue:
		g, isBool := got.(bool)
		if !isBool {
			return false, false
		}
		return g, true // declared true is satisfied only by measured true
	case SecureFalse:
		g, isBool := got.(bool)
		if !isBool {
			return false, false
		}
		return !g, true // declared false (secure) is satisfied only by measured false
	case Floor:
		wi, wok := toInt(want)
		gi, gok := toInt(got)
		if !wok || !gok {
			return false, false
		}
		return gi >= wi, true
	case Exact:
		return fmt.Sprint(want) == fmt.Sprint(got), true
	case Set:
		ws, wok := toStringSet(want)
		gs, gok := toStringSet(got)
		if !wok || !gok {
			return false, false
		}
		return equalSortedStrings(ws, gs), true
	}
	return false, false
}

// toStringSet normalises a []any or []string into a SORTED []string, so two sets that
// differ only in element order compare equal. A non-list, or a list with a non-string
// element, is not comparable as a set (returns ok=false → unverifiable).
func toStringSet(v any) ([]string, bool) {
	var out []string
	switch xs := v.(type) {
	case []string:
		out = append(out, xs...)
	case []any:
		for _, e := range xs {
			s, ok := e.(string)
			if !ok {
				return nil, false
			}
			out = append(out, s)
		}
	default:
		return nil, false
	}
	sort.Strings(out)
	return out, true
}

func equalSortedStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func toInt(v any) (int, bool) {
	switch n := v.(type) {
	case int:
		return n, true
	case int64:
		return int(n), true
	case float64:
		// yaml/json numbers; only an integral float is a whole-second/day count
		if n == float64(int(n)) {
			return int(n), true
		}
	}
	return 0, false
}
