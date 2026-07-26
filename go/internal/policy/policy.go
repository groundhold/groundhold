// Package policy holds the autonomy/consent predicates that MUST be
// identical at compile time and apply time. They were duplicated
// byte-for-byte in the compiler and the executor (bad-habits review);
// a single copy is the point — if plan-time and apply-time consent
// could diverge, a plan could be sealed under one rule and executed
// under another, which is precisely the drift this project exists to
// prevent. One definition, two callers.
package policy

import (
	"groundhold/internal/contract"
	"groundhold/internal/vocab"
)

// StatefulOf reports whether a capability is stateful. FAIL CLOSED: an
// absent capability or an absent vocabulary means we cannot PROVE
// statelessness, so it is treated as stateful for delete/replace policy
// (D47).
func StatefulOf(c *contract.Contract, capID string,
	vocabs map[string]vocab.Vocabulary) bool {
	capRaw, ok := c.Capabilities[capID]
	if !ok {
		return true
	}
	typ, _ := capRaw["type"].(string)
	voc, ok := vocabs[typ]
	if !ok {
		return true
	}
	return voc.Stateful
}

// ForbidsDeleteStateful reports whether the contract's autonomy block
// forbids destroying stateful capabilities (D47).
func ForbidsDeleteStateful(c *contract.Contract) bool {
	forbidden, _ := c.Autonomy["forbidden"].([]any)
	for _, it := range forbidden {
		entry, _ := it.(map[string]any)
		if v, _ := entry["delete_stateful"].(bool); v {
			return true
		}
	}
	return false
}

// RequiresProvenHardBasis reports whether the contract arms the D195 gate:
// a hard constraint satisfied on an ASSUMED candidate value must not seal.
// This is the opt-in that makes D5's "policy can gate on satisfied-but-assumed"
// reachable — the verifier still only REPORTS the basis (D5 default preserved);
// when set, the compiler emits the no-assumed-hard-basis precondition the
// executor enforces.
func RequiresProvenHardBasis(c *contract.Contract) bool {
	v, _ := c.Autonomy["no_assumed_hard_basis"].(bool)
	return v
}

// AllowsReplaceStateful reports whether the contract scopes
// allow_replace_stateful consent to this capability (D48).
func AllowsReplaceStateful(c *contract.Contract, capID string) bool {
	allowed, _ := c.Autonomy["allow_replace_stateful"].([]any)
	for _, it := range allowed {
		if s, _ := it.(string); s == capID {
			return true
		}
	}
	return false
}
