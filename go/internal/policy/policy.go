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

// ProtectionOf reports whether deleting this capability removes a CONTROL rather
// than a resource (D698).
//
// The two predicates ask different questions and the answer differs. Threat detection
// is `stateful: false` — correctly, it holds no data a delete would lose — and its
// vocabulary reasoned from there that retirement needs no friction at all. The absence
// of DATA loss is not the absence of harm.
//
// This one does NOT fail closed, unlike StatefulOf, and the difference is deliberate.
// Statefulness gates only when a contract opts in (`forbidden: delete_stateful`), so
// guessing "stateful" costs nothing where nobody asked. This gate always binds, so
// guessing "protection" would refuse EVERY retirement compiled without vocabularies —
// a targeted safety rule turned into a universal block, under a message that would be
// false ("would switch OFF a protection" when we simply do not know).
//
// The premise that makes fail-open safe is checked rather than assumed: every
// capability type in the closed v0.1 set has a vocabulary, the set is compiled into
// the binary, and TestEveryCapabilityTypeHasAVocabulary holds that true. The one way
// to reach this with no vocabulary is `--no-vocab`, which already discards all
// attribute typing — a run that has opted out of knowing what its own values mean.
func ProtectionOf(c *contract.Contract, capID string,
	vocabs map[string]vocab.Vocabulary) bool {
	capRaw, ok := c.Capabilities[capID]
	if !ok {
		return false
	}
	typ, _ := capRaw["type"].(string)
	return vocabs[typ].Protection
}

// AllowsProtectionLift reports whether the contract scopes allow_protection_lift
// consent to this capability (D698) — the same scoped shape as D48's
// allow_replace_stateful: consent names the capability it covers, never a blanket.
func AllowsProtectionLift(c *contract.Contract, capID string) bool {
	allowed, _ := c.Autonomy["allow_protection_lift"].([]any)
	for _, it := range allowed {
		if s, _ := it.(string); s == capID {
			return true
		}
	}
	return false
}

// AllowsFieldReclaim reports whether the contract scopes allow_field_reclaim consent
// to this capability (D699) — the D48 shape again: consent names the capability it
// covers, never a blanket. It permits ONE thing: when a server-side apply is refused
// because another field manager holds a field this mapping declares, take those
// fields — and only those — recording which manager they came from.
func AllowsFieldReclaim(c *contract.Contract, capID string) bool {
	allowed, _ := c.Autonomy["allow_field_reclaim"].([]any)
	for _, it := range allowed {
		if s, _ := it.(string); s == capID {
			return true
		}
	}
	return false
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
