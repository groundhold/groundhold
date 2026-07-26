package parity

import (
	"fmt"
	"sort"
)

// Fulfilment is the parity state of one (cloud, capability TYPE): the same
// trichotomy the matrix renders, in a form the CLI and the candidate gate query.
type Fulfilment struct {
	State  string   // "fulfilled" | "gap" | "unbuilt"
	Tokens []string // set when State == "fulfilled" (D76: may be several)
	Class  string   // set when State == "gap"
	Reason string   // set when State == "gap"
}

// CanFulfil answers, deterministically, whether a cloud fulfils a capability TYPE.
// caps is cloud -> (serviceToken -> capabilityTYPE) — the drivers' ServiceCapabilities
// maps. This is the query the bake-off (D92) needs: a structural gap and an unbuilt
// driver are DIFFERENT answers.
func CanFulfil(caps map[string]map[string]string, cloud, capType string) Fulfilment {
	if toks := tokensFor(caps[cloud], capType); len(toks) > 0 {
		return Fulfilment{State: "fulfilled", Tokens: toks}
	}
	if g, ok := structuralGaps[capType][cloud]; ok {
		return Fulfilment{State: "gap", Class: g.Class, Reason: g.Reason}
	}
	return Fulfilment{State: "unbuilt"}
}

// Clouds returns the fixed cloud order (for stable CLI/matrix output).
func Clouds() []string { return append([]string(nil), clouds...) }

// CheckBinding refuses a candidate capability whose declared (provider, service)
// does not fulfil its declared capability TYPE — the confused-capability hole the
// matrix closes. It is deterministic and network-free. Providers with no parity
// map (the fake, read-only/community drivers) are skipped, and an empty field is a
// no-op (a retirement/unbound capability declares no service). A mismatch is
// enriched with WHY: the cloud fulfils the type with other tokens, or has a
// structural gap, or the driver is simply unbuilt.
func CheckBinding(caps map[string]map[string]string, capID, cloud, service, capType string) error {
	if cloud == "" || cloud == "fake" || service == "" || capType == "" {
		return nil
	}
	cloudMap, known := caps[cloud]
	if !known {
		return nil // a provider without a ServiceCapabilities map is not gated here
	}
	if cloudMap[service] == capType {
		return nil // the binding is coherent
	}

	// Incoherent — explain precisely against the matrix.
	f := CanFulfil(caps, cloud, capType)
	switch {
	case cloudMap[service] != "":
		return fmt.Errorf(
			"capability %s declares type %s but %s service %q fulfils %s "+
				"(a confused-capability binding — the service does not provide the declared type)",
			capID, capType, cloud, service, cloudMap[service])
	case f.State == "gap":
		return fmt.Errorf(
			"capability %s targets %s for %s, which %s structurally cannot fulfil: %s (%s)",
			capID, cloud, capType, cloud, f.Reason, f.Class)
	case f.State == "fulfilled":
		return fmt.Errorf(
			"capability %s binds %s service %q, which is not a known %s service for %s "+
				"(that capability is fulfilled by %v)",
			capID, cloud, service, cloud, capType, f.Tokens)
	default: // unbuilt
		return fmt.Errorf(
			"capability %s targets %s for %s, but groundhold has no %s driver for it yet "+
				"(unbuilt — a driver could be written; the cloud is not the blocker)",
			capID, cloud, capType, cloud)
	}
}

// CapabilityTypes returns every capability TYPE that appears in any cloud's map or
// in a structural gap — the queryable row set for the CLI when no vocab dir is on
// disk (a shipped binary). Sorted, deduped.
func CapabilityTypes(caps map[string]map[string]string) []string {
	set := map[string]bool{}
	for _, m := range caps {
		for _, t := range m {
			set[t] = true
		}
	}
	for t := range structuralGaps {
		set[t] = true
	}
	out := make([]string, 0, len(set))
	for t := range set {
		out = append(out, t)
	}
	sort.Strings(out)
	return out
}
