package compiler

import (
	"fmt"
	"sort"

	"groundhold/internal/provider"
)

// adviseExistenceNotWitnessed answers the question D513 found the expensive way.
//
// The provider contract reserves `resource.absent` for a BOUND resource the API
// authoritatively 404s, and the compile above turns a fresh `true` into a CREATE
// so an out-of-band delete self-heals. What it cannot do is tell the difference
// between "the driver looked and the resource is there" and "the driver never
// answers this question at all" — in BOTH cases the key is simply missing from
// the observation set, and the compile plans nothing.
//
// That silence is what let a converge report CONVERGED after five bound resources
// had been deleted by hand: observe ran, ran freshly, returned attributes for the
// ones that existed and NOTHING for the ones that did not, and nothing is what a
// no-op looks like.
//
// Emitting the marker is the driver's job and most drivers do not do it yet (at
// the time of writing: every k8s service, and AWS Lambda). Until they do, the
// honest thing is to SAY that existence was not witnessed rather than to imply it
// was. This is D75's skip-loudly precedent: a check that cannot be performed is
// reported, never silently passed. It is an advisory, not a block — turning it
// into a refusal today would freeze every capability on three drivers, which is a
// bigger lie than the one it fixes (the resources are, overwhelmingly, there).
//
// A capability qualifies only when it is BOUND and observe actually produced
// something for it. A capability with no observations at all is a different and
// already-handled state (observation-required), and firing here too would drown
// the real signal.
func adviseExistenceNotWitnessed(in Inputs) []Advisory {
	var caps []string
	for capID, obs := range in.Observations {
		if in.Bindings[capID] == "" {
			continue // not bound: existence is not yet a question
		}
		if len(obs) == 0 {
			continue // nothing observed at all — observation-required's business
		}
		if _, ok := obs[provider.ResourceAbsentPath]; ok {
			continue // the driver answers the question, either way
		}
		caps = append(caps, capID)
	}
	sort.Strings(caps)

	out := make([]Advisory, 0, len(caps))
	for _, capID := range caps {
		out = append(out, Advisory{
			Code:       "existence-not-witnessed",
			Capability: capID,
			Pointer:    fmt.Sprintf("/capabilities/%s", capID),
			Detail: fmt.Sprintf("the driver observed %s but never reported whether the bound "+
				"resource still EXISTS (no %s observation), so a delete made outside groundhold "+
				"would read here as no change at all", capID, provider.ResourceAbsentPath),
			Next: "treat a converged verdict for this capability as covering its attributes, " +
				"not its existence; the driver owes the reserved absence marker",
		})
	}
	if len(out) == 0 {
		return nil
	}
	return out
}
