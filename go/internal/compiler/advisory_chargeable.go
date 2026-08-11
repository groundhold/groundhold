package compiler

import (
	"fmt"
	"sort"

	"groundhold/internal/contract"
)

// chargeableComponent names a declaration that makes the tool build something the
// provider bills SEPARATELY from the resource itself (D770).
//
// This is deliberately NOT a price model. `costproj` aggregates the cost.monthly the
// AUTHOR declared and computes nothing — introducing a price table would mean shipping an
// oracle that drifts every time a cloud changes a rate card, and being wrong about money
// with the tool's authority behind it. What the drivers DO know, without any table, is
// which switches add a separately-billed component, because they are the ones that turn
// them on.
//
// The register is small on purpose. Each entry is a fact I can state and defend:
// AWSManagedRulesBotControlRuleSet is a PAID managed rule group, unlike the common
// baseline, which is free. An entry nobody can defend does not belong here — an advisory
// about money that is wrong is worse than none.
type chargeableComponent struct {
	provider string
	service  string
	path     string
	value    any
	what     string
}

var chargeableComponents = []chargeableComponent{
	{"aws", "wafv2", "bot.protection", true,
		"AWSManagedRulesBotControlRuleSet, a managed rule group AWS bills SEPARATELY " +
			"from the web ACL and its baseline rules"},
}

// adviseChargeableComponent tells an author that a switch they set adds a billed
// component, when the same capability also declares a cost.
//
// From the field: a candidate declared `cost.monthly: 6 EUR` for a WAF whose bill was
// 14.6, because `bot.protection: true` had added a paid rule group nobody had priced. The
// budget constraint compared 6 against 15 and passed. With 3.1% of the budget left, that
// one unpriced line consumed all of it.
//
// The advisory fires only when a cost IS declared: an author who declared none has not
// made a claim this could contradict, and an advisory that fires on every capability
// teaches nothing.
func adviseChargeableComponent(c *contract.Contract, cand *contract.Candidate) []Advisory {
	if c == nil || cand == nil {
		return nil
	}
	var out []Advisory
	caps := make([]string, 0, len(cand.Capabilities))
	for capID := range cand.Capabilities {
		caps = append(caps, capID)
	}
	sort.Strings(caps)

	for _, capID := range caps {
		attrs := cand.Capabilities[capID]
		if _, declaresCost := attrs["cost.monthly"]; !declaresCost {
			continue
		}
		extras := cand.Extras[capID]
		prov, _ := extras["provider"].(string)
		svc, _ := extras["service"].(string)
		for _, cc := range chargeableComponents {
			if cc.provider != prov || cc.service != svc {
				continue
			}
			pv, ok := attrs[cc.path]
			if !ok || pv.Scalar == nil || pv.Scalar.Raw != cc.value {
				continue
			}
			out = append(out, Advisory{
				Code:       "chargeable-component-outside-the-declared-cost",
				Capability: capID,
				Pointer:    fmt.Sprintf("/capabilities/%s/attributes/%s", capID, cc.path),
				Detail: fmt.Sprintf("%s: %v makes this build %s — the cost.monthly declared "+
					"here is the author's own figure, and nothing in this tool prices what it "+
					"builds, so a budget constraint on it compares one declaration against "+
					"another", cc.path, cc.value, cc.what),
				Next: "check the declared cost against the provider's rate card for the " +
					"component named above; the tool cannot do it for you and does not pretend to",
			})
		}
	}
	return out
}
