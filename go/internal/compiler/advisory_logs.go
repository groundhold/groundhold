package compiler

import (
	"fmt"
	"sort"

	"groundhold/internal/contract"
)

// Advisory is something the compile NOTICED: not proven, not blocking, and
// carried in the plan so an agent driving the tool reads it (D365 — a warning
// only a human can parse is, to an agent, indistinguishable from silence).
//
// It never touches `preconditions`, `writes` or any verdict. The four-valued
// verdict remains the only thing that gates execution.
type Advisory struct {
	Code       string `json:"code"` // stable, routable
	Capability string `json:"capability"`
	Pointer    string `json:"pointer"` // into the candidate
	Detail     string `json:"detail"`
	Next       string `json:"next"` // what to do about it
}

// logProducerOutput is the output a driver declares when the resource it creates
// brings its OWN log destination with it. Asking the DRIVERS which services those
// are (D317) is the difference between a rule and a hardcoded list that rots.
const logProducerOutput = "logGroupName"

// adviseUnattachedLogGroup answers a question a field report asked the hard way: a
// `capability.monitoring.logs` was declared with a 365-day retention, converge went
// green, and the group it created held zero bytes — because the application's logs
// went to the group its own runtime creates, which expires never. The capability was
// satisfied and had no effect.
//
// D226 + a `logGroupName` output made the correct wiring EXPRESSIBLE. This makes the
// gap VISIBLE, which is a different thing and the one the reporter actually pressed
// on: we built a way to do it right, not a way to make it hard to do wrong.
//
// THE CONDITION IS NARROW ON PURPOSE, because a standalone log group is a perfectly
// ordinary thing — VPC flow logs and a cluster's control-plane logs both want one,
// and a warning that fires on normal input trains people to ignore it (D364). All
// three must hold:
//
//   - the logs capability provisions its OWN group (no `log_group` operand binding
//     it to somewhere else),
//   - the same candidate contains a capability whose driver declares that it brings
//     its own log destination,
//   - and nothing wires the two together.
//
// The third condition is what keeps this quiet once the advice has been taken.
func adviseUnattachedLogGroup(c *contract.Contract, cand *contract.Candidate,
	in Inputs) []Advisory {
	if c == nil || cand == nil {
		return nil
	}
	// Which capabilities bring their own log destination? Ask the drivers.
	producers := map[string]bool{}
	for id, extras := range cand.Extras {
		prov, _ := extras["provider"].(string)
		svc, _ := extras["service"].(string)
		if _, ok := outputKind(in.providerFor(prov), svc, logProducerOutput); ok {
			producers[id] = true
		}
	}
	if len(producers) == 0 {
		return nil // nothing in this candidate produces logs of its own
	}

	// Which log groups are already bound to a producer? A capability that wired
	// itself has taken the advice and must not be told again.
	attached := map[string]bool{}
	for id, extras := range cand.Extras {
		impl, _ := extras["implementation"].(map[string]any)
		if _, bound := impl["log_group"]; bound {
			attached[id] = true
		}
	}

	var out []Advisory
	for capID, raw := range c.Capabilities {
		typ, _ := raw["type"].(string)
		if typ != "capability.monitoring.logs" || attached[capID] {
			continue
		}
		if _, declared := cand.Extras[capID]; !declared {
			continue
		}
		names := make([]string, 0, len(producers))
		for id := range producers {
			names = append(names, id)
		}
		sort.Strings(names)
		out = append(out, Advisory{
			Code:       "logs-group-has-no-producer",
			Capability: capID,
			Pointer: fmt.Sprintf("capabilities.%s.implementation.log_group",
				capID),
			Detail: fmt.Sprintf(
				"%s provisions its own log group, and nothing in this candidate "+
					"writes to it. %s %s their own log destination, whose "+
					"retention this capability does NOT govern — so the retention "+
					"declared here can be satisfied while the logs it was meant to "+
					"cover expire never",
				capID, joinNames(names), verbFor(len(names))),
			Next: fmt.Sprintf(
				"if this group is meant to hold %s's logs, bind it: "+
					"capabilities.%s.implementation.log_group: "+
					"{$ref: {capability: %s, output: %s}}. If a standalone group "+
					"IS the intent (flow logs, a control plane), nothing needs to change",
				names[0], capID, names[0], logProducerOutput),
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Capability < out[j].Capability })
	return out
}

func joinNames(names []string) string {
	switch len(names) {
	case 1:
		return names[0]
	case 2:
		return names[0] + " and " + names[1]
	default:
		s := ""
		for i, n := range names[:len(names)-1] {
			if i > 0 {
				s += ", "
			}
			s += n
		}
		return s + " and " + names[len(names)-1]
	}
}

func verbFor(n int) string {
	if n == 1 {
		return "brings"
	}
	return "bring"
}
