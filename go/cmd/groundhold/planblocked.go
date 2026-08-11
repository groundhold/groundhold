package main

import (
	"fmt"
	"io"
	"sort"

	"groundhold/internal/compiler"
	"groundhold/internal/contract"
)

// renderBlocked names every capability the compiler could not plan (D721).
//
// The plan document has carried `blocked` since D249 and converge has surfaced it in
// prose ever since; `plan` printed the JSON and exited 0. The information existed and
// the tool never said it, so a reader had to know to look for a fifth key in a
// document whose first key is `actions`. A field report measured the cost: a plan of
// 24 actions for a 27-capability contract read as complete, and the reason was learned
// from converge, after the applied half had already gone out.
//
// The declared/planned counts are printed alongside, because the reporter's own words
// were "różnicę potrafi zauważyć tylko ktoś, kto liczy".
// It returns the blocked capabilities that appear in NO other channel. A witness
// capability that is not bound is blocked AND recorded in `witnessed` with its own
// reason — D177 put it there precisely so "a signed/capsuled plan cannot be misread as
// capability forgotten" — and the conformance suite decides that such a plan is a
// success. A capability whose operand shape refused is named nowhere else, and that is
// the state this entry is about.
func renderBlocked(w io.Writer, doc *compiler.Document, c *contract.Contract) (unaccounted []string) {
	if doc == nil || len(doc.Plan.Blocked) == 0 {
		return nil
	}
	covered := map[string]bool{}
	for _, a := range doc.Plan.Actions {
		covered[a.Capability] = true
	}
	for _, n := range doc.Plan.NoOp {
		covered[n.Capability] = true
	}
	for _, wt := range doc.Plan.Witnessed {
		covered[wt.Capability] = true
	}
	declared := 0
	if c != nil {
		declared = len(c.Capabilities)
	}

	blocked := make([]compiler.BlockedCapability, len(doc.Plan.Blocked))
	copy(blocked, doc.Plan.Blocked)
	sort.Slice(blocked, func(i, j int) bool { return blocked[i].Capability < blocked[j].Capability })

	named := map[string]bool{}
	for _, u := range doc.Plan.Unverified {
		named[u.Capability] = true
	}
	for k := range covered {
		named[k] = true
	}
	for _, b := range blocked {
		if !named[b.Capability] {
			unaccounted = append(unaccounted, b.Capability)
		}
	}

	fmt.Fprintf(w, "\n%d capability(ies) COULD NOT BE PLANNED and are not covered by "+
		"this plan:\n", len(blocked))
	for _, b := range blocked {
		fmt.Fprintf(w, "  %s: %s\n", b.Capability, b.Reason)
	}
	if declared > 0 {
		fmt.Fprintf(w, "  the contract declares %d capability(ies); this plan covers %d\n",
			declared, len(covered))
	}
	fmt.Fprintln(w, "  applying this plan leaves them as they are — fix the candidate, "+
		"then re-plan")
	return unaccounted
}
