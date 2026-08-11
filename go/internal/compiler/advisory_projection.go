package compiler

import (
	"fmt"
	"sort"

	"groundhold/internal/contract"
	"groundhold/internal/vocab"
)

// adviseUnprovableHardConstraint names the one case where a hard constraint's evidence
// bar can NEVER be met by anything but the author's own declaration (D769).
//
// From the field, with a price on it: a budget constraint compared `cost.monthly: 6 EUR`
// — a number the author wrote — against a threshold the author wrote, and read satisfied
// while the bill was 14.6. The reporter's sentence: "Ograniczenie oparte na liczbie,
// którą sam wpisałem, nie jest ograniczeniem. Jest powtórzeniem mojego założenia."
//
// D766 fixed the WORD (the verdict no longer prints `observed` over a declaration). This
// is the second sentence, and it is the one the author could not have known: for an
// attribute the vocabulary marks `evidence: projection`, there is no reading and there
// never will be — the compiler already filters such attributes out before they reach a
// driver, BY DESIGN (D311). So a `static` bar on one is not a weak choice among several;
// it is the only reachable state, forever.
//
// It is an ADVISORY and deliberately not a refusal. The project's own thesis example
// declares `recovery.rto` — another projection — with `verify: {method: probe}` and is
// REFUSED at plan for being unproven, which is the pitch: you may state a requirement you
// cannot yet prove. Refusing at load would say "you may not even ask", and that is the
// opposite product. The author keeps the decision; what changes is that they are told.
func adviseUnprovableHardConstraint(c *contract.Contract,
	vocabs map[string]vocab.Vocabulary) []Advisory {
	if c == nil || len(vocabs) == 0 {
		return nil
	}
	type hit struct{ id, subject, path string }
	var hits []hit
	for _, cn := range c.Constraints {
		if cn.Severity != "hard" || cn.Path == "" || cn.Subject == "" {
			continue
		}
		// The RUNTIME bar is what `audit` demands of recorded reality (D728); a
		// design-time bar says nothing about what evidence will ever exist.
		if cn.RuntimeMethod != "static" {
			continue
		}
		voc, ok := vocabs[capTypeOf(c, cn.Subject)]
		if !ok || !isProjectionAttr(voc, cn.Path) {
			continue
		}
		hits = append(hits, hit{cn.ID, cn.Subject, cn.Path})
	}
	sort.Slice(hits, func(i, j int) bool { return hits[i].id < hits[j].id })

	out := make([]Advisory, 0, len(hits))
	for _, h := range hits {
		out = append(out, Advisory{
			Code:       "hard-constraint-on-a-projection",
			Capability: h.subject,
			Pointer:    fmt.Sprintf("/constraints/hard/%s", h.id),
			Detail: fmt.Sprintf("%s is a PROJECTION (%s maps to no provider setting by "+
				"design), and this constraint's runtime bar is `static` — so the only "+
				"evidence it can ever have is the value declared in the candidate. It will "+
				"read satisfied whenever the declaration satisfies it, and no reading will "+
				"ever contradict that", h.path, h.path),
			Next: "keep it if a stated assumption is what you want; raise the bar to " +
				"`probe` to demand a measurement (and be refused until one exists, which " +
				"is the point); or make it `soft`, which is what an unprovable assertion is",
		})
	}
	if len(out) == 0 {
		return nil
	}
	return out
}
