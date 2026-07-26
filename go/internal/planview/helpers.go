package planview

import (
	"fmt"
	"sort"
)

// topo returns action ids in execution order: topological over DependsOn with a
// lexicographic tiebreak within a rank, so a permuted Actions[] array renders
// identically (order is derived, not input order). A dependency cycle (which the
// compiler refuses) degrades to lexicographic — the renderer never panics.
func topo(actions []action) []string {
	indeg := map[string]int{}
	adj := map[string][]string{}
	ids := make([]string, 0, len(actions))
	present := map[string]bool{}
	for _, a := range actions {
		ids = append(ids, a.ID)
		present[a.ID] = true
		if _, ok := indeg[a.ID]; !ok {
			indeg[a.ID] = 0
		}
	}
	for _, a := range actions {
		for _, d := range a.DependsOn {
			if !present[d] {
				continue
			}
			adj[d] = append(adj[d], a.ID)
			indeg[a.ID]++
		}
	}
	var ready []string
	for _, id := range ids {
		if indeg[id] == 0 {
			ready = append(ready, id)
		}
	}
	sort.Strings(ready)
	var out []string
	for len(ready) > 0 {
		id := ready[0]
		ready = ready[1:]
		out = append(out, id)
		next := append([]string(nil), adj[id]...)
		sort.Strings(next)
		for _, m := range next {
			indeg[m]--
			if indeg[m] == 0 {
				ready = insertSorted(ready, m)
			}
		}
	}
	if len(out) != len(ids) { // a cycle left some unplaced — append them sorted, deterministically
		placed := map[string]bool{}
		for _, id := range out {
			placed[id] = true
		}
		var rest []string
		for _, id := range ids {
			if !placed[id] {
				rest = append(rest, id)
			}
		}
		sort.Strings(rest)
		out = append(out, rest...)
	}
	return out
}

func insertSorted(s []string, v string) []string {
	i := sort.SearchStrings(s, v)
	s = append(s, "")
	copy(s[i+1:], s[i:])
	s[i] = v
	return s
}

func byID(actions []action, id string) action {
	for _, a := range actions {
		if a.ID == id {
			return a
		}
	}
	return action{ID: id}
}

// glyph is shape-first (D89). A create carrying a Replaces is a replacement
// (`+x`); a bare create is `+`. There is no "replace" operation in the IR — a
// replace is a create-with-Replaces plus a separate delete of the old gen.
func glyph(a action) string {
	switch a.Operation {
	case "create":
		if a.Replaces != nil {
			return "+x replace"
		}
		return "+  create"
	case "update":
		return "~  update"
	case "delete":
		return "x  delete"
	case "claim":
		return "=  claim "
	}
	return "?  " + a.Operation
}

// isDestructive triggers the rail + recap from the PLAN's own signals (the
// contract's "stateful" label is not in the plan; these are): a delete, a
// replacement, certain data loss, an identity replacement, or R4 irreversibility.
func isDestructive(a action) bool {
	return a.Operation == "delete" ||
		a.Replaces != nil ||
		a.Risk.DataLoss == "certain" ||
		a.Risk.IdentityReplacement ||
		a.Risk.Reversibility == "R4"
}

// destructiveWhy names the plan signals that flagged the action, verbatim.
func destructiveWhy(a action) string {
	var why []string
	if a.Risk.Reversibility == "R4" {
		why = append(why, "R4")
	}
	if a.Risk.DataLoss == "certain" {
		why = append(why, "dataLoss certain")
	}
	if a.Risk.IdentityReplacement {
		why = append(why, "identity REPLACED")
	}
	if len(why) == 0 {
		why = append(why, a.Operation) // delete/replace with milder risk still rails
	}
	return joinComma(why)
}

func worst(actions []action, get func(action) string, rank func(string) int) string {
	best, val := -1, "none"
	for _, a := range actions {
		v := get(a)
		if r := rank(v); r > best {
			best, val = r, v
		}
	}
	return val
}

func revRank(s string) int {
	switch s {
	case "R1":
		return 1
	case "R2":
		return 2
	case "R3":
		return 3
	case "R4":
		return 4
	}
	return 0
}

func tri(s string) int {
	switch s {
	case "none", "":
		return 0
	case "possible":
		return 1
	case "certain":
		return 2
	}
	return 1 // any non-none exposure value ranks above none
}

func cost(m money) string {
	c := m.Currency
	if c == "" {
		c = "?"
	}
	return fmt.Sprintf("%+.2f %s/mo", m.Amount, c)
}

func short(hash string) string {
	if len(hash) <= 14 {
		return hash
	}
	return hash[:14] + ".."
}

func val(v any) string {
	if v == nil {
		return "null"
	}
	return fmt.Sprintf("%v", v)
}

func plural(n int, w string) string {
	if n == 1 {
		return w
	}
	return w + "s"
}

func joinComma(ss []string) string {
	out := ""
	for i, s := range ss {
		if i > 0 {
			out += ", "
		}
		out += s
	}
	return out
}

// ttlWindow renders an observation's shelf life in the units an operator
// thinks in. It is a DURATION, never a deadline: the plan carries no
// evaluation clock, and computing "expires at" here would invent a time
// this package is forbidden to read (the D227 clock discipline).
func ttlWindow(seconds int) string {
	switch {
	case seconds <= 0:
		return "no stated window"
	case seconds%3600 == 0:
		return fmt.Sprintf("%dh", seconds/3600)
	case seconds%60 == 0:
		return fmt.Sprintf("%dm", seconds/60)
	default:
		return fmt.Sprintf("%ds", seconds)
	}
}
