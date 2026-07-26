package converge

import (
	"fmt"
	"io"
	"strings"

	"groundhold/internal/render"
)

// Checklist is the live phase roadmap for a converge run (D232). It PRE-LISTS the
// full canonical loop — the shape is deterministic and known to the binary, so
// hiding it is false modesty — and every row reaches exactly ONE terminal state
// before the region freezes (the invariant that makes pre-listing honest: a
// `pending` row claims `unknown`, never "will run"). The two lies a naive
// checklist would tell are foreclosed structurally: a conditional phase carries
// its condition inline and resolves to `skipped(why)`, and an early exit resolves
// every unreached row to `skipped(loop ended)` — never a dangling `pending`, never
// `failed` (the rows didn't run; the four-valued discipline forbids implying they
// succeeded OR failed).
//
// The checklist NEVER renders a loop verdict: `done` means only "the sub-step ran
// and its exit code said proceed" — it carries no converged/not-converged claim.
// The banner (finish) is the sole verdict carrier; the rows are subordinate to it.
type Checklist struct {
	w         io.Writer
	m         render.Mode
	sticky    bool // repaint a sticky region (a TTY) vs append-only transition lines
	rows      []*checkRow
	byID      map[string]*checkRow
	prevLines int
	frozen    bool
}

type checkRow struct {
	id    string // stable row id (distinguishes the two observes)
	label string // display name
	cond  string // "" for unconditional; the condition text for conditional rows
	state string // pending | active | done | refused | failed | skipped
	why   string // mandatory for skipped
}

// canonicalPhases is the converge loop in order. observe appears twice, named by
// ROLE (refresh vs evidence) so a row never completes twice. The conditional rows
// carry their condition; they resolve to done or skipped(why) when reached.
func canonicalRows() []*checkRow {
	return []*checkRow{
		{id: "verify", label: "verify"},
		{id: "plan", label: "plan"},
		{id: "observe-refresh", label: "observe", cond: "refresh — if evidence stale"},
		{id: "forecast", label: "forecast"},
		{id: "confirm", label: "confirm"},
		{id: "apply", label: "apply"},
		{id: "observe-evidence", label: "observe", cond: "evidence"},
		{id: "convergence-check", label: "convergence-check", cond: "if apply ran"},
	}
}

// NewChecklist builds the pre-listed roadmap. sticky=true repaints an in-place
// region (a TTY); false prints append-only transition lines (plain/CI). A nil
// writer disables rendering (the checklist becomes a no-op — converge stays
// functional without it).
func NewChecklist(w io.Writer, m render.Mode, sticky bool) *Checklist {
	rows := canonicalRows()
	byID := make(map[string]*checkRow, len(rows))
	for _, r := range rows {
		r.state = "pending"
		byID[r.id] = r
	}
	return &Checklist{w: w, m: m, sticky: sticky, rows: rows, byID: byID}
}

// Enter marks a row active and the previously-active row done (a sub-step whose
// exit code said proceed). Unknown ids are ignored (a phase not in the canonical
// list is a no-op, never a crash). Renders the frame.
func (c *Checklist) Enter(id string) {
	if c == nil || c.frozen {
		return
	}
	for _, r := range c.rows {
		if r.state == "active" {
			r.state = "done"
		}
	}
	if r, ok := c.byID[id]; ok {
		r.state = "active"
	}
	c.render()
}

// Skip resolves a conditional row that will not run, with a mandatory why
// (D227's skipWhy rule). E.g. the stale-refresh observe when evidence is fresh.
func (c *Checklist) Skip(id, why string) {
	if c == nil || c.frozen {
		return
	}
	if r, ok := c.byID[id]; ok && r.state == "pending" {
		r.state, r.why = "skipped", why
	}
	c.render()
}

// Fail resolves a row whose sub-verb DID run and did not deliver (D291). It is
// distinct from Skip (a conditional row that never ran) and from Freeze's
// refused (the verb refused, which is doing its job): the work was attempted
// and produced nothing usable. Used for ADVISORY phases only — a phase whose
// failure must stop the loop returns a refusal instead of reaching here. The
// why is mandatory for the same reason Skip's is: a resolved row that does not
// say why is indistinguishable from one that succeeded.
func (c *Checklist) Fail(id, why string) {
	if c == nil || c.frozen {
		return
	}
	if r, ok := c.byID[id]; ok && (r.state == "active" || r.state == "pending") {
		r.state, r.why = "failed", why
	}
	c.render()
}

// Freeze concludes the checklist: the currently-active row terminates, and every
// still-pending row resolves to skipped(loop ended: <reason>) — NEVER left
// dangling as pending, never marked failed. `refused` true marks the active row
// refused (the sub-verb refused — did its job, D89), else done. The frozen frame
// is the last checklist output; the banner follows once, from finish().
func (c *Checklist) Freeze(refused bool, endReason string) {
	if c == nil || c.frozen {
		return
	}
	for _, r := range c.rows {
		switch {
		case r.state == "active":
			if refused {
				r.state = "refused"
			} else {
				r.state = "done"
			}
		case r.state == "pending":
			r.state, r.why = "skipped", endReason
		}
	}
	if c.sticky {
		c.repaint()
	} else if c.w != nil {
		// plain/CI: print the full final roadmap ONCE so the log carries the
		// complete picture — which phases ran, refused, or were skipped.
		fmt.Fprintln(c.w, "converge phases:")
		for _, line := range c.frameLines() {
			fmt.Fprintln(c.w, line)
		}
	}
	c.frozen = true
}

// render prints the checklist. On a TTY it repaints in place (a sticky region);
// off a TTY (plain/CI) it prints append-only transition lines. Presentation only,
// on stderr — never parsed, never on stdout.
func (c *Checklist) render() {
	if c.w == nil {
		return
	}
	if c.sticky {
		c.repaint()
		return
	}
	// plain: one line for the most-recently-changed non-pending, non-frozen row —
	// but simplest honest degrade is a single status line of the active/last row.
	c.printPlainLine()
}

func (c *Checklist) frameLines() []string {
	out := make([]string, 0, len(c.rows))
	for _, r := range c.rows {
		g := c.m.PhaseGlyph(r.state)
		if col := render.PhaseColor(r.state); col != "" {
			g = c.m.Paint(col, g)
		}
		line := fmt.Sprintf("  %s %s", g, r.label)
		extra := ""
		if r.cond != "" && (r.state == "pending" || r.state == "active") {
			extra = " (" + r.cond + ")"
		}
		if r.why != "" {
			extra = " (" + r.why + ")"
		}
		if extra != "" {
			line += c.m.Dim(extra)
		}
		out = append(out, line)
	}
	return out
}

func (c *Checklist) printPlainLine() {
	// append-only: print only the row that just became active or terminal, as a
	// transition line, so CI logs stay flat (no repaint, no christmas tree).
	for _, r := range c.rows {
		if r.state == "active" {
			fmt.Fprintf(c.w, "converge → %s\n", r.label)
			return
		}
	}
	// on freeze there is no active row; print nothing extra (the banner concludes).
}

func (c *Checklist) repaint() {
	frame := strings.Join(c.frameLines(), "\n") + "\n"
	var b strings.Builder
	if c.prevLines > 0 {
		fmt.Fprintf(&b, "\x1b[%dA\x1b[0J", c.prevLines)
	}
	b.WriteString(frame)
	_, _ = c.w.Write([]byte(b.String()))
	c.prevLines = strings.Count(frame, "\n")
}
