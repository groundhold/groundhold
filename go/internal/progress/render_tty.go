package progress

import (
	"fmt"
	"sort"
	"strings"
)

// ActionView is one row of the TTY sticky region — a pure projection of the
// folded state, so the frame composer takes no live source of its own.
type ActionView struct {
	Index      int
	Op         string
	Capability string
	Target     string
	State      ActionState
	Glyph      rune
	ElapsedMS  int64
	Band       *ETABand
	Reason     string
	Phase      string // provider-reported LRO phase (e.g. "Pending", "provisioning")
}

// glyphFor is shape-first (D89): the SHAPE carries the state, never colour
// alone. `~` animates in motion states; `.` is quiet/pending; `!` is a frozen
// alarm (stalled/blocked); check/cross/dash are terminal.
func glyphFor(s ActionState) rune {
	switch s {
	case StateRunning, StateProviderWait:
		return '~'
	case StateStalled, StateBlockedConsent:
		return '!'
	case StateDone, StateSkipped:
		return 'v'
	case StateFailed, StateIndeterminate:
		return 'x'
	default: // pending, ready
		return '.'
	}
}

// Views returns the render rows for the non-terminal actions in manifest order
// (a TTY shows what is still in flight; terminal actions have scrolled into
// history). Deterministic: ordered by the manifest index.
func (f *Fold) Views() []ActionView {
	var vs []ActionView
	for _, id := range f.order {
		if f.done[id] {
			continue
		}
		m := f.manifest[id]
		vs = append(vs, ActionView{
			Index: m.Index, Op: m.Operation, Capability: m.Capability,
			Target: m.Target, State: f.states[id], Glyph: glyphFor(f.states[id]),
			ElapsedMS: f.elapsed[id], Band: f.band[id], Reason: f.reason[id],
			Phase: f.phase[id],
		})
	}
	sort.Slice(vs, func(i, j int) bool { return vs[i].Index < vs[j].Index })
	return vs
}

// Frame composes the sticky-region text (no ANSI cursor control — the terminal
// driver owns repaint; this is the pure, testable content). maxRows caps the
// visible rows; the overflow collapses to one honest summary line rather than
// scrolling. The header carries k/N, the one determinate truth.
func Frame(f *Fold, maxRows int) string {
	views := f.Views()
	var b strings.Builder
	fmt.Fprintf(&b, "[%2d/%d] resolved\n", f.k, f.n)

	shown := views
	overflow := 0
	if maxRows > 0 && len(views) > maxRows {
		shown = views[:maxRows]
		overflow = len(views) - maxRows
	}
	for _, v := range shown {
		b.WriteString(rowLine(v))
		b.WriteByte('\n')
	}
	if overflow > 0 {
		fmt.Fprintf(&b, "  (+%d more in flight)\n", overflow)
	}
	return b.String()
}

func rowLine(v ActionView) string {
	// glyph  op  capability  target  STATE  elapsed  [band | reason]
	s := fmt.Sprintf("%c %-7s %-24s %-12s %-14s %s",
		v.Glyph, v.Op, v.Capability, truncate(v.Target, 12),
		stateWord(v), fmtElapsed(v.ElapsedMS))

	// the provider-reported LRO phase (D257) is the "what is it waiting on"
	// signal Acme asked for — show it whenever a motion state carries one.
	if v.Phase != "" && IsMotion(v.State) {
		s += " " + v.Phase
	}

	switch {
	case v.State == StateStalled:
		// a stall names the silence; no band (a stalled action's estimate is void)
		if v.Reason != "" {
			s += " — " + v.Reason
		}
	case v.Band != nil && BandWithdrawn(v.Band, v.ElapsedMS):
		// beyond the seen worst: withdraw the band for honest prose (D227)
		s += fmt.Sprintf("  beyond seen worst (%s), still waiting", fmtElapsed(v.Band.WorstMS))
	case v.Band != nil && IsMotion(v.State):
		s += fmt.Sprintf("  typ ~%s (n=%d)", fmtElapsed(v.Band.TypicalMS), v.Band.Samples)
	case v.State == StatePending && v.Reason != "":
		s += " (" + v.Reason + ")"
	}
	return s
}

// stateWord upper-cases the alarm states so a stall/block reads at a glance,
// lower-cases the routine ones (D89 vocabulary).
func stateWord(v ActionView) string {
	if v.State == StateStalled || v.State == StateBlockedConsent {
		return strings.ToUpper(string(v.State))
	}
	return string(v.State)
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	if n <= 1 {
		return s[:n]
	}
	return s[:n-1] + "…"
}
