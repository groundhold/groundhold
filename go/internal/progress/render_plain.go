package progress

import "fmt"

// plainLine renders one event as a no-ANSI human/CI line (clig.dev's
// christmas-tree rule: no animation off a TTY). The TTY sticky region with
// columns/glyphs is T1; T0 plain is honest and greppable. Returns "" for
// events that produce no line.
func plainLine(ev Event) string {
	switch ev.Kind {
	case KindRunStart:
		return fmt.Sprintf("progress %d actions", ev.Manifest.TotalActions)
	case KindRunEnd:
		return fmt.Sprintf("progress done %d/%d resolved", ev.K, ev.N)
	case KindTransition, KindTick:
		return progressLine(ev)
	}
	return ""
}

// progressLine is the k/N + action + state + elapsed line. It never invents a
// percent — a provider figure appears only when the event carries one.
func progressLine(ev Event) string {
	s := fmt.Sprintf("progress [%d/%d] %s %s elapsed=%s",
		ev.K, ev.N, ev.ActionID, ev.State, fmtElapsed(ev.ElapsedMS))
	if ev.ProviderPhase != "" {
		// the provider-reported LRO phase (D257) — the "what is it waiting on"
		// signal a long silent create needs (Acme field report #1).
		s += " phase=" + ev.ProviderPhase
	}
	if ev.ProviderPercent != nil {
		s += fmt.Sprintf(" provider=%.0f%%", *ev.ProviderPercent)
	}
	if ev.ETA != nil {
		s += fmt.Sprintf(" typ=%s(n=%d)", fmtElapsed(ev.ETA.TypicalMS), ev.ETA.Samples)
	}
	if ev.Outcome != "" {
		s += " outcome=" + string(ev.Outcome)
	}
	if ev.Reason != "" {
		s += " — " + ev.Reason
	}
	return s
}

// fmtElapsed renders a duration as MM:SS (or H:MM:SS past an hour). Durations
// only — never an absolute time, which would read as a freshness claim.
func fmtElapsed(ms int64) string {
	if ms < 0 {
		ms = 0
	}
	sec := ms / 1000
	h := sec / 3600
	m := (sec % 3600) / 60
	s := sec % 60
	if h > 0 {
		return fmt.Sprintf("%d:%02d:%02d", h, m, s)
	}
	return fmt.Sprintf("%02d:%02d", m, s)
}
