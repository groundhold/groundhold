package progress

import "fmt"

// Fold rebuilds the current view from a delta stream AND enforces the honesty
// contracts (D227). It is the single consumer-side folder — the TTY/CI
// renderers and the conformance invariant checks both drive it, so the rules
// live in one place. Apply returns an error the moment a stream violates a
// contract; a well-formed run never triggers one.
type Fold struct {
	started bool
	ended   bool
	n       int
	k       int
	seq     uint64
	seenSeq bool
	states  map[string]ActionState // actionId -> current state
	done    map[string]bool        // actionId -> reached a terminal state
	// render support (T1): retained from the stream so a TTY frame can be
	// composed without a second source.
	order    []string                  // action ids in manifest (execution) order
	manifest map[string]ManifestAction // actionId -> manifest entry
	elapsed  map[string]int64          // actionId -> latest elapsedMs
	reason   map[string]string         // actionId -> latest reason
	phase    map[string]string         // actionId -> latest provider phase (LRO)
	band     map[string]*ETABand       // actionId -> latest eta band
}

// NewFold returns an empty folder.
func NewFold() *Fold {
	return &Fold{states: map[string]ActionState{}, done: map[string]bool{},
		manifest: map[string]ManifestAction{}, elapsed: map[string]int64{},
		reason: map[string]string{}, phase: map[string]string{}, band: map[string]*ETABand{}}
}

// State returns the current folded state of an action (or "" if unseen).
func (f *Fold) State(actionID string) ActionState { return f.states[actionID] }

// K, N report the resolved-count position.
func (f *Fold) K() int { return f.k }
func (f *Fold) N() int { return f.n }

// Apply folds one event and validates it. The checks ARE the spec's honesty
// contracts: monotone seq; run-start first and once; a transition rides a legal
// edge and moves k only on a terminal; a tick changes neither state nor k; no
// event follows a terminal for the same action; k never exceeds n.
func (f *Fold) Apply(e Event) error {
	if e.Stream != Stream {
		return fmt.Errorf("wrong stream %q (want %q)", e.Stream, Stream)
	}
	if f.seenSeq && e.Seq <= f.seq {
		return fmt.Errorf("seq not monotonic: %d after %d", e.Seq, f.seq)
	}
	f.seq, f.seenSeq = e.Seq, true

	switch e.Kind {
	case KindRunStart:
		if f.started {
			return fmt.Errorf("duplicate run-start")
		}
		if e.Manifest == nil {
			return fmt.Errorf("run-start without a manifest")
		}
		f.started = true
		f.n = e.Manifest.TotalActions
		for _, a := range e.Manifest.Actions {
			f.states[a.ActionID] = StatePending
			f.manifest[a.ActionID] = a
			f.order = append(f.order, a.ActionID)
		}
		return nil

	case KindBanner:
		return nil // banners carry no action state

	case KindRunEnd:
		if !f.started {
			return fmt.Errorf("run-end before run-start")
		}
		f.ended = true
		return nil

	case KindTransition, KindTick:
		if !f.started {
			return fmt.Errorf("%s before run-start", e.Kind)
		}
		if e.ActionID == "" {
			return fmt.Errorf("%s without an actionId", e.Kind)
		}
		if f.done[e.ActionID] {
			return fmt.Errorf("%s after action %s reached a terminal state", e.Kind, e.ActionID)
		}
	default:
		return fmt.Errorf("unknown event kind %q", e.Kind)
	}

	cur := f.states[e.ActionID]

	// retain the latest render facts (T1) for both ticks and transitions.
	f.elapsed[e.ActionID] = e.ElapsedMS
	if e.Reason != "" {
		f.reason[e.ActionID] = e.Reason
	}
	if e.ProviderPhase != "" {
		f.phase[e.ActionID] = e.ProviderPhase
	}
	if e.ETA != nil {
		f.band[e.ActionID] = e.ETA
	}

	if e.Kind == KindTick {
		// A tick is liveness only: it must not claim a state change or advance k.
		if e.State != "" && e.State != cur {
			return fmt.Errorf("tick on %s claims state %q but current is %q (a tick cannot change state)",
				e.ActionID, e.State, cur)
		}
		if e.K != f.k {
			return fmt.Errorf("tick on %s moves k to %d (a tick cannot advance k)", e.ActionID, e.K)
		}
		return nil
	}

	// transition
	if e.Prev != cur {
		return fmt.Errorf("transition on %s declares prev %q but current is %q", e.ActionID, e.Prev, cur)
	}
	if !CanTransition(cur, e.State) {
		return fmt.Errorf("illegal transition on %s: %q -> %q", e.ActionID, cur, e.State)
	}
	f.states[e.ActionID] = e.State

	if IsTerminal(e.State) {
		f.done[e.ActionID] = true
		f.k++
		if e.Outcome != Outcome(e.State, e.SkipWhy) {
			return fmt.Errorf("transition to %s on %s carries outcome %q, want %q",
				e.State, e.ActionID, e.Outcome, Outcome(e.State, e.SkipWhy))
		}
	}
	if e.K != f.k {
		return fmt.Errorf("transition on %s reports k=%d, folded k=%d", e.ActionID, e.K, f.k)
	}
	if f.k > f.n {
		return fmt.Errorf("k=%d exceeds n=%d", f.k, f.n)
	}
	return nil
}

// Done reports whether the run closed cleanly: run-end seen and every action
// terminal (k == n). Used by the fold-consistency differential check.
func (f *Fold) Done() (bool, error) {
	if !f.ended {
		return false, fmt.Errorf("stream did not end")
	}
	if f.k != f.n {
		return false, fmt.Errorf("run ended with k=%d, n=%d actions resolved", f.k, f.n)
	}
	return true, nil
}
