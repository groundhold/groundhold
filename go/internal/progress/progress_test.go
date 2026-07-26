package progress

import "testing"

// a minimal well-formed run: two actions, one create that goes through an LRO,
// one that is skipped because it depends on... nothing here; both terminal.
func manifest2() Event {
	return Event{Stream: Stream, Seq: 1, Kind: KindRunStart, RunID: "r", N: 2,
		Manifest: &RunManifest{TotalActions: 2, Actions: []ManifestAction{
			{ActionID: "a-create-db", Index: 1, Operation: "create", Capability: "db"},
			{ActionID: "a-create-net", Index: 2, Operation: "create", Capability: "net"},
		}}}
}

func TestFoldHappyPath(t *testing.T) {
	f := NewFold()
	seq := []Event{
		manifest2(),
		{Stream: Stream, Seq: 2, Kind: KindTransition, ActionID: "a-create-db", Prev: StatePending, State: StateReady, N: 2},
		{Stream: Stream, Seq: 3, Kind: KindTransition, ActionID: "a-create-db", Prev: StateReady, State: StateRunning, N: 2},
		{Stream: Stream, Seq: 4, Kind: KindTransition, ActionID: "a-create-db", Prev: StateRunning, State: StateProviderWait, N: 2},
		{Stream: Stream, Seq: 5, Kind: KindTick, ActionID: "a-create-db", ElapsedMS: 10000, N: 2},
		{Stream: Stream, Seq: 6, Kind: KindTransition, ActionID: "a-create-db", Prev: StateProviderWait, State: StateDone, Outcome: Satisfied, K: 1, N: 2},
		{Stream: Stream, Seq: 7, Kind: KindTransition, ActionID: "a-create-net", Prev: StatePending, State: StateReady, K: 1, N: 2},
		{Stream: Stream, Seq: 8, Kind: KindTransition, ActionID: "a-create-net", Prev: StateReady, State: StateRunning, K: 1, N: 2},
		{Stream: Stream, Seq: 9, Kind: KindTransition, ActionID: "a-create-net", Prev: StateRunning, State: StateDone, Outcome: Satisfied, K: 2, N: 2},
		{Stream: Stream, Seq: 10, Kind: KindRunEnd, N: 2},
	}
	for _, e := range seq {
		if err := f.Apply(e); err != nil {
			t.Fatalf("seq %d: %v", e.Seq, err)
		}
	}
	if ok, err := f.Done(); !ok {
		t.Fatalf("Done: %v", err)
	}
	if f.K() != 2 {
		t.Fatalf("k=%d, want 2", f.K())
	}
}

func TestTickCannotChangeStateOrK(t *testing.T) {
	f := NewFold()
	must(t, f, manifest2())
	must(t, f, Event{Stream: Stream, Seq: 2, Kind: KindTransition, ActionID: "a-create-db", Prev: StatePending, State: StateReady, N: 2})
	// a tick claiming a new state is a lie
	if err := f.Apply(Event{Stream: Stream, Seq: 3, Kind: KindTick, ActionID: "a-create-db", State: StateRunning, N: 2}); err == nil {
		t.Fatal("tick changing state was accepted")
	}
	// a tick advancing k is a lie
	if err := f.Apply(Event{Stream: Stream, Seq: 4, Kind: KindTick, ActionID: "a-create-db", K: 1, N: 2}); err == nil {
		t.Fatal("tick advancing k was accepted")
	}
}

func TestIllegalTransitionRejected(t *testing.T) {
	f := NewFold()
	must(t, f, manifest2())
	// pending -> running skips ready: not a legal edge
	if err := f.Apply(Event{Stream: Stream, Seq: 2, Kind: KindTransition, ActionID: "a-create-db", Prev: StatePending, State: StateRunning, N: 2}); err == nil {
		t.Fatal("illegal edge pending->running was accepted")
	}
}

func TestNoEventAfterTerminal(t *testing.T) {
	f := NewFold()
	must(t, f, manifest2())
	must(t, f, Event{Stream: Stream, Seq: 2, Kind: KindTransition, ActionID: "a-create-db", Prev: StatePending, State: StateReady, N: 2})
	must(t, f, Event{Stream: Stream, Seq: 3, Kind: KindTransition, ActionID: "a-create-db", Prev: StateReady, State: StateSkipped, SkipWhy: SkipCached, Outcome: Satisfied, K: 1, N: 2})
	if err := f.Apply(Event{Stream: Stream, Seq: 4, Kind: KindTick, ActionID: "a-create-db", N: 2}); err == nil {
		t.Fatal("event after terminal was accepted")
	}
}

func TestWrongOutcomeRejected(t *testing.T) {
	f := NewFold()
	must(t, f, manifest2())
	must(t, f, Event{Stream: Stream, Seq: 2, Kind: KindTransition, ActionID: "a-create-db", Prev: StatePending, State: StateReady, N: 2})
	must(t, f, Event{Stream: Stream, Seq: 3, Kind: KindTransition, ActionID: "a-create-db", Prev: StateReady, State: StateRunning, N: 2})
	// done must carry satisfied, not violated
	if err := f.Apply(Event{Stream: Stream, Seq: 4, Kind: KindTransition, ActionID: "a-create-db", Prev: StateRunning, State: StateDone, Outcome: Violated, K: 1, N: 2}); err == nil {
		t.Fatal("done with outcome=violated was accepted")
	}
}

func TestDepFailedSkipIsUnknownNotSatisfied(t *testing.T) {
	if got := Outcome(StateSkipped, SkipDepFailed); got != Unknown {
		t.Fatalf("dep-failed skip outcome=%q, want unknown", got)
	}
	if got := Outcome(StateSkipped, SkipCached); got != Satisfied {
		t.Fatalf("cached skip outcome=%q, want satisfied", got)
	}
}

func TestSeqMustBeMonotonic(t *testing.T) {
	f := NewFold()
	must(t, f, manifest2())
	if err := f.Apply(Event{Stream: Stream, Seq: 1, Kind: KindTick, ActionID: "a-create-db", N: 2}); err == nil {
		t.Fatal("non-monotonic seq accepted")
	}
}

func TestMotionAndTerminalTables(t *testing.T) {
	if !IsMotion(StateRunning) || !IsMotion(StateProviderWait) {
		t.Fatal("running/provider-wait must be motion states")
	}
	for _, s := range []ActionState{StatePending, StateReady, StateStalled, StateBlockedConsent} {
		if IsMotion(s) {
			t.Fatalf("%q must render as stillness", s)
		}
	}
	for _, s := range []ActionState{StateDone, StateFailed, StateSkipped, StateIndeterminate} {
		if !IsTerminal(s) {
			t.Fatalf("%q must be terminal", s)
		}
		if len(transitions[s]) != 0 {
			t.Fatalf("terminal %q must have no out-edges", s)
		}
	}
}

func must(t *testing.T, f *Fold, e Event) {
	t.Helper()
	if err := f.Apply(e); err != nil {
		t.Fatalf("seq %d: %v", e.Seq, err)
	}
}
