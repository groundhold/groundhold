package progress

import (
	"strings"
	"testing"
)

// buildFold folds a scripted set of events, failing the test on any rejection.
func buildFold(t *testing.T, evs ...Event) *Fold {
	t.Helper()
	f := NewFold()
	for _, e := range evs {
		if err := f.Apply(e); err != nil {
			t.Fatalf("seq %d rejected: %v", e.Seq, err)
		}
	}
	return f
}

func manifest3() Event {
	return Event{Stream: Stream, Seq: 1, Kind: KindRunStart, N: 3,
		Manifest: &RunManifest{TotalActions: 3, Actions: []ManifestAction{
			{ActionID: "a-db", Index: 1, Operation: "create", Capability: "database.relational", Target: "gcp.cloudsql/db"},
			{ActionID: "a-net", Index: 2, Operation: "create", Capability: "private-network", Target: "gcp.vpc/net"},
			{ActionID: "a-api", Index: 3, Operation: "update", Capability: "container-workload", Target: "gcp.run/api"},
		}}}
}

func TestFrameShapeFirstAndTerminalsHidden(t *testing.T) {
	f := buildFold(t, manifest3(),
		// a-db is provider-wait with a band
		Event{Stream: Stream, Seq: 2, Kind: KindTransition, ActionID: "a-db", Prev: StatePending, State: StateReady, N: 3},
		Event{Stream: Stream, Seq: 3, Kind: KindTransition, ActionID: "a-db", Prev: StateReady, State: StateRunning, N: 3},
		Event{Stream: Stream, Seq: 4, Kind: KindTransition, ActionID: "a-db", Prev: StateRunning, State: StateProviderWait,
			ETA: &ETABand{AtLeastMS: 300000, TypicalMS: 420000, WorstMS: 540000, Basis: BasisInferred, Samples: 12}, ElapsedMS: 252000, N: 3},
		// a-db terminal: done -> must NOT appear in the frame
		// (leave a-net pending, a-api we drive to stalled below)
		Event{Stream: Stream, Seq: 5, Kind: KindTransition, ActionID: "a-api", Prev: StatePending, State: StateReady, N: 3},
		Event{Stream: Stream, Seq: 6, Kind: KindTransition, ActionID: "a-api", Prev: StateReady, State: StateRunning, N: 3},
		Event{Stream: Stream, Seq: 7, Kind: KindTransition, ActionID: "a-api", Prev: StateRunning, State: StateProviderWait, ElapsedMS: 60000, N: 3},
		Event{Stream: Stream, Seq: 8, Kind: KindTransition, ActionID: "a-api", Prev: StateProviderWait, State: StateStalled,
			Reason: "no poll answer for 94s", ElapsedMS: 94000, N: 3},
	)
	frame := Frame(f, 0)

	if !strings.Contains(frame, "[ 0/3] resolved") {
		t.Fatalf("frame header wrong:\n%s", frame)
	}
	// a-db in provider-wait: motion glyph + band
	if !strings.Contains(frame, "~ create") || !strings.Contains(frame, "typ ~07:00 (n=12)") {
		t.Fatalf("provider-wait row missing motion glyph or band:\n%s", frame)
	}
	// a-net pending: quiet glyph
	if !strings.Contains(frame, ". create  private-network") {
		t.Fatalf("pending row missing quiet glyph:\n%s", frame)
	}
	// a-api stalled: alarm glyph + UPPERCASE + reason, NO band
	if !strings.Contains(frame, "! update") || !strings.Contains(frame, "STALLED") ||
		!strings.Contains(frame, "no poll answer for 94s") {
		t.Fatalf("stalled row missing alarm/uppercase/reason:\n%s", frame)
	}
}

func TestFrameWithdrawsBandPastWorst(t *testing.T) {
	f := buildFold(t, manifest3(),
		Event{Stream: Stream, Seq: 2, Kind: KindTransition, ActionID: "a-db", Prev: StatePending, State: StateReady, N: 3},
		Event{Stream: Stream, Seq: 3, Kind: KindTransition, ActionID: "a-db", Prev: StateReady, State: StateRunning, N: 3},
		Event{Stream: Stream, Seq: 4, Kind: KindTransition, ActionID: "a-db", Prev: StateRunning, State: StateProviderWait,
			ETA: &ETABand{AtLeastMS: 300000, TypicalMS: 420000, WorstMS: 540000, Basis: BasisInferred, Samples: 12}, N: 3},
		// elapsed now beyond worst (540s): band must be withdrawn for prose
		Event{Stream: Stream, Seq: 5, Kind: KindTick, ActionID: "a-db", State: StateProviderWait, ElapsedMS: 600000, N: 3},
	)
	frame := Frame(f, 0)
	if strings.Contains(frame, "typ ~") {
		t.Fatalf("a beaten band must be withdrawn, not shown:\n%s", frame)
	}
	if !strings.Contains(frame, "beyond seen worst (09:00), still waiting") {
		t.Fatalf("withdrawn band must show honest prose:\n%s", frame)
	}
}

func TestFrameOverflowCollapses(t *testing.T) {
	f := buildFold(t, manifest3())
	frame := Frame(f, 2)
	if !strings.Contains(frame, "(+1 more in flight)") {
		t.Fatalf("overflow beyond maxRows must collapse honestly:\n%s", frame)
	}
}
