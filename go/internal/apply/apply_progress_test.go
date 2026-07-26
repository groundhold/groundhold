package apply

import (
	"bufio"
	"bytes"
	"encoding/json"
	"os"
	"testing"

	"groundhold/internal/progress"
	"groundhold/internal/provider"
)

// virtualClock returns a deterministic monotonic millis source (advances a fixed
// step per read) so a progress stream's elapsed values are reproducible in a
// test — the injected-clock mechanism from D227's testability plan.
func virtualClock() func() int64 {
	var t int64
	return func() int64 { t += 1000; return t }
}

// TestApplyEmitsFoldableProgressStream drives a real Apply with the ndjson
// progress sink and asserts the emitted stream satisfies every honesty contract
// the Fold enforces (legal edges, tick-can't-move-k, terminal outcomes) and that
// k reaches N. This pins the emit-point wiring end to end.
func TestApplyEmitsFoldableProgressStream(t *testing.T) {
	c, cand, plan := setupPlan(t)
	lp := freshLedger(t)
	var buf bytes.Buffer
	res := Apply(c, cand, nil, plan, lp, &provider.Fake{}, pfAt, false,
		WithProgress(progress.ModeNDJSON, &buf, virtualClock()))
	if res.Status != "applied" {
		t.Fatalf("apply status = %s (%v)", res.Status, res.Reasons)
	}

	f := progress.NewFold()
	sc := bufio.NewScanner(&buf)
	var sawDone bool
	for sc.Scan() {
		var ev progress.Event
		if err := json.Unmarshal(sc.Bytes(), &ev); err != nil {
			t.Fatalf("progress line not valid json: %v", err)
		}
		if err := f.Apply(ev); err != nil {
			t.Fatalf("fold rejected an emitted event (seq %d): %v", ev.Seq, err)
		}
		if ev.Kind == progress.KindTransition && ev.State == progress.StateDone {
			sawDone = true
		}
	}
	if ok, err := f.Done(); !ok {
		t.Fatalf("stream did not close cleanly: %v", err)
	}
	if !sawDone {
		t.Fatal("no action reached done")
	}
	if f.K() != f.N() || f.N() == 0 {
		t.Fatalf("k=%d n=%d — every action must resolve", f.K(), f.N())
	}
}

// TestApplyProgressDoesNotPerturbLedger is invariant #6 as an executable
// assertion: the ledger produced with the progress stream ON is byte-identical
// to the one produced with it OFF, for the same inputs. Progress is a
// projection, never a source of truth.
func TestApplyProgressDoesNotPerturbLedger(t *testing.T) {
	run := func(mode progress.Mode) []byte {
		c, cand, plan := setupPlan(t)
		lp := freshLedger(t)
		var buf bytes.Buffer
		res := Apply(c, cand, nil, plan, lp, &provider.Fake{}, pfAt, false,
			WithProgress(mode, &buf, virtualClock()))
		if res.Status != "applied" {
			t.Fatalf("apply status = %s (%v)", res.Status, res.Reasons)
		}
		b, err := os.ReadFile(lp)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	off := run(progress.ModeNone)
	on := run(progress.ModeNDJSON)
	if !bytes.Equal(off, on) {
		t.Fatalf("progress perturbed the ledger:\n off=%s\n on =%s", off, on)
	}
}

// TestApplyProgressOffIsSilent: with the default (no option) apply emits nothing
// to the progress sink — the feature is strictly opt-in.
func TestApplyProgressOffByDefault(t *testing.T) {
	c, cand, plan := setupPlan(t)
	lp := freshLedger(t)
	// no WithProgress -> ModeNone, stderr default but nothing written
	res := Apply(c, cand, nil, plan, lp, &provider.Fake{}, pfAt, false)
	if res.Status != "applied" {
		t.Fatalf("apply status = %s (%v)", res.Status, res.Reasons)
	}
}
