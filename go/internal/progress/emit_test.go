package progress

import (
	"bufio"
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

// driveScript runs a fixed action through the emitter with caller-supplied
// elapsed (the executor owns the clock), captures the ndjson, and folds it back
// — the emitter must produce a stream the Fold accepts, and k must land at N.
func TestEmitterNDJSONFoldsClean(t *testing.T) {
	var buf bytes.Buffer
	e := New(&buf, ModeNDJSON, "run-1", "sha256:abc")
	e.Start(RunManifest{TotalActions: 1, Actions: []ManifestAction{
		{ActionID: "a-create-db", Index: 1, Operation: "create", Capability: "db"},
	}})
	e.Transition("a-create-db", StatePending, StateReady, Detail{})
	e.Transition("a-create-db", StateReady, StateRunning, Detail{})
	e.Transition("a-create-db", StateRunning, StateProviderWait, Detail{ElapsedMS: 2000})
	e.Tick("a-create-db", StateProviderWait, Detail{ElapsedMS: 12000})
	e.Transition("a-create-db", StateProviderWait, StateDone, Detail{ElapsedMS: 30000})
	e.End()

	f := NewFold()
	sc := bufio.NewScanner(&buf)
	var count int
	for sc.Scan() {
		var ev Event
		if err := json.Unmarshal(sc.Bytes(), &ev); err != nil {
			t.Fatalf("line %d not valid json: %v", count, err)
		}
		if err := f.Apply(ev); err != nil {
			t.Fatalf("fold rejected emitted event %d: %v", ev.Seq, err)
		}
		count++
	}
	if ok, err := f.Done(); !ok {
		t.Fatalf("Done: %v", err)
	}
	if count != 7 {
		t.Fatalf("expected 7 events, got %d", count)
	}
}

// The emitter fills a terminal Outcome the caller omitted, and advances k
// itself — the call site stays clean.
func TestEmitterFillsTerminalOutcomeAndK(t *testing.T) {
	var buf bytes.Buffer
	e := New(&buf, ModeNDJSON, "r", "h")
	e.Start(RunManifest{TotalActions: 1, Actions: []ManifestAction{{ActionID: "x", Index: 1}}})
	e.Transition("x", StatePending, StateReady, Detail{})
	e.Transition("x", StateReady, StateRunning, Detail{})
	e.Transition("x", StateRunning, StateFailed, Detail{}) // no Outcome supplied

	last := lastEvent(t, &buf)
	if last.Outcome != Violated {
		t.Fatalf("failed transition outcome=%q, want violated", last.Outcome)
	}
	if last.K != 1 {
		t.Fatalf("k=%d after one terminal, want 1", last.K)
	}
}

// ModeNone writes nothing at all.
func TestModeNoneIsSilent(t *testing.T) {
	var buf bytes.Buffer
	e := New(&buf, ModeNone, "r", "h")
	e.Start(RunManifest{TotalActions: 1})
	e.Transition("x", StatePending, StateReady, Detail{})
	e.End()
	if buf.Len() != 0 {
		t.Fatalf("ModeNone wrote %d bytes", buf.Len())
	}
}

// Plain mode never invents a percent and shows k/N + elapsed.
func TestPlainLineNoInventedPercent(t *testing.T) {
	var buf bytes.Buffer
	e := New(&buf, ModePlain, "r", "h")
	e.Start(RunManifest{TotalActions: 2, Actions: []ManifestAction{{ActionID: "a"}, {ActionID: "b"}}})
	e.Transition("a", StatePending, StateReady, Detail{})
	e.Transition("a", StateReady, StateRunning, Detail{})
	e.Transition("a", StateRunning, StateProviderWait, Detail{ElapsedMS: 252000})
	out := buf.String()
	if strings.Contains(out, "%") {
		t.Fatalf("plain output invented a percent: %q", out)
	}
	if !strings.Contains(out, "[0/2]") {
		t.Fatalf("plain output missing k/N: %q", out)
	}
	if !strings.Contains(out, "elapsed=04:12") {
		t.Fatalf("plain output missing/wrong elapsed: %q", out)
	}
}

func lastEvent(t *testing.T, buf *bytes.Buffer) Event {
	t.Helper()
	var last Event
	sc := bufio.NewScanner(buf)
	for sc.Scan() {
		if len(strings.TrimSpace(sc.Text())) == 0 {
			continue
		}
		if err := json.Unmarshal(sc.Bytes(), &last); err != nil {
			t.Fatalf("bad json: %v", err)
		}
	}
	return last
}

// ModeTTY folds its own stream and repaints a sticky frame; the buffer must
// carry the frame content and the ANSI repaint control (cursor-up + clear).
func TestTTYModeRepaintsFrame(t *testing.T) {
	var buf bytes.Buffer
	e := New(&buf, ModeTTY, "r", "h")
	e.Start(RunManifest{TotalActions: 1, Actions: []ManifestAction{
		{ActionID: "a-db", Index: 1, Operation: "create", Capability: "db"},
	}})
	e.Transition("a-db", StatePending, StateReady, Detail{})
	e.Transition("a-db", StateReady, StateRunning, Detail{})
	e.Transition("a-db", StateRunning, StateDone, Detail{ElapsedMS: 5000})
	out := buf.String()
	if !strings.Contains(out, "resolved") {
		t.Fatalf("tty frame missing header:\n%q", out)
	}
	if !strings.Contains(out, "\x1b[") {
		t.Fatalf("tty mode emitted no ANSI repaint control:\n%q", out)
	}
	// after the terminal transition the action leaves the in-flight rows; the
	// last frame shows 1/1 resolved
	if !strings.Contains(out, "[ 1/1] resolved") {
		t.Fatalf("final frame must show 1/1 resolved:\n%q", out)
	}
}
