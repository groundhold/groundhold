package progress

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"sync"
)

// Mode selects the sink. The executor owns the clock (progress is a projection
// of the executor, D227), so the Emitter never reads time — the caller passes
// elapsed. The Emitter only sequences (monotonic seq), tracks k (terminal
// count), and renders.
type Mode string

const (
	ModeNDJSON Mode = "ndjson" // pure machine stream, one JSON object per line
	ModePlain  Mode = "plain"  // human/CI lines, no ANSI (clig.dev christmas-tree rule)
	ModeTTY    Mode = "tty"    // sticky region: the frame repaints in place (TTY only)
	ModeNone   Mode = "none"   // discard — apply semantics are identical
)

// Detail carries the optional fields of a transition/tick. Zero values are
// omitted from the event.
type Detail struct {
	ElapsedMS       int64
	StartedAt       string
	Outcome         Verdict
	SkipWhy         string
	Reason          string
	Code            string
	ProviderPercent *float64
	ProviderPhase   string
	RetryAfterMS    *int64
	ETA             *ETABand
}

// Emitter serializes the progress stream for one run. Safe for concurrent
// actions (the concurrency budget may run several at once).
type Emitter struct {
	mu       sync.Mutex
	w        io.Writer
	mode     Mode
	seq      uint64
	n, k     int
	runID    string
	planHash string
	// tty sticky-region state: the emitter folds its own stream and repaints
	// the frame in place. Only used in ModeTTY.
	fold      *Fold
	prevLines int
	rows      int
}

// New builds an Emitter. A nil writer or ModeNone discards everything.
func New(w io.Writer, mode Mode, runID, planHash string) *Emitter {
	e := &Emitter{w: w, mode: mode, runID: runID, planHash: planHash, rows: 8}
	if mode == ModeTTY {
		e.fold = NewFold()
	}
	return e
}

// off reports whether nothing should be written (keeps call sites clean).
func (e *Emitter) off() bool { return e == nil || e.mode == ModeNone || e.w == nil }

// next stamps the shared envelope fields and advances seq under the lock.
func (e *Emitter) next(ev *Event) {
	e.seq++
	ev.Stream = Stream
	ev.Seq = e.seq
	ev.RunID = e.runID
	ev.PlanHash = e.planHash
	ev.N = e.n
	ev.K = e.k
}

// Start opens the stream with the run manifest and records N.
func (e *Emitter) Start(m RunManifest) {
	if e.off() {
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	e.n = m.TotalActions
	ev := Event{Kind: KindRunStart, Manifest: &m}
	e.next(&ev)
	e.write(ev)
}

// Transition emits a state change. On a terminal state it advances k; the caller
// need not track it. The emitter trusts the executor's edge (the Fold validates
// on the consumer side and in conformance); it fills Outcome for terminals if
// the caller left it unset.
func (e *Emitter) Transition(actionID string, prev, next ActionState, d Detail) {
	if e.off() {
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if IsTerminal(next) {
		e.k++
		if d.Outcome == "" {
			d.Outcome = Outcome(next, d.SkipWhy)
		}
	}
	ev := Event{Kind: KindTransition, ActionID: actionID, Prev: prev, State: next}
	fill(&ev, d)
	e.next(&ev)
	e.write(ev)
}

// Tick emits a liveness heartbeat: elapsed and (if the provider supplied one) a
// fresh percent. It changes neither state nor k.
func (e *Emitter) Tick(actionID string, state ActionState, d Detail) {
	if e.off() {
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	ev := Event{Kind: KindTick, ActionID: actionID, State: state}
	fill(&ev, d)
	e.next(&ev)
	e.write(ev)
}

// Banner rides a D89 banner through the stream so an ndjson consumer sees a pure
// channel (the human/plain renderer prints the banner directly).
func (e *Emitter) Banner(text string) {
	if e.off() || e.mode != ModeNDJSON {
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	ev := Event{Kind: KindBanner, Reason: text}
	e.next(&ev)
	e.write(ev)
}

// End closes the stream.
func (e *Emitter) End() {
	if e.off() {
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	ev := Event{Kind: KindRunEnd}
	e.next(&ev)
	e.write(ev)
}

func fill(ev *Event, d Detail) {
	ev.ElapsedMS = d.ElapsedMS
	ev.StartedAt = d.StartedAt
	ev.Outcome = d.Outcome
	ev.SkipWhy = d.SkipWhy
	ev.Reason = d.Reason
	ev.Code = d.Code
	ev.ProviderPercent = d.ProviderPercent
	ev.ProviderPhase = d.ProviderPhase
	ev.RetryAfterMS = d.RetryAfterMS
	ev.ETA = d.ETA
}

// write renders one event per mode. NDJSON is canonical (encoding/json, sorted
// keys via struct order); plain is a human/CI line.
func (e *Emitter) write(ev Event) {
	switch e.mode {
	case ModeNDJSON:
		b, err := json.Marshal(ev)
		if err != nil {
			return
		}
		_, _ = e.w.Write(append(b, '\n'))
	case ModePlain:
		if s := plainLine(ev); s != "" {
			fmt.Fprintln(e.w, s)
		}
	case ModeTTY:
		e.repaint(ev)
	}
}

// repaint folds the event and reprints the sticky frame in place: move the
// cursor up to the top of the previous frame, clear to the end of the screen,
// and write the new frame. `\x1b[0J` handles a frame that SHRANK (fewer rows as
// actions finish) — no stale lines left behind. Best-effort: a fold rejection
// (a mis-emitted edge) never crashes rendering.
func (e *Emitter) repaint(ev Event) {
	_ = e.fold.Apply(ev)
	frame := Frame(e.fold, e.rows)
	var b strings.Builder
	if e.prevLines > 0 {
		fmt.Fprintf(&b, "\x1b[%dA\x1b[0J", e.prevLines)
	}
	b.WriteString(frame)
	_, _ = e.w.Write([]byte(b.String()))
	e.prevLines = strings.Count(frame, "\n")
}
