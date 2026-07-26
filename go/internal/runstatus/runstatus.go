// Package runstatus derives the state of a background run PURELY from ledger
// events plus an explicit clock (D229). It is the single source of run truth:
// there is no separate status store to disagree with the ledger. The
// four-valued discipline extends to run state — a run whose writer's lease has
// lapsed with no terminal event is `stalled`/`needs-reconcile` (run `resume`),
// never silently `failed` and never still `running`. Judging lease liveness
// against a defaulted clock would be exactly the stale-freshness lie N1 exists
// to prevent, so `status`/`wait` join the N1 family (the caller supplies now).
package runstatus

import (
	"bufio"
	"encoding/json"
	"os"
	"sort"

	"groundhold/internal/ledger"
	"groundhold/internal/perr"
)

// RunEvent is one ledger event, flattened to what run-status needs.
type RunEvent struct {
	Type  string
	Clock int // parsed occurredAt (the coordination clock)
	Body  map[string]any
}

// State is the closed run-state set (D229). No `queued`: the ledger cannot prove
// a queue — a run has either reached admission (an event exists) or it does not
// exist yet (`unknown`).
type State string

const (
	StateUnknown        State = "unknown"         // no event carries this handle
	StateRunning        State = "running"         // started, no terminal, lease live
	StateStalled        State = "stalled"         // started, no terminal, lease lapsed, nothing pending
	StateNeedsReconcile State = "needs-reconcile" // started, no terminal, lease lapsed, a receipt is unsettled
	StateDone           State = "done"            // apply.finished / converge.finished{converged}
	StateFailed         State = "failed"          // apply.failed / converge.failed
)

// LeaseView is the honest liveness signal — the lease TTL, not a PID.
type LeaseView struct {
	Live      bool   `json:"live"`
	ExpiresAt string `json:"expiresAt,omitempty"`
}

// RunStatus is the derived answer. It is a pure function of (events, now).
type RunStatus struct {
	Handle      string    `json:"handle"`
	Kind        string    `json:"kind"` // apply | converge
	State       State     `json:"state"`
	Code        perr.Code `json:"code"`
	Phase       string    `json:"phase,omitempty"` // converge: the phase reached
	StartedAt   string    `json:"startedAt,omitempty"`
	ConcludedAt string    `json:"concludedAt,omitempty"`
	Lease       LeaseView `json:"lease"`
	Pending     []string  `json:"pendingReceipts,omitempty"`
	ExitCode    int       `json:"exitCode,omitempty"`
	Remediation string    `json:"remediation,omitempty"`
	// Source is "ledger" for a run with events, or "registry-only" for a handle
	// found in the detach registry with NO ledger events — launched but never
	// admitted (D231). A registry-only run is always `unknown`; the tag says WHY
	// (it may have died pre-admission), which is the single most attention-worthy
	// condition the dashboard surfaces.
	Source string `json:"source,omitempty"`
}

var codeFor = map[State]perr.Code{
	StateUnknown:        perr.RunUnknown,
	StateRunning:        perr.RunRunning,
	StateStalled:        perr.RunStalled,
	StateNeedsReconcile: perr.RunNeedsReconcile,
	StateDone:           perr.RunDone,
	StateFailed:         perr.RunFailed,
}

// ReadEvents parses a ledger JSONL file into run events (type + clock + body).
func ReadEvents(path string) ([]RunEvent, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []RunEvent
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 1024*1024), 8*1024*1024)
	for sc.Scan() {
		line := sc.Bytes()
		if len(line) == 0 {
			continue
		}
		var doc struct {
			Event struct {
				Type       string         `json:"type"`
				OccurredAt string         `json:"occurredAt"`
				Body       map[string]any `json:"body"`
			} `json:"event"`
		}
		if err := json.Unmarshal(line, &doc); err != nil {
			return nil, err
		}
		clk, _ := ledger.ParseTs(doc.Event.OccurredAt)
		out = append(out, RunEvent{Type: doc.Event.Type, Clock: clk, Body: doc.Event.Body})
	}
	return out, sc.Err()
}

func str(m map[string]any, k string) string { s, _ := m[k].(string); return s }

func intOf(m map[string]any, k string) int {
	switch v := m[k].(type) {
	case int:
		return v
	case float64:
		return int(v)
	}
	return 0
}

// runID returns the handle an event is scoped to (apply.* and converge.* both
// carry it in the body under applyRunId / convergeRunId).
func handleOf(e RunEvent) string {
	if h := str(e.Body, "applyRunId"); h != "" {
		return h
	}
	return str(e.Body, "convergeRunId")
}

// DeriveRunStatus computes a run's state from the ledger events and an explicit
// now-clock. Pure and deterministic — the whole design's testable heart.
func DeriveRunStatus(evs []RunEvent, handle string, nowClock int) RunStatus {
	rs := RunStatus{Handle: handle, State: StateUnknown}
	var (
		started, finished, failed bool
		leaseAcqClock, leaseTTL   int
		leaseAcquired, leaseEnded bool
		phase                     string
	)
	pending := map[string]bool{} // operationId -> unsettled

	for _, e := range evs {
		if handleOf(e) != handle && e.Type != "lease.released" && e.Type != "lease.renewed" {
			continue
		}
		switch e.Type {
		case "apply.started":
			started, rs.Kind = true, "apply"
			rs.StartedAt = fmtClock(e.Clock)
		case "converge.started":
			started, rs.Kind = true, "converge"
			rs.StartedAt = fmtClock(e.Clock)
		case "converge.phase.entered":
			phase = str(e.Body, "phase")
		case "apply.finished", "converge.finished":
			finished = true
			rs.ConcludedAt = fmtClock(e.Clock)
			rs.ExitCode = intOf(e.Body, "exitCode")
		case "apply.failed", "converge.failed":
			failed = true
			rs.ConcludedAt = fmtClock(e.Clock)
			rs.ExitCode = intOf(e.Body, "exitCode")
			if p := str(e.Body, "phase"); p != "" {
				phase = p
			}
		case "lease.acquired":
			if handleOf(e) == handle {
				leaseAcquired, leaseAcqClock, leaseTTL = true, e.Clock, intOf(e.Body, "ttlSeconds")
			}
		case "lease.released":
			// leases are serialized; a release at/after our acquire ends ours.
			if leaseAcquired && e.Clock >= leaseAcqClock {
				leaseEnded = true
			}
		case "operation.receipt":
			op := str(e.Body, "operationId")
			switch str(e.Body, "status") {
			case "pending":
				pending[op] = true
			default: // succeeded/failed/unknown-with-id conclude the intent
				delete(pending, op)
			}
		}
	}
	rs.Phase = phase

	leaseLive := leaseAcquired && !leaseEnded && nowClock < leaseAcqClock+leaseTTL
	if leaseAcquired {
		rs.Lease = LeaseView{Live: leaseLive, ExpiresAt: fmtClock(leaseAcqClock + leaseTTL)}
	}
	for op := range pending {
		rs.Pending = append(rs.Pending, op)
	}

	switch {
	case !started:
		rs.State = StateUnknown
	case finished:
		rs.State = StateDone
	case failed:
		rs.State = StateFailed
	case leaseLive:
		rs.State = StateRunning
	case len(pending) > 0:
		rs.State = StateNeedsReconcile
		rs.Remediation = "run `groundhold resume` — an in-flight receipt is unsettled"
	default:
		rs.State = StateStalled
		rs.Remediation = "the writer's lease lapsed with no outcome — run `groundhold resume`"
	}
	rs.Code = codeFor[rs.State]
	return rs
}

// ListRuns enumerates every run and derives each one's status (D231). The handle
// set comes from the LEDGER — the sole run truth (D229), holding EVERY run,
// foreground and detached — ordered most-recent-first by start clock, with the
// chain-index (first-seen) then handle as deterministic tiebreaks so golden tests
// are stable. A ledger run whose start event is missing (e.g. a compacted tail)
// reads `unknown` and sorts last, never dropped.
//
// registryHandles are detach-registry pointers (from detach.ListRegistry); a
// handle there with NO ledger events is unioned in as a `registry-only` run:
// `unknown`, tagged so — a run launched but never admitted (it may have died
// pre-admission), the single most attention-worthy condition the ledger alone
// cannot surface. Registry pointers contribute ONLY to the question set; the
// verdict still derives solely from events + clock. Registry-only runs sort after
// every ledger run (they have no start clock), ordered by handle.
func ListRuns(evs []RunEvent, nowClock int, registryHandles []string) []RunStatus {
	// first-seen order of handles, plus each handle's start clock (the earliest
	// *.started, or the earliest event carrying it if no start is present).
	startClock := map[string]int{}
	hasStart := map[string]bool{}
	var order []string
	seen := map[string]bool{}
	for _, e := range evs {
		h := handleOf(e)
		if h == "" {
			continue
		}
		if !seen[h] {
			seen[h] = true
			order = append(order, h)
			startClock[h] = e.Clock
		}
		if e.Type == "apply.started" || e.Type == "converge.started" {
			if !hasStart[h] || e.Clock < startClock[h] {
				startClock[h] = e.Clock
			}
			hasStart[h] = true
		}
	}
	firstSeen := map[string]int{}
	for i, h := range order {
		firstSeen[h] = i
	}
	out := make([]RunStatus, 0, len(order))
	for _, h := range order {
		rs := DeriveRunStatus(evs, h, nowClock)
		rs.Source = "ledger"
		out = append(out, rs)
	}
	// most-recent-first by start clock; chain-index then handle break ties.
	sort.SliceStable(out, func(i, j int) bool {
		ci, cj := startClock[out[i].Handle], startClock[out[j].Handle]
		if ci != cj {
			return ci > cj
		}
		if firstSeen[out[i].Handle] != firstSeen[out[j].Handle] {
			return firstSeen[out[i].Handle] < firstSeen[out[j].Handle]
		}
		return out[i].Handle < out[j].Handle
	})

	// union in registry-only handles (launched, never admitted) — unknown, tagged.
	var regOnly []RunStatus
	for _, h := range registryHandles {
		if seen[h] {
			continue // it has ledger events; the ledger already spoke for it
		}
		rs := DeriveRunStatus(evs, h, nowClock) // no events -> unknown
		rs.Source = "registry-only"
		rs.Remediation = "launched but no ledger events — it may have died before admission; check its log"
		regOnly = append(regOnly, rs)
	}
	sort.Slice(regOnly, func(i, j int) bool { return regOnly[i].Handle < regOnly[j].Handle })
	return append(out, regOnly...)
}

func fmtClock(clk int) string { return ledger.FormatTs(clk) }
