package runstatus

import "testing"

const h = "abc123"

func ev(t string, clk int, body map[string]any) RunEvent {
	if body == nil {
		body = map[string]any{}
	}
	return RunEvent{Type: t, Clock: clk, Body: body}
}

func started(clk int) RunEvent {
	return ev("apply.started", clk, map[string]any{"applyRunId": h, "plan": "sha256:p"})
}
func lease(clk, ttl int) RunEvent {
	return ev("lease.acquired", clk, map[string]any{"applyRunId": h, "ttlSeconds": ttl})
}

func TestUnknownWhenNoEventCarriesHandle(t *testing.T) {
	evs := []RunEvent{ev("apply.started", 100, map[string]any{"applyRunId": "other"})}
	if s := DeriveRunStatus(evs, h, 100); s.State != StateUnknown {
		t.Fatalf("state=%s, want unknown", s.State)
	}
}

func TestRunningWhileLeaseLive(t *testing.T) {
	evs := []RunEvent{started(100), lease(100, 300)}
	s := DeriveRunStatus(evs, h, 200) // 200 < 100+300
	if s.State != StateRunning || !s.Lease.Live {
		t.Fatalf("state=%s leaseLive=%v, want running+live", s.State, s.Lease.Live)
	}
}

func TestStalledWhenLeaseLapsedNothingPending(t *testing.T) {
	evs := []RunEvent{started(100), lease(100, 300)}
	s := DeriveRunStatus(evs, h, 500) // 500 > 100+300, no pending
	if s.State != StateStalled {
		t.Fatalf("state=%s, want stalled", s.State)
	}
	if s.Code != codeFor[StateStalled] || s.Remediation == "" {
		t.Fatalf("stalled must carry a resume remediation, got code=%s rem=%q", s.Code, s.Remediation)
	}
}

func TestNeedsReconcileWhenLeaseLapsedWithPending(t *testing.T) {
	evs := []RunEvent{started(100), lease(100, 300),
		ev("operation.receipt", 110, map[string]any{"applyRunId": h, "operationId": "op1", "status": "pending"})}
	s := DeriveRunStatus(evs, h, 500)
	if s.State != StateNeedsReconcile {
		t.Fatalf("state=%s, want needs-reconcile", s.State)
	}
	if len(s.Pending) != 1 {
		t.Fatalf("pending=%v, want 1", s.Pending)
	}
}

func TestPendingReceiptWhileLeaseLiveIsStillRunning(t *testing.T) {
	// receipts pend mid-flight normally; a live lease means running, not reconcile.
	evs := []RunEvent{started(100), lease(100, 300),
		ev("operation.receipt", 110, map[string]any{"applyRunId": h, "operationId": "op1", "status": "pending"})}
	if s := DeriveRunStatus(evs, h, 200); s.State != StateRunning {
		t.Fatalf("state=%s, want running (pending under a live lease is normal)", s.State)
	}
}

func TestConcludedReceiptClearsPending(t *testing.T) {
	evs := []RunEvent{started(100), lease(100, 300),
		ev("operation.receipt", 110, map[string]any{"applyRunId": h, "operationId": "op1", "status": "pending"}),
		ev("operation.receipt", 120, map[string]any{"applyRunId": h, "operationId": "op1", "status": "succeeded"})}
	s := DeriveRunStatus(evs, h, 500) // lease lapsed, but the receipt concluded
	if s.State != StateStalled {
		t.Fatalf("state=%s, want stalled (no pending left)", s.State)
	}
}

func TestDoneOnFinished(t *testing.T) {
	evs := []RunEvent{started(100), lease(100, 300), ev("apply.finished", 130, map[string]any{"applyRunId": h})}
	if s := DeriveRunStatus(evs, h, 500); s.State != StateDone { // done even though lease TTL lapsed
		t.Fatalf("state=%s, want done", s.State)
	}
}

func TestFailedCarriesExitCode(t *testing.T) {
	evs := []RunEvent{started(100), lease(100, 300),
		ev("apply.failed", 130, map[string]any{"applyRunId": h, "action": "a-create-db", "exitCode": 4})}
	s := DeriveRunStatus(evs, h, 140)
	if s.State != StateFailed || s.ExitCode != 4 {
		t.Fatalf("state=%s exit=%d, want failed+4", s.State, s.ExitCode)
	}
}

func TestStalledIsNeverFailed(t *testing.T) {
	// the four-valued discipline on run state: a lapsed writer is not a failure.
	evs := []RunEvent{started(100), lease(100, 300)}
	if s := DeriveRunStatus(evs, h, 9999); s.State == StateFailed {
		t.Fatal("a stalled run must never be reported as failed")
	}
}

func TestConvergePhaseReached(t *testing.T) {
	ch := "conv1"
	evs := []RunEvent{
		ev("converge.started", 100, map[string]any{"convergeRunId": ch}),
		ev("converge.phase.entered", 101, map[string]any{"convergeRunId": ch, "phase": "verify"}),
		ev("converge.phase.entered", 102, map[string]any{"convergeRunId": ch, "phase": "apply"}),
		ev("lease.acquired", 102, map[string]any{"convergeRunId": ch, "ttlSeconds": 300}),
	}
	s := DeriveRunStatus(evs, ch, 150)
	if s.Kind != "converge" || s.Phase != "apply" || s.State != StateRunning {
		t.Fatalf("converge status wrong: kind=%s phase=%s state=%s", s.Kind, s.Phase, s.State)
	}
}

func TestListRunsOrdersMostRecentFirst(t *testing.T) {
	evs := []RunEvent{
		// run A: started at 100, done
		ev("apply.started", 100, map[string]any{"applyRunId": "A"}),
		ev("apply.finished", 130, map[string]any{"applyRunId": "A"}),
		// run B (converge): started at 300, running under a live lease
		ev("converge.started", 300, map[string]any{"convergeRunId": "B"}),
		ev("lease.acquired", 300, map[string]any{"convergeRunId": "B", "ttlSeconds": 300}),
		// run C: started at 200, stalled (lease lapsed)
		ev("apply.started", 200, map[string]any{"applyRunId": "C"}),
		ev("lease.acquired", 200, map[string]any{"applyRunId": "C", "ttlSeconds": 100}),
	}
	runs := ListRuns(evs, 400, nil) // now=400: B lease live (300+300), C lapsed (200+100)
	if len(runs) != 3 {
		t.Fatalf("expected 3 runs, got %d", len(runs))
	}
	// most-recent-first by start clock: B(300) > C(200) > A(100)
	got := []string{runs[0].Handle, runs[1].Handle, runs[2].Handle}
	if got[0] != "B" || got[1] != "C" || got[2] != "A" {
		t.Fatalf("order = %v, want [B C A] (most-recent-first)", got)
	}
	if runs[0].Kind != "converge" || runs[0].State != StateRunning {
		t.Fatalf("B should be a running converge, got kind=%s state=%s", runs[0].Kind, runs[0].State)
	}
	if runs[1].State != StateStalled {
		t.Fatalf("C should be stalled, got %s", runs[1].State)
	}
	if runs[2].State != StateDone {
		t.Fatalf("A should be done, got %s", runs[2].State)
	}
}

func TestListRunsEmptyLedger(t *testing.T) {
	if runs := ListRuns(nil, 100, nil); len(runs) != 0 {
		t.Fatalf("empty ledger must list no runs, got %d", len(runs))
	}
}

func TestListRunsDeterministicTiebreak(t *testing.T) {
	// two runs at the SAME start clock -> the ledger is a total order, so the
	// first-seen (chain) index breaks the tie deterministically: zzz appears
	// first in the event stream, so it lists first.
	evs := []RunEvent{
		ev("apply.started", 100, map[string]any{"applyRunId": "zzz"}),
		ev("apply.started", 100, map[string]any{"applyRunId": "aaa"}),
	}
	runs := ListRuns(evs, 100, nil)
	if runs[0].Handle != "zzz" || runs[1].Handle != "aaa" {
		t.Fatalf("equal-clock tiebreak must follow chain order (first-seen): %v",
			[]string{runs[0].Handle, runs[1].Handle})
	}
}

func TestListRunsRegistryOnlyIsUnknownAndTagged(t *testing.T) {
	// one ledger run (admitted) + one registry handle with NO events (launched,
	// never admitted). The registry-only run must be unknown, tagged, and sort last.
	evs := []RunEvent{
		ev("apply.started", 100, map[string]any{"applyRunId": "admitted"}),
		ev("apply.finished", 130, map[string]any{"applyRunId": "admitted"}),
	}
	runs := ListRuns(evs, 200, []string{"ghost", "admitted"})
	if len(runs) != 2 {
		t.Fatalf("expected 2 runs (1 ledger + 1 registry-only), got %d", len(runs))
	}
	// ledger run first, registry-only last
	if runs[0].Handle != "admitted" || runs[0].Source != "ledger" {
		t.Fatalf("first must be the ledger run, got %+v", runs[0])
	}
	if runs[1].Handle != "ghost" || runs[1].Source != "registry-only" || runs[1].State != StateUnknown {
		t.Fatalf("registry-only run must be unknown+tagged, got %+v", runs[1])
	}
	// a registry handle that DOES have events is not double-listed
	runs2 := ListRuns(evs, 200, []string{"admitted"})
	if len(runs2) != 1 {
		t.Fatalf("a registry handle with ledger events must not be duplicated, got %d", len(runs2))
	}
}
