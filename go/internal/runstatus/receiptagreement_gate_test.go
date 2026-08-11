package runstatus

import (
	"testing"

	"groundhold/internal/ledger"
)

// D641. `operation.receipt` is folded in TWO places — the ledger's own projection
// (`PendingCount`, what `resume` acts on) and this package's run-state derivation
// (what `status`, `runs` and `wait` report). They disagreed about `unknown`.
//
// The gate is a cross-check, not a second copy of the answer: for every status in
// the ledger's closed set, fold one receipt through BOTH and require the same
// verdict about whether the intent is still unsettled. Two folds of one event that
// nobody compares is the "published set copied instead of shared" class, and the
// copy nobody looks at is always the one that drifts.
func TestBothFoldsAgreeOnWhichReceiptsStayPending(t *testing.T) {
	statuses := ledger.ReceiptStatuses()
	if len(statuses) < 4 {
		t.Fatalf("the receipt-status set collapsed to %d — this gate is measuring "+
			"nothing (D328)", len(statuses))
	}
	for _, st := range statuses {
		evs := []RunEvent{
			started(100),
			lease(100, 300),
			ev("operation.receipt", 150, map[string]any{
				"applyRunId": h, "operationId": "op-1", "status": st}),
		}
		rs := DeriveRunStatus(evs, h, 500) // lease lapsed: pending decides the state
		runSaysPending := len(rs.Pending) > 0
		ledgerSaysPending := ledger.ReceiptLeavesIntentPending(st)

		if runSaysPending != ledgerSaysPending {
			t.Errorf("status %q: the ledger says pending=%v and run-status says "+
				"pending=%v.\nThe ledger is what `resume` reads, so the two verbs "+
				"describe the same run differently: `resume` blocks on an unsettled "+
				"receipt while `status` reports %q with the remediation %q.",
				st, ledgerSaysPending, runSaysPending, rs.State, rs.Remediation)
		}
	}
}

// The consequence, stated as its own case so a regression names the harm rather
// than a set-membership mismatch. An `unknown` receipt means the mutation MAY have
// landed — a resource may exist and be billed. Reporting that as "the writer's
// lease lapsed with no outcome" is a false sentence about the most dangerous state
// the system has.
func TestAnUnknownReceiptNeedsReconcileRatherThanStalled(t *testing.T) {
	evs := []RunEvent{
		started(100), lease(100, 300),
		ev("operation.receipt", 140, map[string]any{
			"applyRunId": h, "operationId": "op-1", "status": "pending"}),
		// The terminal unknown receipt: apply wrote it because the provider's answer
		// was lost. apply.go's own comment says "`unknown` must KEEP its pending
		// intent (only a succeeded receipt clears it)".
		ev("operation.receipt", 160, map[string]any{
			"applyRunId": h, "operationId": "op-1", "status": "unknown",
			"targetProviderId": "sql:eu-central-1:widgets"}),
	}
	s := DeriveRunStatus(evs, h, 500)
	if s.State != StateNeedsReconcile {
		t.Errorf("state=%s want needs-reconcile — a run whose last word was "+
			"\"I do not know whether I created it\" was reported as %q, remediation "+
			"%q", s.State, s.State, s.Remediation)
	}
	if len(s.Pending) != 1 || s.Pending[0] != "op-1" {
		t.Errorf("pendingReceipts=%v — the unsettled operation is not named, so "+
			"neither a human nor a dashboard can find the resource that may exist",
			s.Pending)
	}
}

// The control: `retryable` provably did NOT land (D241), so it must still conclude
// the intent. The cheap way to pass the case above is to keep everything pending.
func TestARetryableReceiptStillConcludesTheIntent(t *testing.T) {
	evs := []RunEvent{
		started(100), lease(100, 300),
		ev("operation.receipt", 140, map[string]any{
			"applyRunId": h, "operationId": "op-1", "status": "pending"}),
		ev("operation.receipt", 160, map[string]any{
			"applyRunId": h, "operationId": "op-1", "status": "retryable"}),
	}
	if s := DeriveRunStatus(evs, h, 500); s.State != StateStalled || len(s.Pending) != 0 {
		t.Errorf("state=%s pending=%v — a throttled mutation that did not land must "+
			"not hold the run in needs-reconcile forever", s.State, s.Pending)
	}
}

// D656. Two terminal events under one handle: the LAST one is the run's outcome.
// Preferring `finished` reported a success that a later refusal had superseded —
// with the refusal's own exit code sitting in the same record, which is how the
// contradiction was visible at all.
func TestTheLastTerminalEventDecides(t *testing.T) {
	evs := []RunEvent{
		ev("converge.started", 100, map[string]any{"convergeRunId": h}),
		ev("converge.finished", 150, map[string]any{"convergeRunId": h, "exitCode": 0}),
		ev("converge.failed", 200, map[string]any{"convergeRunId": h, "exitCode": 2}),
	}
	s := DeriveRunStatus(evs, h, 500)
	if s.State != StateFailed {
		t.Errorf("state=%s exitCode=%d — the run was refused after it was reported "+
			"done, and a CI gate reading this gets a green light", s.State, s.ExitCode)
	}
	// And the other order, so this is a rule about recency rather than about
	// preferring bad news.
	evs2 := []RunEvent{
		ev("converge.started", 100, map[string]any{"convergeRunId": h}),
		ev("converge.failed", 150, map[string]any{"convergeRunId": h, "exitCode": 2}),
		ev("converge.finished", 200, map[string]any{"convergeRunId": h, "exitCode": 0}),
	}
	if s2 := DeriveRunStatus(evs2, h, 500); s2.State != StateDone {
		t.Errorf("state=%s — a retry that succeeded after a failure reads as failed",
			s2.State)
	}
}
