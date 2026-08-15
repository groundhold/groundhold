package horizon

import (
	"os"
	"path/filepath"
	"testing"

	"groundhold/internal/contract"
	"groundhold/internal/ledger"
	"groundhold/internal/runstatus"
)

func loadContract(t *testing.T, body string) *contract.Contract {
	t.Helper()
	p := filepath.Join(t.TempDir(), "c.yaml")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := contract.LoadContract(p)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func seedObs(led *ledger.Ledger, cap string, byPath map[string]ledger.ObsRecord) {
	led.ObservationsBySource[cap] = map[string]map[string]ledger.ObsRecord{}
	for path, rec := range byPath {
		led.ObservationsBySource[cap][path] = map[string]ledger.ObsRecord{rec.Source: rec}
	}
}

// TestHorizonProjectsDecayAndLapse pins the thesis: given a hard constraint whose
// proof expires at obs+ttl and a live run whose lease lapses (with a pending receipt),
// horizon projects EXACTLY two blocking transitions at the right instants, and the
// windowed run gates (exit 2). Both come from re-running audit@T / status@T, never
// re-derived arithmetic.
func TestHorizonProjectsDecayAndLapse(t *testing.T) {
	c := loadContract(t, `
apiVersion: contract/v0.1
kind: InfrastructureContract
meta: { id: h, environment: test, version: 1 }
capabilities:
  - id: db
    type: capability.database.relational
constraints:
  hard:
    - id: c-region
      subject: db
      path: location.region
      op: equals
      value: europe-central2
      verify: { method: static }
`)
	t0str := "2026-07-15T12:00:00Z"
	t0, err := ledger.ParseTs(t0str)
	if err != nil {
		t.Fatal(err)
	}

	led := ledger.New()
	seedObs(led, "db", map[string]ledger.ObsRecord{
		"location.region": {Value: "europe-central2", ObservedAt: t0str,
			TTLSeconds: 3600, Derivation: "measured", Source: "provider-api"},
	})

	// a live run (lease ttl 300) with a pending receipt -> lapse is needs-reconcile.
	evs := []runstatus.RunEvent{
		{Type: "apply.started", Clock: t0, Caps: []string{"db"},
			Body: map[string]any{"applyRunId": "run-1"}},
		{Type: "lease.acquired", Clock: t0, Caps: []string{"db"},
			Body: map[string]any{"applyRunId": "run-1", "ttlSeconds": 300}},
		{Type: "operation.receipt", Clock: t0 + 10, Caps: []string{"db"},
			Body: map[string]any{"applyRunId": "run-1", "operationId": "op1", "status": "pending"}},
	}

	doc, err := Project(led, evs, []*contract.Contract{c}, nil, t0, 86400, true)
	if err != nil {
		t.Fatal(err)
	}

	if len(doc.Transitions) != 2 {
		t.Fatalf("want exactly 2 transitions, got %d: %+v", len(doc.Transitions), doc.Transitions)
	}
	byKind := map[string]Transition{}
	for _, tr := range doc.Transitions {
		byKind[tr.Kind] = tr
	}

	lapse, ok := byKind["lease-lapse"]
	if !ok {
		t.Fatalf("no lease-lapse transition: %+v", doc.Transitions)
	}
	if lapse.At != ledger.FormatTs(t0+300) || lapse.To != "needs-reconcile" || !lapse.blocking {
		t.Fatalf("lease lapse wrong: at=%s to=%s blocking=%v (want %s needs-reconcile true)",
			lapse.At, lapse.To, lapse.blocking, ledger.FormatTs(t0+300))
	}

	dec, ok := byKind["constraint-decay"]
	if !ok {
		t.Fatalf("no constraint-decay transition: %+v", doc.Transitions)
	}
	if dec.At != ledger.FormatTs(t0+3601) || dec.FreshThrough != ledger.FormatTs(t0+3600) ||
		dec.From != "satisfied" || dec.To != "unknown" || !dec.blocking {
		t.Fatalf("constraint decay wrong: %+v (want at=%s freshThrough=%s satisfied->unknown blocking)",
			dec, ledger.FormatTs(t0+3601), ledger.FormatTs(t0+3600))
	}

	if doc.Summary.HardBlocking != 2 {
		t.Fatalf("HardBlocking = %d, want 2", doc.Summary.HardBlocking)
	}
	if doc.ExitCode() != 2 {
		t.Fatalf("windowed run with hard blocking must exit 2, got %d", doc.ExitCode())
	}
	if doc.Code != "horizon-action-required" {
		t.Fatalf("code = %q, want horizon-action-required", doc.Code)
	}
	if doc.Summary.FirstHardDeadline != ledger.FormatTs(t0+300) {
		t.Fatalf("firstHardDeadline = %s, want the lease lapse %s", doc.Summary.FirstHardDeadline, ledger.FormatTs(t0+300))
	}
}

// TestHorizonClearWindowIsNotVacuous: a window with nothing decaying exits 0, but must
// have EXAMINED a non-empty subject (D328) — a gate that examined nothing is vacuous.
func TestHorizonClearWindowIsNotVacuous(t *testing.T) {
	c := loadContract(t, `
apiVersion: contract/v0.1
kind: InfrastructureContract
meta: { id: h2, environment: test, version: 1 }
capabilities:
  - id: db
    type: capability.database.relational
constraints:
  hard:
    - id: c-region
      subject: db
      path: location.region
      op: equals
      value: europe-central2
      verify: { method: static }
`)
	t0str := "2026-07-15T12:00:00Z"
	t0, _ := ledger.ParseTs(t0str)
	led := ledger.New()
	seedObs(led, "db", map[string]ledger.ObsRecord{
		"location.region": {Value: "europe-central2", ObservedAt: t0str,
			TTLSeconds: 3600, Derivation: "measured", Source: "provider-api"},
	})
	// window of 60s: the proof (ttl 3600) does not decay inside it.
	doc, err := Project(led, nil, []*contract.Contract{c}, nil, t0, 60, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(doc.Transitions) != 0 {
		t.Fatalf("clear window must have no transitions, got %+v", doc.Transitions)
	}
	if doc.ExitCode() != 0 {
		t.Fatalf("clear window exits 0, got %d", doc.ExitCode())
	}
	if doc.Examined.Constraints == 0 {
		t.Fatal("a clear window must still assert it EXAMINED a non-empty subject (D328), got 0 constraints")
	}
}

// TestHorizonGatesOnAPresentBlock pins the false-secure fix: a hard constraint whose
// proof EXPIRED before the evaluation instant is already blocking at atClock. horizon's
// window opens on it, so a --within gate must exit 2 (not go green over a block apply
// already refuses) with an already-blocking entry stamped at atClock and the deadline now.
func TestHorizonGatesOnAPresentBlock(t *testing.T) {
	c := loadContract(t, `
apiVersion: contract/v0.1
kind: InfrastructureContract
meta: { id: h3, environment: test, version: 1 }
capabilities:
  - id: db
    type: capability.database.relational
constraints:
  hard:
    - id: c-region
      subject: db
      path: location.region
      op: equals
      value: europe-central2
      verify: { method: static }
`)
	obsStr := "2026-07-15T12:00:00Z"
	led := ledger.New()
	seedObs(led, "db", map[string]ledger.ObsRecord{
		"location.region": {Value: "europe-central2", ObservedAt: obsStr,
			TTLSeconds: 3600, Derivation: "measured", Source: "provider-api"},
	})
	// evaluate a day later: the proof (ttl 3600) expired long ago, so the constraint is
	// already unknown at atClock — no CHANGE decays it, it predates the window.
	evalStr := "2026-07-16T12:00:00Z"
	eval, _ := ledger.ParseTs(evalStr)
	doc, err := Project(led, nil, []*contract.Contract{c}, nil, eval, 3600, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(doc.Transitions) != 1 || doc.Transitions[0].Kind != "already-blocking" {
		t.Fatalf("want one already-blocking entry, got %+v", doc.Transitions)
	}
	if doc.Transitions[0].At != evalStr || doc.Transitions[0].FreshThrough != "" {
		t.Fatalf("present block must be stamped at atClock with no freshThrough: %+v", doc.Transitions[0])
	}
	if doc.Summary.HardBlocking != 1 || doc.Summary.FirstHardDeadline != evalStr {
		t.Fatalf("present block must gate with deadline now: hardBlocking=%d first=%s",
			doc.Summary.HardBlocking, doc.Summary.FirstHardDeadline)
	}
	if doc.ExitCode() != 2 {
		t.Fatalf("a --within gate must exit 2 over a present hard block, got %d", doc.ExitCode())
	}
	// and the reporter (no window) reports it but does not gate.
	rep, _ := Project(led, nil, []*contract.Contract{c}, nil, eval, 0, false)
	if rep.Summary.HardBlocking != 1 || rep.ExitCode() != 0 || rep.Code != "" {
		t.Fatalf("reporter must report the present block (hardBlocking 1) yet exit 0 with no code: "+
			"hardBlocking=%d exit=%d code=%q", rep.Summary.HardBlocking, rep.ExitCode(), rep.Code)
	}
}
