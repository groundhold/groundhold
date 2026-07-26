package audit

import (
	"os"
	"path/filepath"
	"testing"

	"groundhold/internal/contract"
	"groundhold/internal/ledger"
)

// seedObs populates the per-source projection audit reads (D191), keyed by
// each record's Source — mirroring what projectObservations builds on replay.
func seedObs(led *ledger.Ledger, capID string, byPath map[string]ledger.ObsRecord) {
	led.ObservationsBySource[capID] = map[string]map[string]ledger.ObsRecord{}
	for path, rec := range byPath {
		led.ObservationsBySource[capID][path] = map[string]ledger.ObsRecord{rec.Source: rec}
	}
}

// Non-negotiable #1: unknown OR UNVERIFIABLE on a hard constraint
// blocks — with no bypass. audit's machine surface (exit code + status)
// is what monitoring routes on, so a hard unverifiable must make audit
// report violations-found / exit 2, matching the BLOCKED banner. The
// reviewer's scenario: a hard cost constraint in USD, reality recorded
// in EUR -> currency mismatch -> unverifiable -> must NOT be status
// clean / exit 0 (found by the pre-GA review; previously escaped).
func TestAuditHardUnverifiableBlocks(t *testing.T) {
	td := t.TempDir()
	cpath := filepath.Join(td, "c.yaml")
	if err := os.WriteFile(cpath, []byte(`
apiVersion: contract/v0.1
kind: InfrastructureContract
meta: { id: money, environment: test, version: 1 }
capabilities:
  - id: db
    type: capability.database.relational
constraints:
  hard:
    - id: c-cost
      subject: db
      path: cost.monthly
      op: lte
      value: "100 USD"
      verify: { method: static }
`), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := contract.LoadContract(cpath)
	if err != nil {
		t.Fatal(err)
	}
	// reality recorded in a DIFFERENT currency — incomparable, not false
	led := ledger.New()
	seedObs(led, "db", map[string]ledger.ObsRecord{
		"cost.monthly": {Value: "90 EUR", ObservedAt: "2026-07-15T12:00:00Z",
			TTLSeconds: 86400, Derivation: "measured", Source: "provider-api"},
	})
	res, err := Run(c, led, filepath.Join(td, "l.jsonl"),
		"2026-07-15T12:05:00Z", false)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Verdicts) != 1 || res.Verdicts[0].Verdict != "unverifiable" {
		t.Fatalf("currency mismatch must be unverifiable, got %+v", res.Verdicts)
	}
	// Violations>0 is what main maps to exit 2 — the machine surface
	// (exit + status) now matches the BLOCKED banner
	if res.Status != "violations-found" || res.Violations != 1 {
		t.Fatalf("a hard unverifiable MUST block the machine surface, "+
			"got status=%q violations=%d", res.Status, res.Violations)
	}
}

// TestAuditFutureDatedObservationIsUnverifiable pins D188 Finding 1: an
// observation whose observedAt is AFTER the evaluation --at has negative age,
// which slips past the `age > TTL` staleness test and would read as fresh — a
// fail-open reachable by time-travel evaluation (--at earlier than a recorded
// observation). A future observation that would SATISFY a hard constraint must
// instead be unverifiable and BLOCK. Fails before the fix (satisfied / clean).
func TestAuditFutureDatedObservationIsUnverifiable(t *testing.T) {
	td := t.TempDir()
	cpath := filepath.Join(td, "c.yaml")
	if err := os.WriteFile(cpath, []byte(`
apiVersion: contract/v0.1
kind: InfrastructureContract
meta: { id: money, environment: test, version: 1 }
capabilities:
  - id: db
    type: capability.database.relational
constraints:
  hard:
    - id: c-cost
      subject: db
      path: cost.monthly
      op: lte
      value: "100 USD"
      verify: { method: static }
`), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := contract.LoadContract(cpath)
	if err != nil {
		t.Fatal(err)
	}
	led := ledger.New()
	// the observation SATISFIES the constraint (90 <= 100 USD) but is dated
	// SIX HOURS AFTER the evaluation --at — it did not exist at the evaluated
	// instant, so it is invalid evidence, not fresh proof
	seedObs(led, "db", map[string]ledger.ObsRecord{
		"cost.monthly": {Value: "90 USD", ObservedAt: "2026-07-15T18:00:00Z",
			TTLSeconds: 86400, Derivation: "measured", Source: "provider-api"},
	})
	res, err := Run(c, led, filepath.Join(td, "l.jsonl"),
		"2026-07-15T12:00:00Z", false) // eval BEFORE the observation
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Verdicts) != 1 || res.Verdicts[0].Verdict != "unverifiable" {
		t.Fatalf("a future-dated observation must be unverifiable, not fresh, got %+v",
			res.Verdicts)
	}
	if res.Status != "violations-found" || res.Violations != 1 {
		t.Fatalf("a hard unverifiable MUST block, got status=%q violations=%d",
			res.Status, res.Violations)
	}
}

// TestAuditEnforcesVerifyMethodEvidence pins D190: a hard constraint declaring
// verify.method=probe (an OUTCOME the author says must be measured) must NOT be
// satisfied by a provider-api config read, even one whose value matches. The
// author's evidence bar is honored at the runtime gate — insufficient source is
// unknown (probe first), which blocks. Fails before the fix (satisfied on the
// weaker provider-api evidence — the false PASS the method field was meant to
// prevent).
func TestAuditEnforcesVerifyMethodEvidence(t *testing.T) {
	td := t.TempDir()
	cpath := filepath.Join(td, "c.yaml")
	if err := os.WriteFile(cpath, []byte(`
apiVersion: contract/v0.1
kind: InfrastructureContract
meta: { id: ev, environment: test, version: 1 }
capabilities:
  - id: db
    type: capability.database.relational
constraints:
  hard:
    - id: c-rto
      subject: db
      path: recovery.rto
      op: lte
      value: 1h
      verify: { method: probe }
`), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := contract.LoadContract(cpath)
	if err != nil {
		t.Fatal(err)
	}
	led := ledger.New()
	// the value SATISFIES (35m <= 1h) and is fresh, but its SOURCE is a
	// provider-api read (config-intent / observe), not a probe — insufficient
	// evidence for an outcome the contract says must be measured
	seedObs(led, "db", map[string]ledger.ObsRecord{
		"recovery.rto": {Value: "35m", ObservedAt: "2026-07-15T12:00:00Z",
			TTLSeconds: 86400, Derivation: "config-intent", Source: "provider-api"},
	})
	res, err := Run(c, led, filepath.Join(td, "l.jsonl"),
		"2026-07-15T12:05:00Z", false)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Verdicts) != 1 || res.Verdicts[0].Verdict != "unknown" {
		t.Fatalf("a probe-method constraint with only provider-api evidence must "+
			"be unknown, got %+v", res.Verdicts)
	}
	if res.Status != "violations-found" || res.Violations != 1 {
		t.Fatalf("insufficient evidence on a hard constraint MUST block, "+
			"got status=%q violations=%d", res.Status, res.Violations)
	}

	// and a probe-sourced observation of the same value DOES satisfy it
	seedObs(led, "db", map[string]ledger.ObsRecord{
		"recovery.rto": {Value: "35m", ObservedAt: "2026-07-15T12:00:00Z",
			TTLSeconds: 86400, Derivation: "measured", Source: "probe"}})
	res, err = Run(c, led, filepath.Join(td, "l.jsonl"), "2026-07-15T12:05:00Z", false)
	if err != nil {
		t.Fatal(err)
	}
	if res.Verdicts[0].Verdict != "satisfied" {
		t.Fatalf("a probe-sourced measurement must satisfy the probe-method "+
			"constraint, got %+v", res.Verdicts[0])
	}
}

// TestAuditRetainsProbeEvidenceOverNewerObserve pins D191: a probe measurement
// must survive a later provider-api observe of the SAME path. The single-slot
// projection is newest-time-wins, so the newer (insufficient, here also
// violating) observe would erase the probe and flip the probe-method verdict to
// unknown/violated; per-source retention keeps the probe, which still satisfies.
func TestAuditRetainsProbeEvidenceOverNewerObserve(t *testing.T) {
	td := t.TempDir()
	cpath := filepath.Join(td, "c.yaml")
	if err := os.WriteFile(cpath, []byte(`
apiVersion: contract/v0.1
kind: InfrastructureContract
meta: { id: ret, environment: test, version: 1 }
capabilities:
  - id: db
    type: capability.database.relational
constraints:
  hard:
    - id: c-rto
      subject: db
      path: recovery.rto
      op: lte
      value: 1h
      verify: { method: probe }
`), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := contract.LoadContract(cpath)
	if err != nil {
		t.Fatal(err)
	}
	led := ledger.New()
	// a probe measured 35m at 12:00; a LATER provider-api observe read 2h (a
	// config value that would VIOLATE) at 13:00. Per-source retention keeps
	// both; audit judges the probe-method constraint on the probe record.
	led.ObservationsBySource["db"] = map[string]map[string]ledger.ObsRecord{
		"recovery.rto": {
			"probe": {Value: "35m", ObservedAt: "2026-07-15T12:00:00Z",
				TTLSeconds: 86400, Derivation: "measured", Source: "probe"},
			"provider-api": {Value: "2h", ObservedAt: "2026-07-15T13:00:00Z",
				TTLSeconds: 86400, Derivation: "config-intent", Source: "provider-api"},
		},
	}
	res, err := Run(c, led, filepath.Join(td, "l.jsonl"), "2026-07-15T13:05:00Z", false)
	if err != nil {
		t.Fatal(err)
	}
	if res.Verdicts[0].Verdict != "satisfied" {
		t.Fatalf("the retained probe measurement must satisfy the probe-method "+
			"constraint despite a newer provider-api observe, got %+v", res.Verdicts[0])
	}
}
