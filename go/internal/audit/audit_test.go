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
		"2026-07-15T12:05:00Z", false, nil)
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
		"2026-07-15T12:00:00Z", false, nil) // eval BEFORE the observation
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
		"2026-07-15T12:05:00Z", false, nil)
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
	res, err = Run(c, led, filepath.Join(td, "l.jsonl"), "2026-07-15T12:05:00Z", false, nil)
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
	res, err := Run(c, led, filepath.Join(td, "l.jsonl"), "2026-07-15T13:05:00Z", false, nil)
	if err != nil {
		t.Fatal(err)
	}
	if res.Verdicts[0].Verdict != "satisfied" {
		t.Fatalf("the retained probe measurement must satisfy the probe-method "+
			"constraint despite a newer provider-api observe, got %+v", res.Verdicts[0])
	}
}

// D722, from the field, on a live account with a hard EU-residency requirement:
//
//	{"path":"egress.restricted","value":true,"derivation":"config-intent"}
//
// The contract's HARD constraint `egress.restricted == true` read SATISFIED. Measured
// independently, both security groups in that network allowed `-1` to `0.0.0.0/0` —
// default-allow, the exact opposite of the vocabulary's "default-deny egress
// allow-list". The reporter's sentence: "Narzędzie ma znacznik `derivation` i go nie
// używa przy ocenie ograniczeń."
//
// `config-intent` means the resource STORES the value and does not itself enforce it.
// It is a rung below a provider-api MEASUREMENT, and the evidence ladder ranked it the
// same, because it keyed on `source` alone.
func TestConfigIntentCannotSatisfyAProviderAPIConstraint(t *testing.T) {
	td := t.TempDir()
	cpath := filepath.Join(td, "c.yaml")
	if err := os.WriteFile(cpath, []byte(`
apiVersion: contract/v0.1
kind: InfrastructureContract
meta: { id: net, environment: test, version: 1 }
capabilities:
  - id: vpc
    type: capability.network.private
constraints:
  hard:
    - id: c-egress
      subject: vpc
      path: egress.restricted
      op: equals
      value: true
      verify: { method: provider-api }
`), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := contract.LoadContract(cpath)
	if err != nil {
		t.Fatal(err)
	}
	led := ledger.New()
	seedObs(led, "vpc", map[string]ledger.ObsRecord{
		"egress.restricted": {Value: true, ObservedAt: "2026-08-03T12:00:00Z",
			TTLSeconds: 86400, Derivation: "config-intent", Source: "provider-api"},
	})
	res, err := Run(c, led, filepath.Join(td, "l.jsonl"), "2026-08-03T12:05:00Z", false, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Verdicts) != 1 {
		t.Fatalf("expected one verdict, got %+v", res.Verdicts)
	}
	if got := res.Verdicts[0].Verdict; got != "unknown" {
		t.Fatalf("a hard constraint asking for provider-api evidence was ruled %q on a "+
			"config-intent reading — the marker exists and the judgement ignores it; "+
			"the estate that produced this had default-allow egress", got)
	}
}

// The other side, so the rule is not a blanket downgrade: an author who declares
// `verify: {method: static}` has accepted the document's own word, and a config-intent
// reading is exactly that. It must still satisfy.
func TestConfigIntentStillSatisfiesAStaticConstraint(t *testing.T) {
	td := t.TempDir()
	cpath := filepath.Join(td, "c.yaml")
	if err := os.WriteFile(cpath, []byte(`
apiVersion: contract/v0.1
kind: InfrastructureContract
meta: { id: net, environment: test, version: 1 }
capabilities:
  - id: vpc
    type: capability.network.private
constraints:
  hard:
    - id: c-egress
      subject: vpc
      path: egress.restricted
      op: equals
      value: true
      verify: { method: static }
`), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := contract.LoadContract(cpath)
	if err != nil {
		t.Fatal(err)
	}
	led := ledger.New()
	seedObs(led, "vpc", map[string]ledger.ObsRecord{
		"egress.restricted": {Value: true, ObservedAt: "2026-08-03T12:00:00Z",
			TTLSeconds: 86400, Derivation: "config-intent", Source: "provider-api"},
	})
	res, err := Run(c, led, filepath.Join(td, "l.jsonl"), "2026-08-03T12:05:00Z", false, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := res.Verdicts[0].Verdict; got != "satisfied" {
		t.Fatalf("a static-method constraint accepts the configuration's own word; got %q", got)
	}
}

// D728: the whole point of the two bars is that they are consulted by different
// commands. This is the audit half — the same constraint that passes `verify` on the
// candidate's declaration must be judged against its RUNTIME bar here, so a
// config-intent reading does not satisfy it.
func TestAuditJudgesAgainstTheRuntimeBarNotTheDesignBar(t *testing.T) {
	td := t.TempDir()
	cpath := filepath.Join(td, "c.yaml")
	if err := os.WriteFile(cpath, []byte(`
apiVersion: contract/v0.1
kind: InfrastructureContract
meta: { id: net, environment: test, version: 1 }
capabilities:
  - id: vpc
    type: capability.network.private
constraints:
  hard:
    - id: c-egress
      subject: vpc
      path: egress.restricted
      op: equals
      value: true
      verify: { design: static, runtime: provider-api }
`), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := contract.LoadContract(cpath)
	if err != nil {
		t.Fatal(err)
	}
	if c.Constraints[0].VerifyMethod != "static" ||
		c.Constraints[0].RuntimeMethod != "provider-api" {
		t.Fatalf("the two bars did not survive loading: design=%q runtime=%q",
			c.Constraints[0].VerifyMethod, c.Constraints[0].RuntimeMethod)
	}
	led := ledger.New()
	seedObs(led, "vpc", map[string]ledger.ObsRecord{
		"egress.restricted": {Value: true, ObservedAt: "2026-08-03T12:00:00Z",
			TTLSeconds: 86400, Derivation: "config-intent", Source: "provider-api"},
	})
	res, err := Run(c, led, filepath.Join(td, "l.jsonl"), "2026-08-03T12:05:00Z", false, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := res.Verdicts[0].Verdict; got != "unknown" {
		t.Fatalf("audit ruled %q — it judged against the DESIGN bar (static, which any "+
			"declaration meets) instead of the runtime bar the contract wrote for it", got)
	}
}

// D759. A third derivation, because the set had two values and reality has three.
// Measured across the drivers: 65 of 72 `config-intent` observations were BARE CONSTANTS
// — `encryption.atRest: true` on a service that always encrypts — and the published
// definition of that label is "a value the resource STORES but does not itself enforce".
// The resource stores nothing of the kind. The values are true; the provenance was not.
//
// It earns the SAME bar as config-intent, and that is the load-bearing half. A provider
// guarantee is tempting to rank high — it cannot be otherwise — and three entries in one
// day were an author asserting a guarantee that was not one (D752, D753, D754). Nothing
// about THIS resource was read, so the static bar is what it earns. The new value buys
// honest provenance, never more trust.
func TestPlatformInvariantIsHonestProvenanceNotMoreTrust(t *testing.T) {
	contractFor := func(t *testing.T, method string) *contract.Contract {
		t.Helper()
		cpath := filepath.Join(t.TempDir(), "c.yaml")
		if err := os.WriteFile(cpath, []byte(`
apiVersion: contract/v0.1
kind: InfrastructureContract
meta: { id: net, environment: test, version: 1 }
capabilities:
  - id: vpc
    type: capability.network.private
constraints:
  hard:
    - id: c-egress
      subject: vpc
      path: egress.restricted
      op: equals
      value: true
      verify: { method: `+method+` }
`), 0o600); err != nil {
			t.Fatal(err)
		}
		c, err := contract.LoadContract(cpath)
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	verdictFor := func(t *testing.T, method, derivation string) string {
		t.Helper()
		led := ledger.New()
		seedObs(led, "vpc", map[string]ledger.ObsRecord{
			"egress.restricted": {Value: true, ObservedAt: "2026-08-03T12:00:00Z",
				TTLSeconds: 86400, Derivation: derivation, Source: "provider-api"},
		})
		res, err := Run(contractFor(t, method), led, filepath.Join(t.TempDir(), "l.jsonl"),
			"2026-08-03T12:05:00Z", false, nil)
		if err != nil {
			t.Fatal(err)
		}
		if len(res.Verdicts) != 1 {
			t.Fatalf("expected one verdict, got %+v", res.Verdicts)
		}
		return res.Verdicts[0].Verdict
	}

	if got := verdictFor(t, "provider-api", "platform-invariant"); got != "unknown" {
		t.Errorf("a hard constraint asking for a provider-api READING was ruled %q on a "+
			"platform guarantee — nothing was read about this resource, and an author who "+
			"asserted a guarantee wrongly is exactly how D752/D753/D754 happened", got)
	}
	if got := verdictFor(t, "static", "platform-invariant"); got != "satisfied" {
		t.Errorf("a static-bar constraint was ruled %q on a platform guarantee — the "+
			"author accepted a claim, and this is one", got)
	}
	// The control: the new value must not be the old one under another name, nor
	// silently rejected as an unknown basis.
	if got := verdictFor(t, "static", "measured"); got != "satisfied" {
		t.Errorf("measured at the static bar = %q, want satisfied", got)
	}
	if got := verdictFor(t, "provider-api", "measured"); got != "satisfied" {
		t.Errorf("measured at the provider-api bar = %q, want satisfied — the fix must "+
			"not demote real readings", got)
	}
}
