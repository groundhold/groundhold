package apply

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"groundhold/internal/compiler"
	"groundhold/internal/contract"
	"groundhold/internal/ledger"
	"groundhold/internal/perr"
	"groundhold/internal/provider"
	"groundhold/internal/verify"
)

// D75 permission preflight — the live half is Go-only (Python has no
// executor), pinned here. The deterministic derivation is pinned by
// conformance (plan-emits-required-permissions-for-gcp-create).

const pfContract = `apiVersion: contract/v0.1
kind: InfrastructureContract
meta: { id: pfa, environment: test, version: 1 }
capabilities:
  - id: db
    type: capability.database.relational
constraints:
  hard:
    - id: c-region
      subject: db
      path: location.region
      op: equals
      value: europe-west1
      verify: { method: static }
`

const pfCandidate = `apiVersion: candidate/v0.1
kind: ImplementationCandidate
contract: pfa
capabilities:
  db:
    provider: fake
    service: mock
    attributes:
      location.region: europe-west1
`

const pfAt = "2026-07-12T10:00:00Z"

// noPreflight wraps a Provider but embeds only the INTERFACE, so
// CheckPermissions is not promoted — the type does not implement Preflighter.
type noPreflight struct{ provider.Provider }

func setupPlan(t *testing.T) (*contract.Contract, *contract.Candidate, map[string]any) {
	t.Helper()
	td := t.TempDir()
	cp := filepath.Join(td, "c.yaml")
	kp := filepath.Join(td, "k.yaml")
	if err := os.WriteFile(cp, []byte(pfContract), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(kp, []byte(pfCandidate), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := contract.LoadContract(cp)
	if err != nil {
		t.Fatal(err)
	}
	cand, err := contract.LoadCandidate(kp, c, nil)
	if err != nil {
		t.Fatal(err)
	}
	report, _ := verify.Verify(c, cand, nil)
	if !report.Executable {
		t.Fatalf("not executable: %v", report.BlockingReasons)
	}
	doc, err := compiler.Compile(c, cand, nil, report, "proj-x", compiler.Inputs{
		Heads:        map[string]string{},
		Bindings:     map[string]string{},
		Observations: map[string]map[string]ledger.ObsRecord{},
		// Providers empty: the fake cap resolves to the Fake fallback (D186)
	})
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(doc)
	var planDoc map[string]any
	if err := json.Unmarshal(raw, &planDoc); err != nil {
		t.Fatal(err)
	}
	return c, cand, planDoc
}

func freshLedger(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "l.jsonl")
	if err := os.WriteFile(p, []byte{}, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestPreflightPasses(t *testing.T) {
	c, cand, plan := setupPlan(t)
	res := Apply(c, cand, nil, plan, freshLedger(t), &provider.Fake{}, pfAt, false)
	if res.Status != "applied" {
		t.Fatalf("status=%s code=%s reasons=%v", res.Status, res.Code, res.Reasons)
	}
	if res.Preflight == nil || res.Preflight.Status != "passed" {
		t.Fatalf("preflight=%+v", res.Preflight)
	}
}

func TestPreflightMissingRefuses(t *testing.T) {
	c, cand, plan := setupPlan(t)
	fake := &provider.Fake{MissingPermissions: map[string]bool{"fake.resources.get": true}}
	res := Apply(c, cand, nil, plan, freshLedger(t), fake, pfAt, false)
	if res.Code != perr.ProviderPermissionDenied || res.Exit != 2 {
		t.Fatalf("expected provider-permission-denied/2, got %s/%d", res.Code, res.Exit)
	}
	if len(res.Events) != 0 {
		t.Fatalf("a permission refusal must append nothing, got %v", res.Events)
	}
	// D230: the denied set is surfaced structurally so main can build a grant next.
	if len(res.Denied) == 0 || res.Denied[0] != "fake.resources.get" {
		t.Fatalf("res.Denied must carry the exact denied set, got %v", res.Denied)
	}
}

// D78: an UNATTESTED permission (the provider check could not vouch for it) is
// NOT a denial — the apply proceeds (the mutation is the authorization oracle),
// surfacing an inconclusive preflight rather than lying about missing access.
func TestPreflightUnattestedProceeds(t *testing.T) {
	c, cand, plan := setupPlan(t)
	fake := &provider.Fake{UnattestedPermissions: map[string]bool{"fake.resources.get": true}}
	res := Apply(c, cand, nil, plan, freshLedger(t), fake, pfAt, false)
	if res.Status != "applied" {
		t.Fatalf("unattested must proceed, got status=%s code=%s", res.Status, res.Code)
	}
	if res.Preflight == nil || res.Preflight.Status != "inconclusive" {
		t.Fatalf("expected inconclusive preflight, got %+v", res.Preflight)
	}
	if len(res.Preflight.Unattested) != 1 || res.Preflight.Unattested[0] != "fake.resources.get" {
		t.Fatalf("expected unattested=[fake.resources.get], got %+v", res.Preflight)
	}
}

// Under --require-preflight, an unattested permission blocks (the operator
// demanded certainty the provider cannot give) — but as inconclusive, never
// as an authoritative denial.
func TestRequirePreflightUnattestedRefuses(t *testing.T) {
	c, cand, plan := setupPlan(t)
	fake := &provider.Fake{UnattestedPermissions: map[string]bool{"fake.resources.get": true}}
	res := Apply(c, cand, nil, plan, freshLedger(t), fake, pfAt, true)
	if res.Code != perr.PreflightInconclusive || res.Exit != 2 {
		t.Fatalf("expected preflight-inconclusive/2, got %s/%d", res.Code, res.Exit)
	}
	if len(res.Events) != 0 {
		t.Fatalf("an inconclusive refusal must append nothing, got %v", res.Events)
	}
}

func TestPreflightCheckErrorRefuses(t *testing.T) {
	c, cand, plan := setupPlan(t)
	res := Apply(c, cand, nil, plan, freshLedger(t),
		&provider.Fake{PreflightErr: true}, pfAt, false)
	if res.Code != perr.PreflightInconclusive || res.Exit != 2 {
		t.Fatalf("expected preflight-inconclusive/2, got %s/%d", res.Code, res.Exit)
	}
}

func TestPreflightSkipsLoudlyWithoutCapability(t *testing.T) {
	c, cand, plan := setupPlan(t)
	prov := noPreflight{Provider: &provider.Fake{}}
	res := Apply(c, cand, nil, plan, freshLedger(t), prov, pfAt, false)
	if res.Status != "applied" {
		t.Fatalf("status=%s code=%s reasons=%v", res.Status, res.Code, res.Reasons)
	}
	if res.Preflight == nil || res.Preflight.Status != "skipped" {
		t.Fatalf("expected skipped, got %+v", res.Preflight)
	}
}

func TestRequirePreflightRefusesWithoutCapability(t *testing.T) {
	c, cand, plan := setupPlan(t)
	prov := noPreflight{Provider: &provider.Fake{}}
	res := Apply(c, cand, nil, plan, freshLedger(t), prov, pfAt, true)
	if res.Code != perr.PreflightInconclusive || res.Exit != 2 {
		t.Fatalf("expected preflight-inconclusive/2, got %s/%d", res.Code, res.Exit)
	}
}

// concurrentCommitter simulates a SECOND executor (D56): during THIS executor's
// permission preflight — the network round-trip window between the pre-lease
// staleness check and the lease — it acquires the lease, commits a
// binding.updated that MOVES db's decision head, and releases. This is exactly
// the interleaving the re-check-under-lease exists to catch.
type concurrentCommitter struct {
	*provider.Fake
	ledgerPath string
	fired      bool
	t          *testing.T
}

func (p *concurrentCommitter) CheckPermissions(project string, perms []string) ([]string, []string, error) {
	if !p.fired {
		p.fired = true
		clock, _ := ledger.ParseTs(pfAt)
		fresh, err := ledger.ReplayFile(p.ledgerPath)
		if err != nil {
			p.t.Fatalf("concurrent replay: %v", err)
		}
		var evs []string
		w := &ledger.Writer{Path: p.ledgerPath, Led: fresh, Env: "test",
			Clock: clock, Actor: "executor-b", Events: &evs}
		tok, err := w.AppendLease([]string{"db"}, map[string]any{"ttlSeconds": 300})
		if err != nil {
			p.t.Fatalf("concurrent lease: %v", err)
		}
		if err := w.Append("binding.updated", []string{"db"},
			map[string]any{"providerId": "fake:committed-by-B"}, tok); err != nil {
			p.t.Fatalf("concurrent binding.updated: %v", err)
		}
		if err := w.Append("lease.released", []string{"db"}, nil, tok); err != nil {
			p.t.Fatalf("concurrent release: %v", err)
		}
	}
	return p.Fake.CheckPermissions(project, perms)
}

// TestReCheckUnderLeaseSeesConcurrentDecisionMove is the lost-update guard.
// Executor B moves db's decision head DURING A's preflight window; A must
// re-check against the FRESH post-lease ledger and REFUSE the now-stale plan,
// never execute it against state B already changed (a double-create, or an
// update/delete aimed at an id B just rebound). Pins that the re-check reads the
// post-lease ledger, not the entry-time snapshot — a stale re-check is a no-op
// and the lease's whole reason for being (CAS-under-lease) evaporates.
func TestReCheckUnderLeaseSeesConcurrentDecisionMove(t *testing.T) {
	c, cand, plan := setupPlan(t)
	lp := freshLedger(t)
	prov := &concurrentCommitter{Fake: &provider.Fake{}, ledgerPath: lp, t: t}
	res := Apply(c, cand, nil, plan, lp, prov, pfAt, false)
	if res.Code != perr.StaleDecision {
		t.Fatalf("A must refuse the stale plan after B moved db's decision head, "+
			"got status=%s code=%s exit=%d", res.Status, res.Code, res.Exit)
	}
}

const hbArmedContract = `apiVersion: contract/v0.1
kind: InfrastructureContract
meta: { id: hba, environment: test, version: 1 }
autonomy: { no_assumed_hard_basis: %t }
capabilities:
  - id: db
    type: capability.database.relational
constraints:
  hard:
    - id: c-region
      subject: db
      path: location.region
      op: equals
      value: europe-west1
      verify: { method: static }
`

const hbAssumedCandidate = `apiVersion: candidate/v0.1
kind: ImplementationCandidate
contract: hba
capabilities:
  db:
    provider: fake
    service: mock
    attributes:
      location.region: { value: europe-west1, status: assumed }
`

func hbPlan(t *testing.T, armed bool) (*contract.Contract, *contract.Candidate, map[string]any) {
	t.Helper()
	td := t.TempDir()
	cp := filepath.Join(td, "c.yaml")
	kp := filepath.Join(td, "k.yaml")
	if err := os.WriteFile(cp, []byte(fmt.Sprintf(hbArmedContract, armed)), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(kp, []byte(hbAssumedCandidate), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := contract.LoadContract(cp)
	if err != nil {
		t.Fatal(err)
	}
	cand, err := contract.LoadCandidate(kp, c, nil)
	if err != nil {
		t.Fatal(err)
	}
	report, _ := verify.Verify(c, cand, nil)
	if !report.Executable {
		t.Fatalf("D5: an assumed value still satisfies + is executable; got %v", report.BlockingReasons)
	}
	doc, err := compiler.Compile(c, cand, nil, report, "proj", compiler.Inputs{})
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(doc)
	var plan map[string]any
	if err := json.Unmarshal(raw, &plan); err != nil {
		t.Fatal(err)
	}
	return c, cand, plan
}

// TestApplyRefusesAssumedHardBasisWhenArmed pins D195: an armed contract makes
// apply refuse a plan whose HARD constraint is satisfied only on an ASSUMED
// value (a guess), via the no-assumed-hard-basis precondition — while an
// UNARMED contract applies the identical assumed value (D5 default preserved:
// the verifier only reports the basis).
func TestApplyRefusesAssumedHardBasisWhenArmed(t *testing.T) {
	c, cand, plan := hbPlan(t, true)
	res := Apply(c, cand, nil, plan, freshLedger(t), &provider.Fake{}, pfAt, false)
	if res.Exit != 2 {
		t.Fatalf("armed contract must refuse an assumed hard basis, got status=%s exit=%d",
			res.Status, res.Exit)
	}
	if !strings.Contains(fmt.Sprint(res.Reasons), "no-assumed-hard-basis") {
		t.Fatalf("refusal must name the precondition, got %v", res.Reasons)
	}

	// D5 default: the SAME assumed value applies when the knob is not armed
	c2, cand2, plan2 := hbPlan(t, false)
	res2 := Apply(c2, cand2, nil, plan2, freshLedger(t), &provider.Fake{}, pfAt, false)
	if res2.Status != "applied" {
		t.Fatalf("unarmed contract must apply an assumed value (D5), got status=%s reasons=%v",
			res2.Status, res2.Reasons)
	}
}

// emptyRequiredSet makes `requiredUnion` come back EMPTY by pointing the plan's
// read-set at a provider `PermissionsFor` has no case for. That is a stand-in for the
// likelier production route — a SERVICE added to a driver without its `PermissionsFor`
// case, which falls through the same switch to `return nil` — and it is the trigger,
// not the defect: the defect is what the executor does when the set is empty.
//
// It edits the PLAN rather than the provider object on purpose. The first version of
// this test overrode the provider's `Name()` and proved nothing, because
// `requiredUnion` reads the name from `reads.provider` in the sealed plan and never
// asks the object. Both mutants below survived it. That is the empty-probe failure
// this record keeps warning about, caught here by mutating rather than by luck.
func emptyRequiredSet(t *testing.T, plan map[string]any) {
	t.Helper()
	body, _ := plan["plan"].(map[string]any)
	reads, _ := body["reads"].(map[string]any)
	if reads == nil {
		t.Fatal("the compiled plan has no reads block — this helper is editing nothing")
	}
	prov, _ := reads["provider"].(map[string]any)
	if prov == nil {
		prov = map[string]any{}
		reads["provider"] = prov
	}
	prov["name"] = "a-provider-with-no-declared-permissions"

	// The union has TWO sources (requiredUnion): the executor's own derivation from
	// `PermissionsFor`, and the list the compiler SEALED into each action (D75). A
	// service with no permission case yields nothing from either — the compiler asks
	// the same function — so a faithful fixture clears both. Clearing only the first
	// left the sealed list behind and the union non-empty, which is why the earlier
	// draft of this helper proved nothing.
	acts, _ := body["actions"].([]any)
	if len(acts) == 0 {
		t.Fatal("the compiled plan has no actions — this helper is editing nothing")
	}
	for _, it := range acts {
		a, _ := it.(map[string]any)
		delete(a, "requiredPermissions")
	}
}

// D1175. "Nothing was checked" must not read as "everything passed".
func TestAnEmptyRequiredSetSkipsLoudly(t *testing.T) {
	c, cand, plan := setupPlan(t)
	emptyRequiredSet(t, plan)
	res := Apply(c, cand, nil, plan, freshLedger(t), &provider.Fake{}, pfAt, false)
	if res.Status != "applied" {
		t.Fatalf("status=%s code=%s reasons=%v", res.Status, res.Code, res.Reasons)
	}
	if res.Preflight == nil {
		t.Fatal("the preflight left NO record at all. A run that verified nothing is " +
			"indistinguishable from one that verified everything, which is the whole " +
			"reason `skipped` is a published status beside `passed`.")
	}
	if res.Preflight.Status != "skipped" {
		t.Fatalf("expected skipped, got %+v", res.Preflight)
	}
}

// The flag's promise. `--require-preflight` means the operator demanded certainty; an
// empty required set gives none, so returning success is the gate-that-cannot-fail
// shape — ask what it would print with the permission map emptied, and the answer must
// not be what it prints now.
func TestRequirePreflightRefusesOnAnEmptyRequiredSet(t *testing.T) {
	c, cand, plan := setupPlan(t)
	emptyRequiredSet(t, plan)
	res := Apply(c, cand, nil, plan, freshLedger(t), &provider.Fake{}, pfAt, true)
	if res.Code != perr.PreflightInconclusive || res.Exit != 2 {
		t.Fatalf("expected preflight-inconclusive/2, got %s/%d (%v)",
			res.Code, res.Exit, res.Reasons)
	}
}
