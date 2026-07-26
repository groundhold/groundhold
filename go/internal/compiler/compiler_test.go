package compiler

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"groundhold/internal/contract"
	"groundhold/internal/ledger"
	"groundhold/internal/provider"
	"groundhold/internal/verify"
)

// classifyDouble is a driver whose ClassifyChange returns a per-driver note,
// so a plan reveals WHICH driver classified each capability.
type classifyDouble struct {
	*provider.Fake
	note string
}

func (d classifyDouble) ClassifyChange(service, path string, current, desired any,
	implementation map[string]any) (string, string) {
	return "mutable", d.note
}

// unsupportedDouble classifies every change as unsupported (an unwired classifier,
// e.g. Acme's F15 acm) — used to prove D249 isolation of a not-classifiable cap.
type unsupportedDouble struct{ *provider.Fake }

func (unsupportedDouble) ClassifyChange(service, path string, current, desired any,
	implementation map[string]any) (string, string) {
	return "unsupported", "change-classification is not wired for this service"
}

const mixContract = `apiVersion: contract/v0.1
kind: InfrastructureContract
meta: { id: mix, environment: test, version: 1 }
capabilities:
  - id: capa
    type: capability.database.relational
  - id: capb
    type: capability.database.relational
constraints:
  hard:
    - id: c-a
      subject: capa
      path: location.region
      op: equals
      value: europe-west1
      verify: { method: static }
    - id: c-b
      subject: capb
      path: location.region
      op: equals
      value: europe-west1
      verify: { method: static }
`

const mixCandidate = `apiVersion: candidate/v0.1
kind: ImplementationCandidate
contract: mix
capabilities:
  capa:
    provider: pa
    service: sa
    attributes:
      location.region: europe-west1
  capb:
    provider: pb
    service: sb
    attributes:
      location.region: europe-west1
`

// TestClassifyChangeDispatchesPerCapabilityProvider pins D186: a mixed-provider
// candidate must classify each bound capability with ITS OWN driver. Before the
// fix a single driver was picked by map-iteration order and used for the whole
// candidate — nondeterministic, and the wrong driver for at least one cap. Here
// two drifted capabilities bound to different providers must each carry the note
// of their own driver; a single shared driver would stamp both with one note.
func TestClassifyChangeDispatchesPerCapabilityProvider(t *testing.T) {
	td := t.TempDir()
	cp := filepath.Join(td, "c.yaml")
	kp := filepath.Join(td, "k.yaml")
	if err := os.WriteFile(cp, []byte(mixContract), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(kp, []byte(mixCandidate), 0o600); err != nil {
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

	at := "2026-07-12T10:00:00Z"
	clock, err := ledger.ParseTs(at)
	if err != nil {
		t.Fatal(err)
	}
	// both capabilities are bound and DRIFTED (observed != desired), so both
	// reach classifyBound -> ClassifyChange
	obs := map[string]map[string]ledger.ObsRecord{
		"capa": {"location.region": {Value: "us-central1",
			ObservedAt: at, TTLSeconds: 86400, Derivation: "measured"}},
		"capb": {"location.region": {Value: "us-east1",
			ObservedAt: at, TTLSeconds: 86400, Derivation: "measured"}},
	}
	in := Inputs{
		Bindings:     map[string]string{"capa": "pa:db-a", "capb": "pb:db-b"},
		Observations: obs,
		Generations:  map[string]int{"capa": 1, "capb": 1},
		EvalClock:    clock,
		Providers: map[string]provider.Provider{
			"pa": classifyDouble{&provider.Fake{}, "from-pa"},
			"pb": classifyDouble{&provider.Fake{}, "from-pb"},
		},
	}
	doc, err := Compile(c, cand, nil, report, "proj", in)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}

	notes := map[string]string{}
	for _, a := range doc.Plan.Actions {
		if a.Operation == "update" && len(a.Changes) == 1 {
			notes[a.Capability] = a.Changes[0].Caveat
		}
	}
	if notes["capa"] != "from-pa" {
		t.Errorf("capa must be classified by its own (pa) driver, got note %q", notes["capa"])
	}
	if notes["capb"] != "from-pb" {
		t.Errorf("capb must be classified by its own (pb) driver, got note %q", notes["capb"])
	}
	// the decisive check: a single shared driver would stamp both caps with
	// ONE note — per-capability dispatch gives them different ones
	if notes["capa"] == notes["capb"] {
		t.Fatalf("both caps carry the same note %q — dispatch is not per-capability", notes["capa"])
	}
}

// TestCompileRefusesFutureDatedObservation pins D188 Finding 1 on the seal
// path: a future-dated observation (observedAt after the eval clock) has
// negative age, which slips past the `> TTL` staleness test and would seal the
// plan against a reading that did not exist at the evaluated instant. Compile
// must refuse. Fails before the fix (seals a plan against the future reading).
func TestCompileRefusesFutureDatedObservation(t *testing.T) {
	td := t.TempDir()
	cp := filepath.Join(td, "c.yaml")
	kp := filepath.Join(td, "k.yaml")
	if err := os.WriteFile(cp, []byte(mixContract), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(kp, []byte(mixCandidate), 0o600); err != nil {
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
	evalClock, err := ledger.ParseTs("2026-07-12T10:00:00Z")
	if err != nil {
		t.Fatal(err)
	}
	// capa bound + an observation dated AFTER the eval clock (drift value so
	// it would reach ClassifyChange — but the future-age guard fires first)
	obs := map[string]map[string]ledger.ObsRecord{
		"capa": {"location.region": {Value: "us-central1",
			ObservedAt: "2026-07-12T18:00:00Z", TTLSeconds: 86400, Derivation: "measured"}},
	}
	in := Inputs{
		Bindings:     map[string]string{"capa": "pa:db-a"},
		Observations: obs,
		Generations:  map[string]int{"capa": 1},
		EvalClock:    evalClock,
		Providers: map[string]provider.Provider{
			"pa": classifyDouble{&provider.Fake{}, "from-pa"},
		},
	}
	// D188/D249: a future-dated observation is re-observe-fixable (a fresh observe
	// gives a current timestamp), so it stays a hard refusal — NOT isolated — and
	// Compile still refuses rather than sealing against the future reading.
	_, err = Compile(c, cand, nil, report, "proj", in)
	if err == nil || !strings.Contains(err.Error(), "dated after the evaluation time") {
		t.Fatalf("Compile must refuse a future-dated observation, got err=%v", err)
	}
}

// TestCompileIsolatesUnreconcilableCapability pins D249 (Acme F16/F17): a bound
// capability with NO observation must NOT freeze the whole plan. capa is
// un-reobservable (blocked); capb has drifted and reconciles fine. Before the fix,
// "capa.location.region: no observation" aborted Compile and capb never planned.
func TestCompileIsolatesUnreconcilableCapability(t *testing.T) {
	td := t.TempDir()
	cp := filepath.Join(td, "c.yaml")
	kp := filepath.Join(td, "k.yaml")
	if err := os.WriteFile(cp, []byte(mixContract), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(kp, []byte(mixCandidate), 0o600); err != nil {
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
	at := "2026-07-12T10:00:00Z"
	clock, _ := ledger.ParseTs(at)
	// Both bound + drifted (fresh observations). capa's provider cannot classify
	// the change (an unwired classifier, F15) -> capa is BLOCKED. capb's provider
	// classifies fine -> capb reconciles. The isolation: capa's block must NOT
	// abort capb's plan.
	obs := map[string]map[string]ledger.ObsRecord{
		"capa": {"location.region": {Value: "us-central1",
			ObservedAt: at, TTLSeconds: 86400, Derivation: "measured"}},
		"capb": {"location.region": {Value: "us-east1",
			ObservedAt: at, TTLSeconds: 86400, Derivation: "measured"}},
	}
	in := Inputs{
		Bindings:     map[string]string{"capa": "pa:db-a", "capb": "pb:db-b"},
		Observations: obs,
		Generations:  map[string]int{"capa": 1, "capb": 1},
		EvalClock:    clock,
		Providers: map[string]provider.Provider{
			"pa": unsupportedDouble{&provider.Fake{}},
			"pb": classifyDouble{&provider.Fake{}, "from-pb"},
		},
	}
	doc, err := Compile(c, cand, nil, report, "proj", in)
	if err != nil {
		t.Fatalf("one un-reconcilable capability must not abort the compile: %v", err)
	}
	// capb still plans (the isolation win).
	var sawB bool
	for _, a := range doc.Plan.Actions {
		if a.Capability == "capb" {
			sawB = true
		}
		if a.Capability == "capa" {
			t.Fatal("a blocked capability must have NO action")
		}
	}
	if !sawB {
		t.Fatal("capb (reconcilable) must still get its action despite capa being blocked")
	}
	// capa is blocked, honestly recorded, and never in writes.
	if len(doc.Plan.Blocked) != 1 || doc.Plan.Blocked[0].Capability != "capa" ||
		!strings.Contains(doc.Plan.Blocked[0].Reason, "not wired") {
		t.Fatalf("capa must be blocked with its unwired-classifier reason, got %+v", doc.Plan.Blocked)
	}
	for _, w := range doc.Plan.Writes {
		if w == "capa" {
			t.Fatal("a blocked capability must never be in writes")
		}
	}
}

const hardBasisContract = `apiVersion: contract/v0.1
kind: InfrastructureContract
meta: { id: hb, environment: test, version: 1 }
autonomy:
  no_assumed_hard_basis: true
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

const hardBasisCandidate = `apiVersion: candidate/v0.1
kind: ImplementationCandidate
contract: hb
capabilities:
  db:
    provider: fake
    service: mock
    attributes:
      location.region: europe-west1
`

// TestCompileEmitsNoAssumedHardBasisWhenArmed pins D195: a contract that arms
// autonomy.no_assumed_hard_basis makes the compiler emit the matching sealed-plan
// precondition; a contract that does not stays at report-executable only. The
// verifier never gates (D5 preserved) — this is where the opt-in enters the plan.
func TestCompileEmitsNoAssumedHardBasisWhenArmed(t *testing.T) {
	td := t.TempDir()
	cp := filepath.Join(td, "c.yaml")
	kp := filepath.Join(td, "k.yaml")
	if err := os.WriteFile(cp, []byte(hardBasisContract), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(kp, []byte(hardBasisCandidate), 0o600); err != nil {
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
	doc, err := Compile(c, cand, nil, report, "proj", Inputs{})
	if err != nil {
		t.Fatal(err)
	}
	has := false
	for _, p := range doc.Plan.Preconditions {
		if p.Type == "no-assumed-hard-basis" {
			has = true
		}
	}
	if !has {
		t.Fatalf("armed contract must emit no-assumed-hard-basis, got %+v",
			doc.Plan.Preconditions)
	}
}
