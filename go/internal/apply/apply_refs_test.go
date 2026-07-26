package apply

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"

	"groundhold/internal/compiler"
	"groundhold/internal/contract"
	"groundhold/internal/ledger"
	"groundhold/internal/perr"
	"groundhold/internal/provider"
	"groundhold/internal/verify"
)

// D275 (the apply slice of D226/F13): a consumer's operand arrives from the
// producer's receipted outputs of the SAME run — resolved before the write-
// ahead intent, validated on the resolved values, refused fail-closed when the
// contract between driver and executor breaks.

const refContract = `apiVersion: contract/v0.1
kind: InfrastructureContract
meta: { id: reft, environment: test, version: 1 }
capabilities:
  - id: network
    type: capability.network.private
  - id: db
    type: capability.database.relational
constraints:
  hard:
    - id: c-net-managed
      subject: network
      path: service.managed
      op: equals
      value: true
      verify: { method: static }
    - id: c-db-managed
      subject: db
      path: service.managed
      op: equals
      value: true
      verify: { method: static }
`

const refCandidate = `apiVersion: candidate/v0.1
kind: ImplementationCandidate
contract: reft
capabilities:
  network:
    attributes:
      service.managed: true
  db:
    attributes:
      service.managed: true
    implementation:
      subnetIds:
        $ref: { capability: network, output: privateSubnetIds }
`

// refSpy wraps provider.Fake, records the chronological driver-call log and
// the operand map each Create received, and can corrupt a create's outputs to
// exercise the fail-closed paths.
type refSpy struct {
	*provider.Fake
	log        []string
	createImpl map[string]map[string]any
	// mangleOutputs, when set for a capability, replaces the fake's outputs.
	// A nil map entry means "drop all outputs".
	mangleOutputs map[string]map[string]any
	refuseCaps    map[string]bool // Validate refuses these capabilities
}

func newRefSpy() *refSpy {
	return &refSpy{Fake: &provider.Fake{},
		createImpl: map[string]map[string]any{}}
}

func (s *refSpy) Validate(service, capability, environment string,
	attrs, impl map[string]any, generation int) error {
	s.log = append(s.log, "validate:"+capability)
	if s.refuseCaps[capability] {
		return fmt.Errorf("injected refusal for %s", capability)
	}
	return s.Fake.Validate(service, capability, environment, attrs, impl, generation)
}

func (s *refSpy) Create(service, capability, environment string,
	attrs, impl map[string]any, key string, generation int) provider.CreateResult {
	s.log = append(s.log, "create:"+capability)
	cp := map[string]any{}
	for k, v := range impl {
		cp[k] = v
	}
	s.createImpl[capability] = cp
	res := s.Fake.Create(service, capability, environment, attrs, impl, key, generation)
	if m, ok := s.mangleOutputs[capability]; ok {
		res.Outputs = m
	}
	return res
}

func setupRefPlan(t *testing.T) (*contract.Contract, *contract.Candidate, map[string]any) {
	t.Helper()
	td := t.TempDir()
	cp := td + "/c.yaml"
	kp := td + "/k.yaml"
	if err := os.WriteFile(cp, []byte(refContract), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(kp, []byte(refCandidate), 0o600); err != nil {
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

// ledgerEvents decodes the raw ndjson ledger into (type, body) pairs.
func ledgerEvents(t *testing.T, path string) []map[string]any {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var out []map[string]any
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		var doc map[string]any
		if err := json.Unmarshal(sc.Bytes(), &doc); err != nil {
			t.Fatal(err)
		}
		ev, _ := doc["event"].(map[string]any)
		out = append(out, ev)
	}
	return out
}

func receiptsFor(evs []map[string]any, capID string) []map[string]any {
	var out []map[string]any
	for _, ev := range evs {
		if ev["type"] != "operation.receipt" {
			continue
		}
		caps, _ := ev["capabilities"].([]any)
		for _, c := range caps {
			if c == capID {
				out = append(out, ev)
			}
		}
	}
	return out
}

func TestApplyResolvesIntraPlanReference(t *testing.T) {
	c, cand, plan := setupRefPlan(t)
	spy := newRefSpy()
	lp := freshLedger(t)
	res := Apply(c, cand, nil, plan, lp, spy, pfAt, false)
	if res.Status != "applied" {
		t.Fatalf("apply status = %s (%v)", res.Status, res.Reasons)
	}

	// The consumer's driver call got the PRODUCER's receipted list, not the
	// candidate's $ref map.
	got, ok := spy.createImpl["db"]["subnetIds"].([]any)
	if !ok || len(got) != 2 {
		t.Fatalf("db create impl subnetIds = %#v, want the fake's 2-subnet list",
			spy.createImpl["db"]["subnetIds"])
	}
	for _, v := range got {
		s, _ := v.(string)
		if !strings.HasPrefix(s, "subnet-") {
			t.Fatalf("resolved subnet id %#v does not look like a fake subnet", v)
		}
	}

	// Order: the ref-consumer's Validate is DEFERRED — it runs after the
	// producer's create, on resolved operands, never up front (D275).
	want := []string{"validate:network", "create:network", "validate:db", "create:db"}
	if strings.Join(spy.log, ",") != strings.Join(want, ",") {
		t.Fatalf("driver call order = %v, want %v", spy.log, want)
	}

	// The producer's terminal receipt carries the filtered declared outputs —
	// and the value the consumer used is byte-equal to the receipted one.
	evs := ledgerEvents(t, lp)
	netReceipts := receiptsFor(evs, "network")
	var outs map[string]any
	for _, ev := range netReceipts {
		body, _ := ev["body"].(map[string]any)
		if body["status"] == "succeeded" {
			outs, _ = body["outputs"].(map[string]any)
		}
	}
	if outs == nil {
		t.Fatalf("no succeeded network receipt with outputs; receipts: %v", netReceipts)
	}
	recList, _ := outs["privateSubnetIds"].([]any)
	if fmt.Sprint(recList) != fmt.Sprint(got) {
		t.Fatalf("receipted outputs %v != resolved operand %v", recList, got)
	}
	for _, name := range []string{"id", "selfLink", "endpoint", "privateSubnetIds"} {
		if _, ok := outs[name]; !ok {
			t.Fatalf("declared output %q missing from receipt: %v", name, outs)
		}
	}
}

func TestApplyMissingDeclaredOutputConcludesUnknown(t *testing.T) {
	c, cand, plan := setupRefPlan(t)
	spy := newRefSpy()
	// The fake declares privateSubnetIds; the driver result omits it.
	spy.mangleOutputs = map[string]map[string]any{"network": {
		"id": "fake:x", "selfLink": "fake://x", "endpoint": "x.fake.internal"}}
	lp := freshLedger(t)
	res := Apply(c, cand, nil, plan, lp, spy, pfAt, false)
	if res.Status != "unknown" || res.Code != perr.ReconcileRequired {
		t.Fatalf("status/code = %s/%s, want unknown/%s (%v)",
			res.Status, res.Code, perr.ReconcileRequired, res.Reasons)
	}
	for _, call := range spy.log {
		if call == "create:db" {
			t.Fatal("consumer create ran although the producer's outputs were unusable")
		}
	}
	evs := ledgerEvents(t, lp)
	var sawUnknown bool
	for _, ev := range receiptsFor(evs, "network") {
		body, _ := ev["body"].(map[string]any)
		if body["status"] == "unknown" {
			sawUnknown = true
			reason, _ := body["reason"].(string)
			if !strings.Contains(reason, "declared outputs are unusable") {
				t.Fatalf("unknown receipt reason %q does not name the output break", reason)
			}
			if _, has := body["outputs"]; has {
				t.Fatal("an unusable output set must not be receipted")
			}
		}
	}
	if !sawUnknown {
		t.Fatal("no unknown network receipt found")
	}
}

func TestApplyWrongKindedOutputConcludesUnknown(t *testing.T) {
	c, cand, plan := setupRefPlan(t)
	spy := newRefSpy()
	spy.mangleOutputs = map[string]map[string]any{"network": {
		"id": "fake:x", "selfLink": "fake://x", "endpoint": "x.fake.internal",
		"privateSubnetIds": "not-a-list"}}
	lp := freshLedger(t)
	res := Apply(c, cand, nil, plan, lp, spy, pfAt, false)
	if res.Status != "unknown" || res.Code != perr.ReconcileRequired {
		t.Fatalf("status/code = %s/%s, want unknown/%s (%v)",
			res.Status, res.Code, perr.ReconcileRequired, res.Reasons)
	}
	for _, call := range spy.log {
		if call == "create:db" {
			t.Fatal("consumer create ran on a wrong-kinded producer output")
		}
	}
}

func TestApplyDeferredValidateRefusesBeforeIntent(t *testing.T) {
	c, cand, plan := setupRefPlan(t)
	spy := newRefSpy()
	spy.refuseCaps = map[string]bool{"db": true}
	lp := freshLedger(t)
	res := Apply(c, cand, nil, plan, lp, spy, pfAt, false)
	if res.Status != "failed" || res.Code != perr.ProviderRefused {
		t.Fatalf("status/code = %s/%s, want failed/%s (%v)",
			res.Status, res.Code, perr.ProviderRefused, res.Reasons)
	}
	if len(res.Reasons) == 0 ||
		!strings.Contains(res.Reasons[0], "validated on resolved references") {
		t.Fatalf("refusal reason %v does not name the deferred validate", res.Reasons)
	}
	// The producer's work is durable; the consumer never wrote an intent and
	// never reached the driver.
	for _, call := range spy.log {
		if call == "create:db" {
			t.Fatal("consumer create ran despite the deferred-validate refusal")
		}
	}
	evs := ledgerEvents(t, lp)
	if n := len(receiptsFor(evs, "db")); n != 0 {
		t.Fatalf("db has %d receipts, want 0 — no intent may be written on a "+
			"pre-intent refusal", n)
	}
	if n := len(receiptsFor(evs, "network")); n != 2 {
		t.Fatalf("network has %d receipts, want pending+terminal", n)
	}
	var sawFailed bool
	for _, ev := range evs {
		if ev["type"] == "apply.failed" {
			sawFailed = true
		}
	}
	if !sawFailed {
		t.Fatal("apply.failed missing — the run record must close cleanly")
	}
}

func TestPreflightReportsReferenceWiredSlots(t *testing.T) {
	td := t.TempDir()
	cp := td + "/c.yaml"
	kp := td + "/k.yaml"
	if err := os.WriteFile(cp, []byte(refContract), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(kp, []byte(refCandidate), 0o600); err != nil {
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
	report := Preflight(c, cand, nil, newRefSpy())
	if !report.Ready {
		t.Fatalf("preflight not ready: %+v", report.Capabilities)
	}
	var db *PreflightCap
	for i := range report.Capabilities {
		if report.Capabilities[i].Capability == "db" {
			db = &report.Capabilities[i]
		}
	}
	if db == nil || len(db.References) != 1 ||
		db.References[0] != "subnetIds <- network.privateSubnetIds" {
		t.Fatalf("db preflight references = %+v, want the wired slot named", db)
	}
}

// shapeSpy is a driver that validates operand SHAPE (an ARN prefix), the way
// real drivers do — the behaviour that exposed the D289 preflight bug.
type shapeSpy struct{ *provider.Fake }

func (s *shapeSpy) OutputsFor(service string) []provider.OutputSpec {
	return []provider.OutputSpec{{Name: "roleArn", Kind: "string",
		Sample: "arn:aws:iam::000000000000:role/groundhold-preflight"}}
}

func (s *shapeSpy) Validate(service, capability, environment string,
	attrs, impl map[string]any, generation int) error {
	if capability != "db" {
		return nil // only the CONSUMER carries the shape-checked operand
	}
	arn, _ := impl["iamRoleArn"].(string)
	if !strings.HasPrefix(arn, "arn:aws:iam::") {
		return fmt.Errorf("requires implementation.iamRoleArn (an arn:aws:iam::<acct>:role/<name>)")
	}
	return nil
}

// TestPreflightStandInSatisfiesShapeValidation (D289): a slot wired by $ref is
// judged with the PRODUCER driver's format-plausible sample, so a consumer that
// validates operand shape does not report a wired slot as a missing operand.
// Before this, preflight answered "not ready" for a candidate that applies
// cleanly — a false negative on the surface whose whole job is to tell an
// operator, in ONE round trip, what is actually missing.
func TestPreflightStandInSatisfiesShapeValidation(t *testing.T) {
	td := t.TempDir()
	cp, kp := td+"/c.yaml", td+"/k.yaml"
	if err := os.WriteFile(cp, []byte(refContract), 0o600); err != nil {
		t.Fatal(err)
	}
	// db consumes an ARN-shaped operand from network's roleArn output
	cand := strings.Replace(refCandidate,
		`      subnetIds:
        $ref: { capability: network, output: privateSubnetIds }`,
		`      iamRoleArn:
        $ref: { capability: network, output: roleArn }`, 1)
	if err := os.WriteFile(kp, []byte(cand), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := contract.LoadContract(cp)
	if err != nil {
		t.Fatal(err)
	}
	k, err := contract.LoadCandidate(kp, c, nil)
	if err != nil {
		t.Fatal(err)
	}
	report := Preflight(c, k, nil, &shapeSpy{Fake: &provider.Fake{}})
	if !report.Ready {
		for _, cp := range report.Capabilities {
			if !cp.OK {
				t.Fatalf("a wired ARN slot must not report as missing: %s — %s",
					cp.Capability, cp.Refusal)
			}
		}
	}
}
