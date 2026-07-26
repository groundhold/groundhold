package adopt

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"groundhold/internal/contract"
	"groundhold/internal/ledger"
	"groundhold/internal/provider"
	"groundhold/internal/verify"
)

// serviceRequiringFake refuses an empty service exactly as a real cloud
// driver does (aws_provider.go: "unknown service"). It is the regression
// guard: adopt used to hand the recording observe the pre-write ledger,
// whose BoundServices() lacked the just-written binding, so a real driver
// saw an empty service and refused with the binding already on disk.
type serviceRequiringFake struct{ *provider.Fake }

func (s serviceRequiringFake) Observe(service, capability, providerID string) ([]provider.Observation, []string, error) {
	if service == "" {
		return nil, nil, fmt.Errorf("driver: unknown service %q — refusing (no default)", service)
	}
	return s.Fake.Observe(service, capability, providerID)
}

// competingFake reports a foreign continuous reconciler owning the object, so
// the adopt gate must refuse before it ever binds.
type competingFake struct {
	*provider.Fake
	managers []string
}

func (c competingFake) CompetingManagers(service, providerID string) ([]string, error) {
	return c.managers, nil
}

func adoptFixture(t *testing.T) (*contract.Contract, *contract.Candidate, *ledger.Ledger, string) {
	t.Helper()
	dir := t.TempDir()
	write := func(name, body string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	cPath := write("c.yaml", `apiVersion: contract/v0.1
kind: InfrastructureContract
meta: { id: t, owner: o@e.test, environment: dev, version: 1 }
capabilities:
  - id: store
    type: capability.storage.object
constraints:
  hard:
    - id: c-managed
      subject: store
      path: service.managed
      op: equals
      value: true
      verify: { method: static }
`)
	candPath := write("cand.yaml", `apiVersion: candidate/v0.1
kind: ImplementationCandidate
contract: t
capabilities:
  store:
    provider: fake
    service: sql
    attributes:
      service.managed: true
`)
	c, err := contract.LoadContract(cPath)
	if err != nil {
		t.Fatal(err)
	}
	cand, err := contract.LoadCandidate(candPath, c, nil)
	if err != nil {
		t.Fatal(err)
	}
	ledgerPath := filepath.Join(dir, "ledger.ndjson")
	w := &ledger.Writer{Path: ledgerPath, Led: ledger.New(), Env: "dev", Clock: 1752600000, Actor: "o@e.test"}
	if err := w.Append("contract.published", []string{"store"},
		map[string]any{"contract": "t", "version": 1}, 0); err != nil {
		t.Fatal(err)
	}
	led, err := ledger.ReplayFile(ledgerPath)
	if err != nil {
		t.Fatal(err)
	}
	return c, cand, led, ledgerPath
}

func TestAdoptRefusesCompetingReconciler(t *testing.T) {
	c, cand, led, ledgerPath := adoptFixture(t)
	report, _ := verify.Verify(c, cand, nil)
	prov := competingFake{Fake: &provider.Fake{}, managers: []string{"argocd"}}
	res, code := Run(c, cand, report, map[string]string{"store": "fake:my-bucket"},
		prov, led, ledgerPath, "2026-07-17T11:00:00Z", "")
	if code == 0 {
		t.Fatalf("adopt must refuse an object a competing reconciler owns, got %+v", res)
	}
	if res.Code != "binding-conflict" {
		t.Fatalf("want binding-conflict, got code %q reasons %v", res.Code, res.Reasons)
	}
	joined := fmt.Sprint(res.Reasons)
	if !strings.Contains(joined, "argocd") || !strings.Contains(joined, "competing reconciler") {
		t.Fatalf("refusal must name the competing manager, got %v", res.Reasons)
	}
}

func TestAdoptRecordsObservationWithBoundService(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	cPath := write("c.yaml", `apiVersion: contract/v0.1
kind: InfrastructureContract
meta: { id: t, owner: o@e.test, environment: dev, version: 1 }
capabilities:
  - id: store
    type: capability.storage.object
constraints:
  hard:
    - id: c-managed
      subject: store
      path: service.managed
      op: equals
      value: true
      verify: { method: static }
`)
	candPath := write("cand.yaml", `apiVersion: candidate/v0.1
kind: ImplementationCandidate
contract: t
capabilities:
  store:
    provider: fake
    service: sql
    attributes:
      service.managed: true
`)

	c, err := contract.LoadContract(cPath)
	if err != nil {
		t.Fatal(err)
	}
	cand, err := contract.LoadCandidate(candPath, c, nil)
	if err != nil {
		t.Fatal(err)
	}

	ledgerPath := filepath.Join(dir, "ledger.ndjson")
	w := &ledger.Writer{Path: ledgerPath, Led: ledger.New(), Env: "dev", Clock: 1752600000, Actor: "o@e.test"}
	if err := w.Append("contract.published", []string{"store"},
		map[string]any{"contract": "t", "version": 1}, 0); err != nil {
		t.Fatal(err)
	}
	led, err := ledger.ReplayFile(ledgerPath)
	if err != nil {
		t.Fatal(err)
	}

	report, _ := verify.Verify(c, cand, nil)
	prov := serviceRequiringFake{&provider.Fake{}}
	res, code := Run(c, cand, report, map[string]string{"store": "fake:my-bucket"},
		prov, led, ledgerPath, "2026-07-17T11:00:00Z", "")
	if code != 0 {
		t.Fatalf("adopt must observe with the bound service (regression: stale ledger → empty service), got code %d: %+v", code, res)
	}

	// the recording observe must have appended the observation it decided on
	saw := false
	for _, e := range res.Events {
		if e == "observation.recorded" {
			saw = true
		}
	}
	if !saw {
		t.Fatalf("adopt must record the observation, got events %v", res.Events)
	}
}

// buildBound writes a ledger with db bound to fake:A — adopted (origin set) or
// groundhold-created (no origin), optionally with a pending operation receipt.
func buildBound(t *testing.T, adopted, pending bool) (*ledger.Ledger, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "l.jsonl")
	w := &ledger.Writer{Path: path, Led: ledger.New(), Env: "dev",
		Clock: 1752600000, Actor: "t"}
	tok, err := w.AppendLease([]string{"db"}, map[string]any{"ttlSeconds": 300})
	if err != nil {
		t.Fatal(err)
	}
	res := map[string]any{"id": "primary", "type": "t",
		"providerId": "fake:A", "generation": 1}
	if adopted {
		res["origin"] = "adopted"
	}
	if err := w.Append("binding.updated", []string{"db"},
		map[string]any{"resources": []any{res}}, tok); err != nil {
		t.Fatal(err)
	}
	if pending {
		if err := w.Append("operation.receipt", []string{"db"}, map[string]any{
			"operationId": "op-1", "status": "pending",
			"idempotencyKey": "k1"}, tok); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Append("lease.released", []string{"db"}, nil, tok); err != nil {
		t.Fatal(err)
	}
	led, err := ledger.ReplayFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return led, path
}

// TestUnadoptRefusesCreatedBinding pins D192 F2: unadopt reverses an ADOPTION;
// it must refuse a capability groundhold CREATED (no origin:adopted), else the
// ledger would forget a live, groundhold-owned resource (a later discover then
// sees it as a shadow).
func TestUnadoptRefusesCreatedBinding(t *testing.T) {
	led, path := buildBound(t, false, false)
	res, code := Unadopt("db", led, path, "dev", "2026-07-17T12:00:00Z")
	if code == 0 {
		t.Fatalf("unadopt must refuse a groundhold-created binding, got %+v", res)
	}
	if !strings.Contains(fmt.Sprint(res.Reasons), "NOT adopted") {
		t.Fatalf("refusal must name it as not-adopted, got %v", res.Reasons)
	}
}

// TestUnadoptRefusesPendingOps pins D192 F5: unadopt mirrors adopt's D29 gate —
// releasing a binding with an operation still in flight orphans its receipt.
func TestUnadoptRefusesPendingOps(t *testing.T) {
	led, path := buildBound(t, true, true)
	res, code := Unadopt("db", led, path, "dev", "2026-07-17T12:00:00Z")
	if code == 0 {
		t.Fatalf("unadopt must refuse with in-flight ops, got %+v", res)
	}
	if !strings.Contains(fmt.Sprint(res.Reasons), "reconciled first") {
		t.Fatalf("refusal must ask to reconcile, got %v", res.Reasons)
	}
}
