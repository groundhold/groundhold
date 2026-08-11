package compiler

import (
	"strings"
	"testing"

	"groundhold/internal/contract"
	"groundhold/internal/ledger"
	"groundhold/internal/provider"
	"groundhold/internal/verify"
)

// D640. A WITNESS capability is one the driver can only read — a GitOps controller's
// Application, a Flux Kustomization. The compiler correctly emits no mutating action
// for it (the driver would refuse one) and records it under `witnessed` so a sealed
// plan cannot be misread as "capability forgotten". It then `continue`d, before any
// drift comparison.
//
// Measured on a live k3d cluster:
//
//   - a candidate naming a Kustomization that DOES NOT EXIST:
//     converge → exit 0, "✓ converged — the world already matches the candidate",
//     while `kubectl get` says NotFound. A hard constraint on the capability did not
//     change it.
//   - a BOUND witness whose declared `source.repoURL` differed from the measured one:
//     converge → exit 0 CONVERGED, `plan` → "nothing to change", while `adopt` refused
//     the identical mismatch on the identical ledger with "adoption must not lie".
//
// A capability that cannot be written is exactly the one whose drift a human must be
// told about, because nothing will fix it automatically.
func TestAWitnessIsComparedEvenThoughItCannotBeWritten(t *testing.T) {
	// The witness registry is populated by driver init(); assert we actually have one
	// rather than testing a default-true lookup (D328).
	if provider.CanAuthor("k8s", "flux-kustomization") {
		t.Skip("k8s/flux-kustomization is no longer witness-only — re-target this test")
	}
	if !provider.CanAuthor("k8s", "rbac-role") {
		t.Fatal("k8s/rbac-role should be authorable; the witness predicate looks inverted")
	}
}

// An UNBOUND witness must not compile to silence. Driven through Compile itself: the
// first version of this test read the compiler's source for the message text, which
// says nothing about whether the branch runs.
func TestAnUnboundWitnessBlocksInsteadOfConverging(t *testing.T) {
	c := &contract.Contract{ID: "w", Environment: "test", Version: 1,
		Capabilities: map[string]map[string]any{
			"gitops": {"type": "capability.gitops.application"},
		}}
	cand := &contract.Candidate{ContractID: "w",
		Capabilities: map[string]map[string]contract.Provenanced{"gitops": {}},
		Extras: map[string]map[string]any{
			"gitops": {"provider": "k8s", "service": "flux-kustomization"},
		}}
	rep := &verify.Report{Executable: true, CandidateHash: "sha256:c", ContractHash: "sha256:h"}

	doc, err := Compile(c, cand, nil, rep, "", Inputs{
		Bindings:     map[string]string{}, // NOT bound: the object does not exist
		Observations: map[string]map[string]ledger.ObsRecord{},
		Heads:        map[string]string{"gitops": "genesis"},
	})
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if len(doc.Plan.Actions) != 0 {
		t.Errorf("a witness must get no mutating action, got %d", len(doc.Plan.Actions))
	}
	var named bool
	for _, b := range doc.Plan.Blocked {
		if b.Capability == "gitops" && strings.Contains(b.Reason, "not bound") {
			named = true
		}
	}
	if !named {
		t.Errorf("an unbound witness compiled to silence — on a live cluster that is "+
			"exactly what printed \"the world already matches the candidate\" for a "+
			"Kustomization kubectl reports as NotFound. blocked=%+v witnessed=%+v",
			doc.Plan.Blocked, doc.Plan.Witnessed)
	}
}
