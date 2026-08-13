package apply

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"groundhold/internal/compiler"
	"groundhold/internal/contract"
	"groundhold/internal/ledger"
	"groundhold/internal/provider"
	"groundhold/internal/verify"
	"groundhold/internal/vocab"
)

// compilePlanDoc compiles a plan for a contract+candidate and returns the mutable planDoc
// and the embedded vocabs (which carry the protection/stateful markers apply re-derives), so
// a test can hand-author the exact bypass shape (D959: a hand-authored/stale plan must not
// slip a consent the pinned contract never granted past apply).
func compilePlanDoc(t *testing.T, contractYAML, candYAML string) (*contract.Contract, *contract.Candidate, map[string]any, map[string]vocab.Vocabulary) {
	t.Helper()
	vocabs, err := vocab.Embedded()
	if err != nil {
		t.Fatal(err)
	}
	td := t.TempDir()
	cp := filepath.Join(td, "c.yaml")
	kp := filepath.Join(td, "k.yaml")
	if err := os.WriteFile(cp, []byte(contractYAML), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(kp, []byte(candYAML), 0o600); err != nil {
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
	report, _ := verify.Verify(c, cand, vocabs)
	if !report.Executable {
		t.Fatalf("not executable: %v", report.BlockingReasons)
	}
	doc, err := compiler.Compile(c, cand, vocabs, report, "proj-x", compiler.Inputs{
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
	return c, cand, planDoc, vocabs
}

func planActionMaps(planDoc map[string]any) []map[string]any {
	p, _ := planDoc["plan"].(map[string]any)
	raw, _ := p["actions"].([]any)
	var out []map[string]any
	for _, it := range raw {
		if a, ok := it.(map[string]any); ok {
			out = append(out, a)
		}
	}
	return out
}

const protContract = `apiVersion: contract/v0.1
kind: InfrastructureContract
meta: { id: prot, environment: test, version: 1 }
capabilities:
  - id: guard
    type: capability.security.threatdetection
`

const protCandidate = `apiVersion: candidate/v0.1
kind: ImplementationCandidate
contract: prot
capabilities:
  guard:
    provider: fake
    service: mock
    attributes:
      location.region: eu-central-1
      detection.enabled: true
`

// D959: apply must RE-DERIVE allow_protection_lift from the pinned contract. A protection:
// capability (threatdetection) is stateful:false, so the delete_stateful gate never catches
// it — without this re-check a hand-authored/stale plan deletes it (switching a security
// control off) with none of the consent the compiler demands (D698).
func TestApplyRefusesProtectionLiftWithoutConsent(t *testing.T) {
	c, cand, planDoc, vocabs := compilePlanDoc(t, protContract, protCandidate)
	// hand-author the bypass: turn the compiled create into a delete of the protection cap.
	for _, a := range planActionMaps(planDoc) {
		if a["operation"] == "create" && a["capability"] == "guard" {
			a["operation"] = "delete"
			a["targetProviderId"] = "fake:the-detector"
			a["targetGeneration"] = float64(1)
		}
	}
	res := Apply(c, cand, vocabs, planDoc, freshLedger(t), &provider.Fake{}, pfAt, false)
	if !strings.Contains(strings.Join(res.Reasons, " "), "allow_protection_lift") {
		t.Fatalf("deleting a protection capability without consent must refuse and name "+
			"allow_protection_lift; reasons=%v outcomes=%v", res.Reasons, res.Outcomes)
	}
}

// D959: apply must RE-DERIVE allow_field_reclaim from the pinned contract — a hand-authored
// plan cannot assert fieldReclaim=true (force over another field manager) for a capability
// the contract never scoped. replContract grants allow_replace_stateful but NOT field_reclaim.
func TestApplyRefusesFieldReclaimWithoutConsent(t *testing.T) {
	c, cand, planDoc, vocabs := compilePlanDoc(t, replContract, replCandidate)
	for _, a := range planActionMaps(planDoc) {
		a["fieldReclaim"] = true // forge the consent the pinned contract never gave
	}
	res := Apply(c, cand, vocabs, planDoc, freshLedger(t), &provider.Fake{}, pfAt, false)
	if !strings.Contains(strings.Join(res.Reasons, " "), "allow_field_reclaim") {
		t.Fatalf("a forged fieldReclaim without consent must refuse and name "+
			"allow_field_reclaim; reasons=%v outcomes=%v", res.Reasons, res.Outcomes)
	}
}

// D1034: the same defence for the emission-adopt consent. A hand-authored plan cannot
// assert emissionAdopt=true (take over a provider-created log group) for a capability
// the pinned contract never scoped — apply re-derives the consent from the contract.
func TestApplyRefusesEmissionAdoptWithoutConsent(t *testing.T) {
	c, cand, planDoc, vocabs := compilePlanDoc(t, replContract, replCandidate)
	for _, a := range planActionMaps(planDoc) {
		a["emissionAdopt"] = true // forge the consent the pinned contract never gave
	}
	res := Apply(c, cand, vocabs, planDoc, freshLedger(t), &provider.Fake{}, pfAt, false)
	if !strings.Contains(strings.Join(res.Reasons, " "), "allow_emission_adopt") {
		t.Fatalf("a forged emissionAdopt without consent must refuse and name "+
			"allow_emission_adopt; reasons=%v outcomes=%v", res.Reasons, res.Outcomes)
	}
}
