package vocab

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// D668. `ValidateEvidence` refuses an unrecognised `evidence:` value, and its
// docstring says "a closed set that silently tolerates a typo is not closed". It
// had no runtime caller: the only one was a gate test over the EMBEDDED set. A
// `--vocab` directory an operator supplies was therefore unvalidated, `EvidenceOf`
// fell back to `resource`, and the consequence measured by an audit was:
//
//	preflight --vocab <typo'd dir>   exit 2  "cost.monthly has no S3 mapping — refusing"
//	plan      --vocab <typo'd dir>   exit 0  SEALED
//
// The refusal arrived at `apply`, past the gate, at the mutation boundary.
func TestALoadedVocabularyValidatesItsEvidenceClasses(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("good.yaml", `capability: capability.database.relational
version: 0.1
stateful: true
attributes:
  cost.monthly:
    kind: money
    evidence: projection
`)
	if _, err := LoadDir(dir); err != nil {
		t.Fatalf("a well-formed vocabulary was refused: %v", err)
	}

	write("typo.yaml", `capability: capability.storage.object
version: 0.1
stateful: true
attributes:
  cost.monthly:
    kind: money
    evidence: projction
`)
	_, err := LoadDir(dir)
	if err == nil {
		t.Fatal("a vocabulary declaring an unrecognised evidence class loaded " +
			"cleanly — the typo then weakens a reconcile and the refusal surfaces " +
			"at apply, after the gate")
	}
	if !strings.Contains(err.Error(), "projction") {
		t.Errorf("the refusal does not name the offending value: %v", err)
	}
	if !strings.Contains(err.Error(), "typo.yaml") {
		t.Errorf("the refusal does not name the file: %v", err)
	}
}
