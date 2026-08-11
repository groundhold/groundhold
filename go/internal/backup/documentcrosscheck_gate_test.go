package backup

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// D616. `restore --documents` is the last step of a disaster recovery: it says whether
// the contract blobs that came back are the ones this history was built on. It was
// handed only the directory, so it compared each blob to `manifest.json` — a plain file
// sitting beside those blobs, written by whoever made the backup.
//
// Measured by an adversarial audit: replace a contract blob with one where both hard
// constraints are flipped to `false`, rename it to its own (different) hash, write a
// one-entry manifest naming that hash, and restore:
//
//	exit 0   {"kind":"DocumentVerifyReport","status":"verified",
//	          "documents":[{"hash":"sha256:c623cffc…","status":"verified"}]}
//
// while the restored ledger pins `sha256:546690ae…`. Two weaker variants of the same
// root: an empty manifest verified zero documents and reported success, and flipping
// `"present": false` made the blob unread and still "verified" — a guard conditional on
// a field the attacker sets, which is the shape D312 closed for anchors.
//
// The authority is the RESTORED LEDGER: it pins the contract hashes this history was
// compiled against, and restore has just replayed them.
func TestDocumentsAreCheckedAgainstTheLedgerNotTheManifest(t *testing.T) {
	dir := t.TempDir()
	docs := filepath.Join(dir, "documents")
	if err := os.MkdirAll(docs, 0o755); err != nil {
		t.Fatal(err)
	}

	// A ledger pinning one contract hash, in the shape collectDocRefs reads.
	const pinned = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
	const foreign = "sha256:2222222222222222222222222222222222222222222222222222222222222222"
	ledgerPath := filepath.Join(dir, "l.jsonl")
	line := map[string]any{"apiVersion": "state/v0", "kind": "LedgerEvent",
		"event": map[string]any{"type": "plan.sealed", "occurredAt": "2026-01-01T00:00:00Z",
			"body": map[string]any{"reads": map[string]any{"contractHash": pinned}}}}
	b, _ := json.Marshal(line)
	if err := os.WriteFile(ledgerPath, append(b, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}

	writeManifest := func(refs []DocRef) {
		mb, _ := json.Marshal(refs)
		if err := os.WriteFile(filepath.Join(docs, "manifest.json"), mb, 0o644); err != nil {
			t.Fatal(err)
		}
	}

	t.Run("a manifest naming a document the ledger does not pin is refused", func(t *testing.T) {
		// `present:false` on purpose: the blob is never read, so ONLY the
		// cross-check can catch it — which is the variant that used to pass.
		writeManifest([]DocRef{{Hash: foreign, Kind: "contract", Present: false}})
		rep, code := VerifyDocumentsAgainst(docs, ledgerPath)
		if code == ExitOK {
			t.Errorf("verified a document set that does not match the ledger: %+v", rep)
		}
		if rep.Status != "refused" {
			t.Errorf("status = %q, want refused", rep.Status)
		}
	})

	t.Run("an empty manifest is not a clean bill of health", func(t *testing.T) {
		writeManifest(nil)
		rep, code := VerifyDocumentsAgainst(docs, ledgerPath)
		if code == ExitOK {
			t.Error("an empty manifest verified nothing and reported success — the " +
				"ledger pins a contract that is not accounted for anywhere (D328)")
		}
		var unaccounted bool
		for _, d := range rep.Documents {
			if d.Hash == pinned && d.Status == "unaccounted" {
				unaccounted = true
			}
		}
		if !unaccounted {
			t.Errorf("the report does not name the pinned contract as unaccounted: %+v",
				rep.Documents)
		}
	})

	t.Run("without a ledger the weaker answer is stated, not hidden", func(t *testing.T) {
		writeManifest([]DocRef{{Hash: foreign, Kind: "contract", Present: false}})
		rep, _ := VerifyDocumentsAgainst(docs, "")
		var said bool
		for _, r := range rep.Reasons {
			if len(r) > 0 && r[0] == 'n' { // "no ledger given: …"
				said = true
			}
		}
		if !said {
			t.Errorf("a manifest-only check must say so in the report: %+v", rep.Reasons)
		}
	})
}
