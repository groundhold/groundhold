package backup

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"groundhold/internal/canonical"
	"groundhold/internal/contract"
)

// D643. D616 made the RESTORED LEDGER the authority on which documents must be
// accounted for, and its entry lists among the closed variants: "flipping
// `\"present\": false` left the blob unread and still `verified`". The gate written
// with it pins a manifest naming a hash the ledger does NOT pin — which refuses on
// the unaccounted path. The named variant, a hash the ledger DOES pin plus a
// substituted blob sitting on disk, was never exercised, and it still passed:
//
//	restore --out … --check anchor.json --documents documents  capsule
//	exit 0   "status": "verified"
//	         {"status":"absent","reason":"referenced but not copied into this backup"}
//
// Two attacker-set fields each turn the check off for a blob that is right there:
// `present: false` (never read) and `kind: "candidate"` (deferred). The manifest is
// the artefact under test; it cannot be the thing that decides whether to look.
//
// The rule: the DIRECTORY says what exists, and every blob that exists is verified
// against its own name. A manifest entry can say a blob is absent — it cannot say a
// blob that is present should not be read.
func TestAManifestCannotWaveOffABlobThatIsOnDisk(t *testing.T) {
	const pinned = "sha256:1111111111111111111111111111111111111111111111111111111111111111"

	setup := func(t *testing.T, refs []DocRef) (string, string) {
		t.Helper()
		dir := t.TempDir()
		docs := filepath.Join(dir, "documents")
		if err := os.MkdirAll(docs, 0o755); err != nil {
			t.Fatal(err)
		}
		// The substituted blob: a real, loadable contract whose canonical hash is
		// NOT the name it is filed under. This is what an attacker leaves behind.
		swapped := []byte(`{"apiVersion":"contract/v0.1","kind":"InfrastructureContract",
		  "meta":{"id":"swapped","environment":"prod","version":1},
		  "capabilities":[{"id":"db","type":"capability.database.relational"}]}`)
		if err := os.WriteFile(filepath.Join(docs, pinned), swapped, 0o644); err != nil {
			t.Fatal(err)
		}
		mb, _ := json.Marshal(refs)
		if err := os.WriteFile(filepath.Join(docs, "manifest.json"), mb, 0o644); err != nil {
			t.Fatal(err)
		}
		ledgerPath := filepath.Join(dir, "l.jsonl")
		line := map[string]any{"apiVersion": "state/v0", "kind": "LedgerEvent",
			"event": map[string]any{"type": "plan.sealed", "occurredAt": "2026-01-01T00:00:00Z",
				"body": map[string]any{"reads": map[string]any{"contractHash": pinned}}}}
		b, _ := json.Marshal(line)
		if err := os.WriteFile(ledgerPath, append(b, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
		return docs, ledgerPath
	}

	for _, tc := range []struct {
		name string
		refs []DocRef
	}{
		{"present:false", []DocRef{{Hash: pinned, Kind: "contract", Present: false}}},
		{"kind:candidate", []DocRef{{Hash: pinned, Kind: "candidate", Present: true,
			File: pinned}}},
		// The blob is on disk and the manifest does not mention it at all.
		{"unmentioned", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			docs, ledgerPath := setup(t, tc.refs)
			rep, code := VerifyDocumentsAgainst(docs, ledgerPath)
			if code == ExitOK {
				t.Fatalf("a substituted contract blob sitting in the backup was "+
					"certified because the manifest said not to read it. This is the "+
					"last step of a disaster recovery: %+v", rep)
			}
			var named bool
			for _, d := range rep.Documents {
				if d.Hash == pinned && d.Status == "tampered" {
					named = true
				}
			}
			if !named {
				t.Errorf("the report does not name the blob as tampered, so an "+
					"operator cannot tell which document lied: %+v", rep.Documents)
			}
		})
	}
}

// The control: an honest backup must still verify, and a contract the operator's
// document store genuinely did not contain (no blob on disk) stays a reported
// absence rather than becoming a refusal. Refusing everything is the cheap way to
// pass the cases above.
func TestAnHonestDocumentSetStillVerifies(t *testing.T) {
	dir := t.TempDir()
	docs := filepath.Join(dir, "documents")
	if err := os.MkdirAll(docs, 0o755); err != nil {
		t.Fatal(err)
	}
	raw := []byte(`{"apiVersion":"contract/v0.1","kind":"InfrastructureContract",
	  "meta":{"id":"real","environment":"prod","version":1},
	  "capabilities":[{"id":"db","type":"capability.database.relational"}]}`)
	tmp := filepath.Join(dir, "c.json")
	if err := os.WriteFile(tmp, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	h := hashOfContractFile(t, tmp)
	if err := os.WriteFile(filepath.Join(docs, h), raw, 0o644); err != nil {
		t.Fatal(err)
	}
	const absent = "sha256:3333333333333333333333333333333333333333333333333333333333333333"
	mb, _ := json.Marshal([]DocRef{
		{Hash: h, Kind: "contract", Present: true, File: h},
		{Hash: absent, Kind: "contract", Present: false},
	})
	if err := os.WriteFile(filepath.Join(docs, "manifest.json"), mb, 0o644); err != nil {
		t.Fatal(err)
	}

	rep, code := VerifyDocuments(docs)
	if code != ExitOK {
		t.Fatalf("an honest backup must verify: %+v", rep)
	}
	var okSeen, absSeen bool
	for _, d := range rep.Documents {
		if d.Hash == h && d.Status == "verified" {
			okSeen = true
		}
		if d.Hash == absent && d.Status == "absent" {
			absSeen = true
		}
	}
	if !okSeen || !absSeen {
		t.Errorf("verified=%v absent-reported=%v: %+v", okSeen, absSeen, rep.Documents)
	}
}

func hashOfContractFile(t *testing.T, path string) string {
	t.Helper()
	c, err := contract.LoadContract(path)
	if err != nil {
		t.Fatal(err)
	}
	h, err := canonical.HashContract(c)
	if err != nil {
		t.Fatal(err)
	}
	return h
}
