// Capsule-based disaster recovery, slice 4 (D103 lineage): `groundhold backup`
// bundles a ledger's complete recovery set into ONE directory — the off-host
// anchor (D70, the manifest), one evidence capsule per capability (D103), and,
// when a document store is supplied, the content-addressed CONTRACT documents
// the ledger pins by hash. It adds no verification math; it composes BuildAnchor
// and EmitCapsule and writes them where `groundhold restore` expects them.
//
// The backup is the operational UNIT the restore slices consume: its output
// feeds `groundhold restore --check <out>/anchor.json <out>/capsules/*.json`
// directly. It also SURFACES the ledger's external-document dependencies (which
// contracts/candidates a decision was made against) in a manifest, so a complete
// recovery preserves them — a backup that silently omits its contracts is worse
// than one that names what it could not find.
//
// Documents: the ledger pins contractHash (contract.published, plan.sealed reads)
// and candidateHash (plan.sealed reads, candidate.verified) — hashes only, never
// content. With --documents <store>, backup matches each referenced CONTRACT hash
// against the store (LoadContract -> HashContract) and copies the verbatim bytes
// to documents/<hash>, so restore can recompute and re-verify. Candidate-blob
// backup is DEFERRED (recomputing a candidate hash needs its contract as context)
// and recorded honestly as referenced-but-not-copied rather than faked.
package backup

import (
	"encoding/json"
	"fmt"
	"groundhold/internal/perr"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"groundhold/internal/canonical"
	"groundhold/internal/contract"
	"groundhold/internal/ledger"
)

const (
	ExitOK       = 0
	ExitRefused  = 5
	ExitOperator = 1
)

// Options are the parsed CLI inputs.
type Options struct {
	LedgerPath     string // --ledger: the ledger to back up
	Out            string // --out: the backup directory to create (must not exist)
	DocumentsStore string // --documents: a directory of contract/candidate files to source blobs from (optional)
}

// DocRef is one external document the ledger references by hash.
type DocRef struct {
	Hash    string `json:"hash"`
	Kind    string `json:"kind"`           // contract | candidate
	File    string `json:"file,omitempty"` // the copied blob's name under documents/ (contracts, when found)
	Present bool   `json:"present"`        // whether the blob was located and copied
	Note    string `json:"note,omitempty"`
}

// BackupReport is the deterministic receipt written to <out>/backup.json.
type BackupReport struct {
	APIVersion string `json:"apiVersion"`
	Kind       string `json:"kind"`
	Status     string `json:"status"` // backed-up | refused
	// Code (D624): the published coverage rule is "every JSON-emitting verb carries
	// `code`". This report refused with reasons and no code, so a caller had to read
	// prose to learn whether the ledger was damaged or the path was wrong.
	Code         string   `json:"code,omitempty"`
	LedgerID     string   `json:"ledgerId,omitempty"`
	Capabilities []string `json:"capabilities,omitempty"`
	Capsules     []string `json:"capsules,omitempty"`
	// CredentialWarnings counts EVENTS carrying credential-shaped values (D536).
	// A count, never the values: a warning that quotes the secret defeats itself.
	// The ledger is append-only, so a value that was a plaintext credential when it
	// was recorded is still one inside every copy made afterwards — and a backup is
	// made precisely to be moved off-host.
	CredentialWarnings int              `json:"credentialWarnings"`
	CredentialSites    []CredentialSite `json:"credentialSites,omitempty"`
	Documents          []DocRef         `json:"documents,omitempty"`
	Reasons            []string         `json:"reasons,omitempty"`
}

// CredentialSite locates one event whose recorded body carries a
// credential-shaped value. The capsule and the event index are enough for an
// operator to go and look; the VALUE is never carried (D536).
type CredentialSite struct {
	Capsule string `json:"capsule"`
	Event   int    `json:"event"`
	Kind    string `json:"kind"`    // what the pattern recognised, in prose
	Pointer string `json:"pointer"` // the path inside the event body
}

// Run performs a backup, returning the report and the CLI exit code.
func Run(opts Options) (*BackupReport, int) {
	rep := &BackupReport{APIVersion: "backup/v0.1", Kind: "BackupReport", Status: "refused"}
	if opts.LedgerPath == "" {
		return op(rep, "backup requires --ledger <file>")
	}
	if opts.Out == "" {
		return op(rep, "backup requires --out <dir>")
	}
	if _, err := os.Stat(opts.Out); err == nil {
		return op(rep, fmt.Sprintf("refusing to write into existing path %s — "+
			"backup creates a FRESH directory", opts.Out))
	}

	// replay first: a backup of a corrupt ledger is not a backup.
	led, err := ledger.ReplayFile(opts.LedgerPath)
	if err != nil {
		return refuse(rep, fmt.Sprintf("the ledger does not replay: %v", err))
	}

	// D313: a compacted ledger (D137) cannot be backed up as capsules AT ALL. A
	// capsule is a subchain from genesis, so every capability whose history began
	// before the snapshot refuses — in practice all of them. Emitting from the
	// archive does not rescue it either: those capsules end at the PRE-snapshot
	// head and the live anchor pins the post-snapshot one, so restore calls them
	// stale; and archive+live for one capability are disjoint sets, which merge
	// adjudicates as a fork. Say that here, before creating anything, instead of
	// discovering it capsule by capsule.
	snap, snapState, serr := ledger.SnapshotStateOf(opts.LedgerPath)
	if snapState == ledger.SnapshotUnreadable {
		// D708: the sidecar EXISTS and could not be read, so this ledger cannot be
		// shown to be uncompacted — and the refusal below exists because a compacted
		// ledger cannot be backed up as capsules at all. The old test was
		// `serr == nil && snap != nil`, which sent an unreadable snapshot down the
		// same path as an absent one: capsules emitted, success reported, and nothing
		// that could restore. A backup that reports success and cannot restore is the
		// worst kind there is.
		return refuse(rep, fmt.Sprintf("a snapshot sidecar exists beside this ledger "+
			"and could not be read (%v) — capsule DR and compaction are mutually "+
			"exclusive, so a backup cannot be shown to be restorable while that file "+
			"is unreadable", serr))
	}
	if snapState == ledger.SnapshotPresent && len(snap.Heads) > 0 {
		return refuse(rep, "this ledger has been compacted (a snapshot at "+
			fmt.Sprintf("%d events", snap.BaseEvents)+"): capsule backup covers a "+
			"chain from genesis, so every capability whose history predates the "+
			"snapshot cannot be proven from the live file — and archive-emitted "+
			"capsules do not satisfy the live anchor either. Capsule DR and "+
			"compaction are mutually exclusive today; preserve the archive files "+
			"themselves as the backup of the compacted era")
	}

	if err := os.MkdirAll(opts.Out, 0o700); err != nil {
		return op(rep, err.Error())
	}
	if err := writeJSON(filepath.Join(opts.Out, "anchor.json"),
		ledger.BuildAnchor(led)); err != nil {
		return op(rep, err.Error())
	}

	// one capsule per capability (the backup unit).
	capsDir := filepath.Join(opts.Out, "capsules")
	if err := os.MkdirAll(capsDir, 0o700); err != nil {
		return op(rep, err.Error())
	}
	caps := sortedKeys(led.Heads)
	for _, cap := range caps {
		c, err := ledger.EmitCapsule(opts.LedgerPath, cap)
		if err != nil {
			return refuse(rep, fmt.Sprintf("emit capsule for %q: %v", cap, err))
		}
		name := safeName(cap) + ".capsule.json"
		if err := writeJSON(filepath.Join(capsDir, name), c); err != nil {
			return op(rep, err.Error())
		}
		rep.Capsules = append(rep.Capsules, name)
		rep.CredentialSites = append(rep.CredentialSites, scanCapsule(name, c)...)
	}
	// D536: say it out loud, and say what to DO. Never refuse — the finding is a
	// pattern, the history is immutable by design, and redacting it would break the
	// hash chain restore verifies against. Reported after the capsules so the count
	// is over all of them.
	rep.CredentialWarnings = len(rep.CredentialSites)
	if rep.CredentialWarnings > 0 {
		rep.Reasons = append(rep.Reasons, fmt.Sprintf(
			"warning: %d recorded event(s) carry credential-shaped values — the ledger is "+
				"append-only, so values that were plaintext when recorded travel in every "+
				"copy. ENCRYPT this backup before moving it off-host; see credentialSites "+
				"for where to look (values are never printed).", rep.CredentialWarnings))
	}

	// documents the ledger pins by hash — recorded always, copied when a store
	// is supplied and a contract blob matches.
	refs, err := collectDocRefs(opts.LedgerPath)
	if err != nil {
		return refuse(rep, err.Error())
	}
	if opts.DocumentsStore != "" && len(refs) > 0 {
		index, ierr := indexContracts(opts.DocumentsStore)
		if ierr != nil {
			return op(rep, ierr.Error())
		}
		docsDir := filepath.Join(opts.Out, "documents")
		if err := os.MkdirAll(docsDir, 0o700); err != nil {
			return op(rep, err.Error())
		}
		for i := range refs {
			if refs[i].Kind != "contract" {
				refs[i].Note = "candidate-blob backup deferred (rehash needs the contract as context); preserve externally"
				continue
			}
			src, ok := index[refs[i].Hash]
			if !ok {
				refs[i].Note = "no contract in --documents store hashes to this reference"
				continue
			}
			raw, rerr := os.ReadFile(src)
			if rerr != nil {
				return op(rep, rerr.Error())
			}
			if werr := os.WriteFile(filepath.Join(docsDir, refs[i].Hash), raw, 0o600); werr != nil {
				return op(rep, werr.Error())
			}
			refs[i].Present = true
			refs[i].File = refs[i].Hash
		}
		if err := writeJSON(filepath.Join(docsDir, "manifest.json"), refs); err != nil {
			return op(rep, err.Error())
		}
	}
	rep.Documents = refs

	rep.Status = "backed-up"
	rep.LedgerID = led.LedgerId()
	rep.Capabilities = caps
	if err := writeJSON(filepath.Join(opts.Out, "backup.json"), rep); err != nil {
		return op(rep, err.Error())
	}
	return rep, ExitOK
}

// collectDocRefs walks every ledger event body for the document hashes the
// ledger pins — contractHash (kind contract) and candidateHash (kind candidate)
// — deduped and returned in a deterministic order.
func collectDocRefs(ledgerPath string) ([]DocRef, error) {
	raw, err := os.ReadFile(ledgerPath)
	if err != nil {
		return nil, err
	}
	kind := map[string]string{} // hash -> kind (first wins; a hash is one document)
	for _, line := range strings.Split(strings.TrimRight(string(raw), "\n"), "\n") {
		if line == "" {
			continue
		}
		var doc map[string]any
		if json.Unmarshal([]byte(line), &doc) != nil {
			continue // a malformed line would have failed ReplayFile already
		}
		ev, _ := doc["event"].(map[string]any)
		walkHashes(ev["body"], kind)
	}
	refs := make([]DocRef, 0, len(kind))
	hashes := make([]string, 0, len(kind))
	for h := range kind {
		hashes = append(hashes, h)
	}
	sort.Strings(hashes)
	for _, h := range hashes {
		refs = append(refs, DocRef{Hash: h, Kind: kind[h]})
	}
	return refs, nil
}

// walkHashes recursively collects contractHash/candidateHash string values.
func walkHashes(v any, out map[string]string) {
	switch x := v.(type) {
	case map[string]any:
		for k, val := range x {
			if s, ok := val.(string); ok && s != "" {
				if k == "contractHash" {
					if _, seen := out[s]; !seen {
						out[s] = "contract"
					}
				} else if k == "candidateHash" {
					if _, seen := out[s]; !seen {
						out[s] = "candidate"
					}
				}
			}
			walkHashes(val, out)
		}
	case []any:
		for _, it := range x {
			walkHashes(it, out)
		}
	}
}

// indexContracts hashes every contract-shaped file in the store to build a
// hash->path index. A file that is not a loadable contract is skipped silently
// (the store may hold candidates and other artifacts).
func indexContracts(store string) (map[string]string, error) {
	index := map[string]string{}
	entries, err := os.ReadDir(store)
	if err != nil {
		return nil, err
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		p := filepath.Join(store, e.Name())
		c, err := contract.LoadContract(p)
		if err != nil {
			continue // not a contract — skip
		}
		h, err := canonical.HashContract(c)
		if err != nil {
			continue
		}
		if _, dup := index[h]; !dup {
			index[h] = p
		}
	}
	return index, nil
}

// DocStatus is one document's fate under `restore --documents`.
type DocStatus struct {
	Hash   string `json:"hash"`
	Kind   string `json:"kind"`
	Status string `json:"status"` // verified | tampered | absent | deferred
	Reason string `json:"reason,omitempty"`
}

// VerifyReport is the receipt for VerifyDocuments.
type VerifyReport struct {
	APIVersion string `json:"apiVersion"`
	Kind       string `json:"kind"`
	Status     string `json:"status"` // verified | refused
	// Code (D624): the coverage rule again — a refusal that names no code makes a
	// caller read prose to learn whether a document was tampered with or the set
	// simply does not describe this ledger.
	Code      string      `json:"code,omitempty"`
	Documents []DocStatus `json:"documents,omitempty"`
	Reasons   []string    `json:"reasons,omitempty"`
}

// VerifyDocuments re-verifies a backup's documents directory: for every CONTRACT
// blob the manifest marks Present, it recomputes the canonical hash of the
// verbatim bytes and refuses (exit 5) if it no longer matches the filename — a
// tampered document cannot be laundered through recovery. Candidate references
// are reported deferred; a contract that was never copied is reported absent
// (honest, not fatal — the ledger itself restored). No manifest is an operator
// error: there is nothing to verify against.
// VerifyDocumentsAgainst re-verifies a documents directory against the hashes the
// RESTORED LEDGER pins, not merely against the manifest that ships beside the blobs.
//
// D616: `VerifyDocuments(dir)` was handed only the directory. It read `manifest.json`
// — a plain file the attacker controls if they control the backup — and compared each
// blob to the hash written there. The ledger's own pinned `contractHash` values, which
// restore has just replayed into memory, were never consulted. So a substituted
// contract, renamed to its own (different) hash with a one-entry manifest to match,
// came back `{"status":"verified"}` at exit 0 while the restored ledger pinned a
// different document entirely. Two weaker variants of the same root: `[]` as the
// manifest verified zero documents (vacuous), and flipping `"present": false` made the
// blob unread and still "verified" — a guard conditional on a field the attacker sets,
// the shape D312 closed for anchors.
//
// ledgerPath may be empty, in which case this degrades to the manifest-only check with
// that stated in the report — an honest weaker answer, not a silent one.
func VerifyDocumentsAgainst(docsDir, ledgerPath string) (*VerifyReport, int) {
	rep, code := VerifyDocuments(docsDir)
	if ledgerPath == "" {
		rep.Reasons = append(rep.Reasons, "no ledger given: the manifest was checked "+
			"against itself, which cannot detect a substituted document")
		return rep, code
	}
	pinned, err := collectDocRefs(ledgerPath)
	if err != nil {
		rep.Status = "refused"
		rep.Code = string(perr.LedgerCorrupted)
		rep.Reasons = append(rep.Reasons, fmt.Sprintf(
			"cannot read the restored ledger to learn which documents it pins: %v", err))
		return rep, ExitRefused
	}

	inReport := map[string]bool{}
	for _, d := range rep.Documents {
		inReport[d.Hash] = true
	}
	missing := false
	for _, r := range pinned {
		if r.Kind != "contract" || inReport[r.Hash] {
			continue
		}
		missing = true
		rep.Documents = append(rep.Documents, DocStatus{Hash: r.Hash, Kind: r.Kind,
			Status: "unaccounted",
			Reason: "the restored ledger pins this contract and the manifest does " +
				"not mention it — the manifest is not a description of this history"})
	}
	// A blob the ledger does NOT pin is not evidence about this ledger. Report it
	// rather than counting it towards a clean verdict.
	pinnedSet := map[string]bool{}
	for _, r := range pinned {
		pinnedSet[r.Hash] = true
	}
	for i, d := range rep.Documents {
		if d.Status == "verified" && !pinnedSet[d.Hash] {
			rep.Documents[i].Status = "foreign"
			rep.Documents[i].Reason = "this document is not pinned anywhere in the " +
				"restored ledger — it verifies against the manifest and says nothing " +
				"about this history"
			missing = true
		}
	}
	if missing {
		rep.Status = "refused"
		rep.Code = string(perr.AdoptionMismatch)
		rep.Reasons = append(rep.Reasons, "the documents do not correspond to the "+
			"restored ledger — a manifest that agrees with itself is not evidence")
		return rep, ExitRefused
	}
	return rep, code
}

func VerifyDocuments(docsDir string) (*VerifyReport, int) {
	rep := &VerifyReport{APIVersion: "backup-verify/v0.1", Kind: "DocumentVerifyReport", Status: "refused"}
	raw, err := os.ReadFile(filepath.Join(docsDir, "manifest.json"))
	if err != nil {
		rep.Reasons = append(rep.Reasons, fmt.Sprintf("no documents manifest at %s: %v", docsDir, err))
		return rep, ExitOperator
	}
	var refs []DocRef
	if err := json.Unmarshal(raw, &refs); err != nil {
		rep.Reasons = append(rep.Reasons, fmt.Sprintf("unreadable documents manifest: %v", err))
		return rep, ExitOperator
	}
	// D643: the DIRECTORY says what exists. The manifest is the artefact under
	// test, so it cannot be what decides whether a blob is read: `present: false`
	// and `kind: "candidate"` each left a substituted contract on disk unread and
	// still reported `verified`, at the last step of a disaster recovery. A manifest
	// entry may say a blob is ABSENT — it may not say a blob that is here should be
	// ignored.
	onDisk := map[string]bool{}
	if ents, derr := os.ReadDir(docsDir); derr == nil {
		for _, e := range ents {
			if e.IsDir() || e.Name() == "manifest.json" {
				continue
			}
			onDisk[e.Name()] = true
		}
	}

	tampered := false
	for _, r := range refs {
		st := DocStatus{Hash: r.Hash, Kind: r.Kind}
		switch {
		case r.Kind != "contract" && !onDisk[r.Hash]:
			st.Status = "deferred"
			st.Reason = "candidate-blob backup deferred; preserve externally"
		case !r.Present && !onDisk[r.Hash]:
			st.Status = "absent"
			st.Reason = "referenced but not copied into this backup"
		default:
			c, lerr := contract.LoadContract(filepath.Join(docsDir, r.Hash))
			if lerr != nil {
				st.Status, st.Reason, tampered = "tampered", fmt.Sprintf("blob unreadable as a contract: %v", lerr), true
				break
			}
			h, herr := canonical.HashContract(c)
			if herr != nil {
				st.Status, st.Reason, tampered = "tampered", herr.Error(), true
				break
			}
			switch {
			case h != r.Hash:
				st.Status, st.Reason, tampered = "tampered",
					fmt.Sprintf("recomputed %s != pinned %s", h, r.Hash), true
			case !r.Present || r.Kind != "contract":
				// The blob is here and verifies, but the manifest describes it as
				// something that should not have been read. The bytes are fine; the
				// manifest is lying about the backup, which is what the check is for.
				st.Status, st.Reason, tampered = "tampered", fmt.Sprintf(
					"the blob is present and hashes correctly, but the manifest "+
						"records it as kind=%q present=%v — a manifest that waves off "+
						"a blob that is on disk is not a description of this backup",
					r.Kind, r.Present), true
			default:
				st.Status = "verified"
			}
		}
		delete(onDisk, r.Hash)
		rep.Documents = append(rep.Documents, st)
	}
	// Whatever is left is a blob the manifest never mentioned. It is in the backup
	// and it is not accounted for; the only honest thing to do is read it and say
	// what it is.
	for _, name := range sortedKeys(onDisk) {
		st := DocStatus{Hash: name, Kind: "contract", Status: "tampered", Reason: "this blob is " +
			"in the backup and the manifest does not mention it — an unlisted blob is " +
			"exactly what a substitution leaves behind"}
		if c, lerr := contract.LoadContract(filepath.Join(docsDir, name)); lerr == nil {
			if h, herr := canonical.HashContract(c); herr == nil && h == name {
				st.Reason = "this blob hashes to its own name but the manifest does " +
					"not mention it — the manifest is not a description of this backup"
			}
		}
		tampered = true
		rep.Documents = append(rep.Documents, st)
	}
	if tampered {
		rep.Code = string(perr.LedgerCorrupted)
		rep.Reasons = append(rep.Reasons, "a document blob does not match its pinned hash — corruption cannot be laundered through recovery")
		return rep, ExitRefused
	}
	rep.Status = "verified"
	return rep, ExitOK
}

func op(rep *BackupReport, reason string) (*BackupReport, int) {
	rep.Reasons = append(rep.Reasons, reason)
	rep.Status = "refused"
	rep.Code = string(perr.StructuralError) // D624: an operator error, named
	return rep, ExitOperator
}

func refuse(rep *BackupReport, reason string) (*BackupReport, int) {
	rep.Reasons = append(rep.Reasons, reason)
	rep.Status = "refused"
	rep.Code = string(perr.LedgerCorrupted) // D624: the history, not the command line
	return rep, ExitRefused
}

func writeJSON(path string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(b, '\n'), 0o600)
}

// safeName makes a capability id a safe single filename segment.
func safeName(cap string) string {
	r := strings.NewReplacer("/", "_", " ", "_", ":", "_")
	return r.Replace(cap)
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// scanCapsule reports the credential-shaped values recorded inside one capsule,
// using the SAME detector the candidate path uses (contract.ScanValue, D364).
// Two detectors would drift, and the one nobody exercised would be the one that
// mattered.
func scanCapsule(name string, c any) []CredentialSite {
	raw, err := json.Marshal(c)
	if err != nil {
		return nil
	}
	var doc struct {
		Events []map[string]any `json:"events"`
	}
	if json.Unmarshal(raw, &doc) != nil {
		return nil
	}
	var out []CredentialSite
	for i, ev := range doc.Events {
		// A capsule event is the ledger envelope {apiVersion, kind, event}; the
		// recorded body is one level in. Scanning the top level found nothing and
		// looked exactly like a clean ledger — which is why the test that proves
		// the WARNING fires had to exist before the code did.
		inner, ok := ev["event"].(map[string]any)
		if !ok {
			continue
		}
		body, ok := inner["body"]
		if !ok {
			continue
		}
		for _, f := range contract.ScanValue("body", body) {
			out = append(out, CredentialSite{
				Capsule: name, Event: i, Kind: f.Kind, Pointer: f.Pointer})
		}
	}
	return out
}
