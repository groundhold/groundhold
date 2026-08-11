// Ledger snapshots (D137): the file backend's compaction valve. A
// snapshot is the FULL fold of a history prefix — every projection the
// replay reconstructs, serialized — plus the chain position it stands
// for (baseEvents, baseHead) and the ledger's identity (D134). The
// compacted prefix is ARCHIVED, never deleted: capsules and audits of
// old history read the archive; the live file carries only the tail.
//
// The correctness anchor is an equivalence property, pinned by a
// same-package test over the ENTIRE Ledger struct:
//
//	fold(prefix + tail) == fold(snapshot(prefix)) + tail
//
// reflect.DeepEqual over unexported fields means a future projection
// added to Ledger without snapshot support fails that test loudly —
// silent state loss is the one failure mode this design refuses to
// leave possible.
package ledger

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"

	"groundhold/internal/canonical"
)

// Snapshot is the serialized fold. Every field mirrors a Ledger
// projection; the exported mirrors of unexported state (leases) keep
// the JSON honest without opening the Ledger's internals.
type Snapshot struct {
	APIVersion string `json:"apiVersion"` // snapshot/v0.1
	Kind       string `json:"kind"`       // LedgerSnapshot
	// identity + position (D134/D70): which ledger, and how much of it
	LedgerId   string `json:"ledgerId,omitempty"`
	BaseEvents int    `json:"baseEvents"`
	BaseHead   string `json:"baseHead"`

	Clock         int                             `json:"clock"`
	MaxOccurred   int                             `json:"maxOccurred"`
	Heads         map[string]string               `json:"heads"`
	DecisionHeads map[string]string               `json:"decisionHeads"`
	Bindings      map[string]map[string]any       `json:"bindings,omitempty"`
	Observations  map[string]map[string]ObsRecord `json:"observations,omitempty"`
	// D286: the wiring projection travels with the snapshot, separate from
	// the semantic observations (a snapshot must reconstruct BOTH exactly).
	Outputs map[string]map[string]ObsRecord `json:"outputs,omitempty"`
	// D191: per-source retention so a probe record survives a later observe.
	ObservationsBySource map[string]map[string]map[string]ObsRecord `json:"observationsBySource,omitempty"`
	ViolationState       map[string]string                          `json:"violationState,omitempty"`
	Environments         map[string]string                          `json:"environments,omitempty"`
	Leases               map[string]SnapLease                       `json:"leases,omitempty"`
	MaxToken             map[string]int                             `json:"maxToken,omitempty"`
	Pending              map[string][]string                        `json:"pending,omitempty"`
	PendingBody          map[string]map[string]map[string]any       `json:"pendingBody,omitempty"`
	Replaced             map[string][]string                        `json:"replaced,omitempty"`
	Tombstoned           map[string][]string                        `json:"tombstoned,omitempty"`
	LastGen              map[string]map[string]int                  `json:"lastGen,omitempty"`
	// Claimed (D140): capabilities groundhold has claimed authorship of
	// (ownership.claimed). This projection lives ONLY in the claimed map —
	// the claim event touches no binding body — so a snapshot that drops it
	// resurrects a one-time claim action against an already-owned resource
	// on every post-compaction run (breaks the converged no-op).
	Claimed map[string]bool `json:"claimed,omitempty"`
	// Observed: capabilities observe was recorded for (even zero-attribute). Like
	// Claimed, this projection lives only in its own map — a snapshot that dropped
	// it would let a bound blind-observer capability re-freeze the compiler after
	// compaction.
	Observed map[string]bool `json:"observed,omitempty"`

	// VerifiedUnder is the receipt of the verification the rotation
	// replay ACTUALLY ran (adversarial review): a snapshot is not a cached
	// fold, it is a signed receipt of a verified prefix — and what it
	// was verified under is part of the claim.
	VerifiedUnder *VerifiedUnder `json:"verifiedUnder,omitempty"`
	// Archive binds the compacted bytes: the snapshot names the file it
	// replaced and pins its content hash — "baseEvents: N" with a
	// swapped or truncated archive is detectable, not deniable.
	Archive *ArchiveRef `json:"archive,omitempty"`
	// PreviousSnapshotHash chains compactions: audit reconstruction
	// follows hashes, never filenames and operator memory.
	PreviousSnapshotHash string `json:"previousSnapshotHash,omitempty"`

	// Sig (optional): detached, like D102 events — a snapshot written
	// by a signing process is verifiable by the same trust set.
	Sig map[string]any `json:"sig,omitempty"`
}

// VerifiedUnder: mode is "filesystem" (no trust armed — plain file
// trust, said out loud) or "trust". From records an armed --trust-from
// boundary the rotation replay honored — the tail replay seeds
// "boundary reached" from this receipt, since the boundary event now
// lives in the archive.
type VerifiedUnder struct {
	Mode string   `json:"mode"`
	Keys []string `json:"keys,omitempty"`
	From string   `json:"from,omitempty"`
}

type ArchiveRef struct {
	File   string `json:"file"`
	Sha256 string `json:"sha256"`
	Events int    `json:"events"` // absolute count the archive ends at
}

type SnapLease struct {
	Token  int  `json:"token"`
	Expiry int  `json:"expiry"`
	TTL    int  `json:"ttl"`
	Ended  bool `json:"ended"`
	// Seq identifies the LEASE across its capabilities (D633). It must survive the
	// compaction boundary: without it a seeded fold cannot tell two same-token leases
	// apart, and the one-mutation-one-lease rule would relax to the old per-capability
	// check for any ledger that has been snapshotted — the silent projection loss the
	// snapshot-equivalence fuzz exists to catch, and did.
	Seq int `json:"seq,omitempty"`
}

// HashSnapshot: identity of the fold — the raw canonical tree with the
// detached `sig` excluded, exactly the D102 rule for events.
func HashSnapshot(doc map[string]any) (string, error) {
	if _, ok := doc["sig"]; ok {
		stripped := make(map[string]any, len(doc)-1)
		for k, v := range doc {
			if k != "sig" {
				stripped[k] = v
			}
		}
		doc = stripped
	}
	return canonical.Hash("groundhold/canon/v1:snapshot", doc)
}

func setToSorted(m map[string]map[string]bool) map[string][]string {
	if len(m) == 0 {
		return nil
	}
	out := map[string][]string{}
	for k, set := range m {
		out[k] = sortedKeys(set)
	}
	return out
}

func sortedToSet(m map[string][]string) map[string]map[string]bool {
	out := map[string]map[string]bool{}
	for k, list := range m {
		set := map[string]bool{}
		for _, it := range list {
			set[it] = true
		}
		out[k] = set
	}
	return out
}

// LoadSnapshotFile reads the sidecar; nil when absent (no snapshot is
// a normal state, a malformed one never is).
// SnapshotState is the THREE-valued answer to "is this ledger compacted?" (D708).
//
// LoadSnapshotFile has always answered three ways — absent is (nil, nil), unreadable
// is (nil, err), present is (snap, nil) — and three of its six callers wrote a
// two-valued test:
//
//	if snap, err := LoadSnapshotFile(p); err == nil && snap != nil { … }
//
// which folds "I could not read this" into "this is not there". `backup` skipped the
// refusal that exists because capsule DR and compaction are mutually exclusive, and
// emitted capsules that cannot restore while reporting success. `attest` left the
// snapshot facts empty, so a report meant to be evidence read as "no snapshot".
// `runstatus` silently stopped reading the archive, so runs that live in it became
// "no such run".
//
// This type exists so the third answer has a name a caller has to look at. It is not
// a different mechanism — it is the same call, with the outcome that was being
// discarded made into a value.
type SnapshotState string

const (
	SnapshotAbsent     SnapshotState = "absent"
	SnapshotPresent    SnapshotState = "present"
	SnapshotUnreadable SnapshotState = "unreadable"
)

// SnapshotStateOf reads the sidecar beside a ledger and says which of the three it
// found. The error is returned as well, for callers that report the reason.
func SnapshotStateOf(ledgerPath string) (*Snapshot, SnapshotState, error) {
	snap, err := LoadSnapshotFile(SnapshotPath(ledgerPath))
	switch {
	case err != nil:
		return nil, SnapshotUnreadable, err
	case snap == nil:
		return nil, SnapshotAbsent, nil
	default:
		return snap, SnapshotPresent, nil
	}
}

func LoadSnapshotFile(path string) (*Snapshot, error) {
	raw, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var s Snapshot
	if err := json.Unmarshal(raw, &s); err != nil {
		return nil, fmt.Errorf("snapshot: %v", err)
	}
	if s.Kind != "LedgerSnapshot" || s.APIVersion != "snapshot/v0.1" {
		return nil, fmt.Errorf("snapshot: not a snapshot/v0.1 " +
			"LedgerSnapshot document")
	}
	normalizeSnapshot(&s)
	return &s, nil
}

// snapshotDomain: what a snapshot signature attests, separated from
// events — a fold is a different claim than a single line.
const snapshotDomain = "groundhold/snapshot/v1"

// SignSnapshotDoc attaches the detached envelope when signing is armed
// — the same key, the same detached rule as D102 events.
func SignSnapshotDoc(doc map[string]any, ledgerID string) error {
	if signKey == nil {
		return nil
	}
	h, err := HashSnapshot(doc)
	if err != nil {
		return err
	}
	msg := []byte(snapshotDomain + ":" + ledgerID + ":" + h)
	doc["sig"] = map[string]any{
		"alg":    "ed25519",
		"pub":    hex.EncodeToString(signKey.Public().(ed25519.PublicKey)),
		"sig":    hex.EncodeToString(ed25519.Sign(signKey, msg)),
		"ledger": ledgerID,
	}
	return nil
}

// verifySnapshotTrust enforces --trust on the seed itself: an unsigned
// or foreign snapshot under trust refuses — otherwise compaction would
// be a signature-stripping laundry (fold history, drop every event
// signature, present the unsigned fold).
func VerifySnapshotTrust(s *Snapshot) error {
	if len(trustSet) == 0 {
		return nil
	}
	if s.Sig == nil {
		return fmt.Errorf("snapshot is unsigned but --trust was given — " +
			"a fold must be as verifiable as the history it replaces")
	}
	if s.Sig["alg"] != "ed25519" {
		return fmt.Errorf("snapshot: unsupported signature alg %v — this "+
			"verifier implements ed25519 only (review fix: the alg is "+
			"outside the hash, it must still be pinned)", s.Sig["alg"])
	}
	pubHex, _ := s.Sig["pub"].(string)
	pub, err := hex.DecodeString(pubHex)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return fmt.Errorf("snapshot: malformed signature public key")
	}
	inSet := false
	for _, t := range trustSet {
		if t.Equal(ed25519.PublicKey(pub)) {
			inSet = true
			break
		}
	}
	if !inSet {
		return fmt.Errorf("snapshot signed by a FOREIGN key %s… — not "+
			"among the trusted keys", pubHex[:16])
	}
	sigHex, _ := s.Sig["sig"].(string)
	sigBytes, err := hex.DecodeString(sigHex)
	if err != nil || len(sigBytes) != ed25519.SignatureSize {
		return fmt.Errorf("snapshot: malformed signature")
	}
	claim, _ := s.Sig["ledger"].(string)
	if claim != s.LedgerId {
		return fmt.Errorf("snapshot signature claims ledger %s but the "+
			"snapshot says %s — spliced", claim, s.LedgerId)
	}
	var doc map[string]any
	raw, _ := json.Marshal(s)
	if err := json.Unmarshal(raw, &doc); err != nil {
		return err
	}
	normalize(doc)
	h, err := HashSnapshot(doc)
	if err != nil {
		return err
	}
	msg := []byte(snapshotDomain + ":" + claim + ":" + h)
	if !ed25519.Verify(ed25519.PublicKey(pub), msg, sigBytes) {
		return fmt.Errorf("snapshot signature does not verify — the fold " +
			"was altered after signing")
	}
	return nil
}

// BuildSnapshot serializes the complete fold at the ledger's tip.
func BuildSnapshot(led *Ledger) *Snapshot {
	s := &Snapshot{
		APIVersion: "snapshot/v0.1", Kind: "LedgerSnapshot",
		BaseEvents: led.BaseEvents + len(led.EventHashes),
		BaseHead:   led.headAtTip(),
		LedgerId:   led.LedgerId(),
		Clock:      led.Clock, MaxOccurred: led.maxOccurred,
		Heads: copyMap(led.Heads), DecisionHeads: copyMap(led.DecisionHeads),
		Bindings: led.Bindings, Observations: led.Observations,
		Outputs:              led.Outputs,
		ObservationsBySource: led.ObservationsBySource,
		ViolationState:       led.ViolationState, Environments: led.Environments,
		MaxToken: led.maxToken, PendingBody: led.pendingBody,
		Replaced: setToSorted(led.replaced), Tombstoned: setToSorted(led.tombstoned),
		Pending: setToSorted(led.pending), LastGen: led.lastGen,
		Claimed: copyBoolMap(led.claimed), Observed: copyBoolMap(led.observed),
	}
	if len(led.leases) > 0 {
		s.Leases = map[string]SnapLease{}
		for c, l := range led.leases {
			s.Leases[c] = SnapLease{Token: l.token, Expiry: l.expiry,
				TTL: l.ttl, Ended: l.ended, Seq: l.seq}
		}
	}
	return s
}

// normalizeSnapshot undoes JSON's float64 drift inside the any-typed
// projections (binding bodies, receipt bodies, observed values) — the
// same normalize() the replay applies to event lines, applied to the
// snapshot's serialization boundary.
func normalizeSnapshot(s *Snapshot) {
	for _, b := range s.Bindings {
		normalize(b)
	}
	for _, ops := range s.PendingBody {
		for _, body := range ops {
			normalize(body)
		}
	}
	for _, byPath := range s.Observations {
		for k, o := range byPath {
			if f, ok := o.Value.(float64); ok && f == float64(int(f)) {
				o.Value = int(f)
				byPath[k] = o
			} else {
				normalize(o.Value)
			}
		}
	}
	for _, byName := range s.Outputs {
		for k, o := range byName {
			if f, ok := o.Value.(float64); ok && f == float64(int(f)) {
				o.Value = int(f)
				byName[k] = o
			} else {
				normalize(o.Value)
			}
		}
	}
	for _, byPath := range s.ObservationsBySource {
		for _, bySource := range byPath {
			for k, o := range bySource {
				if f, ok := o.Value.(float64); ok && f == float64(int(f)) {
					o.Value = int(f)
					bySource[k] = o
				} else {
					normalize(o.Value)
				}
			}
		}
	}
}

// ArchivePath names where a compacted prefix lands — never deleted:
// capsules and audits of old history read the archive.
// ArchiveIntegrity is the answer to "is the file this snapshot archived the file
// it says it archived?" — four-valued on purpose, because "I could not look" and
// "it does not match" are different facts (D646).
type ArchiveIntegrity struct {
	Status string `json:"status"` // not-claimed | matched | mismatched | missing | misnamed
	File   string `json:"file,omitempty"`
	Detail string `json:"detail,omitempty"`
}

// CheckArchive reads the archive a snapshot names and compares it to the hash the
// snapshot pinned. Until D646 that field had ZERO readers anywhere in the tree,
// while the spec told operators a swapped or truncated archive was detectable —
// truncating an 18-event archive to 3 left every verb green.
//
// The snapshot does not get to nominate WHICH file satisfies its own hash: the
// name must be the one compaction would have written for this ledger at this base.
// Only the directory is allowed to differ, so a backup that was moved still checks.
func CheckArchive(ledgerPath string, snap *Snapshot) ArchiveIntegrity {
	if snap == nil || snap.Archive == nil || snap.Archive.Sha256 == "" {
		return ArchiveIntegrity{Status: "not-claimed"}
	}
	want := ArchivePath(ledgerPath, snap.BaseEvents)
	if filepath.Base(snap.Archive.File) != filepath.Base(want) {
		return ArchiveIntegrity{Status: "misnamed", File: snap.Archive.File,
			Detail: fmt.Sprintf("the snapshot points its archive hash at %q, but a "+
				"compaction at base %d writes %q — a sidecar does not get to choose "+
				"which file satisfies its own hash",
				snap.Archive.File, snap.BaseEvents, filepath.Base(want))}
	}
	raw, err := os.ReadFile(want)
	if err != nil {
		return ArchiveIntegrity{Status: "missing", File: want,
			Detail: fmt.Sprintf("%v — the compacted history is not beside the "+
				"ledger, so nothing here can prove what was folded away", err)}
	}
	got := fmt.Sprintf("sha256:%x", sha256.Sum256(raw))
	if got != snap.Archive.Sha256 {
		return ArchiveIntegrity{Status: "mismatched", File: want,
			Detail: fmt.Sprintf("the archive hashes to %s but the snapshot pinned "+
				"%s — it was truncated, swapped or edited after compaction",
				got, snap.Archive.Sha256)}
	}
	return ArchiveIntegrity{Status: "matched", File: want}
}

func ArchivePath(ledgerPath string, baseEvents int) string {
	return fmt.Sprintf("%s.archive.%d", ledgerPath, baseEvents)
}

// Rotate performs the compaction (D137). It holds an exclusive flock on
// the ledger for the WHOLE operation — the same lock commitUnderLock
// takes, so a concurrent append cannot interleave a lost write between
// the fold, the archive hash and the renames (all three must see ONE
// set of bytes). Ordering favors loud over pretty: copy the outgoing
// sidecar to its archive, fsync, activate the new snapshot, fsync the
// dir, THEN move the ledger to its archive — so no crash window leaves
// "no snapshot and no ledger" (the silently-empty state D137 forbids).
func Rotate(ledgerPath string) (*Snapshot, *Anchor, error) {
	// D655: lockLedger opens with O_CREATE (an append names the file into
	// existence), but a compaction of a file that is not there is a typo, not a
	// rotation — the same distinction D617 drew for every other verb.
	if _, err := os.Stat(ledgerPath); err != nil {
		if os.IsNotExist(err) {
			return nil, nil, fmt.Errorf("%w at %s — nothing to compact",
				ErrNoLedger, ledgerPath)
		}
		return nil, nil, err
	}
	// D675: `os.Rename` acts on the LINK, not its target. Compacting through a
	// symlink therefore moved the link into `<path>.archive.<N>` — so the "archive"
	// aliased a file that is still live, a fresh regular file took the operator's
	// path, and the next write through the real path made the ledger permanently
	// un-exportable (attest: archive mismatched, repair exit 5). Measured with no
	// concurrency at all.
	//
	// Resolving instead of refusing would be worse: every reader derives the
	// snapshot, archive and anchor paths from the path IT was given, so a rotation
	// that wrote them beside the resolved file would leave a reader following the
	// link unable to see any of them — and a tail read as a whole history is the
	// silent answer this refuses to give.
	if fi, lerr := os.Lstat(ledgerPath); lerr == nil && fi.Mode()&os.ModeSymlink != 0 {
		target, _ := filepath.EvalSymlinks(ledgerPath)
		return nil, nil, fmt.Errorf(
			"%s is a symlink (to %s) and compaction renames the path it is given — "+
				"the link would become the archive while the real file stays live, "+
				"and the ledger would be permanently un-exportable. Compact the "+
				"target path directly (D675)", ledgerPath, target)
	}
	// take the lock FIRST, on the ledger file, and hold it throughout. D655: and
	// verify the locked descriptor is still the file at this path — two rotations
	// racing would otherwise archive the same inode twice, which is the same
	// lost-write window from the other side.
	lf, err := lockLedger(ledgerPath)
	if err != nil {
		return nil, nil, err
	}
	defer lf.Close()
	defer syscall.Flock(int(lf.Fd()), syscall.LOCK_UN)

	led, err := ReplayFile(ledgerPath)
	if err != nil {
		return nil, nil, err
	}
	if err := EnforceAnchor(ledgerPath, led); err != nil {
		return nil, nil, err
	}
	if len(led.EventHashes) == 0 {
		return nil, nil, fmt.Errorf(
			"nothing to compact — the tail is already empty")
	}
	// armed trust but no signing key would write a fold that claims
	// mode:trust yet cannot be signed — the next replay refuses it and
	// bricks the ledger. Refuse UP FRONT (review fix).
	keys, from := ArmedPolicy()
	if len(keys) > 0 && !SigningArmed() {
		return nil, nil, fmt.Errorf("--trust is armed but no --sign-key: " +
			"a trust-verifiable snapshot needs a signing key (a fold that " +
			"claims trust yet carries no signature would be rejected when " +
			"next read)")
	}
	snap := BuildSnapshot(led)
	snap.VerifiedUnder = &VerifiedUnder{Mode: "filesystem"}
	if len(keys) > 0 {
		snap.VerifiedUnder = &VerifiedUnder{Mode: "trust", Keys: keys, From: from}
	}
	// ONE byte buffer feeds the fold's archive hash AND the archived
	// file — under the lock they are guaranteed identical.
	fileBytes, err := os.ReadFile(ledgerPath)
	if err != nil {
		return nil, nil, err
	}
	arch := ArchivePath(ledgerPath, snap.BaseEvents)
	if _, err := os.Stat(arch); err == nil {
		return nil, nil, fmt.Errorf(
			"%s already exists — refusing to overwrite an archive", arch)
	}
	snap.Archive = &ArchiveRef{
		File:   arch,
		Sha256: fmt.Sprintf("sha256:%x", sha256.Sum256(fileBytes)),
		Events: snap.BaseEvents,
	}
	prevSnap, err := LoadSnapshotFile(SnapshotPath(ledgerPath))
	if err != nil {
		return nil, nil, err // never swallow: previousSnapshotHash must be honest
	}
	if prevSnap != nil {
		var prevDoc map[string]any
		rawPrev, _ := json.Marshal(prevSnap)
		if err := json.Unmarshal(rawPrev, &prevDoc); err != nil {
			return nil, nil, err
		}
		normalize(prevDoc)
		h, err := HashSnapshot(prevDoc)
		if err != nil {
			return nil, nil, err
		}
		snap.PreviousSnapshotHash = h
	}
	var doc map[string]any
	rawDoc, _ := json.Marshal(snap)
	if err := json.Unmarshal(rawDoc, &doc); err != nil {
		return nil, nil, err
	}
	normalize(doc)
	if err := SignSnapshotDoc(doc, snap.LedgerId); err != nil {
		return nil, nil, err
	}
	out, err := json.Marshal(doc)
	if err != nil {
		return nil, nil, err
	}

	dir := filepath.Dir(ledgerPath)
	// 1. archive the OUTGOING sidecar by COPY (not rename): the live
	//    snapshot path is never absent, so no crash window replays the
	//    tail as a fresh genesis (review fix — window B).
	if prevSnap != nil {
		prevArch := fmt.Sprintf("%s.archive.%d", SnapshotPath(ledgerPath),
			prevSnap.BaseEvents)
		if _, err := os.Stat(prevArch); err == nil {
			return nil, nil, fmt.Errorf(
				"%s already exists — refusing to overwrite", prevArch)
		}
		cur, err := os.ReadFile(SnapshotPath(ledgerPath))
		if err != nil {
			return nil, nil, err
		}
		if err := writeFsync(prevArch, cur); err != nil {
			return nil, nil, err
		}
	}
	// 2. write the new snapshot to tmp, fsync, atomically activate,
	//    fsync the DIR so the rename is durable before the ledger moves.
	tmp := SnapshotPath(ledgerPath) + ".tmp"
	if err := writeFsync(tmp, out); err != nil {
		return nil, nil, err
	}
	if err := os.Rename(tmp, SnapshotPath(ledgerPath)); err != nil {
		return nil, nil, err
	}
	if err := fsyncDir(dir); err != nil {
		return nil, nil, err
	}
	// 3. NOW move the ledger to its archive and create a fresh empty
	//    tail with O_EXCL (never O_TRUNC — a concurrent recreate must
	//    not be truncated away). Dir fsync again.
	if err := os.Rename(ledgerPath, arch); err != nil {
		return nil, nil, err
	}
	if err := createEmpty(ledgerPath); err != nil {
		return nil, nil, err
	}
	if err := fsyncDir(dir); err != nil {
		return nil, nil, err
	}
	// a beside-anchor (D135) pinned pre-compaction positions — refresh
	// it under the SAME armed policy (absolute totals, D137), pinning
	// the fold hash so a swapped snapshot is detectable. tmp+rename.
	anchor := BuildAnchor(led)
	// D710: never swallow, for exactly the reason `previousSnapshotHash` above says
	// it. This pin is what lets a receiver detect a SWAPPED FOLD rather than only a
	// rewritten tail, and `CheckAnchor` only makes that comparison when the pin is
	// non-empty — so a hash failure here used to write an anchor that silently
	// carries no swap detection, two lines under a comment promising it does.
	hs, err := HashSnapshot(doc)
	if err != nil {
		return nil, nil, fmt.Errorf("cannot hash the snapshot to pin it in the "+
			"anchor (%v) — an anchor without that pin detects a rewritten tail but "+
			"not a swapped fold, and would say nothing about the difference", err)
	}
	anchor.SnapshotHash = hs
	// D647: an anchor the OPERATOR placed pins the trust policy on purpose (D135),
	// and a refresh keeps that. An anchor compaction creates on its own is a
	// WITNESS of the fold — writing a policy into it would arm one nobody chose,
	// and the next replay would refuse for a reason the operator never configured.
	hadAnchor := false
	if _, serr := os.Stat(AnchorPath(ledgerPath)); serr == nil {
		hadAnchor = true
	}
	if !hadAnchor {
		anchor.Trust = nil
	}
	// D647: this used to refresh the anchor only if one already happened to exist.
	// Compaction is the moment the ledger's integrity story is weakest — a fold
	// replaces history, and without a key nothing co-located can authenticate it
	// (D646). The anchor is the one artefact an operator can copy OFF-HOST, where
	// an attacker who owns this directory cannot reach it, so compaction now
	// always leaves one. Rotate already computed it and threw it away.
	{
		araw, _ := json.Marshal(anchor)
		atmp := AnchorPath(ledgerPath) + ".tmp"
		if err := writeFsync(atmp, araw); err != nil {
			return nil, nil, err
		}
		if err := os.Rename(atmp, AnchorPath(ledgerPath)); err != nil {
			return nil, nil, err
		}
		if err := fsyncDir(dir); err != nil {
			return nil, nil, err
		}
	}
	return snap, anchor, nil
}

// createEmpty makes a fresh, empty tail file, refusing if one already
// exists (O_EXCL) so a concurrent writer's recreate is never truncated.
func createEmpty(path string) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		if os.IsExist(err) {
			return nil // a writer already recreated it — its line stands
		}
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

// fsyncDir makes a rename durable — POSIX does not order rename
// durability without it (review fix: power-loss between the two
// renames must not lose both files).
func fsyncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

func writeFsync(path string, data []byte) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	if data != nil {
		if _, err := f.Write(data); err != nil {
			f.Close()
			return err
		}
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

// SeedLedger reconstructs the fold a snapshot recorded — the starting
// state tail replay continues from. Positions stay ABSOLUTE: anchors
// and event counts keep meaning what they always meant.
// sortedLeaseKeys keeps the synthetic seq assignment above deterministic — a fold
// that depends on map order is a fold that disagrees with itself.
func sortedLeaseKeys(m map[string]SnapLease) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func SeedLedger(s *Snapshot) (*Ledger, error) {
	if s.APIVersion != "snapshot/v0.1" || s.Kind != "LedgerSnapshot" {
		return nil, fmt.Errorf("not a snapshot/v0.1 LedgerSnapshot document")
	}
	if s.BaseEvents < 1 || s.BaseHead == "" {
		return nil, fmt.Errorf("snapshot carries no chain position " +
			"(baseEvents/baseHead) — a fold of nothing proves nothing")
	}
	led := New()
	led.BaseEvents = s.BaseEvents
	led.BaseHead = s.BaseHead
	led.ledgerId = s.LedgerId
	// boundary credit (D137, review fix — CRITICAL): the receipt seeds
	// the --trust-from obligation ONLY when the rotation replay ran
	// under TRUST mode. A signed fold of filesystem-verified history
	// carrying a forged `from` must earn nothing.
	if s.VerifiedUnder != nil && s.VerifiedUnder.Mode == "trust" {
		led.verifiedFrom = s.VerifiedUnder.From
	}
	led.Clock = s.Clock
	led.maxOccurred = s.MaxOccurred
	if s.Heads != nil {
		led.Heads = copyMap(s.Heads)
	}
	if s.DecisionHeads != nil {
		led.DecisionHeads = copyMap(s.DecisionHeads)
	}
	if s.Bindings != nil {
		led.Bindings = s.Bindings
	}
	if s.ObservationsBySource != nil {
		led.ObservationsBySource = s.ObservationsBySource
	}
	if s.Observations != nil {
		led.Observations = s.Observations
	}
	if s.Outputs != nil {
		led.Outputs = s.Outputs
	}
	if s.ViolationState != nil {
		led.ViolationState = s.ViolationState
	}
	if s.Environments != nil {
		led.Environments = s.Environments
	}
	if s.MaxToken != nil {
		led.maxToken = s.MaxToken
	}
	if s.PendingBody != nil {
		led.pendingBody = s.PendingBody
	}
	if s.Pending != nil {
		led.pending = sortedToSet(s.Pending)
	}
	if s.Replaced != nil {
		led.replaced = sortedToSet(s.Replaced)
	}
	if s.Tombstoned != nil {
		led.tombstoned = sortedToSet(s.Tombstoned)
	}
	if s.LastGen != nil {
		led.lastGen = s.LastGen
	}
	if len(s.Claimed) > 0 {
		led.claimed = map[string]bool{}
		for c, v := range s.Claimed {
			if v {
				led.claimed[c] = true
			}
		}
	}
	if len(s.Observed) > 0 {
		led.observed = map[string]bool{}
		for c, v := range s.Observed {
			if v {
				led.observed[c] = true
			}
		}
	}
	// D644: a snapshot written before lease identity carries no seq, and
	// `omitempty` makes its absence indistinguishable from 0. Reading them all as
	// one lease is the silence-is-agreement answer, and it turns the covering-lease
	// rule off for every ledger an older binary compacted. Each such lease gets a
	// DISTINCT synthetic seq and is marked as unprovable, so a multi-capability
	// mutation over it refuses with the reason that is actually true.
	for _, c := range sortedLeaseKeys(s.Leases) {
		l := s.Leases[c]
		le := &lease{token: l.Token, expiry: l.Expiry, ttl: l.TTL, ended: l.Ended,
			seq: l.Seq}
		if l.Seq == 0 && !l.Ended {
			led.leaseSeq++
			le.seq, le.seqUnknown = led.leaseSeq, true
		}
		led.leases[c] = le
		if le.seq > led.leaseSeq {
			led.leaseSeq = le.seq
		}
	}
	return led, nil
}

// ArchivedLines returns every event line the compactions moved out of the live
// ledger, in chain order, together with a NOTE when they do not add up to what the
// snapshot says was folded.
//
// D672: this lived inside internal/export (D645), which is why `runs`, `status` and
// `wait` still could not see a compacted run: they read the live file alone, so a
// COMPLETED deploy read `unknown` and `wait` blocked to its timeout and exited 3 —
// the reconcile-required code, whose published remediation is `groundhold resume`.
// One reader now, and a third caller gets it for free.
//
// A short or pruned archive is reported rather than refused: spec/state-model.md
// §10 says pruning archives is an operator decision, and a reporting verb that
// becomes permanently unusable after a lawful prune would be a worse answer than
// "here is what I can see, and here is what I cannot".
func ArchivedLines(ledgerPath string, want int) ([]string, string, error) {
	names, err := filepath.Glob(ledgerPath + ".archive.*")
	if err != nil {
		return nil, "", err
	}
	type arch struct {
		n     int
		lines []string
	}
	var found []arch
	for _, name := range names {
		n, cerr := strconv.Atoi(strings.TrimPrefix(name, ledgerPath+".archive."))
		if cerr != nil {
			continue // not one of ours
		}
		raw, rerr := os.ReadFile(name)
		if rerr != nil {
			return nil, "", fmt.Errorf("cannot read the archive holding the compacted "+
				"history (%s): %v", name, rerr)
		}
		if len(raw) > 0 && raw[len(raw)-1] != '\n' {
			return nil, "", fmt.Errorf("%s has a torn final line — repair required", name)
		}
		var ls []string
		for _, l := range strings.Split(strings.TrimRight(string(raw), "\n"), "\n") {
			if l != "" {
				ls = append(ls, l)
			}
		}
		found = append(found, arch{n: n, lines: ls})
	}
	sort.Slice(found, func(i, j int) bool { return found[i].n < found[j].n })
	var out []string
	for _, a := range found {
		out = append(out, a.lines...)
	}
	note := ""
	if len(out) != want {
		note = fmt.Sprintf("the snapshot says %d events were compacted and the "+
			"archives beside the ledger hold %d — %d events of this history cannot "+
			"be read (looked for %s.archive.*)",
			want, len(out), want-len(out), ledgerPath)
	}
	return out, note, nil
}
