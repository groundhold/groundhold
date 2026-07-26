// Tail anchor (D70): the external witness the D68 boundary asked for.
// The chain protects an event once a successor pins its hash — the
// LAST line has no successor, so its protection must live OUTSIDE the
// file. `anchor` emits (events: N, head: hash of line N) plus the
// per-capability heads; the operator stores it on a medium the
// ledger's writer cannot touch. `anchor --check` re-replays and
// verifies the ledger still EXTENDS the anchored prefix: the check is
// positional — the anchored hash must sit at exactly line N, or a
// drop-and-append game past the last anchor would go unseen. The log is
// a per-capability FOREST (no global previous-event link), so that
// positional hash witnesses only the sub-chain owning line N; the
// recorded per-capability `heads` witness every OTHER capability's
// tail, and the check verifies them whenever the anchor covers the
// whole current ledger (review find — without it a count-preserving
// rewrite of an independent capability passed).
//
// Honest boundary, restated: events appended after the last anchor
// are unprotected until re-anchored (and while a tail sits past the
// anchor, only line N's sub-chain is positionally pinned — re-anchor at
// the tip to witness every capability), and an attacker who can replace
// BOTH the ledger and the anchor is outside this scheme's threat
// model. The anchor is tamper-EVIDENCE, not truth: a legitimate writer
// can still append false, well-formed events.
package ledger

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
)

// AnchorPath is the co-located anchor for a ledger file.
func AnchorPath(ledgerPath string) string { return ledgerPath + ".anchor" }

// EnforceAnchor is the execution-path guard (review): if an anchor
// sits beside the ledger, a mutating verb (apply/resume) verifies the
// replayed ledger still EXTENDS it before touching the cloud. A
// truncated or diverged tail — which the chain alone cannot see on the
// last line — refuses here, fail-closed. No anchor file means no
// enforcement: the anchor stays opt-in, the operator arms it by placing
// the file (and storing a copy off-host).
func EnforceAnchor(ledgerPath string, led *Ledger) error {
	raw, err := os.ReadFile(AnchorPath(ledgerPath))
	if os.IsNotExist(err) {
		return nil // opt-in: no anchor, no enforcement
	}
	if err != nil {
		return err
	}
	var a Anchor
	if err := json.Unmarshal(raw, &a); err != nil || a.Kind != "LedgerAnchor" {
		return fmt.Errorf("anchor file is not a LedgerAnchor document")
	}
	if chk := CheckAnchor(led, &a); chk.Status != "verified" {
		reason := chk.Status
		if len(chk.Reasons) > 0 {
			reason = chk.Reasons[0]
		}
		return fmt.Errorf("ledger fails its anchor (%s): %s — the "+
			"history was truncated or rewritten after anchoring; refuse "+
			"before mutating", chk.Status, reason)
	}
	return nil
}

type Anchor struct {
	APIVersion string `json:"apiVersion" yaml:"apiVersion"`
	Kind       string `json:"kind" yaml:"kind"`
	Events     int    `json:"events" yaml:"events"`
	// Head is the hash of the LAST event — with Events it is the
	// normative check
	Head string `json:"head" yaml:"head"`
	// Manifest is a domain-separated hash over the ORDERED list of every
	// live event hash, seeded by BaseHead — the complete forest guard. The
	// positional Head witnesses only the sub-chain owning the last line
	// (the log is a per-capability forest); the manifest commits to EVERY
	// line's hash in order, so a count-preserving rewrite of ANY interior
	// event — including an independent capability's tail behind a grown
	// suffix — moves it and diverges. Recomputable from any replay that
	// reaches the anchored prefix.
	Manifest string `json:"manifest,omitempty" yaml:"manifest,omitempty"`
	// BaseEvents pins the compaction position the manifest was seeded at
	// (D137). The manifest is verified only when the ledger's compaction
	// has not advanced since (a.BaseEvents == led.BaseEvents); a further
	// compaction moves the archive boundary and the positional/snapshot
	// checks take over.
	BaseEvents int `json:"baseEvents,omitempty" yaml:"baseEvents,omitempty"`
	// Heads/DecisionHeads pin EVERY capability's tip at anchor time. The
	// log is a per-capability forest (each event pins only the heads of
	// the capabilities it lists — there is no global previous-event
	// link), so the positional Head witnesses only the sub-chain that
	// owns the last line. When the anchor covers the whole ledger these
	// per-capability heads are the witness for every OTHER capability's
	// tail: a mismatch is tampering, not "an implementation bug" (a
	// count-preserving rewrite of an independent capability leaves Head
	// untouched but moves that capability's head — the review find).
	Heads         map[string]string `json:"heads" yaml:"heads"`
	DecisionHeads map[string]string `json:"decisionHeads" yaml:"decisionHeads"`
	// LedgerId (D134): the genesis event's canonical hash — the identity
	// signatures bind. Note honestly: forks grown from one genesis share
	// it (a LINEAGE id); the positional Head is what tells branches apart.
	LedgerId string `json:"ledgerId,omitempty" yaml:"ledgerId,omitempty"`
	// SnapshotHash (D137): when an anchor is cut at a compaction, it
	// pins the snapshot document too — a receiver holding this anchor
	// detects a swapped fold, not only a rewritten tail.
	SnapshotHash string `json:"snapshotHash,omitempty" yaml:"snapshotHash,omitempty"`
	// Trust (D135): the policy the EMITTING process actually verified
	// this ledger under. Any path that loads the anchor arms it — a
	// receiver cannot forget --trust if they check their anchor. Never
	// emitted unverified: an armed emit refuses at replay first.
	Trust *AnchorTrust `json:"trust,omitempty" yaml:"trust,omitempty"`
}

// AnchorTrust pins the scheme it applies to (a key policy silently
// applied to an incompatible signature scheme would be ambiguity, not
// security).
type AnchorTrust struct {
	Scheme string   `json:"scheme" yaml:"scheme"`
	Keys   []string `json:"keys" yaml:"keys"`
	From   string   `json:"from,omitempty" yaml:"from,omitempty"`
}

// ledgerManifest hashes the ORDERED list of live event hashes, seeded by
// the archived prefix's BaseHead — the anchor's complete forest guard. A
// separator that cannot occur inside a "sha256:<hex>" token (\x00) keeps
// the concatenation injective. This is Go-only (Python has no anchor), so
// there is no cross-implementation determinism obligation here.
func ledgerManifest(baseHead string, eventHashes []string) string {
	h := sha256.New()
	h.Write([]byte("groundhold/anchor/v1:manifest"))
	h.Write([]byte{0})
	if baseHead == "" {
		baseHead = "genesis"
	}
	h.Write([]byte(baseHead))
	for _, eh := range eventHashes {
		h.Write([]byte{0})
		h.Write([]byte(eh))
	}
	return "sha256:" + hex.EncodeToString(h.Sum(nil))
}

func BuildAnchor(led *Ledger) *Anchor {
	// absolute across snapshots (D137, review fix): a post-compaction
	// anchor counting only the tail would fail its own check
	a := &Anchor{
		APIVersion: "state/v0", Kind: "LedgerAnchor",
		Events: led.TotalEvents(), Head: led.headAtTip(),
		Heads: copyMap(led.Heads), DecisionHeads: copyMap(led.DecisionHeads),
		Manifest:   ledgerManifest(led.BaseHead, led.EventHashes),
		BaseEvents: led.BaseEvents,
	}
	a.LedgerId = led.LedgerId()
	// D137 (review fix): a standalone `groundhold anchor` on a compacted
	// ledger must ALSO pin the fold it stands on, so a later swap is
	// caught — the seeded replay carries the fold hash.
	a.SnapshotHash = led.snapshotHash
	// D135: embed exactly what this process verified — the replay that
	// produced `led` ran under this policy, so the anchor is a receipt
	// of verification that actually happened, never a wish.
	if keys, from := ArmedPolicy(); len(keys) > 0 {
		a.Trust = &AnchorTrust{Scheme: SigScheme, Keys: keys, From: from}
	}
	return a
}

// LoadAnchorFile reads and shape-checks an anchor document.
func LoadAnchorFile(path string) (*Anchor, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var a Anchor
	if err := json.Unmarshal(raw, &a); err != nil || a.Kind != "LedgerAnchor" {
		return nil, fmt.Errorf("%s is not a LedgerAnchor document", path)
	}
	return &a, nil
}

// RequireIdentity refuses an anchor that cannot say WHICH ledger it manifests.
//
// D312: three of restore's guards — the foreign-capsule check, the genesis-presence
// check and the restored-identity check — were each written `if a.LedgerId != ""`,
// so an anchor with no ledgerId turned all three off and restore still reported
// success. A guard conditional on the very field it guards is not a guard.
//
// Nothing groundhold writes lands here: BuildAnchor always sets the id, and it is
// empty only for a ledger with no events at all — which has no capsule to restore
// from either. So this is malformed input, refused at the gate like every other
// operator error, rather than a silent weakening of the proof.
//
// It is deliberately NOT enforced in LoadAnchorFile: two callers load an anchor
// opportunistically (attest facts, trust arming) and must keep degrading quietly
// on a document they merely could not use. The rule belongs where the anchor is
// used AS PROOF.
func (a *Anchor) RequireIdentity() error {
	if a == nil {
		return fmt.Errorf("no anchor")
	}
	if a.LedgerId == "" {
		return fmt.Errorf("the anchor names no ledgerId — it cannot say which " +
			"ledger it manifests, and the identity checks that key on it (foreign " +
			"capsule, genesis presence, restored identity) would all pass vacuously")
	}
	return nil
}

// ApplyAnchorPolicy arms verification from a loaded anchor (D135) —
// call BEFORE replaying the ledger the anchor guards. Conflicts with a
// CLI-armed policy refuse (MergeAnchorPolicy).
func ApplyAnchorPolicy(a *Anchor) error {
	if a == nil || a.Trust == nil {
		return nil
	}
	return MergeAnchorPolicy(a.Trust.Scheme, a.Trust.Keys, a.Trust.From)
}

type AnchorCheck struct {
	Status       string   `json:"status"` // verified | truncated | diverged
	AnchorEvents int      `json:"anchorEvents"`
	LedgerEvents int      `json:"ledgerEvents"`
	Reasons      []string `json:"reasons,omitempty"`
}

// CheckAnchor verifies the replayed ledger extends the anchored
// prefix. Positional: the hash at line anchor.Events must equal
// anchor.Head.
func CheckAnchor(led *Ledger, a *Anchor) *AnchorCheck {
	res := &AnchorCheck{AnchorEvents: a.Events,
		LedgerEvents: led.TotalEvents()}
	if a.Events < 0 {
		res.Status = "diverged"
		res.Reasons = []string{"anchor has a negative event count"}
		return res
	}
	if a.Events == 0 {
		// an anchor of zero events pins nothing; it may only claim the
		// genesis head, or it is a malformed/forged anchor asserting a
		// non-empty head over an empty prefix — reject that, don't
		// rubber-stamp any ledger (adversarial review).
		if a.Head != "" && a.Head != "genesis" {
			res.Status = "diverged"
			res.Reasons = []string{"anchor pins 0 events but a non-genesis " +
				"head — malformed or forged anchor"}
			return res
		}
		res.Status = "verified" // an empty anchor is trivially extended
		return res
	}
	if led.TotalEvents() < a.Events {
		res.Status = "truncated"
		res.Reasons = []string{fmt.Sprintf(
			"the anchor pins %d events but the ledger has %d — the tail "+
				"was cut after anchoring", a.Events, led.TotalEvents())}
		return res
	}
	// D137 (review fix): an anchor cut at a compaction pins the fold
	// itself — a swapped snapshot with a preserved tail is divergence
	if a.SnapshotHash != "" && led.snapshotHash != a.SnapshotHash {
		res.Status = "diverged"
		res.Reasons = []string{fmt.Sprintf(
			"the anchor pins snapshot %s… but the ledger seeds from %s… — "+
				"the fold was swapped after anchoring",
			trunc(a.SnapshotHash), trunc(led.snapshotHash))}
		return res
	}
	// D137: positions are absolute across snapshots. The snapshot
	// boundary itself is checkable (baseHead); anchors strictly inside
	// the compacted prefix cannot be positionally verified against the
	// live file — refuse toward the archive rather than rubber-stamp.
	var got string
	switch {
	case a.Events == led.BaseEvents:
		got = led.BaseHead
	case a.Events < led.BaseEvents:
		res.Status = "diverged"
		res.Reasons = []string{fmt.Sprintf(
			"the anchor pins event %d but the ledger was compacted at "+
				"%d (D137) — verify against the archive, then re-anchor "+
				"the live file", a.Events, led.BaseEvents)}
		return res
	default:
		got = led.EventHashes[a.Events-led.BaseEvents-1]
	}
	if got != a.Head {
		res.Status = "diverged"
		res.Reasons = []string{fmt.Sprintf(
			"event %d is %s but the anchor pinned %s — history was "+
				"rewritten after anchoring", a.Events, got, a.Head)}
		return res
	}
	// Complete forest guard (D185): the positional Head commits only to
	// the sub-chain owning the last line. The manifest commits to EVERY
	// live line hash in order, so recomputing it over the anchored prefix
	// catches a count-preserving rewrite of ANY interior event — including
	// an independent capability's tail behind a grown suffix, which the
	// heads check below (tip-only) cannot see. Gated on an unchanged
	// compaction position: a further compaction moved the archive boundary
	// and the positional/snapshot checks above own that verdict.
	if a.Manifest != "" && a.BaseEvents == led.BaseEvents {
		liveCount := a.Events - led.BaseEvents
		if liveCount >= 0 && liveCount <= len(led.EventHashes) {
			if got := ledgerManifest(led.BaseHead,
				led.EventHashes[:liveCount]); got != a.Manifest {
				res.Status = "diverged"
				res.Reasons = []string{"the ledger manifest diverges from the " +
					"anchor though the last line still matches — an interior " +
					"event was rewritten (the per-capability forest gap)"}
				return res
			}
		}
	}
	// Secondary tip-only guard, and the fallback for a manifest-less
	// (pre-D185) anchor: when the anchor covers the WHOLE current ledger
	// its recorded per-capability heads are reconstructable from this
	// replay and must match exactly.
	if a.Events == led.TotalEvents() {
		if len(a.Heads) > 0 && !mapsEqualStr(led.Heads, a.Heads) {
			res.Status = "diverged"
			res.Reasons = []string{"a capability head diverges from the " +
				"anchor though the last line still matches — an independent " +
				"capability's tail was rewritten count-preservingly"}
			return res
		}
		if len(a.DecisionHeads) > 0 &&
			!mapsEqualStr(led.DecisionHeads, a.DecisionHeads) {
			res.Status = "diverged"
			res.Reasons = []string{"a decision head diverges from the anchor " +
				"though the last line still matches — a decision sub-chain " +
				"was rewritten count-preservingly"}
			return res
		}
	}
	res.Status = "verified"
	return res
}

// mapsEqualStr reports whether two string maps have identical keys and
// values — the anchor's per-capability heads against the replayed fold.
func mapsEqualStr(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}

func copyMap(m map[string]string) map[string]string {
	out := map[string]string{}
	for k, v := range m {
		out[k] = v
	}
	return out
}

// copyBoolMap copies a set-style map, returning nil for an empty input so
// the snapshot stays canon-empty (matches the ledger's canonEmpty and the
// DeepEqual equivalence check).
func copyBoolMap(m map[string]bool) map[string]bool {
	if len(m) == 0 {
		return nil
	}
	out := map[string]bool{}
	for k, v := range m {
		if v {
			out[k] = v
		}
	}
	return out
}
