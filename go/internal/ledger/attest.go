// Integrity attestation (D139): a deterministic, read-only report of a
// ledger's PROVENANCE — its identity, compaction state, signature
// coverage and anchor presence. It is the source a read-only consumer
// projects into an integrity view; such a consumer has no verifier, so
// groundhold must ESTABLISH these facts and the consumer only shows them.
//
// The honesty line the whole design turns on: attest reports what is
// PRESENT and what groundhold can check WITHOUT a policy — every counted
// signature verifies against ITS OWN claimed key (the math is
// deterministic), but "signed by a key you trust" is the operator's
// --trust decision and appears nowhere here. Presence is a fact;
// trust is a judgment, and attest makes only facts.
package ledger

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"sort"

	"groundhold/internal/canonical"
)

type IntegrityReport struct {
	APIVersion  string `json:"apiVersion"` // integrity/v0.1
	Kind        string `json:"kind"`       // IntegrityReport
	GeneratedAt string `json:"generatedAt"`
	// identity + shape (D134/D137)
	LedgerId    string `json:"ledgerId,omitempty"`
	TotalEvents int    `json:"totalEvents"`
	TailEvents  int    `json:"tailEvents"`
	BaseEvents  int    `json:"baseEvents"`

	Signatures SignatureFacts `json:"signatures"`
	Snapshot   *SnapshotFacts `json:"snapshot,omitempty"`
	Anchor     *AnchorFacts   `json:"anchor,omitempty"`
}

// SignatureFacts counts PRESENCE and SELF-CONSISTENCY, never trust —
// the words are chosen so a reader cannot mistake them for a verdict
// (adversarial review). The window is the TAIL ONLY: base events compacted
// into the archive are represented by the snapshot receipt, not
// re-inspected here (ArchivedBase records how many are unaccounted).
//   - SelfVerified: envelope present AND the signature verifies against
//     ITS OWN claimed key and this ledger's identity — the math, no policy.
//   - EnvelopePresentButInvalid: a sig is present but does not verify —
//     tamper evidence, its own fact, never counted as signed.
//   - Unsigned: no envelope.
//
// Signers lists the keys that produced self-verifying signatures.
type SignatureFacts struct {
	TailEvents                int      `json:"tailEvents"`
	SelfVerified              int      `json:"selfVerified"`
	EnvelopePresentButInvalid int      `json:"envelopePresentButInvalid"`
	Unsigned                  int      `json:"unsigned"`
	ArchivedBase              int      `json:"archivedBase"` // compacted, NOT inspected here
	Signers                   []Signer `json:"signers,omitempty"`
}

type Signer struct {
	Pub   string `json:"pub"`
	Count int    `json:"count"`
}

// SnapshotFacts: what the snapshot receipt SAYS (ReceiptMode) is kept
// distinct from what attest checked NOW (SignatureSelfVerifies,
// LedgerIdMatches) — the receipt is the emitter's claim, the checks are
// this run's facts (adversarial review).
type SnapshotFacts struct {
	Present               bool   `json:"present"`
	BaseEvents            int    `json:"baseEvents"`
	ReceiptMode           string `json:"receiptMode,omitempty"` // what verifiedUnder SAYS: filesystem | trust
	SignaturePresent      bool   `json:"signaturePresent"`
	SignatureSelfVerifies bool   `json:"signatureSelfVerifies"` // checked NOW, against its own key
	LedgerIdMatches       bool   `json:"ledgerIdMatches"`
}

// AnchorFacts: presence is decoration without a positional check, so
// Status is the POSITIONAL result of re-checking the anchor against the
// live ledger (adversarial review): absent | verified | truncated | diverged.
type AnchorFacts struct {
	Status       string `json:"status"` // verified | truncated | diverged
	Events       int    `json:"events"`
	Head         string `json:"head,omitempty"`
	SnapshotHash string `json:"snapshotHash,omitempty"`
	PinsTrust    bool   `json:"pinsTrust"`
}

// Attest replays the ledger (seeding from any snapshot) and reports the
// provenance facts. It does NOT arm --trust: presence and self-
// consistency only. A cryptographically invalid signature is counted
// as EnvelopePresentButInvalid, never as self-verified — attest never
// launders tamper into a coverage number.
func Attest(path, generatedAt string) (*IntegrityReport, error) {
	led, err := ReplayFile(path)
	if err != nil {
		return nil, err
	}
	rep := &IntegrityReport{
		APIVersion: "integrity/v0.1", Kind: "IntegrityReport",
		GeneratedAt: generatedAt,
		LedgerId:    led.LedgerId(),
		TotalEvents: led.TotalEvents(),
		TailEvents:  len(led.EventHashes),
		BaseEvents:  led.BaseEvents,
	}
	rep.Signatures = tailSignatureFacts(path, led.LedgerId())
	rep.Signatures.ArchivedBase = led.BaseEvents

	if snap, err := LoadSnapshotFile(SnapshotPath(path)); err == nil && snap != nil {
		sf := &SnapshotFacts{Present: true, BaseEvents: snap.BaseEvents,
			SignaturePresent: snap.Sig != nil,
			LedgerIdMatches:  snap.LedgerId == led.LedgerId(),
			SignatureSelfVerifies: snap.Sig != nil &&
				snapshotSelfVerifies(snap),
		}
		if snap.VerifiedUnder != nil {
			sf.ReceiptMode = snap.VerifiedUnder.Mode
		}
		rep.Snapshot = sf
	}
	if a, err := LoadAnchorFile(AnchorPath(path)); err == nil && a != nil {
		chk := CheckAnchor(led, a)
		rep.Anchor = &AnchorFacts{Status: chk.Status, Events: a.Events,
			Head: a.Head, SnapshotHash: a.SnapshotHash,
			PinsTrust: a.Trust != nil}
	}
	return rep, nil
}

// snapshotSelfVerifies checks the snapshot's own detached signature
// against its own claimed key (the D137 message layout), no policy.
func snapshotSelfVerifies(s *Snapshot) bool {
	pubHex, _ := s.Sig["pub"].(string)
	pub, err := hex.DecodeString(pubHex)
	if err != nil || len(pub) != ed25519.PublicKeySize || s.Sig["alg"] != "ed25519" {
		return false
	}
	sigHex, _ := s.Sig["sig"].(string)
	sigBytes, err := hex.DecodeString(sigHex)
	if err != nil || len(sigBytes) != ed25519.SignatureSize {
		return false
	}
	claim, _ := s.Sig["ledger"].(string)
	if claim != s.LedgerId {
		return false
	}
	var doc map[string]any
	raw, _ := json.Marshal(s)
	if json.Unmarshal(raw, &doc) != nil {
		return false
	}
	normalize(doc)
	h, err := HashSnapshot(doc)
	if err != nil {
		return false
	}
	msg := []byte(snapshotDomain + ":" + claim + ":" + h)
	return ed25519.Verify(ed25519.PublicKey(pub), msg, sigBytes)
}

// tailSignatureFacts counts signatures across the tail lines, verifying
// each against its OWN claimed key — deterministic, policy-free.
func tailSignatureFacts(path, ledgerID string) SignatureFacts {
	docs, err := readLines(path)
	if err != nil {
		return SignatureFacts{}
	}
	facts := SignatureFacts{TailEvents: len(docs)}
	counts := map[string]int{}
	for _, doc := range docs {
		sig, ok := doc["sig"].(map[string]any)
		if !ok {
			facts.Unsigned++
			continue
		}
		if selfVerify(doc, sig, ledgerID) {
			facts.SelfVerified++
			pub, _ := sig["pub"].(string)
			counts[pub]++
		} else {
			facts.EnvelopePresentButInvalid++
		}
	}
	facts.Signers = sortSigners(counts)
	return facts
}

// selfVerify checks a signature against the key IT claims — the
// cryptographic math, no trust policy. A malformed envelope is not
// valid (fail-closed).
func selfVerify(doc, sig map[string]any, ledgerID string) bool {
	if sig["alg"] != "ed25519" {
		return false
	}
	pubHex, _ := sig["pub"].(string)
	pub, err := hex.DecodeString(pubHex)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return false
	}
	sigHex, _ := sig["sig"].(string)
	sigBytes, err := hex.DecodeString(sigHex)
	if err != nil || len(sigBytes) != ed25519.SignatureSize {
		return false
	}
	claim, _ := sig["ledger"].(string)
	// the claim must match the stream identity — a valid signature for
	// a foreign ledger is not a valid signature for THIS one
	if claim != ledgerID {
		return false
	}
	h, err := canonical.HashEvent(doc)
	if err != nil {
		return false
	}
	return ed25519.Verify(ed25519.PublicKey(pub), sigMessage(claim, h), sigBytes)
}

func sortSigners(counts map[string]int) []Signer {
	if len(counts) == 0 {
		return nil
	}
	pubs := make([]string, 0, len(counts))
	for p := range counts {
		pubs = append(pubs, p)
	}
	sort.Strings(pubs)
	out := make([]Signer, 0, len(pubs))
	for _, p := range pubs {
		out = append(out, Signer{Pub: p, Count: counts[p]})
	}
	return out
}
