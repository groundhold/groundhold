// Evidence capsules (D103): a SELF-CONTAINED proof for one capability —
// its full event subchain verbatim (genesis -> tip) plus the tip hash.
// A receiver verifies it with no ledger, no filesystem trust and no
// groundhold deployment: replay the prev[cap] linkage, recompute the
// hashes, check the signatures under --trust, and pin the tip against
// an anchor they hold (--check).
//
// What a verified capsule proves: "this capability's history, in this
// order, said exactly this — and (under --trust) was authored by this
// key". What it does NOT prove: that nothing newer exists. Omission of
// a fresh suffix is countered by the receiver's anchor (D70), never by
// the capsule itself; the spec says so out loud.
//
// Multi-capability events are carried verbatim: their prev entries for
// OTHER capabilities are opaque inputs here (their chains are not in
// this capsule), but they are integrity-bound — the event hash covers
// them, so they cannot be doctored without breaking this chain.
package ledger

import (
	"encoding/json"
	"fmt"
	"strings"

	"groundhold/internal/canonical"
	"groundhold/internal/state"
)

// Verification parameters a capsule must declare (D132): the algebra
// it was built with, so a future verifier refuses instead of silently
// reinterpreting. Exact-match pins — this verifier implements exactly
// these and guesses nothing.
const (
	CapsuleHashAlg = "sha256"
	CapsuleCanon   = "groundhold/canon/v1"
)

type Capsule struct {
	APIVersion string `json:"apiVersion"`
	Kind       string `json:"kind"`
	// self-description (D132): how the hashes below were computed
	EventHashAlg     string           `json:"eventHashAlg"`
	Canonicalization string           `json:"canonicalization"`
	Capability       string           `json:"capability"`
	Head             string           `json:"head"` // tip event hash for this capability
	AsOf             string           `json:"asOf"` // tip event's occurredAt — the claim's own time
	Events           []map[string]any `json:"events"`
}

// EmitCapsule builds the capsule from a VALID ledger — it replays the
// file first (which also enforces --trust when armed): a capsule cut
// from a corrupt ledger would launder corruption into a portable
// document. A capability with no events refuses: an empty proof is a
// lie shaped like a document.
func EmitCapsule(path, capability string) (*Capsule, error) {
	led, err := ReplayFile(path)
	if err != nil {
		return nil, err
	}
	head, ok := led.Heads[capability]
	if !ok {
		return nil, fmt.Errorf(
			"no events for capability %q — nothing to prove", capability)
	}
	// D137: a capsule is the subchain from GENESIS — a capability whose
	// early history was compacted cannot be proven from the tail alone.
	if snap, err := LoadSnapshotFile(SnapshotPath(path)); err != nil {
		return nil, err
	} else if snap != nil && snap.Heads[capability] != "" {
		return nil, fmt.Errorf("capability %q predates the snapshot — a capsule "+
			"is a chain from GENESIS and this one begins in the archive. Emitting "+
			"from the archive does not substitute: those capsules end at the "+
			"pre-snapshot head, which the live anchor no longer pins (D137/D313). "+
			"Preserve the archive files themselves for the compacted era",
			capability)
	}
	docs, err := readLines(path)
	if err != nil {
		return nil, err
	}
	c := &Capsule{APIVersion: "capsule/v0.1", Kind: "EvidenceCapsule",
		EventHashAlg: CapsuleHashAlg, Canonicalization: CapsuleCanon,
		Capability: capability, Head: head}
	for _, doc := range docs {
		ev, _ := doc["event"].(map[string]any)
		if !listsCapability(ev, capability) {
			continue
		}
		c.Events = append(c.Events, doc)
		occurred, _ := ev["occurredAt"].(string)
		c.AsOf = occurred
	}
	return c, nil
}

// VerifyCapsule is the standalone check — pure structure, no ledger.
// anchor may be nil (no omission check, honestly weaker). The returned
// string is the ledger identity the capsule's signatures consistently
// claimed (D134) — and it proves only that the events were signed for
// SOME common ledger, never membership in the receiver's; membership
// is exactly what --check against the receiver's anchor adds.
func VerifyCapsule(c *Capsule, anchor *Anchor) (string, error) {
	if c.APIVersion != "capsule/v0.1" || c.Kind != "EvidenceCapsule" {
		return "", fmt.Errorf("not a capsule/v0.1 EvidenceCapsule document")
	}
	// D132: the capsule must say how it hashes, and it must be the
	// algebra THIS verifier implements — anything else is a guess, and
	// a verifier that guesses is not a verifier.
	if c.EventHashAlg != CapsuleHashAlg {
		return "", fmt.Errorf("capsule declares eventHashAlg %q; this "+
			"verifier implements %q — refusing to guess",
			c.EventHashAlg, CapsuleHashAlg)
	}
	if c.Canonicalization != CapsuleCanon {
		return "", fmt.Errorf("capsule declares canonicalization %q; this "+
			"verifier implements %q — refusing to guess",
			c.Canonicalization, CapsuleCanon)
	}
	if c.Capability == "" || len(c.Events) == 0 {
		return "", fmt.Errorf("capsule carries no capability or no events")
	}
	prev, asOf := "genesis", ""
	trust := NewTrustChecker()
	for i, doc := range c.Events {
		where := fmt.Sprintf("capsule event %d", i+1)
		// A receiver reaches this straight off json.Unmarshal, which decodes
		// every number as float64 — so integer-typed fields (fencingToken,
		// generation) would fail ValidateEvent's int assertion and a valid
		// proof carrying any lease/mutation event would spuriously refuse.
		// Normalize exactly as ReplayFile/loadCapsule do: the standalone
		// verifier must be self-sufficient, not depend on its caller (D103).
		normalize(doc)
		if _, err := state.ValidateEvent(doc); err != nil {
			return "", fmt.Errorf("%s: %v", where, err)
		}
		ev, _ := doc["event"].(map[string]any)
		if !listsCapability(ev, c.Capability) {
			return "", fmt.Errorf("%s: does not list capability %q — a "+
				"foreign event cannot witness this chain", where, c.Capability)
		}
		pm, _ := ev["prev"].(map[string]any)
		got, _ := pm[c.Capability].(string)
		if got != prev {
			return "", fmt.Errorf("%s: linkage broken: prev is %q but the "+
				"chain so far ends at %q (reordered, dropped or spliced)",
				where, got, prev)
		}
		if err := trust.Check(doc, i+1); err != nil {
			return "", err
		}
		h, err := canonical.HashEvent(doc)
		if err != nil {
			return "", fmt.Errorf("%s: %v", where, err)
		}
		prev = h
		asOf, _ = ev["occurredAt"].(string)
	}
	if err := trust.Finish(); err != nil {
		// A capsule is ONE capability's subchain; a --trust-from boundary
		// (armed here from the anchor's embedded policy, D135) names one
		// global event that belongs to whichever capability authored it and
		// need NOT appear in this subchain. Finish then refuses "boundary
		// absent". That refusal is correct — a capsule that does not carry
		// the boundary cannot locally prove which of its events are
		// post-boundary and thus must be signed, so accepting it would be
		// fail-open — but the generic message misreads as truncation. Say
		// the real limitation instead (a naive relaxation is unsafe, so this
		// stays a refusal, not a pass — see spec/capsule.md).
		return "", fmt.Errorf("%w — this is a per-capability capsule verified "+
			"under a --trust-from anchor whose boundary lies in another "+
			"capability's chain; capsules from a partially-signed ledger can "+
			"only be verified against an anchor without a trust boundary, or "+
			"from a ledger signed from genesis", err)
	}
	if prev != c.Head {
		return "", fmt.Errorf("recomputed tip %s does not match the capsule's "+
			"claimed head %s — the carried events are not the events the "+
			"head names", prev, c.Head)
	}
	if c.AsOf != asOf {
		return "", fmt.Errorf("capsule claims asOf %s but its tip event says "+
			"%s — a proof must not claim a different time than its "+
			"evidence", c.AsOf, asOf)
	}
	if anchor != nil {
		// D312: an anchor with no ledgerId cannot discharge the check below —
		// refuse it rather than let the comparison pass vacuously.
		if err := anchor.RequireIdentity(); err != nil {
			return "", err
		}
		// D134: a capsule claiming a different ledger than the anchor
		// pins is someone else's history, even under the same keys
		if trust.LedgerID() != "" && trust.LedgerID() != anchor.LedgerId {
			return "", &TrustError{Err: fmt.Errorf("the capsule's signatures claim "+
				"ledger %s… but the anchor pins %s… — a foreign ledger's capsule "+
				"under a shared key", trunc(trust.LedgerID()), trunc(anchor.LedgerId))}
		}
		want, ok := anchor.Heads[c.Capability]
		if !ok {
			return "", fmt.Errorf("the anchor pins no head for %q — it "+
				"anchors a different ledger or an era before this "+
				"capability", c.Capability)
		}
		if want != c.Head {
			return "", fmt.Errorf("the anchor pins head %s for %q but the "+
				"capsule ends at %s — a stale capsule (newer history was "+
				"withheld) or a foreign one", want, c.Capability, c.Head)
		}
	}
	return trust.LedgerID(), nil
}

// readLines returns the verbatim (normalized) line documents of a
// ledger file that ReplayFile has already accepted.
func readLines(path string) ([]map[string]any, error) {
	raw, err := readLedger(path)
	if err != nil {
		return nil, err
	}
	var out []map[string]any
	for i, line := range splitLines(raw) {
		if line == "" {
			continue
		}
		doc, err := parseLine(line, i+1)
		if err != nil {
			return nil, err
		}
		out = append(out, doc)
	}
	return out, nil
}

func splitLines(raw []byte) []string {
	return strings.Split(strings.TrimRight(string(raw), "\n"), "\n")
}

func parseLine(line string, n int) (map[string]any, error) {
	var doc map[string]any
	if err := json.Unmarshal([]byte(line), &doc); err != nil {
		return nil, fmt.Errorf("ledger line %d: %v", n, err)
	}
	normalize(doc)
	return doc, nil
}

func listsCapability(ev map[string]any, capability string) bool {
	caps, _ := ev["capabilities"].([]any)
	for _, c := range caps {
		if s, _ := c.(string); s == capability {
			return true
		}
	}
	return false
}
