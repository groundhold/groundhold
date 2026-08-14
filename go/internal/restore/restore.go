// Capsule-based disaster recovery, slice 1 (D103 lineage): rebuild a
// ledger from a set of per-capability evidence capsules (spec/capsule.md)
// plus the off-host anchor that manifests them (D70). Restore adds NO new
// verification math — it composes the existing VerifyCapsule and the
// standard replay fold — then deterministically re-weaves the verified
// subchains into one ledger, or refuses a set it cannot vouch for.
//
// The anchor is the backup manifest: heads is the table of contents,
// events is the totality check, ledgerId is the identity, trust is the
// policy (D135, armed automatically here). What restore rebuilds is
// KNOWLEDGE — decision history and bindings — never secrets (excluded
// from the ledger by construction) and never live provider state
// (evidence of a resource is not the resource; the freshness gates make
// restored observations stale until re-observed).
//
// Slice 2 adds MERGE: a capability may have multiple sources (an old backup
// and a newer one, or a re-emit). They are adjudicated to one winning chain by
// closed rules — dedupe identical, longer-contains-shorter wins (proven by set
// containment, never trust), fork refuses — and the winner is pinned to the
// anchor's authoritative tip.
//
// Slice 3 adds --partial: instead of refusing the whole set when one capability
// is missing/tampered/stale/forked/foreign, restore rebuilds the SOUND
// capabilities and records the rest as status:unknown with a code, writing ZERO
// events for them. Invariant #1 then makes every downstream query answer
// unknown for a withheld capability — restore fabricates nothing. A multi-
// capability event whose co-listed capability is unknown couples them: the sound
// capability is demoted (capsule-coupled) rather than write a half-real event.
//
// Documents (slice 4) live in `groundhold backup --documents` and are verified by
// `backup.VerifyDocuments`, NOT here: restore rebuilds the ledger — the decision
// history — and says nothing about the contract blobs those decisions referenced.
// A recovery that needs them runs the document verify separately. (This comment
// said "still a later slice" long after the slice shipped; D312.)
package restore

import (
	"container/heap"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"groundhold/internal/canonical"
	"groundhold/internal/ledger"
)

// Exit codes the CLI wrapper maps directly (match the capsule verb):
//
//	ExitOK       restore succeeded, the ledger + anchor + report exist.
//	ExitRefused  the set does not hold together — a capsule failed
//	             verification, the manifest disagreed, the re-woven
//	             history did not replay, or it could not be linearized.
//	             Corruption-class, exactly like `capsule --verify`.
//	ExitOperator an operator/input error — missing flag, unreadable or
//	             malformed file, refusing to clobber an existing ledger.
const (
	ExitOK       = 0
	ExitRefused  = 5
	ExitOperator = 1
)

// Options are the parsed CLI inputs. AnchorPath is REQUIRED in slice 1:
// without the manifest a capsule set proves each chain internally but
// never "and this is all of them" — the omission gap the anchor closes.
type Options struct {
	Out          string   // --out: the ledger file to write (must not exist)
	AnchorPath   string   // --check: the off-host anchor that manifests the set
	CapsulePaths []string // the capsule.json files, one per capability
	Partial      bool     // --partial: restore the sound capabilities, mark the rest unknown
}

// CapStatus is one capability's fate under --partial: restored, or unknown with
// a code naming why (so downstream honestly answers unknown for it, invariant #1).
type CapStatus struct {
	Capability string `json:"capability"`
	Status     string `json:"status"` // restored | unknown
	Code       string `json:"code,omitempty"`
	Reason     string `json:"reason,omitempty"`
}

// RestoreReport is the deterministic, machine-readable receipt. On
// refusal Status is "refused" and Reasons names why; nothing is written.
type RestoreReport struct {
	APIVersion   string              `json:"apiVersion"`
	Kind         string              `json:"kind"`
	Status       string              `json:"status"` // restored | refused
	LedgerID     string              `json:"ledgerId,omitempty"`
	Events       int                 `json:"events"`
	Capabilities []string            `json:"capabilities,omitempty"`
	RestoredFrom map[string]any      `json:"restoredFrom,omitempty"`
	Merged       map[string][]string `json:"merged,omitempty"`  // cap -> superseded/duplicate source paths (merge)
	Partial      []CapStatus         `json:"partial,omitempty"` // per-capability fate under --partial
	Reasons      []string            `json:"reasons,omitempty"`
}

// Run performs a single-source restore. It returns the report and the
// exit code the CLI should surface; it never panics on bad input and
// writes the output ledger ONLY when every check passed and the rebuilt
// history replayed clean.
func Run(opts Options) (*RestoreReport, int) {
	rep := &RestoreReport{
		APIVersion: "restore/v0.1", Kind: "RestoreReport", Status: "refused"}

	// --- operator-input gate (exit 1): the inputs must be usable ---
	if opts.Out == "" {
		return op(rep, "restore requires --out <ledger>")
	}
	if opts.AnchorPath == "" {
		return op(rep, "restore requires --check <anchor.json> — a capsule "+
			"set without its manifest cannot be proven complete (slice 1 "+
			"has no --no-check)")
	}
	if len(opts.CapsulePaths) == 0 {
		return op(rep, "restore requires at least one capsule")
	}
	if _, err := os.Stat(opts.Out); err == nil {
		return op(rep, fmt.Sprintf("refusing to overwrite existing ledger "+
			"%s — restore writes a FRESH artifact", opts.Out))
	}

	anchor, err := ledger.LoadAnchorFile(opts.AnchorPath)
	if err != nil {
		return op(rep, err.Error())
	}
	// D312: an anchor that cannot identify its ledger is malformed input. Every
	// identity check below keys on this field; without it they pass vacuously and
	// restore would claim success for a set it never proved belongs together.
	if err := anchor.RequireIdentity(); err != nil {
		return op(rep, err.Error())
	}
	// D135: the anchor carries the trust policy the emitting process
	// verified under; arm it BEFORE verifying any capsule, so a
	// signature-stripped backup refuses with no flags given at all.
	if err := ledger.ApplyAnchorPolicy(anchor); err != nil {
		return op(rep, err.Error())
	}

	// --- load + group (exit 1 on malformed input) ---
	// A capability may have MULTIPLE sources (merge, slice 2). Load and group
	// by capability; verification/adjudication happens per capability below.
	groups := map[string][]*capInfo{}
	for _, p := range opts.CapsulePaths {
		c, err := loadCapsule(p)
		if err != nil {
			return op(rep, err.Error()) // malformed input, not corruption
		}
		hs, err := capsuleHashes(c)
		if err != nil {
			return op(rep, fmt.Sprintf("capsule %s: %v", p, err))
		}
		groups[c.Capability] = append(groups[c.Capability],
			&capInfo{path: p, cap: c, hashes: hs})
	}
	// an extra capsule for a capability the anchor does NOT name means the set
	// does not match the manifest — refuse in BOTH modes (it is not a partial
	// backup, it is a wrong one).
	for cap := range groups {
		if _, ok := anchor.Heads[cap]; !ok {
			return refuse(rep, fmt.Sprintf("a capsule names capability %q but the "+
				"anchor pins no head for it — the set does not match the manifest", cap))
		}
	}

	// --- classify each capability (verify + merge + anchor-tip pin) ---
	// Full mode: the FIRST unsound capability refuses the whole restore.
	// --partial mode: an unsound capability is recorded unknown+code and its
	// events are withheld entirely (invariant #1 makes downstream answer
	// unknown), while the sound capabilities still restore.
	byCap := map[string]*ledger.Capsule{}
	merged := map[string][]string{}
	statuses := map[string]CapStatus{}
	for _, cap := range sortedKeys(anchor.Heads) {
		winner, alts, code, reason := classifyCapability(cap, groups[cap], anchor)
		if code != "" {
			if !opts.Partial {
				return refuse(rep, reason)
			}
			statuses[cap] = CapStatus{Capability: cap, Status: "unknown",
				Code: code, Reason: reason}
			continue
		}
		byCap[cap] = winner
		statuses[cap] = CapStatus{Capability: cap, Status: "restored"}
		if len(alts) > 0 {
			merged[cap] = alts
		}
	}

	// --- coupling fixpoint (--partial only) ---
	// A multi-capability event cannot be written unless EVERY capability it
	// lists is restored — writing it would fabricate the missing capability's
	// history. A restored capability whose chain passes through such an event
	// therefore cannot honestly reach its anchor tip, so it is demoted to
	// unknown (capsule-coupled). Repeat until stable.
	if opts.Partial {
		for {
			demoted := ""
			for _, cap := range sortedKeys(byCap) {
				if bad := firstUnknownCoupling(byCap[cap], byCap); bad != "" {
					demoted = cap
					statuses[cap] = CapStatus{Capability: cap, Status: "unknown",
						Code: "capsule-coupled", Reason: fmt.Sprintf("capability %q "+
							"shares an event with %q, which is unknown — its tail "+
							"cannot be restored without fabricating that history", cap, bad)}
					delete(byCap, cap)
					delete(merged, cap)
					break
				}
			}
			if demoted == "" {
				break
			}
		}
	}

	// --- manifest gate (full mode): every anchor capability must restore ---
	if !opts.Partial {
		// D312: sorted — map order must not choose WHICH capability a refusal
		// names. The report is machine-readable output; two identical runs that
		// disagree about their reason are two different answers (D186's rule,
		// applied to the recovery path).
		for _, cap := range sortedKeys(anchor.Heads) {
			if _, ok := byCap[cap]; !ok {
				return refuse(rep, fmt.Sprintf("the anchor names capability %q "+
					"but no capsule was supplied — an incomplete backup is not "+
					"a restore", cap))
			}
		}
	}

	// dedupe multi-capability events by canonical hash (hash excludes the
	// signature, so hash-equal IS event-equal). Only the restored winners
	// contribute — under --partial the withheld capabilities add nothing.
	events, err := dedupe(byCap)
	if err != nil {
		return refuse(rep, err.Error())
	}
	if !opts.Partial {
		if len(events) != anchor.Events {
			return refuse(rep, fmt.Sprintf("the deduped event count %d does not "+
				"equal the anchor's %d — events were dropped or the set is not "+
				"this ledger's", len(events), anchor.Events))
		}
		if events[anchor.LedgerId] == nil {
			return refuse(rep, "the anchor's genesis event is absent from the "+
				"capsule set — the history has no root to restore from")
		}
	}

	// deterministically re-weave the verified subchains into one line order:
	// Kahn over the per-capability prev edges, ties broken by (occurredAt,
	// eventHash), genesis (hash==ledgerId) pinned to line 1 when present.
	lines, err := linearize(events, anchor.LedgerId)
	if err != nil {
		return refuse(rep, err.Error())
	}

	// write, then REPLAY: the restored artifact is accepted only if it folds
	// clean through the exact rules every writer obeyed.
	if err := writeLines(opts.Out, lines); err != nil {
		return op(rep, err.Error())
	}
	restored, err := ledger.ReplayFile(opts.Out)
	if err != nil {
		os.Remove(opts.Out)
		return refuse(rep, fmt.Sprintf("the re-woven history does not "+
			"replay: %v", err))
	}
	// belt-and-suspenders: full mode reproduces the manifest exactly; partial
	// mode asserts only that each RESTORED capability reached its anchor tip.
	if !opts.Partial {
		if restored.LedgerId() != anchor.LedgerId {
			os.Remove(opts.Out)
			return refuse(rep, "the restored ledger's identity does not match "+
				"the anchor's ledgerId")
		}
		if restored.TotalEvents() != anchor.Events {
			os.Remove(opts.Out)
			return refuse(rep, fmt.Sprintf("the restored ledger has %d events, "+
				"the anchor pins %d", restored.TotalEvents(), anchor.Events))
		}
	}
	for _, cap := range sortedKeys(byCap) {
		if restored.Heads[cap] != anchor.Heads[cap] {
			os.Remove(opts.Out)
			return refuse(rep, fmt.Sprintf("restored head for %q is %s, the "+
				"anchor pins %s", cap, restored.Heads[cap], anchor.Heads[cap]))
		}
	}

	// cut a FRESH anchor for the new artifact (its line order is a
	// canonical linearization, not the original interleave — the old
	// positional anchor no longer applies).
	fresh := ledger.BuildAnchor(restored)
	if err := writeAnchor(ledger.AnchorPath(opts.Out), fresh); err != nil {
		os.Remove(opts.Out)
		return op(rep, err.Error())
	}

	rep.Status = "restored"
	rep.LedgerID = restored.LedgerId()
	rep.Events = restored.TotalEvents()
	rep.Capabilities = sortedKeys(byCap)
	if len(merged) > 0 {
		rep.Merged = merged
	}
	if opts.Partial {
		rep.Partial = make([]CapStatus, 0, len(statuses))
		for _, cap := range sortedKeys(statuses) {
			rep.Partial = append(rep.Partial, statuses[cap])
			if statuses[cap].Status == "unknown" {
				rep.Status = "partial"
			}
		}
	}
	rep.RestoredFrom = map[string]any{
		"originalLedgerId":   anchor.LedgerId,
		"originalAnchorHead": anchor.Head,
		"capsuleHeads":       capsuleHeads(byCap),
	}

	// D618: `--partial` returned ExitOK however much it had failed to restore —
	// including ALL of it. A run where every capability came back `unknown` wrote a
	// zero-byte ledger, wrote a FRESH anchor beside it, and exited 0; from the next
	// minute on, `anchor --check` and `attest` both certified that empty file as the
	// recovered history. The truth lived only inside the `partial[]` block of a
	// report nobody re-reads after a green exit.
	//
	// `--partial` means "give me what can be proven and tell me what cannot", not
	// "call an empty recovery a success". A restore that recovered NOTHING is a
	// failed restore, and D313 already established that a refused run must not leave
	// a plausible artefact behind.
	if opts.Partial && restored.TotalEvents() == 0 {
		os.Remove(ledger.AnchorPath(opts.Out))
		os.Remove(opts.Out)
		rep.Status = "refused"
		rep.Events = 0
		rep.Reasons = append(rep.Reasons, "--partial restored ZERO events: every "+
			"capability was unprovable, so there is no history here. The empty ledger "+
			"and its anchor have been removed rather than left for a later check to "+
			"certify as a recovered estate.")
		return rep, ExitRefused
	}
	// D1082: a NON-empty partial recovered some capabilities and left others
	// `unknown`. D618 established that the danger is the AFTERMATH — the recovered
	// ledger and its fresh anchor sit on disk, and `attest`/`anchor --check` certify
	// them from the next minute on, so an exit-0 read as "recovered" over a subset a
	// later check will bless as whole. D618 closed only the all-zero case above; the
	// same reasoning reaches any-unknown. `--partial` means "give me what can be proven
	// and tell me what cannot" — so the recovered subset IS kept (unlike all-zero, which
	// is removed) — but the process exits NON-ZERO so automation never reads a
	// knowingly-incomplete estate as a whole recovery. This is the converge blocked-caps
	// shape (apply what is reconcilable, then a non-zero exit; D249). ExitRefused is its
	// own documented meaning: "the set does not hold together — a capsule failed."
	if opts.Partial && rep.Status == "partial" {
		// The fresh anchor cut above (BuildAnchor over the RECOVERED subset) is
		// self-consistent, so `anchor --check` and `attest` on the output would answer
		// "verified" and promote a subset as a whole recovered estate — gating the exit
		// code alone protects only the consumer that reads it, not the two that
		// re-derive "whole history" from the artefact (the divergence D313 warns of, and
		// the all-zero sibling above avoids by removing its artefacts). Remove the
		// anchor — KEEP the recovered ledger, which IS --partial's deliverable — so the
		// only completeness check left is `anchor --check` against the ORIGINAL off-host
		// anchor, which names the capabilities this recovery is missing.
		os.Remove(ledger.AnchorPath(opts.Out))
		rep.Reasons = append(rep.Reasons, "--partial recovered some capabilities and left "+
			"others unprovable (see partial[]). The recovered ledger was written but its "+
			"fresh anchor was REMOVED — an anchor over a subset would let `attest`/`anchor "+
			"--check` certify it as a whole recovered history. Exits non-zero; check the "+
			"recovered ledger against the ORIGINAL anchor, and supply the missing or "+
			"repaired capsules to complete it.")
		return rep, ExitRefused
	}
	return rep, ExitOK
}

// classifyCapability adjudicates one capability's sources to a winner, or names
// why it is unsound with a stable code: capsule-missing (no source),
// capsule-tampered / capsule-trust-refused (a source fails standalone
// verification), capsule-foreign (a source belongs to another ledger),
// capsule-fork (sources diverge), capsule-stale (the winner does not reach the
// anchor's tip). An empty code means the returned winner is sound.
func classifyCapability(cap string, group []*capInfo, anchor *ledger.Anchor) (*ledger.Capsule, []string, string, string) {
	if len(group) == 0 {
		return nil, nil, "capsule-missing", fmt.Sprintf("the anchor names "+
			"capability %q but no capsule was supplied — an incomplete backup "+
			"is not a restore", cap)
	}
	for _, ci := range group {
		lid, err := ledger.VerifyCapsule(ci.cap, nil)
		if err != nil {
			code := "capsule-tampered"
			if isTrustError(err) {
				code = "capsule-trust-refused"
			}
			return nil, nil, code, fmt.Sprintf("capsule %s: %v", ci.path, err)
		}
		if lid != "" && lid != anchor.LedgerId {
			return nil, nil, "capsule-foreign", fmt.Sprintf("capsule %s: signed "+
				"for ledger %s but the anchor pins %s — a foreign ledger's capsule",
				ci.path, short(lid), short(anchor.LedgerId))
		}
	}
	winner, alts, err := mergeGroup(cap, group)
	if err != nil {
		return nil, nil, "capsule-fork", err.Error()
	}
	if winner.cap.Head != anchor.Heads[cap] {
		return nil, nil, "capsule-stale", fmt.Sprintf("the winning capsule for "+
			"%q ends at %s but the anchor pins %s — newer history was withheld "+
			"(a stale backup) or the set is foreign", cap, winner.cap.Head,
			anchor.Heads[cap])
	}
	return winner.cap, alts, "", ""
}

// firstUnknownCoupling returns the first capability listed by any of c's events
// that is NOT in the restored set (empty if every co-listed capability is
// restored). Such an event cannot be written without fabricating the missing
// capability's chain, so the owning capability must be demoted.
func firstUnknownCoupling(c *ledger.Capsule, restored map[string]*ledger.Capsule) string {
	for _, doc := range c.Events {
		ev, _ := doc["event"].(map[string]any)
		for _, listed := range asList(ev["capabilities"]) {
			s, ok := listed.(string)
			if !ok || s == c.Capability {
				continue
			}
			if _, in := restored[s]; !in {
				return s
			}
		}
	}
	return ""
}

// isTrustError reports whether a VerifyCapsule failure is a signature/trust
// failure (a distinct partial-restore code) rather than structural corruption.
//
// D312: this used to substring-match the message for "key", "signed", "trust"…
// Several verification messages embed the CAPABILITY NAME, so a capability called
// "api-keys" reported every structural corruption as capsule-trust-refused — the
// contract author deciding the machine-readable half of a recovery report. The
// class is carried by the error TYPE now (ledger.TrustError).
func isTrustError(err error) bool { return ledger.IsTrustError(err) }

// capInfo is one candidate source for a capability during merge: the loaded
// capsule plus the set of its event hashes (for containment adjudication).
type capInfo struct {
	path   string
	cap    *ledger.Capsule
	hashes map[string]bool
}

// mergeGroup adjudicates a capability's candidate sources to ONE winning chain
// by the closed merge rules, returning the winner and the superseded/duplicate
// source paths (for the report). The rules never GUESS:
//   - identical tip  -> the same chain (a re-emit or a signature variant);
//     dedupe, record the extra as an alternate.
//   - longer-contains-shorter -> the longer chain WINS, PROVEN by set
//     containment (every shorter event rides verbatim in the longer) — a
//     newer backup legitimately extends an older one.
//   - fork -> REFUSE: two sources whose event sets are incomparable share no
//     prefix relationship; picking one would be guessing which branch is real.
func mergeGroup(cap string, group []*capInfo) (*capInfo, []string, error) {
	// deterministic order: most events first, then head, then path — so the
	// longest chain is the winner and ties resolve identically every run.
	sort.Slice(group, func(i, j int) bool {
		if len(group[i].hashes) != len(group[j].hashes) {
			return len(group[i].hashes) > len(group[j].hashes)
		}
		if group[i].cap.Head != group[j].cap.Head {
			return group[i].cap.Head < group[j].cap.Head
		}
		return group[i].path < group[j].path
	})
	winner := group[0]
	var alternates []string
	for _, other := range group[1:] {
		if other.cap.Head == winner.cap.Head {
			// identical tip: hash-equal events (the hash excludes the signature,
			// D102), so this is the same chain — dedupe. A differing signature
			// envelope is recorded as an alternate, never a conflict.
			alternates = append(alternates, other.path)
			continue
		}
		if !subset(other.hashes, winner.hashes) {
			return nil, nil, fmt.Errorf("capsules for %q FORK: %s and %s share no "+
				"prefix relationship (neither continues the other) — restore refuses "+
				"a fork rather than guess which branch is the real history",
				cap, short(winner.cap.Head), short(other.cap.Head))
		}
		alternates = append(alternates, other.path) // an older prefix source
	}
	return winner, alternates, nil
}

// subset reports whether every hash in a is also in b (a ⊆ b).
func subset(a, b map[string]bool) bool {
	for h := range a {
		if !b[h] {
			return false
		}
	}
	return true
}

// capsuleHashes is the set of a capsule's event hashes — the containment view
// merge adjudicates over. Hash excludes the signature, so it is chain identity.
func capsuleHashes(c *ledger.Capsule) (map[string]bool, error) {
	hs := make(map[string]bool, len(c.Events))
	for _, doc := range c.Events {
		h, err := canonical.HashEvent(doc)
		if err != nil {
			return nil, err
		}
		hs[h] = true
	}
	return hs, nil
}

// --- helpers -------------------------------------------------------------

func op(rep *RestoreReport, reason string) (*RestoreReport, int) {
	rep.Reasons = append(rep.Reasons, reason)
	return rep, ExitOperator
}

func refuse(rep *RestoreReport, reason string) (*RestoreReport, int) {
	rep.Reasons = append(rep.Reasons, reason)
	return rep, ExitRefused
}

func loadCapsule(path string) (*ledger.Capsule, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var c ledger.Capsule
	if err := json.Unmarshal(raw, &c); err != nil {
		return nil, fmt.Errorf("%s: not a capsule document: %v", path, err)
	}
	if c.Capability == "" {
		return nil, fmt.Errorf("%s: capsule names no capability", path)
	}
	// JSON decodes every number as float64; the ledger's own load path
	// (ReplayFile) folds whole-number floats back to int so shape checks
	// like ValidateEvent's fencingToken pass and the written line matches
	// an organic ledger byte-for-byte. Do the same before verifying — the
	// canonical hash is representation-stable, so heads are unaffected.
	for _, doc := range c.Events {
		normalizeNumbers(doc)
	}
	return &c, nil
}

// normalizeNumbers folds whole-number float64 (JSON's only number type)
// to int, in place — the same normalization ReplayFile applies to every
// line it reads.
func normalizeNumbers(v any) {
	switch x := v.(type) {
	case map[string]any:
		for k, val := range x {
			if f, ok := val.(float64); ok && f == float64(int(f)) {
				x[k] = int(f)
			} else {
				normalizeNumbers(val)
			}
		}
	case []any:
		for _, it := range x {
			normalizeNumbers(it)
		}
	}
}

// evMeta is the linearization view of one unique event.
type evMeta struct {
	hash       string
	doc        map[string]any
	caps       []string
	prev       map[string]string
	occurredAt string
}

func extract(doc map[string]any) (*evMeta, error) {
	h, err := canonical.HashEvent(doc)
	if err != nil {
		return nil, err
	}
	ev, _ := doc["event"].(map[string]any)
	if ev == nil {
		return nil, fmt.Errorf("event %s has no event block", short(h))
	}
	var caps []string
	for _, c := range asList(ev["capabilities"]) {
		if s, ok := c.(string); ok {
			caps = append(caps, s)
		}
	}
	prev := map[string]string{}
	if pm, ok := ev["prev"].(map[string]any); ok {
		for k, v := range pm {
			prev[k], _ = v.(string)
		}
	}
	occurred, _ := ev["occurredAt"].(string)
	return &evMeta{hash: h, doc: doc, caps: caps, prev: prev,
		occurredAt: occurred}, nil
}

// dedupe folds every capsule's events into one hash-keyed set. Iterating
// capabilities in sorted order makes "first occurrence wins" deterministic.
func dedupe(byCap map[string]*ledger.Capsule) (map[string]*evMeta, error) {
	events := map[string]*evMeta{}
	for _, cap := range sortedKeys(capsAsStringMap(byCap)) {
		for _, doc := range byCap[cap].Events {
			m, err := extract(doc)
			if err != nil {
				return nil, err
			}
			if _, seen := events[m.hash]; !seen {
				events[m.hash] = m
			}
		}
	}
	return events, nil
}

// linearize returns the events in a deterministic, replay-valid order.
// Every non-genesis prev entry is an edge predecessor->event; Kahn's
// algorithm emits a node only once all its predecessors have, and among
// the ready set picks (rank, occurredAt, hash) — rank pinning the
// genesis to line 1. A missing predecessor or a cycle is corruption:
// the set does not form one connected history and restore refuses it.
func linearize(events map[string]*evMeta, ledgerID string) ([]map[string]any, error) {
	indeg := make(map[string]int, len(events))
	succ := make(map[string][]string, len(events))
	for h := range events {
		indeg[h] = 0
	}
	for h, m := range events {
		for _, cap := range m.caps {
			p, ok := m.prev[cap]
			if !ok || p == "" {
				return nil, fmt.Errorf("event %s lists capability %q with no "+
					"prev entry — its chain is unverifiable", short(h), cap)
			}
			if p == "genesis" {
				continue
			}
			if _, present := events[p]; !present {
				return nil, fmt.Errorf("event %s pins predecessor %s for %q "+
					"but that event is not in the set — an incomplete or "+
					"foreign capsule set", short(h), short(p), cap)
			}
			indeg[h]++
			succ[p] = append(succ[p], h)
		}
	}

	ready := &pq{ledgerID: ledgerID}
	for h, d := range indeg {
		if d == 0 {
			heap.Push(ready, events[h])
		}
	}
	out := make([]map[string]any, 0, len(events))
	for ready.Len() > 0 {
		m := heap.Pop(ready).(*evMeta)
		out = append(out, m.doc)
		for _, s := range succ[m.hash] {
			indeg[s]--
			if indeg[s] == 0 {
				heap.Push(ready, events[s])
			}
		}
	}
	if len(out) != len(events) {
		return nil, fmt.Errorf("the capsule set does not form one connected "+
			"history: %d of %d events could not be ordered (a cycle or a "+
			"missing predecessor) — restore refuses a set it cannot "+
			"linearize", len(events)-len(out), len(events))
	}
	return out, nil
}

// pq orders ready events by (rank, occurredAt, hash); rank 0 pins the
// genesis (hash == ledgerID) ahead of every other line-1-ready event.
type pq struct {
	items    []*evMeta
	ledgerID string
}

func (q *pq) rank(m *evMeta) int {
	if q.ledgerID != "" && m.hash == q.ledgerID {
		return 0
	}
	return 1
}
func (q *pq) Len() int { return len(q.items) }
func (q *pq) Less(i, j int) bool {
	a, b := q.items[i], q.items[j]
	if ra, rb := q.rank(a), q.rank(b); ra != rb {
		return ra < rb
	}
	if a.occurredAt != b.occurredAt {
		return a.occurredAt < b.occurredAt
	}
	return a.hash < b.hash
}
func (q *pq) Swap(i, j int) { q.items[i], q.items[j] = q.items[j], q.items[i] }
func (q *pq) Push(x any)    { q.items = append(q.items, x.(*evMeta)) }
func (q *pq) Pop() any {
	n := len(q.items)
	it := q.items[n-1]
	q.items = q.items[:n-1]
	return it
}

func writeLines(path string, lines []map[string]any) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	var buf []byte
	for _, doc := range lines {
		b, err := json.Marshal(doc)
		if err != nil {
			return err
		}
		buf = append(buf, b...)
		buf = append(buf, '\n') // the final newline the fold requires
	}
	return os.WriteFile(path, buf, 0o600)
}

func writeAnchor(path string, a *ledger.Anchor) error {
	b, err := json.MarshalIndent(a, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o600)
}

func capsuleHeads(byCap map[string]*ledger.Capsule) map[string]any {
	out := map[string]any{}
	for cap, c := range byCap {
		out[cap] = c.Head
	}
	return out
}

func capsAsStringMap(byCap map[string]*ledger.Capsule) map[string]string {
	out := make(map[string]string, len(byCap))
	for k := range byCap {
		out[k] = ""
	}
	return out
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func asList(v any) []any {
	l, _ := v.([]any)
	return l
}

func short(h string) string {
	if len(h) > 17 {
		return h[:17] + "…"
	}
	return h
}
