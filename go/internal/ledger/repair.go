// Ledger repair (D69): the diagnostic path D67 promised for a ledger
// that replays fail-closed — a torn line, a broken chain, or a
// pre-D67 fork (two writers that both won a lease). The default mode
// is a READ-ONLY diagnosis: findings with line numbers, the length of
// the valid prefix, and a fingerprint of the exact bytes examined.
// Quarantine is two-step consent: it runs only against the fingerprint
// of a diagnosis the operator has seen, renames the corrupt file aside
// (history is preserved verbatim, never deleted), and rewrites the
// original path with only the valid prefix. Everything after the cut
// may have mutated the cloud: the remediation is re-observation of
// reality (discover/observe/adopt), never a fabricated history.
package ledger

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"groundhold/internal/perr"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"groundhold/internal/canonical"
	"groundhold/internal/state"
)

type Finding struct {
	Line        int    `json:"line"`
	Kind        string `json:"kind"` // torn-final-line | unparseable-line | missing-prev | chain-broken | rule-rejected | bad-timestamp
	Capability  string `json:"capability,omitempty"`
	Detail      string `json:"detail"`
	Remediation string `json:"remediation"`
}

type Diagnosis struct {
	Status string `json:"status"` // healthy | corrupt
	// Code (D624): "every JSON-emitting verb carries `code`" — this one did not, so
	// a caller diagnosing a ledger had to match on the status word.
	Code string `json:"code,omitempty"`
	// D654: the counts are `attest`'s, so two verbs describing one file use one
	// vocabulary. This used to be a single `events` field holding the physical LINE
	// count of the live file — which on a compacted ledger reported 1 where attest
	// reported 19, and counted blank lines as events.
	TotalEvents int `json:"totalEvents"`
	TailEvents  int `json:"tailEvents"`
	BaseEvents  int `json:"baseEvents"`
	// TailLines is the physical line count of the live file. It is a different
	// unit from the events above and keeps its own name, because --quarantine
	// truncates to a LINE and an off-by-one there throws away real history.
	TailLines        int       `json:"tailLines"`
	ValidPrefixLines int       `json:"validPrefixLines"`
	Findings         []Finding `json:"findings"`
	Fingerprint      string    `json:"fingerprint"`
}

const quarantineRemediation = "quarantine the file (repair --quarantine " +
	"--fingerprint <fp>), then re-observe reality: resources recorded " +
	"after the cut may exist — discover/observe/adopt them"

// upgradeRemediation is the DELIBERATE opposite of quarantining (D1154). An event
// type this build does not know is the signature of a NEWER build, not of damage,
// and `repair` is the worst place for that confusion: its whole job is to cut a file
// down to its clean prefix. Told "corrupt", an operator running the older binary
// would quarantine a file whose chain verifies — and the cut discards every event
// after the first unreadable one, which is exactly the history that build cannot
// read and a newer one can.
const upgradeRemediation = "do NOT quarantine: run a newer groundhold against this " +
	"ledger, or upgrade this one. The event-type registry is additive-only, so a " +
	"type this build does not know was written by a later build; cutting the file " +
	"at this line would discard history that is intact"

// Diagnose folds the file TOLERANTLY: it verifies the chain and the
// rules line by line, records every deviation as a finding instead of
// stopping at the first, and reports the longest clean prefix. The
// fold state past a finding treats the file as record ("this is what
// was written"), so chain verification stays meaningful after a
// rejected event: its hash still advances the heads its successors
// pinned. A structurally unreadable line ends the examination — hashes
// past it cannot be computed, so nothing after it can be judged.
func Diagnose(path string) (*Diagnosis, error) {
	raw, err := readLedger(path)
	if os.IsNotExist(err) {
		// D617: `repair` is the verb an operator reaches for when they suspect
		// corruption, and it answered "healthy" — with the fingerprint of the empty
		// string — for a ledger that is not there. A typo in the path is the ordinary
		// way to arrive here.
		return nil, fmt.Errorf("%w at %s — a diagnosis of a file that does not "+
			"exist is not a clean bill of health", ErrNoLedger, path)
	}
	if err != nil {
		return nil, err
	}
	d := &Diagnosis{Findings: []Finding{}, Fingerprint: fingerprint(raw)}
	body := raw
	torn := len(raw) > 0 && raw[len(raw)-1] != '\n'
	if torn {
		if i := strings.LastIndexByte(string(raw), '\n'); i >= 0 {
			body = raw[:i+1]
		} else {
			body = nil
		}
	}

	// D137: a compacted ledger's tail continues the snapshot heads, not
	// genesis — diagnosing it from an empty New() would call a HEALTHY
	// tail chain-broken and send the operator to --quarantine, which
	// then truncates the healthy tail to zero lines. Seed from the
	// snapshot exactly as ReplayFile does (review fix).
	led := New()
	// D184: a snapshot sidecar that will not load/seed/verify is NOT an
	// excuse to fold the tail from genesis — a compacted tail continues the
	// snapshot's heads, so genesis would call a HEALTHY tail chain-broken
	// and recommend a quarantine that truncates it. Refuse to judge the
	// tail, the same fail-closed posture as ReplayFile (which hard-refuses).
	refuseSnapshot := func(reason string, err error) *Diagnosis {
		d.Status = "corrupt"
		d.Code = string(perr.LedgerCorrupted)
		d.TailLines, d.TotalEvents, d.TailEvents = 0, 0, 0
		d.ValidPrefixLines = 0
		d.Findings = append(d.Findings, Finding{Line: 0,
			Kind: "snapshot-unreadable",
			Detail: fmt.Sprintf("%s: %v — the compacted tail continues the "+
				"snapshot's heads and cannot be diagnosed against genesis",
				reason, err),
			Remediation: "restore or re-verify the snapshot from the archive " +
				"before diagnosing; do NOT quarantine the tail — it may be " +
				"healthy history the genesis fold cannot read"})
		return d
	}
	if snap, serr := LoadSnapshotFile(SnapshotPath(path)); serr != nil {
		return refuseSnapshot("the snapshot sidecar is unreadable", serr), nil
	} else if snap != nil {
		if terr := VerifySnapshotTrust(snap); terr != nil {
			return refuseSnapshot("the snapshot fails its trust check", terr), nil
		}
		// D646: the archive is the only copy of the compacted history, and after
		// D645 it is what a forensic window reads. A snapshot whose archive does
		// not match what it pinned is a diagnosis, not a detail.
		if ai := CheckArchive(path, snap); ai.Status == "mismatched" ||
			ai.Status == "misnamed" {
			return refuseSnapshot("the archived history does not match the snapshot",
				fmt.Errorf("%s", ai.Detail)), nil
		}
		seeded, serr := SeedLedger(snap)
		if serr != nil {
			return refuseSnapshot("the snapshot will not seed", serr), nil
		}
		led = seeded
		// D654: repair never looked at the compaction, so it reported the tail's
		// line count as the whole history — 1 where attest said 19.
		d.BaseEvents = snap.BaseEvents
	}
	led.Lenient = true
	lines := []string{}
	if len(body) > 0 {
		lines = strings.Split(strings.TrimRight(string(body), "\n"), "\n")
	}
	clean := true
	for i, line := range lines {
		n := i + 1
		if line == "" {
			continue
		}
		var doc map[string]any
		if err := json.Unmarshal([]byte(line), &doc); err != nil {
			d.Findings = append(d.Findings, Finding{Line: n,
				Kind:   "unparseable-line",
				Detail: fmt.Sprintf("not a JSON event: %v", err),
				Remediation: quarantineRemediation + "; lines after this " +
					"one were not examined (their chain cannot be verified)"})
			d.ValidPrefixLines = prefixIfClean(d, n-1, clean)
			// TailLines must reflect the physical line count even on the
			// early return, or DroppedLines (TailLines - ValidPrefixLines)
			// goes NEGATIVE in the quarantine result (bad output).
			d.TailLines = len(lines)
			d.TotalEvents = d.BaseEvents + d.TailEvents
			d.Status = "corrupt"
			d.Code = string(perr.LedgerCorrupted)
			return d, nil
		}
		// D654: a line that PARSED is an event record — count it as one. Blank
		// lines are not events, and the old count was of lines.
		d.TailEvents++
		normalize(doc)
		ev, _ := doc["event"].(map[string]any)
		occurred, _ := ev["occurredAt"].(string)
		if clock, err := ParseTs(occurred); err != nil {
			d.Findings = append(d.Findings, Finding{Line: n,
				Kind:        "bad-timestamp",
				Detail:      fmt.Sprintf("occurredAt: %v", err),
				Remediation: quarantineRemediation})
			clean = markCut(d, n, clean)
			continue // unfoldable: no clock, no meaningful rules
		} else if clock > led.Clock {
			led.Clock = clock
		}
		if err := verifyPrev(led, ev, n); err != nil {
			kind := "chain-broken"
			if _, ok := ev["prev"].(map[string]any); !ok {
				kind = "missing-prev"
			}
			d.Findings = append(d.Findings, Finding{Line: n, Kind: kind,
				Detail:      err.Error(),
				Remediation: quarantineRemediation})
			clean = markCut(d, n, clean)
		}
		res, err := led.Append(doc, nil)
		if err != nil {
			kind, remedy := "unparseable-line", quarantineRemediation
			var unknown *state.UnknownTypeError
			if errors.As(err, &unknown) {
				kind, remedy = "version-ahead", upgradeRemediation
			}
			d.Findings = append(d.Findings, Finding{Line: n,
				Kind:        kind,
				Detail:      err.Error(),
				Remediation: remedy})
			clean = markCut(d, n, clean)
			// the event cannot be folded or hashed — advance nothing;
			// later chain findings may cascade, which is honest
			continue
		}
		if res.Status != "ok" {
			cap := ""
			if capsAny, _ := ev["capabilities"].([]any); len(capsAny) > 0 {
				cap, _ = capsAny[0].(string)
			}
			d.Findings = append(d.Findings, Finding{Line: n,
				Kind: "rule-rejected", Capability: cap,
				Detail: fmt.Sprintf("replay %s (%s) — the file records "+
					"an event today's rules refuse; on a lease conflict "+
					"this is a pre-D67 fork: two writers both won",
					res.Status, res.Reason),
				Remediation: quarantineRemediation})
			clean = markCut(d, n, clean)
			// the file says this happened: advance the heads by the
			// event's hash so successors' prev still verifies
			advanceHeads(led, doc, ev)
			continue
		}
		if clean {
			d.ValidPrefixLines = n
		}
	}
	d.TailLines = len(lines)
	d.TotalEvents = d.BaseEvents + d.TailEvents
	if torn {
		d.Findings = append(d.Findings, Finding{Line: len(lines) + 1,
			Kind: "torn-final-line",
			Detail: "the final line has no newline — a write died " +
				"mid-flight; the line was never committed",
			Remediation: quarantineRemediation})
		if clean {
			d.ValidPrefixLines = len(lines)
		}
	}
	if len(d.Findings) == 0 {
		d.Status = "healthy"
		d.ValidPrefixLines = len(lines)
	} else if onlyVersionAhead(d.Findings) {
		// D1154: nothing here is damage. Saying "corrupt" would be false, and it
		// is the false direction that costs something: the published remediation
		// for ledger-corrupted is this very verb's --quarantine.
		d.Status = "version-ahead"
		d.Code = string(perr.LedgerVersionAhead)
	} else {
		d.Status = "corrupt"
		d.Code = string(perr.LedgerCorrupted)
	}
	return d, nil
}

// onlyVersionAhead reports whether EVERY finding is "this build cannot read that
// type" — the one diagnosis that is not damage (D1154).
//
// Every, not any: the conditions are independent and a file can have both, and a
// single real corruption finding must keep the whole diagnosis in the corrupt
// channel. Under-reporting damage is the direction that loses history.
func onlyVersionAhead(fs []Finding) bool {
	for _, f := range fs {
		if f.Kind != "version-ahead" {
			return false
		}
	}
	return len(fs) > 0
}

// markCut freezes the valid prefix at the line BEFORE the first
// finding.
func markCut(d *Diagnosis, line int, clean bool) bool {
	if clean {
		d.ValidPrefixLines = line - 1
	}
	return false
}

func prefixIfClean(d *Diagnosis, lines int, clean bool) int {
	if clean {
		return lines
	}
	return d.ValidPrefixLines
}

// advanceHeads moves the per-capability heads past an event the rules
// rejected — the FILE recorded it, so its successors pin its hash.
func advanceHeads(led *Ledger, doc map[string]any, ev map[string]any) {
	h, err := canonical.HashEvent(doc)
	if err != nil {
		return
	}
	capsAny, _ := ev["capabilities"].([]any)
	for _, ca := range capsAny {
		if c, _ := ca.(string); c != "" {
			led.Heads[c] = h
		}
	}
}

func fingerprint(raw []byte) string {
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}

type RepairResult struct {
	Status        string    `json:"status"` // healthy | repaired | refused
	Code          string    `json:"code,omitempty"`
	KeptLines     int       `json:"keptLines"`
	DroppedLines  int       `json:"droppedLines"`
	QuarantinedTo string    `json:"quarantinedTo,omitempty"`
	Findings      []Finding `json:"findings"`
	Reasons       []string  `json:"reasons,omitempty"`
}

// Quarantine executes the repair the diagnosis proposed — under the
// file lock, and only if the file still has the exact fingerprint the
// operator saw (a writer racing the decision voids the consent). The
// corrupt file is RENAMED aside, never deleted; the original path gets
// the valid prefix back. Run it with writers stopped: the file backend
// locks the inode, and repair swaps the name.
func Quarantine(path, fp string) (*RepairResult, *Diagnosis, error) {
	f, err := os.OpenFile(path, os.O_RDWR, 0o600)
	if err != nil {
		return nil, nil, err
	}
	defer f.Close()
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		return nil, nil, err
	}
	defer syscall.Flock(int(f.Fd()), syscall.LOCK_UN)

	d, err := Diagnose(path)
	if err != nil {
		return nil, nil, err
	}
	if d.Status == "healthy" {
		return &RepairResult{Status: "healthy", KeptLines: d.TailLines,
			Findings: d.Findings,
			Reasons:  []string{"nothing to repair"}}, d, nil
	}
	// D1154: refuse the cut, even with a matching fingerprint. Everything else
	// this function cuts is damage; a version-ahead file is intact history this
	// build cannot READ, and the cut would delete it — irreversibly, since the
	// ledger is the one artefact nothing else can reconstruct. A confirmed
	// fingerprint is consent to remove corruption, and there is none here.
	if onlyVersionAhead(d.Findings) {
		return &RepairResult{Status: "refused",
			Code: string(perr.LedgerVersionAhead), Findings: d.Findings,
			Reasons: []string{"this ledger is not damaged: it holds an event " +
				"type this build does not know, and its hash chain is intact " +
				"up to that line. Cutting here would discard history a newer " +
				"build can read. Run the newer build, or upgrade this one"}}, d, nil
	}
	if fp != d.Fingerprint {
		return &RepairResult{Status: "refused",
			Code: "confirmation-required", Findings: d.Findings,
			Reasons: []string{fmt.Sprintf(
				"fingerprint %s does not match the file's %s — diagnose "+
					"again and confirm the finding you are about to cut",
				fp, d.Fingerprint)}}, d, nil
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, err
	}
	prefix := prefixBytes(raw, d.ValidPrefixLines)
	qpath := path + ".quarantined-" +
		strings.TrimPrefix(d.Fingerprint, "sha256:")[:12]
	// Stage the valid prefix in a temp file and swap it into place with
	// an ATOMIC rename — never os.WriteFile onto the live path, whose
	// truncate-then-write window a racing O_CREATE append could land in
	// and be silently truncated (F6/bad-habits). Order: write temp,
	// preserve history aside, then swap.
	tmp := path + ".repair-tmp-" +
		strings.TrimPrefix(d.Fingerprint, "sha256:")[:12]
	if err := writeFsync(tmp, prefix); err != nil {
		return nil, nil, err
	}
	// D711: LINK the history aside, never RENAME it. The old order was
	// rename(path->qpath) then rename(tmp->path), which leaves the ledger path with
	// NO FILE between the two — and a missing ledger replays as an EMPTY one
	// (ReplayFile treats IsNotExist as a fresh ledger, deliberately, so a first
	// converge can create one). A crash in that window therefore hands the next
	// converge an empty history for a full estate: every capability unbound, every
	// action a create. That is D253's named cost — "a second VPC, a second paid key" —
	// produced by the verb that exists to RECOVER from corruption.
	//
	// A hard link makes the preserved copy appear while the original stays in place,
	// so the path never lacks a file; the rename below then swaps the prefix in
	// atomically. fsync of the directory after each step so the ordering survives a
	// power loss, matching what compaction already does one file over.
	if err := os.Link(path, qpath); err != nil {
		os.Remove(tmp)
		return nil, nil, fmt.Errorf("cannot preserve the history at %s before "+
			"cutting: %v", qpath, err)
	}
	dir := filepath.Dir(path)
	if err := fsyncDir(dir); err != nil {
		os.Remove(tmp)
		os.Remove(qpath)
		return nil, nil, err
	}
	if err := os.Rename(tmp, path); err != nil {
		return nil, nil, fmt.Errorf("prefix swap failed after quarantine "+
			"— the full history is at %s, the valid prefix at %s: %v",
			qpath, tmp, err)
	}
	if err := fsyncDir(dir); err != nil {
		return nil, nil, fmt.Errorf("the prefix was swapped in but the directory "+
			"could not be synced (%v) — the full history is at %s", err, qpath)
	}
	total := d.TailLines
	if hasTorn(d) {
		total++ // the torn fragment is dropped bytes too
	}
	return &RepairResult{
		Status: "repaired", KeptLines: d.ValidPrefixLines,
		DroppedLines: total - d.ValidPrefixLines, QuarantinedTo: qpath,
		Findings: d.Findings,
		Reasons: []string{
			"quarantined events may have mutated the cloud — " +
				"re-observe reality (discover/observe/adopt) before " +
				"trusting any projection that cited them",
			"plans sealed BEFORE this repair are void: the restored " +
				"prefix rewinds decision heads, so CAS alone cannot " +
				"tell an old plan from a fresh one — re-observe and " +
				"re-seal"},
	}, d, nil
}

func hasTorn(d *Diagnosis) bool {
	for _, f := range d.Findings {
		if f.Kind == "torn-final-line" {
			return true
		}
	}
	return false
}

// prefixBytes returns the bytes of the first n newline-terminated
// lines.
func prefixBytes(raw []byte, n int) []byte {
	if n <= 0 {
		return nil
	}
	seen := 0
	for i, b := range raw {
		if b == '\n' {
			seen++
			if seen == n {
				return raw[:i+1]
			}
		}
	}
	return raw
}
