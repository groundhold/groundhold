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
	"fmt"
	"os"
	"strings"
	"syscall"

	"groundhold/internal/canonical"
)

type Finding struct {
	Line        int    `json:"line"`
	Kind        string `json:"kind"` // torn-final-line | unparseable-line | missing-prev | chain-broken | rule-rejected | bad-timestamp
	Capability  string `json:"capability,omitempty"`
	Detail      string `json:"detail"`
	Remediation string `json:"remediation"`
}

type Diagnosis struct {
	Status           string    `json:"status"` // healthy | corrupt
	Events           int       `json:"events"`
	ValidPrefixLines int       `json:"validPrefixLines"`
	Findings         []Finding `json:"findings"`
	Fingerprint      string    `json:"fingerprint"`
}

const quarantineRemediation = "quarantine the file (repair --quarantine " +
	"--fingerprint <fp>), then re-observe reality: resources recorded " +
	"after the cut may exist — discover/observe/adopt them"

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
		return &Diagnosis{Status: "healthy", Findings: []Finding{},
			Fingerprint: fingerprint(nil)}, nil
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
		d.Events = 0
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
		seeded, serr := SeedLedger(snap)
		if serr != nil {
			return refuseSnapshot("the snapshot will not seed", serr), nil
		}
		led = seeded
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
			// Events must reflect the physical line count even on the
			// early return, or DroppedLines (Events - ValidPrefixLines)
			// goes NEGATIVE in the quarantine result (bad output).
			d.Events = len(lines)
			d.Status = "corrupt"
			return d, nil
		}
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
			d.Findings = append(d.Findings, Finding{Line: n,
				Kind:        "unparseable-line",
				Detail:      err.Error(),
				Remediation: quarantineRemediation})
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
	d.Events = len(lines)
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
	} else {
		d.Status = "corrupt"
	}
	return d, nil
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
		return &RepairResult{Status: "healthy", KeptLines: d.Events,
			Findings: d.Findings,
			Reasons:  []string{"nothing to repair"}}, d, nil
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
	if err := os.WriteFile(tmp, prefix, 0o600); err != nil {
		return nil, nil, err
	}
	if err := os.Rename(path, qpath); err != nil {
		os.Remove(tmp)
		return nil, nil, err
	}
	if err := os.Rename(tmp, path); err != nil {
		return nil, nil, fmt.Errorf("prefix swap failed after quarantine "+
			"— the full history is at %s, the valid prefix at %s: %v",
			qpath, tmp, err)
	}
	total := d.Events
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
