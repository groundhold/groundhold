package ledger

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func jsonUnmarshal(line string, doc *map[string]any) error {
	if err := json.Unmarshal([]byte(line), doc); err != nil {
		return err
	}
	normalize(*doc)
	return nil
}

// D69/D70 pins: the repair diagnosis names each corruption kind with
// its line, quarantine is fingerprint-gated and preserves history, and
// the anchor closes the last-line boundary the chain alone leaves open.

func writeHonestLedger(t *testing.T, path string, extra int) {
	t.Helper()
	led, err := ReplayFile(path)
	if err != nil {
		t.Fatal(err)
	}
	w := &Writer{Path: path, Led: led, Env: "test", Clock: 1000, Actor: "t"}
	tok, err := w.AppendLease([]string{"db"},
		map[string]any{"ttlSeconds": 300})
	if err != nil {
		t.Fatal(err)
	}
	if err := w.Append("binding.updated", []string{"db"},
		map[string]any{"resources": []any{map[string]any{
			"id": "primary", "type": "t", "providerId": "fake:db-1",
			"generation": 1}}}, tok); err != nil {
		t.Fatal(err)
	}
	if err := w.Append("lease.released", []string{"db"}, nil,
		tok); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < extra; i++ {
		if err := w.Append("observation.recorded", []string{"db"},
			map[string]any{"observations": []any{}}, 0); err != nil {
			t.Fatal(err)
		}
	}
}

func TestDiagnoseHealthyAndTornLine(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/l.jsonl"
	writeHonestLedger(t, path, 0)

	d, err := Diagnose(path)
	if err != nil {
		t.Fatal(err)
	}
	if d.Status != "healthy" || d.ValidPrefixLines != 3 {
		t.Fatalf("healthy ledger misdiagnosed: %+v", d)
	}

	// tear the final line mid-write
	raw, _ := os.ReadFile(path)
	torn := raw[:len(raw)-10]
	if err := os.WriteFile(path, torn, 0o644); err != nil {
		t.Fatal(err)
	}
	d, err = Diagnose(path)
	if err != nil {
		t.Fatal(err)
	}
	if d.Status != "corrupt" || len(d.Findings) != 1 ||
		d.Findings[0].Kind != "torn-final-line" || d.ValidPrefixLines != 2 {
		t.Fatalf("torn line misdiagnosed: %+v", d)
	}

	// quarantine with the WRONG fingerprint is refused, file untouched
	res, _, err := Quarantine(path, "sha256:deadbeef")
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != "refused" || res.Code != "confirmation-required" {
		t.Fatalf("stale fingerprint must refuse: %+v", res)
	}
	if _, err := ReplayFile(path); err == nil {
		t.Fatal("refused quarantine must not have repaired anything")
	}

	// with the diagnosed fingerprint it repairs; the prefix replays
	res, _, err = Quarantine(path, d.Fingerprint)
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != "repaired" || res.KeptLines != 2 ||
		res.DroppedLines != 1 || res.QuarantinedTo == "" {
		t.Fatalf("quarantine result wrong: %+v", res)
	}
	if _, err := os.Stat(res.QuarantinedTo); err != nil {
		t.Fatalf("history must be preserved verbatim: %v", err)
	}
	if _, err := ReplayFile(path); err != nil {
		t.Fatalf("valid prefix must replay clean: %v", err)
	}
}

func TestDiagnoseChainBreakAndFork(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/l.jsonl"
	writeHonestLedger(t, path, 0)
	raw, _ := os.ReadFile(path)
	lines := strings.Split(strings.TrimRight(string(raw), "\n"), "\n")

	// drop the middle line: line 3's prev no longer matches
	if err := os.WriteFile(path,
		[]byte(lines[0]+"\n"+lines[2]+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	d, err := Diagnose(path)
	if err != nil {
		t.Fatal(err)
	}
	if d.Status != "corrupt" || d.ValidPrefixLines != 1 {
		t.Fatalf("chain break misdiagnosed: %+v", d)
	}
	if d.Findings[0].Kind != "chain-broken" {
		t.Fatalf("expected chain-broken first, got %+v", d.Findings)
	}

	// a pre-D67 fork: two lease.acquired that both "won". Build the
	// second line with a correctly stitched prev but a rule-violating
	// payload — exactly what a stale-snapshot writer used to persist.
	fork := New()
	fork.Lenient = true
	doc1 := map[string]any{"apiVersion": "state/v0", "kind": "LedgerEvent",
		"event": map[string]any{"type": "lease.acquired",
			"environment": "test", "capabilities": []any{"db"},
			"occurredAt": "2026-07-12T10:00:00Z",
			"actor":      map[string]any{"id": "w1", "type": "runtime"},
			"body":       map[string]any{"ttlSeconds": 300},
			"prev":       map[string]any{"db": "genesis"}}}
	res1, err := fork.Append(doc1, nil)
	if err != nil || res1.Status != "ok" {
		t.Fatalf("seed: %v %v", res1, err)
	}
	doc2 := map[string]any{"apiVersion": "state/v0", "kind": "LedgerEvent",
		"event": map[string]any{"type": "lease.acquired",
			"environment": "test", "capabilities": []any{"db"},
			"occurredAt": "2026-07-12T10:00:01Z",
			"actor":      map[string]any{"id": "w2", "type": "runtime"},
			"body":       map[string]any{"ttlSeconds": 300},
			"prev":       map[string]any{"db": res1.Hash}}}
	fpath := dir + "/fork.jsonl"
	for _, doc := range []map[string]any{doc1, doc2} {
		if err := PersistLine(fpath, doc); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := ReplayFile(fpath); err == nil {
		t.Fatal("a forked ledger must fail replay (D67 fail-closed)")
	}
	d, err = Diagnose(fpath)
	if err != nil {
		t.Fatal(err)
	}
	if d.Status != "corrupt" || d.ValidPrefixLines != 1 ||
		d.Findings[0].Kind != "rule-rejected" ||
		!strings.Contains(d.Findings[0].Detail, "active lease exists") {
		t.Fatalf("fork misdiagnosed: %+v", d)
	}
	if _, _, err := Quarantine(fpath, d.Fingerprint); err != nil {
		t.Fatal(err)
	}
	if _, err := ReplayFile(fpath); err != nil {
		t.Fatalf("repaired fork must replay: %v", err)
	}
}

// D69 finding kinds that ledgerops.yaml does not reach: a garbage
// (unparseable) line, a bad occurredAt, a stripped prev. Also pins the
// Events fix — DroppedLines must never go negative on the early return.
func TestDiagnoseReportsAllFindingKinds(t *testing.T) {
	dir := t.TempDir()

	// garbage line after two valid ones: unparseable-line, and Events
	// must reflect the physical line count (not 0 from the early return)
	path := dir + "/garbage.jsonl"
	writeHonestLedger(t, path, 0) // 3 valid lines
	raw, _ := os.ReadFile(path)
	if err := os.WriteFile(path,
		append(raw, []byte("{not json\n")...), 0o600); err != nil {
		t.Fatal(err)
	}
	d, err := Diagnose(path)
	if err != nil {
		t.Fatal(err)
	}
	if d.Status != "corrupt" || d.Findings[0].Kind != "unparseable-line" {
		t.Fatalf("garbage line misdiagnosed: %+v", d.Findings)
	}
	// D654: the arithmetic this guards is in LINES (quarantine truncates to a
	// line), which is now what the field is called. The assertion is unchanged.
	if d.TailLines < d.ValidPrefixLines {
		t.Fatalf("TailLines (%d) < ValidPrefixLines (%d) — DroppedLines "+
			"would go negative", d.TailLines, d.ValidPrefixLines)
	}
	res, _, err := Quarantine(path, d.Fingerprint)
	if err != nil {
		t.Fatal(err)
	}
	if res.DroppedLines < 0 {
		t.Fatalf("DroppedLines is negative: %d", res.DroppedLines)
	}

	// stripped prev: a line whose event lacks prev entirely
	path2 := dir + "/noprev.jsonl"
	writeHonestLedger(t, path2, 0)
	raw2, _ := os.ReadFile(path2)
	lines := strings.Split(strings.TrimRight(string(raw2), "\n"), "\n")
	var ev map[string]any
	if err := jsonUnmarshal(lines[0], &ev); err != nil {
		t.Fatal(err)
	}
	delete(ev["event"].(map[string]any), "prev")
	stripped, _ := json.Marshal(ev)
	if err := os.WriteFile(path2,
		append(stripped, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	d2, err := Diagnose(path2)
	if err != nil {
		t.Fatal(err)
	}
	if d2.Status != "corrupt" || d2.Findings[0].Kind != "missing-prev" {
		t.Fatalf("stripped prev misdiagnosed: %+v", d2.Findings)
	}
}

// EnforceAnchor is opt-in and fail-closed: absent file -> nil; a
// co-located anchor that the ledger no longer extends -> error, before
// any mutation.
func TestEnforceAnchor(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/l.jsonl"
	writeHonestLedger(t, path, 1)
	led, _ := ReplayFile(path)

	// no anchor file: no enforcement
	if err := EnforceAnchor(path, led); err != nil {
		t.Fatalf("absent anchor must not enforce: %v", err)
	}

	// arm the anchor, then truncate the tail: enforcement must refuse
	a := BuildAnchor(led)
	raw, _ := json.Marshal(a)
	if err := os.WriteFile(AnchorPath(path), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	full, _ := os.ReadFile(path)
	lines := strings.Split(strings.TrimRight(string(full), "\n"), "\n")
	if err := os.WriteFile(path,
		[]byte(strings.Join(lines[:3], "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cut, _ := ReplayFile(path)
	if err := EnforceAnchor(path, cut); err == nil {
		t.Fatal("a truncated tail must fail its armed anchor")
	}
}

func TestAnchorClosesTheTailBoundary(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/l.jsonl"
	writeHonestLedger(t, path, 1)

	led, err := ReplayFile(path)
	if err != nil {
		t.Fatal(err)
	}
	a := BuildAnchor(led)
	if a.Events != 4 || !strings.HasPrefix(a.Head, "sha256:") {
		t.Fatalf("anchor malformed: %+v", a)
	}

	// dropping the LAST line replays CLEAN — the exact D68 boundary —
	// but the anchor catches it
	raw, _ := os.ReadFile(path)
	lines := strings.Split(strings.TrimRight(string(raw), "\n"), "\n")
	if err := os.WriteFile(path,
		[]byte(strings.Join(lines[:3], "\n")+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	cut, err := ReplayFile(path)
	if err != nil {
		t.Fatalf("cut tail must replay clean (that is the boundary): %v", err)
	}
	chk := CheckAnchor(cut, a)
	if chk.Status != "truncated" {
		t.Fatalf("anchor must catch tail truncation: %+v", chk)
	}

	// a REWRITTEN tail (same length, different content) diverges
	alt := New()
	alt.Lenient = true
	for _, l := range lines[:3] {
		var doc map[string]any
		if err := jsonUnmarshal(l, &doc); err != nil {
			t.Fatal(err)
		}
		if _, err := alt.Append(doc, nil); err != nil {
			t.Fatal(err)
		}
	}
	w := &Writer{Path: path, Led: alt, Env: "test", Clock: 2000, Actor: "t2"}
	if err := w.Append("observation.recorded", []string{"db"},
		map[string]any{"observations": []any{},
			"note": "rewritten"}, 0); err != nil {
		t.Fatal(err)
	}
	rewritten, err := ReplayFile(path)
	if err != nil {
		t.Fatal(err)
	}
	chk = CheckAnchor(rewritten, a)
	if chk.Status != "diverged" {
		t.Fatalf("anchor must catch a rewritten tail: %+v", chk)
	}

	// the honest extension verifies
	full := New()
	full.Lenient = true
	for _, l := range lines {
		var doc map[string]any
		if err := jsonUnmarshal(l, &doc); err != nil {
			t.Fatal(err)
		}
		if _, err := full.Append(doc, nil); err != nil {
			t.Fatal(err)
		}
	}
	chk = CheckAnchor(full, a)
	if chk.Status != "verified" {
		t.Fatalf("honest ledger must verify: %+v", chk)
	}
}

// TestAnchorCatchesForestTailRewrite pins the forest find: the log is a
// per-capability forest, so the anchor's positional Head witnesses only
// the sub-chain that owns the LAST line. A count-preserving rewrite of an
// INDEPENDENT capability's tail leaves Head untouched — the per-capability
// heads are the only witness, and CheckAnchor must verify them when the
// anchor covers the whole ledger. Fails before the fix (Head still matched
// → verified).
func TestAnchorCatchesForestTailRewrite(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/l.jsonl"

	// forest: capability "a" owns line 1 AND the last line; capability
	// "b"'s only event sits in the interior (line 2).
	led, err := ReplayFile(path)
	if err != nil {
		t.Fatal(err)
	}
	w := &Writer{Path: path, Led: led, Env: "test", Clock: 1000, Actor: "t"}
	for _, cap := range []string{"a", "b", "a"} {
		if err := w.Append("observation.recorded", []string{cap},
			map[string]any{"observations": []any{}}, 0); err != nil {
			t.Fatal(err)
		}
	}
	full, err := ReplayFile(path)
	if err != nil {
		t.Fatal(err)
	}
	a := BuildAnchor(full)
	if a.Events != 3 {
		t.Fatalf("expected 3 events, got %d", a.Events)
	}
	// the untouched ledger verifies (no false positive from the heads check)
	if chk := CheckAnchor(full, a); chk.Status != "verified" {
		t.Fatalf("honest forest must verify: %+v", chk)
	}
	honest, _ := os.ReadFile(path)
	lines := strings.Split(strings.TrimRight(string(honest), "\n"), "\n")

	// forge b's interior event: replay line 1 (a1) into a scratch file so
	// b's head is genesis, then append a DIFFERENT b event — valid prev,
	// new hash.
	scratch := dir + "/scratch.jsonl"
	if err := os.WriteFile(scratch, []byte(lines[0]+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	sled, err := ReplayFile(scratch)
	if err != nil {
		t.Fatal(err)
	}
	sw := &Writer{Path: scratch, Led: sled, Env: "test", Clock: 1000, Actor: "t"}
	if err := sw.Append("observation.recorded", []string{"b"},
		map[string]any{"observations": []any{}, "note": "forged"}, 0); err != nil {
		t.Fatal(err)
	}
	sraw, _ := os.ReadFile(scratch)
	forgedB := strings.Split(strings.TrimRight(string(sraw), "\n"), "\n")[1]

	// splice: honest a1 + forged b1' + honest a2 (the tail is BYTE-IDENTICAL,
	// so the positional Head still matches — only b's head moved)
	forged := lines[0] + "\n" + forgedB + "\n" + lines[2] + "\n"
	if err := os.WriteFile(path, []byte(forged), 0o600); err != nil {
		t.Fatal(err)
	}
	tampered, err := ReplayFile(path)
	if err != nil {
		t.Fatalf("the forged forest still replays clean (that is the attack): %v", err)
	}
	// precondition: the positional Head is untouched — only the heads check
	// can catch this
	if tampered.headAtTip() != a.Head {
		t.Fatalf("the last line must be unchanged so the positional check "+
			"still passes; got %s want %s", tampered.headAtTip(), a.Head)
	}
	chk := CheckAnchor(tampered, a)
	if chk.Status != "diverged" {
		t.Fatalf("a count-preserving rewrite of an independent capability's "+
			"tail must diverge, got %+v", chk)
	}
}

// TestManifestAnchorCatchesForestRewriteBehindGrownTail pins D185: the
// manifest closes the residual D182 could NOT — a forest rewrite of an
// independent capability's interior tail while the ledger has GROWN past
// the anchor. The positional Head still matches (its sub-chain is intact)
// and the tip-only heads guard is skipped (anchor no longer covers the
// tip), so only the manifest catches it. Fails before the fix.
func TestManifestAnchorCatchesForestRewriteBehindGrownTail(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/l.jsonl"
	led, err := ReplayFile(path)
	if err != nil {
		t.Fatal(err)
	}
	// forest [A1, B1, A2], anchor here (capability A owns the last line)
	w := &Writer{Path: path, Led: led, Env: "test", Clock: 1000, Actor: "t"}
	for _, cap := range []string{"a", "b", "a"} {
		if err := w.Append("observation.recorded", []string{cap},
			map[string]any{"observations": []any{}}, 0); err != nil {
			t.Fatal(err)
		}
	}
	atAnchor, err := ReplayFile(path)
	if err != nil {
		t.Fatal(err)
	}
	a := BuildAnchor(atAnchor)
	if a.Events != 3 || a.Manifest == "" {
		t.Fatalf("anchor malformed: %+v", a)
	}
	// GROW the tail past the anchor: append A3 (capability A)
	if err := w.Append("observation.recorded", []string{"a"},
		map[string]any{"observations": []any{}}, 0); err != nil {
		t.Fatal(err)
	}
	grown, _ := os.ReadFile(path)
	glines := strings.Split(strings.TrimRight(string(grown), "\n"), "\n")

	// forge B1 (interior, capability B untouched since the anchor)
	scratch := dir + "/scratch.jsonl"
	if err := os.WriteFile(scratch, []byte(glines[0]+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	sled, err := ReplayFile(scratch)
	if err != nil {
		t.Fatal(err)
	}
	sw := &Writer{Path: scratch, Led: sled, Env: "test", Clock: 1000, Actor: "t"}
	if err := sw.Append("observation.recorded", []string{"b"},
		map[string]any{"observations": []any{}, "note": "forged"}, 0); err != nil {
		t.Fatal(err)
	}
	sraw, _ := os.ReadFile(scratch)
	forgedB := strings.Split(strings.TrimRight(string(sraw), "\n"), "\n")[1]

	// tampered = [A1, B1', A2, A3] — the anchored prefix's interior moved,
	// the grown tail (A2, A3) is byte-identical
	tamperedFile := glines[0] + "\n" + forgedB + "\n" + glines[2] + "\n" + glines[3] + "\n"
	if err := os.WriteFile(path, []byte(tamperedFile), 0o600); err != nil {
		t.Fatal(err)
	}
	tampered, err := ReplayFile(path)
	if err != nil {
		t.Fatalf("the forged forest still replays clean: %v", err)
	}
	// preconditions: positional Head still matches AND the anchor no longer
	// covers the tip, so only the manifest can catch this
	if tampered.EventHashes[a.Events-1] != a.Head {
		t.Fatalf("precondition: position %d must still match a.Head", a.Events)
	}
	if a.Events == tampered.TotalEvents() {
		t.Fatal("precondition: the tail must have grown past the anchor")
	}
	chk := CheckAnchor(tampered, a)
	if chk.Status != "diverged" {
		t.Fatalf("the manifest must catch an interior forest rewrite behind a "+
			"grown tail, got %+v", chk)
	}
}

// TestDiagnoseRefusesUnreadableSnapshot pins D184: a corrupt snapshot sidecar
// beside a HEALTHY compacted tail must make Diagnose refuse (snapshot-
// unreadable), not fold the tail from genesis — which would call the healthy
// tail chain-broken and recommend a quarantine that truncates it. Fails before
// the fix (the tail reports chain-broken from line 1).
func TestDiagnoseRefusesUnreadableSnapshot(t *testing.T) {
	dir := t.TempDir()
	full := dir + "/full.jsonl"
	led, err := ReplayFile(full)
	if err != nil {
		t.Fatal(err)
	}
	w := &Writer{Path: full, Led: led, Env: "test", Clock: 1000, Actor: "t"}
	tok, err := w.AppendLease([]string{"db"}, map[string]any{"ttlSeconds": 300})
	if err != nil {
		t.Fatal(err)
	}
	if err := w.Append("binding.updated", []string{"db"},
		map[string]any{"resources": []any{map[string]any{"id": "primary",
			"type": "t", "providerId": "fake:db-1", "generation": 1}}}, tok); err != nil {
		t.Fatal(err)
	}
	if err := w.Append("lease.released", []string{"db"}, nil, tok); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if err := w.Append("observation.recorded", []string{"db"},
			map[string]any{"observations": []any{}}, 0); err != nil {
			t.Fatal(err)
		}
	}

	raw, _ := os.ReadFile(full)
	lines := strings.Split(strings.TrimRight(string(raw), "\n"), "\n")
	prefix := dir + "/prefix.jsonl"
	tail := dir + "/tail.jsonl"
	write := func(path string, ls []string) {
		if err := os.WriteFile(path,
			[]byte(strings.Join(ls, "\n")+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write(prefix, lines[:3])
	write(tail, lines[3:])
	prefLed, err := ReplayFile(prefix)
	if err != nil {
		t.Fatal(err)
	}
	rawSnap, _ := json.Marshal(BuildSnapshot(prefLed))
	if err := os.WriteFile(SnapshotPath(tail), rawSnap, 0o600); err != nil {
		t.Fatal(err)
	}

	// sanity: with the VALID snapshot the healthy compacted tail is clean
	d, err := Diagnose(tail)
	if err != nil {
		t.Fatal(err)
	}
	if d.Status != "healthy" {
		t.Fatalf("healthy compacted tail must diagnose clean under a valid "+
			"snapshot: %+v", d)
	}

	// now corrupt the snapshot sidecar — the tail is unchanged and healthy
	if err := os.WriteFile(SnapshotPath(tail),
		[]byte("{ not a snapshot"), 0o600); err != nil {
		t.Fatal(err)
	}
	d, err = Diagnose(tail)
	if err != nil {
		t.Fatal(err)
	}
	if d.Status != "corrupt" || len(d.Findings) != 1 ||
		d.Findings[0].Kind != "snapshot-unreadable" {
		t.Fatalf("an unreadable snapshot must refuse with snapshot-unreadable, "+
			"not fold the healthy tail from genesis: %+v", d)
	}
	if strings.Contains(d.Findings[0].Remediation, "quarantine the file") {
		t.Fatalf("must not recommend truncating the healthy tail: %+v", d.Findings[0])
	}
}
