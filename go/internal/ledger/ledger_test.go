package ledger

import (
	"os"
	"strings"
	"testing"
)

// Review-round pins (D62): projection consistency and clock hygiene
// bugs found by the pre-launch review, each locked here.

func ev(etype, at string, caps []string, body map[string]any,
	token int) map[string]any {
	capsAny := make([]any, len(caps))
	for i, c := range caps {
		capsAny[i] = c
	}
	e := map[string]any{
		"type": etype, "environment": "test", "capabilities": capsAny,
		"occurredAt": at,
		"actor":      map[string]any{"id": "t", "type": "runtime"},
	}
	if body != nil {
		e["body"] = body
	}
	if token > 0 {
		e["fencingToken"] = token
	}
	return map[string]any{"apiVersion": "state/v0", "kind": "LedgerEvent",
		"event": e}
}

func mustOK(t *testing.T, l *Ledger, doc map[string]any) Result {
	t.Helper()
	res, err := l.Append(doc, nil)
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != "ok" {
		t.Fatalf("append rejected: %s", res.Reason)
	}
	return res
}

// Fix 1: lease.broken{adoptReceipts} must clear pendingBody too —
// phantom receipts diverged apply (unblocked) from resume/deposed
// (still seeing them).
func TestAdoptReceiptsClearsPendingBodies(t *testing.T) {
	l := New()
	l.Clock = 100
	mustOK(t, l, ev("operation.receipt", "1970-01-01T00:01:40Z",
		[]string{"db"}, map[string]any{"operationId": "op-1",
			"status": "pending", "operation": "create"}, 0))
	if len(l.PendingReceipts()["db"]) != 1 {
		t.Fatal("receipt not pending")
	}
	mustOK(t, l, ev("lease.broken", "1970-01-01T00:01:41Z",
		[]string{"db"}, map[string]any{"adoptReceipts": true}, 0))
	if l.PendingCount("db") != 0 {
		t.Error("pending count survived adoptReceipts")
	}
	if len(l.PendingReceipts()["db"]) != 0 {
		t.Error("phantom receipt bodies survived adoptReceipts — " +
			"resume would re-conclude them")
	}
}

// Fix 2: a terminal-unknown receipt refreshes the stored body — the
// providerOperation it carries is resume's primary authority after a
// process restart.
func TestUnknownReceiptRefreshesPendingBody(t *testing.T) {
	l := New()
	l.Clock = 100
	mustOK(t, l, ev("operation.receipt", "1970-01-01T00:01:40Z",
		[]string{"db"}, map[string]any{"operationId": "op-1",
			"status": "pending", "operation": "create"}, 0))
	mustOK(t, l, ev("operation.receipt", "1970-01-01T00:01:41Z",
		[]string{"db"}, map[string]any{"operationId": "op-1",
			"status": "unknown", "operation": "create",
			"providerOperation": "gcp-op-777"}, 0))
	bodies := l.PendingReceipts()["db"]
	if len(bodies) != 1 {
		t.Fatalf("expected 1 pending body, got %d", len(bodies))
	}
	if bodies[0]["providerOperation"] != "gcp-op-777" {
		t.Errorf("pending body lost providerOperation: %v", bodies[0])
	}
}

// Fix 4: observation recency compares NUMERICALLY — an RFC3339 offset
// form must not let an older observation win.
func TestObservationRecencyIsNumeric(t *testing.T) {
	l := New()
	l.Clock = 100
	obs := func(at string, value any) map[string]any {
		return map[string]any{"observations": []any{map[string]any{
			"kind": "Observation", "capability": "db",
			"path": "service.managed", "value": value,
			"derivation": "measured", "observedAt": at,
			"ttlSeconds": 900}}}
	}
	// 13:00Z first, then an OLDER instant written as +02:00 (=12:00Z)
	// that string-compares GREATER
	mustOK(t, l, ev("observation.recorded", "2026-07-12T13:00:00Z",
		[]string{"db"}, obs("2026-07-12T13:00:00Z", true), 0))
	mustOK(t, l, ev("observation.recorded", "2026-07-12T13:00:01Z",
		[]string{"db"}, obs("2026-07-12T14:00:00+02:00", false), 0))
	rec := l.Observations["db"]["service.managed"]
	if rec.Value != true {
		t.Errorf("older offset-form observation replaced a newer one: %v",
			rec)
	}
}

// Fix 5: a REJECTED event must not advance the coordination clock — a
// forward-dated junk append used to poison it, refusing all honest
// writers behind it.
func TestRejectedEventDoesNotPoisonClock(t *testing.T) {
	l := New()
	l.Lenient = false
	l.Clock = 100
	// mutation without a fencing token, dated far in the future: rejected
	res, err := l.Append(ev("binding.updated", "2030-01-01T00:00:00Z",
		[]string{"db"}, map[string]any{"resources": []any{}}, 0), nil)
	if err != nil || res.Status != "rejected" {
		t.Fatalf("expected rejection, got %v %v", res, err)
	}
	// an honest writer at a sane time must still be accepted
	res = mustOK(t, l, ev("observation.recorded", "2026-07-12T13:00:00Z",
		[]string{"db"}, map[string]any{"observations": []any{}}, 0))
	_ = res
}

// D56 baseline: a genuinely backdated append is refused with the skew
// named; the same time is allowed (many events share a timestamp).
func TestBackdatedAppendRefused(t *testing.T) {
	l := New()
	l.Lenient = false
	l.Clock = 100
	mustOK(t, l, ev("observation.recorded", "2026-07-12T13:00:00Z",
		[]string{"db"}, map[string]any{"observations": []any{}}, 0))
	res, err := l.Append(ev("observation.recorded", "2026-07-12T12:59:59Z",
		[]string{"db"}, map[string]any{"observations": []any{}}, 0), nil)
	if err != nil || res.Status != "rejected" ||
		!strings.Contains(res.Reason, "regresses") {
		t.Fatalf("backdated append must be rejected: %v %v", res, err)
	}
	mustOK(t, l, ev("observation.recorded", "2026-07-12T13:00:00Z",
		[]string{"db"}, map[string]any{"observations": []any{}}, 0))
}

// F16/F25 residual: an observation.recorded event with ZERO observations adds
// nothing to Observations, yet MUST mark the capability observed — the signal the
// compiler uses to isolate a blind-observer capability instead of freezing on it.
func TestEmptyObservationMarksCapabilityObserved(t *testing.T) {
	l := New()
	l.Clock = 100
	mustOK(t, l, ev("observation.recorded", "2026-07-12T13:00:00Z",
		[]string{"db"}, map[string]any{"observations": []any{}}, 0))
	if len(l.Observations["db"]) != 0 {
		t.Fatalf("an empty observation.recorded must add no Observations, got %v",
			l.Observations["db"])
	}
	if !l.ObservedCapabilities()["db"] {
		t.Fatal("a recorded (even empty) observation must mark the capability observed")
	}
	if l.ObservedCapabilities()["never"] {
		t.Fatal("a capability with no observation event must not be marked observed")
	}
}

// D65: replay cost is MEASURED, not guessed. The ledger replays on
// every verb; these numbers bound the file-backend's comfortable range
// and are recorded in the evaluation. Snapshots (D33) activate when a
// deployment outgrows them.
func buildLedgerFile(b *testing.B, events int) string {
	b.Helper()
	dir := b.TempDir()
	path := dir + "/bench.jsonl"
	l := New()
	l.Clock = 0
	for i := 0; i < events; i++ {
		at := FormatTs(i + 1)
		doc := ev("observation.recorded", at, []string{"db"},
			map[string]any{"observations": []any{map[string]any{
				"kind": "Observation", "capability": "db",
				"path": "service.managed", "value": true,
				"derivation": "measured", "observedAt": at,
				"ttlSeconds": 900}}}, 0)
		l.Clock = i + 1
		if _, err := l.Append(doc, nil); err != nil {
			b.Fatal(err)
		}
		if err := PersistLine(path, doc); err != nil {
			b.Fatal(err)
		}
	}
	return path
}

func benchReplay(b *testing.B, n int) {
	path := buildLedgerFile(b, n)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := ReplayFile(path); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkReplay1k(b *testing.B)  { benchReplay(b, 1_000) }
func BenchmarkReplay10k(b *testing.B) { benchReplay(b, 10_000) }
func BenchmarkReplay50k(b *testing.B) { benchReplay(b, 50_000) }

// D67: lease acquisition is linearizable. Two writers over the SAME
// file — each built from an independent replay, as two processes would
// be — cannot both acquire the lease: the second re-replays under the
// lock, sees the first's active lease, and is rejected. No timing race:
// the guarantee is structural.
func TestConcurrentLeaseIsLinearizable(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/l.jsonl"

	mkWriter := func() *Writer {
		led, err := ReplayFile(path)
		if err != nil {
			t.Fatal(err)
		}
		return &Writer{Path: path, Led: led, Env: "test", Clock: 1000,
			Actor: "t"}
	}

	// both writers built from the same (empty) replay — the exact
	// stale-snapshot condition the old bug exploited
	w1, w2 := mkWriter(), mkWriter()

	tok1, err := w1.AppendLease([]string{"db"},
		map[string]any{"ttlSeconds": 300})
	if err != nil {
		t.Fatalf("first lease must succeed: %v", err)
	}
	_, err = w2.AppendLease([]string{"db"},
		map[string]any{"ttlSeconds": 300})
	if err == nil {
		t.Fatal("second concurrent lease MUST be rejected — the race is open")
	}

	// the ledger stays replayable (no fork) and carries exactly one lease
	led, err := ReplayFile(path)
	if err != nil {
		t.Fatalf("ledger bricked after the race: %v", err)
	}
	if led.ActiveToken("db") != tok1 {
		t.Errorf("winner's token not active: %d vs %d",
			led.ActiveToken("db"), tok1)
	}
	lines := 0
	for range led.Heads {
		lines++
	}
	if lines != 1 {
		t.Errorf("expected one bound capability, got %d", lines)
	}
}

// F2/F7: an orphan that becomes bound again (re-adopt, which resume
// recommends) must leave the deposed set — otherwise plan --deposed
// would seal a delete of a LIVE resource. And the pinned generation
// must be keyed per capability, not shared across a reused providerId.
func TestDeposedExcludesReboundAndKeysByCapability(t *testing.T) {
	l := New()
	l.Clock = 100
	bind := func(cap, pid string, gen int, replaces []any) {
		body := map[string]any{
			"capability": cap, "environment": "test",
			"provider": map[string]any{"name": "fake"},
			"resources": []any{map[string]any{"id": "primary", "type": "t",
				"providerId": pid, "generation": gen}},
		}
		if replaces != nil {
			body["lineage"] = map[string]any{"replaces": replaces}
		}
		l.Bindings[cap] = body
		l.accumulateLineage(cap, body)
	}

	// db: fake:x replaced by fake:y; fake:x is a deposed orphan (gen 1)
	bind("db", "fake:x", 1, nil)
	bind("db", "fake:y", 2, []any{"fake:x"})
	dep := l.Deposed(false)
	if len(dep) != 1 || dep[0].ProviderID != "fake:x" || dep[0].Generation != 1 {
		t.Fatalf("expected fake:x gen 1 deposed, got %+v", dep)
	}

	// now fake:x is re-adopted under a DIFFERENT capability at gen 5.
	// It is live-bound again -> it must NOT be deposed anywhere, and its
	// (cap,id)-keyed generation must not leak into db's projection.
	bind("cache", "fake:x", 5, nil)
	dep = l.Deposed(false)
	for _, d := range dep {
		if d.ProviderID == "fake:x" {
			t.Fatalf("re-bound fake:x still reported deposed (%s) — "+
				"plan --deposed would delete a live resource", d.Capability)
		}
	}
}

// F1: an orphaned lease must expire by TTL on the PERSISTED path. A
// crash after lease.acquired but before lease.released must not deadlock
// every future writer — commitUnderLock judges expiry against THIS
// write's --at, not the last persisted occurredAt.
func TestOrphanedLeaseExpiresByTTL(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/l.jsonl"

	// writer A acquires a lease at t=1000, ttl=300, then "crashes"
	// (never releases)
	ledA, _ := ReplayFile(path)
	wA := &Writer{Path: path, Led: ledA, Env: "test", Clock: 1000, Actor: "A"}
	if _, err := wA.AppendLease([]string{"db"},
		map[string]any{"ttlSeconds": 300}); err != nil {
		t.Fatalf("first lease must succeed: %v", err)
	}

	// writer B arrives long after the TTL (t=10000). Before the fix this
	// deadlocked: the replay clock was stuck at 1000, so the lease looked
	// active forever and no new acquire could advance the clock.
	ledB, _ := ReplayFile(path)
	wB := &Writer{Path: path, Led: ledB, Env: "test", Clock: 10000, Actor: "B"}
	if _, err := wB.AppendLease([]string{"db"},
		map[string]any{"ttlSeconds": 300}); err != nil {
		t.Fatalf("lease past TTL must be acquirable — orphaned lease "+
			"deadlock (F1): %v", err)
	}

	// and a writer still WITHIN the TTL must still be rejected
	ledC, _ := ReplayFile(path)
	wC := &Writer{Path: path, Led: ledC, Env: "test", Clock: 10100, Actor: "C"}
	if _, err := wC.AppendLease([]string{"db"},
		map[string]any{"ttlSeconds": 300}); err == nil {
		t.Fatal("a lease within the active TTL must still be rejected")
	}
}

// C2: the hash chain is VERIFIED, not merely written. A tampered,
// reordered or truncated line breaks the chain and is corruption —
// previously such edits replayed clean and silently changed the
// projections that gate deletes.
func TestTamperedLedgerIsRefused(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/l.jsonl"
	led, _ := ReplayFile(path)
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
	if _, err := ReplayFile(path); err != nil {
		t.Fatalf("honest ledger must replay: %v", err)
	}

	// tamper an event that HAS a successor: its hash is pinned by the
	// next event's prev. (The LAST line is not chain-protected — nothing
	// pins it yet; an inherent property of an unanchored chain,
	// documented in spec/state-model.md.)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	tampered := strings.Replace(string(raw), `"ttlSeconds":300`,
		`"ttlSeconds":900`, 1)
	if tampered == string(raw) {
		t.Fatal("tamper did not apply")
	}
	if err := os.WriteFile(path, []byte(tampered), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := ReplayFile(path); err == nil {
		t.Fatal("tampered ledger MUST be refused — the chain is unverified")
	}

	// truncation of a middle line is equally fatal
	if err := os.WriteFile(path, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimRight(string(raw), "\n"), "\n")
	if len(lines) < 2 {
		t.Fatal("need at least two lines")
	}
	if err := os.WriteFile(path,
		[]byte(lines[1]+"\n"), 0o644); err != nil { // drop the lease line
		t.Fatal(err)
	}
	if _, err := ReplayFile(path); err == nil {
		t.Fatal("a dropped line MUST break the chain")
	}
}

// TestBindingReleaseClearsAuthorshipClaim pins D192 F1: releasing a binding
// (unadopt writes binding.updated with empty resources) must clear the
// authorship claim — it was stamped on the resource just released. A stale
// claim would let a later re-adopt of a DIFFERENT resource read
// Adopted && !Claimed == false, so the compiler emits no claim and the new
// resource is bound but never stamped (the D140 takeover hole, re-opened).
func TestBindingReleaseClearsAuthorshipClaim(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/l.jsonl"
	w := &Writer{Path: path, Led: New(), Env: "dev", Clock: 1000, Actor: "t"}
	tok, err := w.AppendLease([]string{"db"}, map[string]any{"ttlSeconds": 300})
	if err != nil {
		t.Fatal(err)
	}
	if err := w.Append("binding.updated", []string{"db"}, map[string]any{
		"resources": []any{map[string]any{"id": "primary", "type": "t",
			"providerId": "fake:A", "generation": 1, "origin": "adopted"}}}, tok); err != nil {
		t.Fatal(err)
	}
	if err := w.Append("ownership.claimed", []string{"db"},
		map[string]any{"note": "takeover"}, tok); err != nil {
		t.Fatal(err)
	}
	if err := w.Append("lease.released", []string{"db"}, nil, tok); err != nil {
		t.Fatal(err)
	}
	led, err := ReplayFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !led.ClaimedCapabilities()["db"] {
		t.Fatal("precondition: db must be claimed after ownership.claimed")
	}

	// unadopt: release the binding (empty resources)
	w2 := &Writer{Path: path, Led: led, Env: "dev", Clock: 2000, Actor: "t"}
	tok2, err := w2.AppendLease([]string{"db"}, map[string]any{"ttlSeconds": 300})
	if err != nil {
		t.Fatal(err)
	}
	if err := w2.Append("binding.updated", []string{"db"}, map[string]any{
		"resources": []any{},
		"unadopted": map[string]any{"providerId": "fake:A", "generation": 1}}, tok2); err != nil {
		t.Fatal(err)
	}
	if err := w2.Append("lease.released", []string{"db"}, nil, tok2); err != nil {
		t.Fatal(err)
	}
	led, err = ReplayFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if led.ClaimedCapabilities()["db"] {
		t.Fatal("releasing the binding must clear the authorship claim (D192)")
	}
}
