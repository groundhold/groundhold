package ledger

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// The D137 equivalence property, over the ENTIRE struct including
// unexported projections: folding the full history must equal seeding
// from a snapshot of its prefix and folding the tail. A projection
// added to Ledger without snapshot support fails HERE, loudly —
// silent state loss is the failure mode this test forbids.
func TestSnapshotEquivalenceOverEveryProjection(t *testing.T) {
	td := t.TempDir()
	full := filepath.Join(td, "full.jsonl")

	// a history that touches every projection family: publish (decision
	// heads, environments), lease+apply receipts (tokens, pending,
	// bodies), a terminal receipt, bindings, observations, a violation
	// detected (state), a second capability left mid-flight
	w := &Writer{Path: full, Led: New(), Env: "prod", Clock: 1752600000, Actor: "t"}
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(w.Append("contract.published", []string{"db", "cache"},
		map[string]any{"contract": "orders", "version": 1}, 0))
	w.Clock += 60
	tok, err := w.AppendLease([]string{"db"}, map[string]any{"ttlSeconds": 300})
	must(err)
	must(w.Append("operation.receipt", []string{"db"}, map[string]any{
		"operationId": "op-1", "status": "pending",
		"idempotencyKey": "k1"}, tok))
	must(w.Append("operation.receipt", []string{"db"}, map[string]any{
		"operationId": "op-1", "status": "succeeded",
		"idempotencyKey": "k1"}, tok))
	must(w.Append("binding.updated", []string{"db"}, map[string]any{
		"providerId": "fake:db-1", "generation": 2}, tok))
	must(w.Append("lease.released", []string{"db"}, nil, tok))
	w.Clock += 60
	must(w.Append("observation.recorded", []string{"db"}, map[string]any{
		"observations": []any{map[string]any{
			"path": "service.managed", "value": true,
			"observedAt": "2026-07-15T18:02:00Z", "ttlSeconds": 86400,
			"derivation": "measured", "source": "provider-api"}}}, 0))
	must(w.Append("violation.detected", []string{"db"}, map[string]any{
		"capability": "db", "constraint": "c-x", "reason": "drift"}, 0))
	// ---- snapshot boundary falls HERE ----
	prefixLines := 8
	w.Clock += 60
	tok2, err := w.AppendLease([]string{"cache"}, map[string]any{"ttlSeconds": 300})
	must(err)
	must(w.Append("operation.receipt", []string{"cache"}, map[string]any{
		"operationId": "op-9", "status": "unknown",
		"idempotencyKey": "k9"}, tok2))
	must(w.Append("violation.resolved", []string{"db"}, map[string]any{
		"capability": "db", "constraint": "c-x"}, 0))

	fullLed, err := ReplayFile(full)
	must(err)

	// split: prefix -> snapshot, tail -> its own file
	raw, _ := os.ReadFile(full)
	lines := splitLines(raw)
	prefix := filepath.Join(td, "prefix.jsonl")
	tail := filepath.Join(td, "tail.jsonl")
	joinWrite := func(path string, ls []string) {
		out := ""
		for _, l := range ls {
			out += l + "\n"
		}
		must(os.WriteFile(path, []byte(out), 0o600))
	}
	joinWrite(prefix, lines[:prefixLines])
	joinWrite(tail, lines[prefixLines:])

	prefLed, err := ReplayFile(prefix)
	must(err)
	snap := BuildSnapshot(prefLed)

	// the REAL path: snapshot sidecar beside the tail file, then the
	// ordinary ReplayFile — serialization boundary (float64 drift and
	// all) included, exactly as production reads it
	rawSnap, err := json.Marshal(snap)
	must(err)
	must(os.WriteFile(SnapshotPath(tail), rawSnap, 0o600))
	seeded, err := ReplayFile(tail)
	must(err)

	// one comparison discipline for both tests (fuzz + this one)
	assertLedgersEquivalent(t, fullLed, seeded)
}
