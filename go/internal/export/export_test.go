package export

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"groundhold/internal/ledger"
)

const sampleEvent = `{"apiVersion":"state/v0","kind":"LedgerEvent",` +
	`"event":{"type":"contract.published","environment":"production",` +
	`"occurredAt":"2026-07-12T08:00:00Z","capabilities":["cache"],` +
	`"actor":{"id":"piotr","type":"human"},"prev":{"cache":"genesis"}}}`

func run(t *testing.T, format string) []map[string]any {
	t.Helper()
	lp := filepath.Join(t.TempDir(), "l.jsonl")
	if err := os.WriteFile(lp, []byte(sampleEvent+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	n, err := Run(Options{LedgerPath: lp, Format: format, Out: &buf})
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("emitted %d, want 1", n)
	}
	var out []map[string]any
	for _, line := range bytes.Split(bytes.TrimSpace(buf.Bytes()), []byte("\n")) {
		var m map[string]any
		if err := json.Unmarshal(line, &m); err != nil {
			t.Fatal(err)
		}
		out = append(out, m)
	}
	return out
}

func TestCloudEventsFold(t *testing.T) {
	rec := run(t, "cloudevents")[0]
	if rec["specversion"] != "1.0" {
		t.Fatalf("specversion=%v", rec["specversion"])
	}
	if rec["type"] != "io.groundhold.contract.published" {
		t.Fatalf("type=%v", rec["type"])
	}
	if rec["source"] != "groundhold://production/ledger" {
		t.Fatalf("source=%v (must be the authority, not a file path)", rec["source"])
	}
	if rec["time"] != "2026-07-12T08:00:00Z" {
		t.Fatalf("time=%v — occurredAt verbatim, never export time", rec["time"])
	}
	if rec["subject"] != "cache" {
		t.Fatalf("subject=%v", rec["subject"])
	}
	// id is the canonical event hash — content-derived, so redelivery dedupes.
	if id, _ := rec["id"].(string); len(id) < 8 {
		t.Fatalf("id=%q, want the canonical event hash", id)
	}
}

func TestNdjsonAndCloudeventsShareTheHashId(t *testing.T) {
	nd := run(t, "ndjson")[0]
	ce := run(t, "cloudevents")[0]
	if nd["id"] != ce["id"] {
		t.Fatalf("ndjson id %v != cloudevents id %v — same event, same id", nd["id"], ce["id"])
	}
}

func TestUnknownFormatRefuses(t *testing.T) {
	lp := filepath.Join(t.TempDir(), "l.jsonl")
	_ = os.WriteFile(lp, []byte(sampleEvent+"\n"), 0o600)
	var buf bytes.Buffer
	if _, err := Run(Options{LedgerPath: lp, Format: "xml", Out: &buf}); err == nil {
		t.Fatal("expected an error for an unknown format")
	}
}

// TestExportWindowProjectsByOccurredAt: --from/--to is a pure PROJECTION over
// occurredAt — every line is still folded/verified, only the emitted set is
// windowed. A [mid,mid] window emits exactly the middle event.
func TestExportWindowProjectsByOccurredAt(t *testing.T) {
	ledger.ResetSigning()
	lp := filepath.Join(t.TempDir(), "l.jsonl")
	led, err := ledger.ReplayFile(lp)
	if err != nil {
		t.Fatal(err)
	}
	w := &ledger.Writer{Path: lp, Led: led, Env: "test", Actor: "t"}
	w.Clock = 1000
	tok, err := w.AppendLease([]string{"cap"}, map[string]any{"ttlSeconds": 100000})
	if err != nil {
		t.Fatal(err)
	}
	w.Clock = 2000
	if err := w.Append("binding.updated", []string{"cap"},
		map[string]any{"resources": []any{map[string]any{
			"id": "primary", "type": "fake.thing", "providerId": "fake:x", "generation": 1}}},
		tok); err != nil {
		t.Fatal(err)
	}
	w.Clock = 3000
	if err := w.Append("lease.released", []string{"cap"}, nil, tok); err != nil {
		t.Fatal(err)
	}

	mid := ledger.FormatTs(2000)
	var buf bytes.Buffer
	n, err := Run(Options{LedgerPath: lp, From: mid, To: mid, Out: &buf})
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("window [mid,mid] must emit exactly the middle event, got %d", n)
	}
	var rec map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(buf.Bytes()), &rec); err != nil {
		t.Fatal(err)
	}
	if rec["type"] != "binding.updated" {
		t.Fatalf("windowed event = %v, want binding.updated", rec["type"])
	}

	// an inverted window is an error, not an empty success.
	if _, err := Run(Options{LedgerPath: lp, From: ledger.FormatTs(3000),
		To: ledger.FormatTs(1000), Out: &bytes.Buffer{}}); err == nil {
		t.Fatal("an inverted --from/--to window must error")
	}
}
