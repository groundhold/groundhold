package publish

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"groundhold/internal/contract"
	"groundhold/internal/perr"
)

// White-box tests for `groundhold publish` (D74): authorship recorded in
// the ledger. publish mutates only the ledger, takes no lease, refuses
// before touching anything when consent/clock/anchor discipline fails.

func testContract() *contract.Contract {
	return &contract.Contract{
		ID:          "c-app",
		Environment: "prod",
		Version:     1,
		Capabilities: map[string]map[string]any{
			"db":    {"kind": "capability.database.managed-relational"},
			"cache": {"kind": "capability.cache"},
		},
	}
}

// readEvents parses a JSONL ledger into its event bodies, in file order.
func readEvents(t *testing.T, path string) []map[string]any {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read ledger: %v", err)
	}
	var out []map[string]any
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		if line == "" {
			continue
		}
		var doc map[string]any
		if err := json.Unmarshal([]byte(line), &doc); err != nil {
			t.Fatalf("bad ledger line: %v", err)
		}
		ev, _ := doc["event"].(map[string]any)
		out = append(out, ev)
	}
	return out
}

func TestRefusals(t *testing.T) {
	cases := []struct {
		name   string
		actor  string
		at     string
		code   perr.Code
		exit   int
		reason string // substring expected in the refusal reason
	}{
		{
			name: "empty actor refuses — authorship needs a named publisher",
			// consent-required fires before the clock is even parsed, so a
			// blank --at must not mask it
			actor: "", at: "",
			code: perr.ConsentRequired, exit: 2, reason: "name the publisher",
		},
		{
			name:  "unparseable --at is a structural error",
			actor: "alice", at: "not-a-timestamp",
			code: perr.StructuralError, exit: 2, reason: "bad --at",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "ledger.jsonl")
			res := Run(testContract(), path, tc.actor, tc.at)
			if res.Status != "refused" {
				t.Fatalf("status = %q, want refused", res.Status)
			}
			if res.Code != tc.code {
				t.Errorf("code = %q, want %q", res.Code, tc.code)
			}
			if res.Exit != tc.exit {
				t.Errorf("exit = %d, want %d", res.Exit, tc.exit)
			}
			if len(res.Reasons) == 0 ||
				!strings.Contains(res.Reasons[0], tc.reason) {
				t.Errorf("reasons = %v, want substring %q", res.Reasons, tc.reason)
			}
			// a refusal must not create the ledger — it mutates nothing
			if _, err := os.Stat(path); !os.IsNotExist(err) {
				t.Errorf("refusal wrote a ledger file (err=%v)", err)
			}
		})
	}
}

func TestHappyPath(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ledger.jsonl")
	res := Run(testContract(), path, "alice", "2026-07-24T00:00:00Z")

	if res.Status != "published" {
		t.Fatalf("status = %q (%v), want published", res.Status, res.Reasons)
	}
	if res.Exit != 0 {
		t.Errorf("exit = %d, want 0", res.Exit)
	}
	if res.Code != "" {
		t.Errorf("code = %q, want empty on success", res.Code)
	}
	if res.Actor != "alice" {
		t.Errorf("actor = %q, want alice", res.Actor)
	}
	if !strings.HasPrefix(res.ContractHash, "sha256:") {
		t.Errorf("contractHash = %q, want sha256: prefix", res.ContractHash)
	}
	if len(res.Events) != 1 || res.Events[0] != "contract.published" {
		t.Fatalf("events = %v, want [contract.published]", res.Events)
	}

	evs := readEvents(t, path)
	if len(evs) != 1 {
		t.Fatalf("ledger has %d events, want 1", len(evs))
	}
	ev := evs[0]
	if ev["type"] != "contract.published" {
		t.Errorf("event type = %v", ev["type"])
	}
	actor, _ := ev["actor"].(map[string]any)
	if actor["id"] != "alice" || actor["type"] != "human" {
		t.Errorf("actor = %v, want {alice, human}", actor)
	}
	body, _ := ev["body"].(map[string]any)
	if body["contract"] != "c-app" || body["contractHash"] != res.ContractHash {
		t.Errorf("body = %v, want contract=c-app hash=%s", body, res.ContractHash)
	}
	// version is a JSON number after round-trip
	if v, _ := body["version"].(float64); v != 1 {
		t.Errorf("body version = %v, want 1", body["version"])
	}
}

// The event's capabilities must be the contract's capability ids, sorted —
// publish sorts them before appending (deterministic record).
func TestCapabilitiesSorted(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ledger.jsonl")
	if res := Run(testContract(), path, "alice",
		"2026-07-24T00:00:00Z"); res.Status != "published" {
		t.Fatalf("publish refused: %v", res.Reasons)
	}
	ev := readEvents(t, path)[0]
	rawCaps, _ := ev["capabilities"].([]any)
	got := make([]string, len(rawCaps))
	for i, c := range rawCaps {
		got[i], _ = c.(string)
	}
	want := []string{"cache", "db"}
	if len(got) != len(want) {
		t.Fatalf("caps = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("caps = %v, want %v (sorted)", got, want)
		}
	}
}

// Re-running an identical publish is safe (docstring: "idempotent-safe to
// re-run … just another dated record of the same hash"). Two records, one
// hash.
func TestReRunAppendsSecondRecord(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ledger.jsonl")
	c := testContract()
	r1 := Run(c, path, "alice", "2026-07-24T00:00:00Z")
	r2 := Run(c, path, "bob", "2026-07-24T01:00:00Z")
	if r1.Status != "published" || r2.Status != "published" {
		t.Fatalf("re-run refused: r1=%v r2=%v", r1.Reasons, r2.Reasons)
	}
	if r1.ContractHash != r2.ContractHash {
		t.Errorf("same contract hashed differently: %s vs %s",
			r1.ContractHash, r2.ContractHash)
	}
	evs := readEvents(t, path)
	if len(evs) != 2 {
		t.Fatalf("ledger has %d events, want 2", len(evs))
	}
}

// A publish whose --at precedes recorded ledger history is refused
// (clock-regress) — history cannot un-happen. Second publish is backdated.
func TestClockRegressRefused(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ledger.jsonl")
	c := testContract()
	if res := Run(c, path, "alice",
		"2026-07-24T12:00:00Z"); res.Status != "published" {
		t.Fatalf("seed publish refused: %v", res.Reasons)
	}
	res := Run(c, path, "alice", "2020-01-01T00:00:00Z")
	if res.Status != "refused" || res.Code != perr.ClockRegress {
		t.Fatalf("status=%q code=%q, want refused/clock-regress",
			res.Status, res.Code)
	}
	if res.Exit != 2 {
		t.Errorf("exit = %d, want 2", res.Exit)
	}
	// the backdated attempt must not have appended
	if evs := readEvents(t, path); len(evs) != 1 {
		t.Errorf("ledger grew to %d events on a refused publish", len(evs))
	}
}

// A torn (no trailing newline) ledger is corruption; ReplayFile refuses and
// publish surfaces ledger-corrupted / exit 5, before any append.
func TestTornLedgerRefused(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ledger.jsonl")
	if err := os.WriteFile(path, []byte(`{"apiVersion":"state/v0"}`),
		0o600); err != nil {
		t.Fatal(err)
	}
	res := Run(testContract(), path, "alice", "2026-07-24T00:00:00Z")
	if res.Status != "refused" || res.Code != perr.LedgerCorrupted {
		t.Fatalf("status=%q code=%q, want refused/ledger-corrupted",
			res.Status, res.Code)
	}
	if res.Exit != 5 {
		t.Errorf("exit = %d, want 5", res.Exit)
	}
}

// An armed anchor beside the ledger is enforced on the publish path: a
// forged anchor pinning 0 events but a non-genesis head diverges, so publish
// refuses fail-closed (ledger-corrupted / exit 5) before appending.
func TestAnchorMismatchRefused(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ledger.jsonl")
	anchor := map[string]any{
		"apiVersion": "state/v0",
		"kind":       "LedgerAnchor",
		"events":     0,
		"head":       "sha256:deadbeef",
	}
	raw, _ := json.Marshal(anchor)
	if err := os.WriteFile(path+".anchor", raw, 0o600); err != nil {
		t.Fatal(err)
	}
	res := Run(testContract(), path, "alice", "2026-07-24T00:00:00Z")
	if res.Status != "refused" || res.Code != perr.LedgerCorrupted {
		t.Fatalf("status=%q code=%q, want refused/ledger-corrupted",
			res.Status, res.Code)
	}
	if res.Exit != 5 {
		t.Errorf("exit = %d, want 5", res.Exit)
	}
	// fail-closed: nothing appended
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Errorf("anchor refusal wrote a ledger (err=%v)", err)
	}
}
