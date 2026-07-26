package scenario

import (
	"reflect"
	"strings"
	"testing"
)

// White-box tests for the deterministic concurrency scenario engine (D37).
// The rules live in internal/ledger — the same code apply drives (D42) — so
// what these scenarios pin is what apply obeys. Here we pin the ENGINE: the
// step parsing, event construction from the logical clock, symbolic "@N"
// references and the four semantic outcomes (ok/conflict/rejected + token,
// fresh/stale). Each case is a fixed interleaving mapping to a fixed result.

// ---- builders -------------------------------------------------------------

func capsOf(cs ...string) []any {
	out := make([]any, len(cs))
	for i, c := range cs {
		out[i] = c
	}
	return out
}

func lease(caps []any, ttl int, actor string) map[string]any {
	return map[string]any{"append": map[string]any{
		"type": "lease.acquired", "capabilities": caps, "actor": actor,
		"body": map[string]any{"ttlSeconds": ttl}}}
}

// mut builds any mutation/coordination append carrying a fencing token.
func mut(etype string, caps []any, actor string, token int) map[string]any {
	return map[string]any{"append": map[string]any{
		"type": etype, "capabilities": caps, "actor": actor,
		"fencingToken": token}}
}

func broken(caps []any, actor string, adopt bool) map[string]any {
	a := map[string]any{"type": "lease.broken", "capabilities": caps, "actor": actor}
	if adopt {
		a["body"] = map[string]any{"adoptReceipts": true}
	}
	return map[string]any{"append": a}
}

func receipt(caps []any, actor, op, status string) map[string]any {
	return map[string]any{"append": map[string]any{
		"type": "operation.receipt", "capabilities": caps, "actor": actor,
		"body": map[string]any{"operationId": op, "status": status}}}
}

func pub(etype string, caps []any) map[string]any {
	return map[string]any{"append": map[string]any{
		"type": etype, "capabilities": caps}}
}

func tick(n int) map[string]any { return map[string]any{"tick": n} }
func chk(m map[string]any) map[string]any {
	return map[string]any{"checkHeads": m}
}
func chkDec(m map[string]any) map[string]any {
	return map[string]any{"checkDecisionHeads": m}
}

func doc(steps ...map[string]any) map[string]any {
	list := make([]any, len(steps))
	for i, s := range steps {
		list[i] = s
	}
	return map[string]any{
		"apiVersion": "scenario/v0", "kind": "ConcurrencyScenario",
		"steps": list}
}

// ---- result assertion -----------------------------------------------------

type R struct {
	status string
	token  int // 0 means "token must be absent"
}

func run(t *testing.T, d map[string]any) []map[string]any {
	t.Helper()
	res, err := Run(d)
	if err != nil {
		t.Fatalf("Run: unexpected error: %v", err)
	}
	return res
}

func check(t *testing.T, got []map[string]any, want []R) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("got %d results, want %d: %v", len(got), len(want), got)
	}
	for i := range want {
		gs, _ := got[i]["status"].(string)
		if gs != want[i].status {
			t.Errorf("step %d: status = %q, want %q", i+1, gs, want[i].status)
		}
		gt, has := got[i]["token"]
		switch {
		case want[i].token > 0 && !has:
			t.Errorf("step %d: missing token, want %d", i+1, want[i].token)
		case want[i].token > 0 && gt.(int) != want[i].token:
			t.Errorf("step %d: token = %v, want %d", i+1, gt, want[i].token)
		case want[i].token == 0 && has:
			t.Errorf("step %d: unexpected token %v", i+1, gt)
		}
	}
}

// ---- semantic scenarios (fixed interleaving -> fixed outcome) -------------

func TestScenarios(t *testing.T) {
	db := capsOf("db")
	cases := []struct {
		name  string
		steps []map[string]any
		want  []R
	}{
		{
			// D28: append succeeds only against the expected head; a
			// concurrent writer at the same head sees a conflict, and the
			// re-read (expectedHeads @1) then commits. Exercises "@N" resolve.
			name: "cas-append-and-conflict",
			steps: []map[string]any{
				{"append": map[string]any{"type": "contract.published",
					"capabilities": db, "actor": "alice", "actorType": "human"},
					"expectedHeads": map[string]any{"db": "genesis"}},
				{"append": map[string]any{"type": "candidate.verified",
					"capabilities": db, "actor": "bob"},
					"expectedHeads": map[string]any{"db": "genesis"}},
				{"append": map[string]any{"type": "candidate.verified",
					"capabilities": db, "actor": "bob"},
					"expectedHeads": map[string]any{"db": "@1"}},
			},
			want: []R{{status: "ok"}, {status: "conflict"}, {status: "ok"}},
		},
		{
			// D29 + D35: tokens derive from history — max prior token + 1,
			// monotonic across release/reacquire (never reset).
			name: "lease-tokens-are-monotonic",
			steps: []map[string]any{
				lease(db, 100, "a"),
				mut("lease.released", db, "a", 1),
				lease(db, 100, "b"),
			},
			want: []R{{status: "ok", token: 1}, {status: "ok"},
				{status: "ok", token: 2}},
		},
		{
			// D29: a worker paused past its TTL resumes and writes with a
			// stale token — rejected. TTL alone would let it falsify history;
			// fencing is what makes lease acquisition safe.
			name: "resumed-stale-worker-cannot-write",
			steps: []map[string]any{
				lease(db, 3, "a"),
				tick(5),
				lease(db, 100, "b"),
				mut("binding.updated", db, "a", 1),
				mut("binding.updated", db, "b", 2),
			},
			want: []R{{status: "ok", token: 1}, {status: "ok"},
				{status: "ok", token: 2}, {status: "rejected"}, {status: "ok"}},
		},
		{
			// Only one writer wins: a second acquire over an ACTIVE lease is
			// rejected (linearizable acquisition, the concurrency invariant).
			name: "cannot-acquire-over-active-lease",
			steps: []map[string]any{
				lease(db, 100, "a"),
				lease(db, 100, "b"),
			},
			want: []R{{status: "ok", token: 1}, {status: "rejected"}},
		},
		{
			// D29: mutations require an active lease AND its token.
			name: "mutation-without-lease-is-rejected",
			steps: []map[string]any{
				mut("binding.updated", db, "a", 1),
				mut("apply.started", db, "a", 1),
			},
			want: []R{{status: "rejected"}, {status: "rejected"}},
		},
		{
			// D29: a pending receipt blocks lease.broken until the operation
			// reaches a terminal status — cloud ops outlive processes.
			name: "receipt-reconciliation-gates-lease-break",
			steps: []map[string]any{
				lease(db, 100, "a"),
				receipt(db, "a", "op-1", "pending"),
				broken(db, "b", false),
				receipt(db, "b", "op-1", "succeeded"),
				broken(db, "b", false),
				lease(db, 100, "b"),
			},
			want: []R{{status: "ok", token: 1}, {status: "ok"},
				{status: "rejected"}, {status: "ok"}, {status: "ok"},
				{status: "ok", token: 2}},
		},
		{
			// D29 + D57: an UNKNOWN outcome is nonterminal — it keeps the op
			// pending exactly like pending; breaking without adoptReceipts
			// stays refused, adoptReceipts concludes it deliberately.
			name: "unknown-receipt-blocks-lease-break",
			steps: []map[string]any{
				lease(db, 100, "a"),
				receipt(db, "a", "op-1", "unknown"),
				broken(db, "b", false),
				broken(db, "b", true),
				lease(db, 100, "b"),
			},
			want: []R{{status: "ok", token: 1}, {status: "ok"},
				{status: "rejected"}, {status: "ok"}, {status: "ok", token: 2}},
		},
		{
			// D29: renewal under the correct token extends the lease from the
			// renewal moment; past the extended TTL the token is stale again.
			name: "lease-renewal-extends-expiry",
			steps: []map[string]any{
				lease(db, 3, "a"),
				tick(2),
				mut("lease.renewed", db, "a", 1),
				tick(2),
				mut("binding.updated", db, "a", 1),
				tick(2),
				mut("binding.updated", db, "a", 1),
			},
			want: []R{{status: "ok", token: 1}, {status: "ok"}, {status: "ok"},
				{status: "ok"}, {status: "ok"}, {status: "ok"},
				{status: "rejected"}},
		},
		{
			// A lease may span several capabilities: one token guards all,
			// and any held member blocks a competing acquire.
			name: "multi-capability-lease",
			steps: []map[string]any{
				lease(capsOf("db", "cache"), 100, "a"),
				mut("binding.updated", capsOf("db", "cache"), "a", 1),
				lease(capsOf("db"), 100, "b"),
				mut("lease.released", capsOf("db", "cache"), "a", 1),
				lease(capsOf("cache"), 100, "b"),
			},
			want: []R{{status: "ok", token: 1}, {status: "ok"},
				{status: "rejected"}, {status: "ok"}, {status: "ok", token: 2}},
		},
		{
			// D28: a checkHeads read-set goes stale the moment any later
			// event lands on the capability.
			name: "checkheads-detects-stale-read-set",
			steps: []map[string]any{
				pub("plan.sealed", db),
				chk(map[string]any{"db": "@1"}),
				pub("contract.published", db),
				chk(map[string]any{"db": "@1"}),
			},
			want: []R{{status: "ok"}, {status: "fresh"}, {status: "ok"},
				{status: "stale"}},
		},
		{
			// D41: knowledge (observations, receipts) and coordination (lease
			// churn) advance the audit chain but never the DECISION heads a
			// sealed plan pins. Learning is not deciding.
			name: "knowledge-does-not-invalidate-decisions",
			steps: []map[string]any{
				pub("contract.published", db),
				chkDec(map[string]any{"db": "@1"}),
				lease(db, 100, "a"),
				chkDec(map[string]any{"db": "@1"}),
				receipt(db, "a", "op-1", "succeeded"),
				chkDec(map[string]any{"db": "@1"}),
				chk(map[string]any{"db": "@1"}),
				mut("binding.updated", db, "a", 1),
				chkDec(map[string]any{"db": "@1"}),
			},
			want: []R{{status: "ok"}, {status: "fresh"}, {status: "ok", token: 1},
				{status: "fresh"}, {status: "ok"}, {status: "fresh"},
				{status: "stale"}, {status: "ok"}, {status: "stale"}},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			check(t, run(t, doc(c.steps...)), c.want)
		})
	}
}

// TestDeterminism pins the whole point of the engine: identical input yields
// byte-identical output, including the hashes behind every "@N"/checkHeads
// verdict. A regression that made any outcome depend on map iteration order
// or wall time would break this.
func TestDeterminism(t *testing.T) {
	db := capsOf("db")
	d := doc(
		pub("plan.sealed", db),
		lease(db, 3, "a"),
		tick(2),
		mut("lease.renewed", db, "a", 1),
		mut("binding.updated", db, "a", 1),
		chk(map[string]any{"db": "@5"}),
		pub("contract.published", db),
		chk(map[string]any{"db": "@5"}),
	)
	first := run(t, d)
	for i := 0; i < 20; i++ {
		got := run(t, d)
		if !reflect.DeepEqual(got, first) {
			t.Fatalf("run %d diverged:\n got=%v\nwant=%v", i, got, first)
		}
	}
}

// TestAppendDefaults pins that an append with no actor/actorType still
// commits (defaults runtime/runtime) — regressions here would reject valid
// scenarios or mis-attribute events.
func TestAppendDefaults(t *testing.T) {
	db := capsOf("db")
	res := run(t, doc(map[string]any{"append": map[string]any{
		"type": "contract.published", "capabilities": db}}))
	check(t, res, []R{{status: "ok"}})
}

// ---- Run-level error paths (authoring errors, surfaced not swallowed) -----

func TestRunErrors(t *testing.T) {
	db := capsOf("db")
	ok := map[string]any{"append": map[string]any{
		"type": "contract.published", "capabilities": db}}
	cases := []struct {
		name    string
		doc     any
		wantSub string
	}{
		{"non-map doc", "nope", "kind must be ConcurrencyScenario"},
		{"wrong kind", map[string]any{"apiVersion": "scenario/v0",
			"kind": "Nope", "steps": []any{ok}}, "kind must be ConcurrencyScenario"},
		{"wrong apiVersion", map[string]any{"apiVersion": "scenario/v9",
			"kind": "ConcurrencyScenario", "steps": []any{ok}},
			"apiVersion must be scenario/v0"},
		{"steps not a list", map[string]any{"apiVersion": "scenario/v0",
			"kind": "ConcurrencyScenario", "steps": "x"},
			"steps must be a non-empty list"},
		{"empty steps", map[string]any{"apiVersion": "scenario/v0",
			"kind": "ConcurrencyScenario", "steps": []any{}},
			"steps must be a non-empty list"},
		{"step not a mapping", map[string]any{"apiVersion": "scenario/v0",
			"kind": "ConcurrencyScenario", "steps": []any{"x"}},
			"step 1: not a mapping"},
		{"unknown step form", doc(map[string]any{"noSuchVerb": 1}),
			"step 1: unknown step form"},
		{"negative tick", doc(tick(-5)), "tick must be a positive integer"},
		{"zero tick", doc(tick(0)), "tick must be a positive integer"},
		{"non-integer tick", doc(map[string]any{"tick": 3.5}),
			"tick must be a positive integer"},
		{"expectedHeads not a mapping", doc(map[string]any{
			"append": map[string]any{"type": "contract.published",
				"capabilities": db}, "expectedHeads": "x"}),
			"expectedHeads must be a mapping"},
		{"head reference not a string", doc(map[string]any{
			"append": map[string]any{"type": "contract.published",
				"capabilities": db},
			"expectedHeads": map[string]any{"db": 1}}),
			"head reference must be a string"},
		{"checkHeads not a mapping", doc(map[string]any{"checkHeads": "x"}),
			"head check must be a mapping"},
		{"bad @ reference (non-numeric)", doc(
			map[string]any{"checkHeads": map[string]any{"db": "@x"}}),
			"bad step reference"},
		{"reference to a non-append step", doc(
			tick(1),
			map[string]any{"checkHeads": map[string]any{"db": "@1"}}),
			"step has no event hash"},
		{"reference to a conflicted step", doc(
			map[string]any{"append": map[string]any{"type": "contract.published",
				"capabilities": db}},
			map[string]any{"append": map[string]any{"type": "candidate.verified",
				"capabilities": db}, "expectedHeads": map[string]any{"db": "genesis"}},
			map[string]any{"append": map[string]any{"type": "candidate.verified",
				"capabilities": db}, "expectedHeads": map[string]any{"db": "@2"}}),
			"step has no event hash"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := Run(c.doc)
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", c.wantSub)
			}
			if !strings.Contains(err.Error(), c.wantSub) {
				t.Fatalf("error = %q, want substring %q", err.Error(), c.wantSub)
			}
		})
	}
}

// ---- pure helpers ---------------------------------------------------------

// TestTS pins the logical-clock -> RFC3339 UTC formatting the engine stamps
// on every event. A drift here (local tz, wrong epoch) would poison event
// hashes and the D56 coordination clock.
func TestTS(t *testing.T) {
	cases := []struct {
		clock int
		want  string
	}{
		{0, "1970-01-01T00:00:00Z"},
		{1, "1970-01-01T00:00:01Z"},
		{100, "1970-01-01T00:01:40Z"},
		{3661, "1970-01-01T01:01:01Z"},
		{86400, "1970-01-02T00:00:00Z"},
	}
	for _, c := range cases {
		if got := ts(c.clock); got != c.want {
			t.Errorf("ts(%d) = %q, want %q", c.clock, got, c.want)
		}
	}
}

// TestResolve pins the symbolic reference resolver: "@N" -> the committed
// hash of step N, plain strings pass through, and every ill-formed reference
// is an authoring error (never a silent genesis).
func TestResolve(t *testing.T) {
	e := &engine{stepHashes: map[int]string{1: "hash-one", 3: "hash-three"}}
	cases := []struct {
		name    string
		ref     any
		want    string
		wantErr string
	}{
		{"resolves @N", "@1", "hash-one", ""},
		{"resolves later @N", "@3", "hash-three", ""},
		{"plain string passthrough", "some-literal-hash", "some-literal-hash", ""},
		{"genesis passthrough", "genesis", "genesis", ""},
		{"missing step index", "@2", "", "step has no event hash"},
		{"non-numeric index", "@nope", "", "bad step reference"},
		{"non-string ref", 42, "", "head reference must be a string"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := e.resolve(c.ref)
			if c.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), c.wantErr) {
					t.Fatalf("resolve(%v) err = %v, want substring %q",
						c.ref, err, c.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("resolve(%v): unexpected error %v", c.ref, err)
			}
			if got != c.want {
				t.Errorf("resolve(%v) = %q, want %q", c.ref, got, c.want)
			}
		})
	}
}

// TestCheckHeads pins the read-set freshness verdict directly: every wanted
// head must match the current stream (absent capability == genesis) or the
// whole set is stale. A single mismatch taints the verdict.
func TestCheckHeads(t *testing.T) {
	e := &engine{stepHashes: map[int]string{1: "h1", 2: "h2"}}
	stream := map[string]string{"db": "h1", "cache": "h2"}
	cases := []struct {
		name    string
		want    map[string]any
		status  string
		wantErr string
	}{
		{"single match is fresh", map[string]any{"db": "@1"}, "fresh", ""},
		{"all match is fresh",
			map[string]any{"db": "@1", "cache": "@2"}, "fresh", ""},
		{"one mismatch taints the set",
			map[string]any{"db": "@1", "cache": "@1"}, "stale", ""},
		{"non-genesis head vs genesis want is stale",
			map[string]any{"db": "genesis"}, "stale", ""},
		{"absent capability defaults to genesis (fresh)",
			map[string]any{"other": "genesis"}, "fresh", ""},
		{"empty want set is vacuously fresh",
			map[string]any{}, "fresh", ""},
		{"bad reference is an error",
			map[string]any{"db": "@x"}, "", "bad step reference"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r, err := e.checkHeads(c.want, stream)
			if c.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), c.wantErr) {
					t.Fatalf("checkHeads err = %v, want substring %q",
						err, c.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("checkHeads: unexpected error %v", err)
			}
			if r["status"] != c.status {
				t.Errorf("checkHeads status = %v, want %q", r["status"], c.status)
			}
		})
	}
}

// TestCheckHeadsNotAMapping pins the direct type guard (the Run-level table
// reaches this via a step; here we hit checkHeads with a non-map chk value).
func TestCheckHeadsNotAMapping(t *testing.T) {
	e := &engine{stepHashes: map[int]string{}}
	if _, err := e.checkHeads("nope", map[string]string{}); err == nil ||
		!strings.Contains(err.Error(), "head check must be a mapping") {
		t.Fatalf("expected 'head check must be a mapping', got %v", err)
	}
}
