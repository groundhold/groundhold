package resume

// White-box tests for the resume verb (D57): the blessed recovery path
// that reconciles pending write-ahead receipts left by a killed apply.
// What these pin is resume's decision surface — the guard/classification
// ladder BEFORE anything mutates, and the per-receipt reconcile decision
// AFTER the fenced lease is taken. The invariants under test are the
// project's non-negotiables: unknown never collapses to a boolean and
// blocks (exit 3), a concluded operation's provider identity survives
// into the binding, and the live binding is never clobbered by a
// concluded-but-orphaned resource.
//
// Every case seeds a REAL on-disk ledger (resume re-replays the file
// under its lease), then runs Run against a fresh replay of it.

import (
	"os"
	"strings"
	"testing"

	"groundhold/internal/contract"
	"groundhold/internal/ledger"
	"groundhold/internal/perr"
	"groundhold/internal/provider"
)

const (
	seedAt   = "2026-07-01T00:00:00Z"
	resumeAt = "2026-07-02T00:00:00Z" // strictly after seedAt: no clock regress
)

// ---- fixtures -------------------------------------------------------------

// seedWriter opens a fresh temp ledger and returns a Writer stamping the
// seed clock. All seed events share one occurredAt (equal is not a
// regress); resume runs strictly later.
func seedWriter(t *testing.T) (*ledger.Writer, string) {
	t.Helper()
	path := t.TempDir() + "/ledger.jsonl"
	led, err := ledger.ReplayFile(path)
	if err != nil {
		t.Fatalf("seed replay: %v", err)
	}
	clock, err := ledger.ParseTs(seedAt)
	if err != nil {
		t.Fatal(err)
	}
	return &ledger.Writer{Path: path, Led: led, Env: "test", Clock: clock,
		Actor: "seed"}, path
}

// seedReceipt writes a pending write-ahead receipt (status pending keeps
// the intent open — exactly what a crash mid-apply leaves behind).
func seedReceipt(t *testing.T, w *ledger.Writer, cap string, body map[string]any) {
	t.Helper()
	b := map[string]any{"status": "pending"}
	for k, v := range body {
		b[k] = v
	}
	if err := w.Append("operation.receipt", []string{cap}, b, 0); err != nil {
		t.Fatalf("seed receipt on %s: %v", cap, err)
	}
}

// seedBinding binds a capability to a providerId at a generation (an
// existing live binding — the ground truth a delete empties, an update
// bumps, and an orphaned create must not clobber).
func seedBinding(t *testing.T, w *ledger.Writer, cap, providerID string, gen int) {
	t.Helper()
	tok, err := w.AppendLease([]string{cap}, map[string]any{"ttlSeconds": 300})
	if err != nil {
		t.Fatalf("seed lease on %s: %v", cap, err)
	}
	body := map[string]any{
		"capability": cap, "environment": "test",
		"provider": map[string]any{"name": "fake"},
		"resources": []any{map[string]any{"id": "primary", "type": "gcp.fake/db",
			"providerId": providerID, "generation": gen}},
	}
	if err := w.Append("binding.updated", []string{cap}, body, tok); err != nil {
		t.Fatalf("seed binding on %s: %v", cap, err)
	}
	if err := w.Append("lease.released", []string{cap}, nil, tok); err != nil {
		t.Fatalf("seed release on %s: %v", cap, err)
	}
}

// runResume replays the seeded file fresh and drives Run.
func runResume(t *testing.T, path string, prov provider.Provider, at string) *Result {
	t.Helper()
	led, err := ledger.ReplayFile(path)
	if err != nil {
		t.Fatalf("resume replay: %v", err)
	}
	return Run(&contract.Contract{Environment: "test"}, led, path, prov, at)
}

// replay is a fresh read of the post-resume ledger.
func replay(t *testing.T, path string) *ledger.Ledger {
	t.Helper()
	led, err := ledger.ReplayFile(path)
	if err != nil {
		t.Fatalf("post replay: %v", err)
	}
	return led
}

// nonReconciler is a Provider that deliberately does NOT implement
// provider.Reconciler — resume must refuse rather than guess.
type nonReconciler struct{}

func (nonReconciler) Name() string { return "no-reconcile" }
func (nonReconciler) Validate(service, capability, environment string,
	attributes, implementation map[string]any, generation int) error {
	return nil
}
func (nonReconciler) Create(service, capability, environment string,
	attributes, implementation map[string]any, idempotencyKey string,
	generation int) provider.CreateResult {
	return provider.CreateResult{}
}
func (nonReconciler) Observe(service, capability, providerID string) (
	[]provider.Observation, []string, error) {
	return nil, nil, nil
}
func (nonReconciler) ClassifyChange(service, path string, current, desired any,
	implementation map[string]any) (string, string) {
	return "", ""
}
func (nonReconciler) Update(service, capability, environment, providerID string,
	attributes, implementation map[string]any, changes []string,
	idempotencyKey string) provider.CreateResult {
	return provider.CreateResult{}
}
func (nonReconciler) Delete(service, capability, environment, providerID,
	idempotencyKey string) provider.CreateResult {
	return provider.CreateResult{}
}

// ---- guard / classification ladder (refuses BEFORE the lease) -------------

// The order of the pre-mutation guards is itself the contract: nothing is
// touched until the receipt is a shape resume knows how to conclude.
func TestGuardLadderRefusesBeforeMutating(t *testing.T) {
	cases := []struct {
		name       string
		receipt    map[string]any // one pending create/whatever on "db"
		wantStatus string
		wantCode   perr.Code
		wantExit   int
		reasonHas  string
	}{
		{
			name:       "legacy receipt with no operation field",
			receipt:    map[string]any{"operationId": "op1"},
			wantStatus: "refused", wantCode: perr.UnsupportedOperation, wantExit: 2,
			reasonHas: "predates resume support",
		},
		{
			name: "unknown operation verb",
			receipt: map[string]any{"operationId": "op1",
				"operation": "frobnicate"},
			wantStatus: "refused", wantCode: perr.UnsupportedOperation, wantExit: 2,
			reasonHas: "manual reconciliation",
		},
		{
			name: "update receipt without a pinned target",
			receipt: map[string]any{"operationId": "op1",
				"operation": "update"},
			wantStatus: "refused", wantCode: perr.UnsupportedOperation, wantExit: 2,
			reasonHas: "predates update-resume support",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w, path := seedWriter(t)
			seedReceipt(t, w, "db", tc.receipt)
			res := runResume(t, path, &provider.Fake{}, resumeAt)

			if res.Status != tc.wantStatus {
				t.Errorf("status = %q, want %q", res.Status, tc.wantStatus)
			}
			if res.Code != tc.wantCode {
				t.Errorf("code = %q, want %q", res.Code, tc.wantCode)
			}
			if res.Exit != tc.wantExit {
				t.Errorf("exit = %d, want %d", res.Exit, tc.wantExit)
			}
			if !anyContains(res.Reasons, tc.reasonHas) {
				t.Errorf("reasons %v, want one containing %q",
					res.Reasons, tc.reasonHas)
			}
			// a refused classification must NOT have written a binding or
			// cleared the pending intent
			if led := replay(t, path); len(led.PendingReceipts()["db"]) != 1 {
				t.Errorf("refused resume must leave the receipt pending, got %v",
					led.PendingReceipts()["db"])
			}
		})
	}
}

func TestNothingToResumeOnEmptyLedger(t *testing.T) {
	_, path := seedWriter(t) // fresh, no receipts
	res := runResume(t, path, &provider.Fake{}, resumeAt)
	if res.Status != "nothing-to-resume" || res.Exit != 0 {
		t.Fatalf("got status=%q exit=%d, want nothing-to-resume/0",
			res.Status, res.Exit)
	}
	if res.Code != "" {
		t.Errorf("nothing-to-resume must carry no error code, got %q", res.Code)
	}
}

func TestProviderThatCannotReconcileRefuses(t *testing.T) {
	w, path := seedWriter(t)
	seedReceipt(t, w, "db", map[string]any{"operationId": "op1",
		"operation": "create", "idempotencyKey": "k1", "target": "gcp.fake/db",
		"generation": 1})
	res := runResume(t, path, nonReconciler{}, resumeAt)
	if res.Status != "refused" || res.Code != perr.UnsupportedOperation ||
		res.Exit != 2 {
		t.Fatalf("got status=%q code=%q exit=%d, want refused/%s/2",
			res.Status, res.Code, res.Exit, perr.UnsupportedOperation)
	}
	if !anyContains(res.Reasons, "cannot reconcile") {
		t.Errorf("reasons %v, want one about cannot reconcile", res.Reasons)
	}
}

func TestBadAtRefusesStructurally(t *testing.T) {
	w, path := seedWriter(t)
	seedReceipt(t, w, "db", map[string]any{"operationId": "op1",
		"operation": "create", "idempotencyKey": "k1", "target": "gcp.fake/db",
		"generation": 1})
	res := runResume(t, path, &provider.Fake{}, "not-a-timestamp")
	if res.Status != "refused" || res.Code != perr.StructuralError ||
		res.Exit != 2 {
		t.Fatalf("got status=%q code=%q exit=%d, want refused/%s/2",
			res.Status, res.Code, res.Exit, perr.StructuralError)
	}
}

// An armed anchor that the replayed ledger no longer matches is
// tamper-evidence: resume refuses fail-closed (exit 5) before its lease.
func TestArmedMismatchedAnchorRefuses(t *testing.T) {
	w, path := seedWriter(t)
	seedReceipt(t, w, "db", map[string]any{"operationId": "op1",
		"operation": "create", "idempotencyKey": "k1", "target": "gcp.fake/db",
		"generation": 1})
	// a well-formed anchor claiming a head/count the ledger does not have
	anchor := `{"apiVersion":"state/v0","kind":"LedgerAnchor","events":999,` +
		`"head":"sha256:0000000000000000000000000000000000000000000000000000000000000000",` +
		`"heads":{},"decisionHeads":{}}`
	if err := os.WriteFile(ledger.AnchorPath(path), []byte(anchor), 0o600); err != nil {
		t.Fatal(err)
	}
	res := runResume(t, path, &provider.Fake{}, resumeAt)
	if res.Status != "refused" || res.Code != perr.LedgerCorrupted ||
		res.Exit != 5 {
		t.Fatalf("got status=%q code=%q exit=%d, want refused/%s/5",
			res.Status, res.Code, res.Exit, perr.LedgerCorrupted)
	}
	if led := replay(t, path); len(led.PendingReceipts()["db"]) != 1 {
		t.Error("anchor refusal must leave the receipt pending")
	}
}

// ---- per-receipt reconcile decisions --------------------------------------

// A concluded create writes its binding, carries the reconciled identity,
// and clears the pending intent.
func TestCreateConcludedWritesBinding(t *testing.T) {
	w, path := seedWriter(t)
	seedReceipt(t, w, "db", map[string]any{"operationId": "op1",
		"operation": "create", "idempotencyKey": "k1", "target": "gcp.fake/db",
		"generation": 1})
	res := runResume(t, path, &provider.Fake{}, resumeAt)

	if res.Status != "resumed" || res.Exit != 0 {
		t.Fatalf("got status=%q exit=%d, want resumed/0", res.Status, res.Exit)
	}
	if len(res.Resolved) != 1 || res.Resolved[0].Status != "succeeded" ||
		res.Resolved[0].ProviderID != "fake:k1" ||
		res.Resolved[0].Operation != "create" {
		t.Fatalf("resolved = %+v, want one succeeded create -> fake:k1",
			res.Resolved)
	}
	if res.Bindings["db"] != "fake:k1" {
		t.Errorf("bindings[db] = %q, want fake:k1", res.Bindings["db"])
	}
	led := replay(t, path)
	if got := led.BoundProviderIDs()["db"]; got != "fake:k1" {
		t.Errorf("post-resume binding = %q, want fake:k1", got)
	}
	if n := len(led.PendingReceipts()["db"]); n != 0 {
		t.Errorf("pending should be cleared, got %d", n)
	}
}

// INVARIANT (four-valued): an unknown outcome never becomes a boolean.
// The receipt stays pending, no binding is written, and resume blocks
// with exit 3 / reconcile-pending — it never guesses success.
func TestUnknownStaysPendingAndBlocks(t *testing.T) {
	w, path := seedWriter(t)
	seedReceipt(t, w, "db", map[string]any{"operationId": "op1",
		"operation": "create", "idempotencyKey": "k1", "target": "gcp.fake/db",
		"generation": 1})
	prov := &provider.Fake{UnknownKeys: map[string]bool{"k1": true}}
	res := runResume(t, path, prov, resumeAt)

	if res.Status != "still-unknown" || res.Exit != 3 ||
		res.Code != perr.ReconcilePending {
		t.Fatalf("got status=%q exit=%d code=%q, want still-unknown/3/%s",
			res.Status, res.Exit, res.Code, perr.ReconcilePending)
	}
	if len(res.Resolved) != 1 || res.Resolved[0].Status != "unknown" {
		t.Fatalf("resolved = %+v, want one unknown", res.Resolved)
	}
	if len(res.Bindings) != 0 {
		t.Errorf("unknown must write no binding, got %v", res.Bindings)
	}
	led := replay(t, path)
	if n := len(led.PendingReceipts()["db"]); n != 1 {
		t.Errorf("unknown must leave the receipt pending, got %d", n)
	}
	if _, bound := led.BoundProviderIDs()["db"]; bound {
		t.Error("unknown must not produce a binding")
	}
}

// A concluded-failed create clears the pending intent (the op is
// terminal) but writes no binding — nothing was created.
func TestFailedConcludedClearsPendingNoBinding(t *testing.T) {
	w, path := seedWriter(t)
	seedReceipt(t, w, "db", map[string]any{"operationId": "op1",
		"operation": "create", "idempotencyKey": "k1", "target": "gcp.fake/db",
		"generation": 1})
	prov := &provider.Fake{FailKeys: map[string]bool{"k1": true}}
	res := runResume(t, path, prov, resumeAt)

	if res.Status != "resumed" || res.Exit != 0 {
		t.Fatalf("got status=%q exit=%d, want resumed/0", res.Status, res.Exit)
	}
	if len(res.Resolved) != 1 || res.Resolved[0].Status != "failed" {
		t.Fatalf("resolved = %+v, want one failed", res.Resolved)
	}
	if len(res.Bindings) != 0 {
		t.Errorf("failed create must write no binding, got %v", res.Bindings)
	}
	led := replay(t, path)
	if n := len(led.PendingReceipts()["db"]); n != 0 {
		t.Errorf("failed op must clear pending, got %d", n)
	}
	if _, bound := led.BoundProviderIDs()["db"]; bound {
		t.Error("failed create must not produce a binding")
	}
}

// A concluded delete empties the binding of the deleted identity and
// records the tombstone lineage; provider identity survives in the body.
func TestDeleteConcludedEmptiesBindingWithTombstone(t *testing.T) {
	w, path := seedWriter(t)
	seedBinding(t, w, "db", "fake:old", 3)
	seedReceipt(t, w, "db", map[string]any{"operationId": "op1",
		"operation": "delete", "idempotencyKey": "k1", "target": "gcp.fake/db",
		"targetProviderId": "fake:old", "targetGeneration": 3})
	res := runResume(t, path, &provider.Fake{}, resumeAt)

	if res.Status != "resumed" || res.Exit != 0 {
		t.Fatalf("got status=%q exit=%d, want resumed/0", res.Status, res.Exit)
	}
	if len(res.Resolved) != 1 || res.Resolved[0].Status != "succeeded" ||
		res.Resolved[0].Operation != "delete" {
		t.Fatalf("resolved = %+v, want one succeeded delete", res.Resolved)
	}
	led := replay(t, path)
	if got := led.BoundProviderIDs()["db"]; got != "" {
		t.Errorf("deleted binding should be empty, still bound to %q", got)
	}
	if n := led.BoundProviderNames()["db"]; n != "fake" {
		t.Errorf("provider identity must survive delete, got name %q", n)
	}
	if !tombstoned(led.Bindings["db"], "fake:old") {
		t.Errorf("delete must record a tombstone for fake:old, body=%v",
			led.Bindings["db"])
	}
	if n := len(led.PendingReceipts()["db"]); n != 0 {
		t.Errorf("delete must clear pending, got %d", n)
	}
}

// INVARIANT (identity survives): a concluded update keeps the pinned
// provider identity and increments the generation (D46/D72).
func TestUpdateConcludedKeepsIdentityBumpsGeneration(t *testing.T) {
	w, path := seedWriter(t)
	seedBinding(t, w, "db", "fake:p1", 1)
	seedReceipt(t, w, "db", map[string]any{"operationId": "op1",
		"operation": "update", "idempotencyKey": "k1", "target": "gcp.fake/db",
		"targetProviderId": "fake:p1", "generation": 2})
	res := runResume(t, path, &provider.Fake{}, resumeAt)

	if res.Status != "resumed" || res.Exit != 0 {
		t.Fatalf("got status=%q exit=%d, want resumed/0", res.Status, res.Exit)
	}
	if res.Resolved[0].Status != "succeeded" ||
		res.Resolved[0].ProviderID != "fake:p1" {
		t.Fatalf("resolved = %+v, want succeeded update keeping fake:p1",
			res.Resolved)
	}
	if res.Bindings["db"] != "fake:p1" {
		t.Errorf("update must keep identity fake:p1, got %q", res.Bindings["db"])
	}
	led := replay(t, path)
	if got := led.BoundProviderIDs()["db"]; got != "fake:p1" {
		t.Errorf("identity must survive update, got %q", got)
	}
	if gen := led.BoundGenerations()["db"]; gen != 2 {
		t.Errorf("generation must bump 1 -> 2, got %d", gen)
	}
	if n := len(led.PendingReceipts()["db"]); n != 0 {
		t.Errorf("update must clear pending, got %d", n)
	}
}

// INVARIANT (never clobber the live binding): a create that concluded
// while the capability was rebound to a DIFFERENT identity is surfaced as
// ORPHANED — the live binding is preserved, no new binding is written,
// but the operation still concludes (pending cleared).
func TestConcludedCreateOrphanDoesNotClobberLiveBinding(t *testing.T) {
	w, path := seedWriter(t)
	seedBinding(t, w, "db", "fake:other", 1) // rebound while the create hung
	seedReceipt(t, w, "db", map[string]any{"operationId": "op1",
		"operation": "create", "idempotencyKey": "k1", "target": "gcp.fake/db",
		"generation": 1})
	res := runResume(t, path, &provider.Fake{}, resumeAt) // reconciles to fake:k1

	if res.Status != "resumed" || res.Exit != 0 {
		t.Fatalf("got status=%q exit=%d, want resumed/0", res.Status, res.Exit)
	}
	if res.Resolved[0].Status != "succeeded" ||
		res.Resolved[0].ProviderID != "fake:k1" {
		t.Fatalf("resolved = %+v, want succeeded create -> fake:k1", res.Resolved)
	}
	if _, set := res.Bindings["db"]; set {
		t.Errorf("orphaned create must NOT set a binding, got %v", res.Bindings)
	}
	if !anyContains(res.Reasons, "ORPHANED") {
		t.Errorf("orphan must be surfaced loudly, reasons=%v", res.Reasons)
	}
	led := replay(t, path)
	if got := led.BoundProviderIDs()["db"]; got != "fake:other" {
		t.Errorf("live binding must be preserved as fake:other, got %q", got)
	}
	if n := len(led.PendingReceipts()["db"]); n != 0 {
		t.Errorf("concluded (orphaned) op must clear pending, got %d", n)
	}
}

// A run with a mix of a concluded and an unknown receipt blocks overall
// (exit 3) yet still commits the concluded work — progress is durable,
// the unknown alone gates.
func TestPartialUnknownBlocksButCommitsConcluded(t *testing.T) {
	w, path := seedWriter(t)
	seedReceipt(t, w, "a", map[string]any{"operationId": "opA",
		"operation": "create", "idempotencyKey": "ka", "target": "gcp.fake/a",
		"generation": 1})
	seedReceipt(t, w, "b", map[string]any{"operationId": "opB",
		"operation": "create", "idempotencyKey": "kb", "target": "gcp.fake/b",
		"generation": 1})
	prov := &provider.Fake{UnknownKeys: map[string]bool{"kb": true}}
	res := runResume(t, path, prov, resumeAt)

	if res.Status != "still-unknown" || res.Exit != 3 {
		t.Fatalf("got status=%q exit=%d, want still-unknown/3",
			res.Status, res.Exit)
	}
	if res.Bindings["a"] != "fake:ka" {
		t.Errorf("concluded 'a' must persist its binding, got %q",
			res.Bindings["a"])
	}
	if _, set := res.Bindings["b"]; set {
		t.Errorf("unknown 'b' must not bind, got %v", res.Bindings)
	}
	led := replay(t, path)
	if n := len(led.PendingReceipts()["a"]); n != 0 {
		t.Errorf("'a' concluded — pending must clear, got %d", n)
	}
	if n := len(led.PendingReceipts()["b"]); n != 1 {
		t.Errorf("'b' unknown — pending must remain, got %d", n)
	}
}

// A concluded update whose capability was rebound to a DIFFERENT identity
// patched a resource that is no longer live: surfaced for re-observe, the
// live binding untouched, no new binding, pending still cleared.
func TestConcludedUpdateOrphanDoesNotClobberLiveBinding(t *testing.T) {
	w, path := seedWriter(t)
	seedBinding(t, w, "db", "fake:live", 4) // rebound while the update hung
	seedReceipt(t, w, "db", map[string]any{"operationId": "op1",
		"operation": "update", "idempotencyKey": "k1", "target": "gcp.fake/db",
		"targetProviderId": "fake:p1", "generation": 2}) // patched fake:p1
	res := runResume(t, path, &provider.Fake{}, resumeAt)

	if res.Status != "resumed" || res.Exit != 0 {
		t.Fatalf("got status=%q exit=%d, want resumed/0", res.Status, res.Exit)
	}
	if res.Resolved[0].Status != "succeeded" {
		t.Fatalf("resolved = %+v, want succeeded", res.Resolved)
	}
	if _, set := res.Bindings["db"]; set {
		t.Errorf("orphaned update must NOT set a binding, got %v", res.Bindings)
	}
	if !anyContains(res.Reasons, "re-observe") {
		t.Errorf("orphaned update must be surfaced, reasons=%v", res.Reasons)
	}
	led := replay(t, path)
	if got := led.BoundProviderIDs()["db"]; got != "fake:live" {
		t.Errorf("live binding must survive as fake:live, got %q", got)
	}
	if gen := led.BoundGenerations()["db"]; gen != 4 {
		t.Errorf("live generation must be untouched at 4, got %d", gen)
	}
	if n := len(led.PendingReceipts()["db"]); n != 0 {
		t.Errorf("concluded (orphaned) update must clear pending, got %d", n)
	}
}

// A concluded delete whose pin is NOT the live binding records the
// tombstone but must NOT empty the live resource (mirrors apply's
// replacement rule): the deleted identity was already superseded.
func TestConcludedDeleteOfNonLivePinKeepsLiveResource(t *testing.T) {
	w, path := seedWriter(t)
	seedBinding(t, w, "db", "fake:live", 2)
	seedReceipt(t, w, "db", map[string]any{"operationId": "op1",
		"operation": "delete", "idempotencyKey": "k1", "target": "gcp.fake/db",
		"targetProviderId": "fake:old", "targetGeneration": 1}) // not the live one
	res := runResume(t, path, &provider.Fake{}, resumeAt)

	if res.Status != "resumed" || res.Exit != 0 {
		t.Fatalf("got status=%q exit=%d, want resumed/0", res.Status, res.Exit)
	}
	led := replay(t, path)
	if got := led.BoundProviderIDs()["db"]; got != "fake:live" {
		t.Errorf("live resource must be kept, got %q", got)
	}
	if !tombstoned(led.Bindings["db"], "fake:old") {
		t.Errorf("delete must tombstone the superseded fake:old, body=%v",
			led.Bindings["db"])
	}
	if n := len(led.PendingReceipts()["db"]); n != 0 {
		t.Errorf("delete must clear pending, got %d", n)
	}
}

// resume is a fenced writer under its OWN lease: an active lease held by
// another writer on the capability blocks it with lease-conflict.
func TestActiveLeaseBlocksResume(t *testing.T) {
	w, path := seedWriter(t)
	// a live, unreleased lease outlasting the resume clock (ttl > 1 day)
	if _, err := w.AppendLease([]string{"db"},
		map[string]any{"ttlSeconds": 100000}); err != nil {
		t.Fatalf("hold lease: %v", err)
	}
	seedReceipt(t, w, "db", map[string]any{"operationId": "op1",
		"operation": "create", "idempotencyKey": "k1", "target": "gcp.fake/db",
		"generation": 1})
	res := runResume(t, path, &provider.Fake{}, resumeAt)

	if res.Status != "refused" || res.Code != perr.LeaseConflict ||
		res.Exit != 2 {
		t.Fatalf("got status=%q code=%q exit=%d, want refused/%s/2",
			res.Status, res.Code, res.Exit, perr.LeaseConflict)
	}
	if led := replay(t, path); len(led.PendingReceipts()["db"]) != 1 {
		t.Error("blocked resume must leave the receipt pending")
	}
}

// ---- helpers --------------------------------------------------------------

func anyContains(ss []string, sub string) bool {
	for _, s := range ss {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}

// tombstoned reports whether a binding body's lineage records a tombstone
// for providerID.
func tombstoned(body map[string]any, providerID string) bool {
	lineage, _ := body["lineage"].(map[string]any)
	tombs, _ := lineage["tombstones"].([]any)
	for _, t := range tombs {
		m, _ := t.(map[string]any)
		if id, _ := m["providerId"].(string); id == providerID {
			return true
		}
	}
	return false
}
