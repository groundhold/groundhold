// Package resume is the blessed recovery path for pending receipts
// (D57): after an apply dies mid-flight or an outcome comes back
// unknown, every next apply refuses until someone answers what
// actually happened. Resume asks the provider (READ-ONLY), writes the
// terminal receipt, and completes the interrupted projection — a
// concluded create gets its binding, a concluded delete its tombstone.
// still-unknown stays pending and exits 3: reconciliation never
// guesses. Hand-written lease.broken{adoptReceipts} is NOT a normal
// recovery mechanism; this verb is.
package resume

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"

	"groundhold/internal/contract"
	"groundhold/internal/ledger"
	"groundhold/internal/perr"
	"groundhold/internal/provider"
)

type Resolved struct {
	Capability  string `json:"capability"`
	OperationID string `json:"operationId"`
	Operation   string `json:"operation"`
	Status      string `json:"status"` // succeeded | failed | unknown
	Reason      string `json:"reason,omitempty"`
	ProviderID  string `json:"providerId,omitempty"`
}

type Result struct {
	Status   string            `json:"status"` // resumed|still-unknown|nothing-to-resume|refused
	Code     perr.Code         `json:"code,omitempty"`
	RunID    string            `json:"runId,omitempty"`
	Resolved []Resolved        `json:"resolved"`
	Bindings map[string]string `json:"bindings,omitempty"`
	Events   []string          `json:"events"`
	Reasons  []string          `json:"reasons,omitempty"`
	Exit     int               `json:"-"`
}

func Run(c *contract.Contract, led *ledger.Ledger, ledgerPath string,
	prov provider.Provider, at string) *Result {
	res0 := &Result{Resolved: []Resolved{}, Events: []string{}}
	refuse := func(code perr.Code, reasons ...string) *Result {
		// preserve what was ALREADY written — the output must not claim
		// nothing happened when the ledger has new lines (review fix)
		res0.Status, res0.Code, res0.Reasons, res0.Exit =
			"refused", code, reasons, 2
		return res0
	}
	pending := led.PendingReceipts()
	if len(pending) == 0 {
		return &Result{Status: "nothing-to-resume",
			Resolved: []Resolved{}, Events: []string{}, Exit: 0}
	}
	// tail tamper-evidence before this fenced writer mutates anything
	// (review): an armed anchor that no longer matches refuses
	if err := ledger.EnforceAnchor(ledgerPath, led); err != nil {
		res0.Status, res0.Code, res0.Reasons, res0.Exit =
			"refused", perr.LedgerCorrupted, []string{err.Error()}, 5
		return res0
	}
	rec, ok := prov.(provider.Reconciler)
	if !ok {
		return refuse(perr.UnsupportedOperation, fmt.Sprintf(
			"provider %s cannot reconcile receipts", prov.Name()))
	}
	caps := make([]string, 0, len(pending))
	for capID := range pending {
		caps = append(caps, capID)
	}
	sort.Strings(caps)

	// D637: resume must be run with the provider that STARTED the operation.
	//
	// `apply` pins `reads.provider` from the sealed plan and cross-checks it. `resume`
	// — the verb an operator types by hand, under pressure, after something died —
	// pinned nothing. So `resume --provider fake` over a ledger whose binding says
	// `aws` concluded the AWS operation as SUCCEEDED (the fake reconciler answers
	// succeeded unconditionally), bumped the binding generation, and rewrote
	// `provider.name` from `aws` to `fake` — the very field the comment fifty lines
	// below calls out as identity that "must survive (F4)".
	//
	// The ledger already records which provider owns each capability. Compare it.
	for _, capID := range caps {
		want := led.BoundProviderNames()[capID]
		if want == "" {
			// An operation that died before its binding landed has no bound provider
			// yet — and that is the case where a wrong driver INVENTS a providerId
			// and binds it. The pending receipt names the driver in its target
			// ("fake.fakedb/db"), which is the only record of who started the work.
			for _, body := range pending[capID] {
				tgt, _ := body["target"].(string)
				if i := strings.Index(tgt, "."); i > 0 {
					want = tgt[:i]
					break
				}
			}
		}
		if want == "" || want == prov.Name() {
			continue
		}
		return refuse(perr.ReadSetMismatch, fmt.Sprintf(
			"%s was started under provider %q and this run is --provider %q — resume "+
				"concludes an operation another driver started, so it must be run "+
				"with THAT driver; concluding it here would record an outcome nobody "+
				"measured and overwrite the binding's provider identity",
			capID, want, prov.Name()))
	}

	// Scope (D57, D72): creates conclude with bindings, deletes with
	// tombstones, updates (whose receipts carry the verifiable target
	// shape — pinned identity + desired values) with a generation bump
	for _, capID := range caps {
		for _, receipt := range pending[capID] {
			op, _ := receipt["operation"].(string)
			switch op {
			case "create", "delete":
			case "update":
				if pid, _ := receipt["targetProviderId"].(string); pid == "" {
					return refuse(perr.UnsupportedOperation, fmt.Sprintf(
						"%s: update receipt predates update-resume support "+
							"(no pinned target) — reconcile manually", capID))
				}
			case "":
				return refuse(perr.UnsupportedOperation, fmt.Sprintf(
					"%s: receipt predates resume support (no operation "+
						"field) — reconcile manually", capID))
			default:
				return refuse(perr.UnsupportedOperation, fmt.Sprintf(
					"%s: pending %s receipts need manual reconciliation — "+
						"resume concludes creates, updates and deletes",
					capID, op))
			}
		}
	}

	clock, err := ledger.ParseTs(at)
	if err != nil {
		return refuse(perr.StructuralError, fmt.Sprintf("bad --at: %v", err))
	}
	if clock > led.Clock {
		led.Clock = clock
	}
	seed := sha256.Sum256([]byte("resume:" + at + ":" +
		fmt.Sprintf("%v", caps)))
	runID := hex.EncodeToString(seed[:])[:12]
	res := res0
	res.Status, res.RunID, res.Exit = "resumed", runID, 0
	res.Bindings = map[string]string{}
	// resume is a fenced writer under its OWN lease — never an adoption
	// of the dead run's (review verdict, D57)
	w := &ledger.Writer{Path: ledgerPath, Led: led, Env: c.Environment,
		Clock: clock, Actor: "groundhold-resume", Events: &res.Events}
	tok, err := w.AppendLease(caps,
		map[string]any{"ttlSeconds": 300, "resumeRunId": runID})
	if err != nil {
		code := perr.LeaseConflict
		if strings.Contains(err.Error(), "regresses") {
			code = perr.ClockRegress
		}
		return refuse(code, err.Error())
	}
	// D960: re-derive the pending set UNDER THE LEASE. `pending` was read from the
	// entry-time ledger (line ~55); between then and AppendLease another run holding the
	// lease could have CONCLUDED some of these receipts — and even updated the resource to
	// a newer generation. Concluding a receipt that is no longer pending would re-write a
	// STALE outcome: the create path reads `generation` from the stale receipt (gen 1) and,
	// because the rebind guard below only catches a DIFFERENT providerId (not a same-id
	// generation regression), would overwrite a live gen-2 binding with gen 1 — recorded as
	// a successful resume (exit 0), so a later gen-pinned update/retire mis-targets. Only
	// conclude what is STILL pending now that we hold the lease. w.Led was re-replayed under
	// the lock by AppendLease, so it is the authoritative post-lease view.
	livePending := map[string]map[string]bool{}
	for capID, receipts := range w.Led.PendingReceipts() {
		ids := map[string]bool{}
		for _, r := range receipts {
			if id, _ := r["operationId"].(string); id != "" {
				ids[id] = true
			}
		}
		livePending[capID] = ids
	}
	release := func() {
		if err := w.Append("lease.released", caps, nil, tok); err != nil {
			// a failed release is not fatal (the lease expires by TTL),
			// but it must be visible, not swallowed (bad-habits review)
			res.Reasons = append(res.Reasons, fmt.Sprintf(
				"lease release failed (expires by TTL): %v", err))
		}
	}

	stillUnknown := false
	for _, capID := range caps {
		for _, receipt := range pending[capID] {
			opID, _ := receipt["operationId"].(string)
			// D960: skip a receipt that was concluded by another run in the window
			// between our ledger load and our lease — re-concluding it would re-write a
			// stale outcome over the state that run already advanced.
			if !livePending[capID][opID] {
				continue
			}
			op, _ := receipt["operation"].(string)
			verdict := rec.Reconcile(capID, c.Environment, receipt)
			entry := Resolved{Capability: capID, OperationID: opID,
				Operation: op, Status: verdict.Status,
				Reason: verdict.Reason, ProviderID: verdict.ProviderID}
			res.Resolved = append(res.Resolved, entry)
			if verdict.Status == "unknown" {
				stillUnknown = true // stays pending — never guessed
				continue
			}

			// terminal receipt, causally linked to this reconciliation. It CLEARS
			// the pending intent, so on the SUCCESS path it must land AFTER the
			// projection (binding.updated) below (D180): a crash between them then
			// leaves the receipt pending for the NEXT resume to reconcile against
			// the written binding, never an orphan. On the failed path there is no
			// projection; on the rebind-orphan paths the operation concluded (no
			// binding is written, to avoid clobbering the live binding) — both
			// still clear pending, so they commit the receipt before continuing.
			terminal := map[string]any{}
			for k, v := range receipt {
				terminal[k] = v
			}
			terminal["status"] = verdict.Status
			terminal["resumeRunId"] = runID
			if verdict.Reason != "" {
				terminal["reason"] = verdict.Reason
			}
			commitTerminal := func() error {
				return w.Append("operation.receipt", []string{capID}, terminal, 0)
			}
			if verdict.Status != "succeeded" {
				if err := commitTerminal(); err != nil { // concluded-failed clears pending
					release()
					return refuse(perr.LedgerCorrupted, err.Error())
				}
				continue
			}

			// complete the interrupted projection
			switch op {
			case "create":
				// read the FRESH projection (F3/D67): w.Led is re-replayed
				// under the lock after every append this run made, so a
				// second pending receipt concluded earlier in this loop is
				// visible — the stale entry-time `led` is not
				if cur := w.Led.BoundProviderIDs()[capID]; cur != "" &&
					cur != verdict.ProviderID {
					// the capability was rebound while this create hung —
					// overwriting would orphan the LIVE binding silently
					// (review fix). The concluded resource is the orphan:
					// surface it loudly, never clobber.
					res.Reasons = append(res.Reasons, fmt.Sprintf(
						"%s: concluded create produced %s but the "+
							"capability is bound to %s — the created "+
							"resource is ORPHANED; adopt it under another "+
							"capability or delete it manually",
						capID, verdict.ProviderID, cur))
					if err := commitTerminal(); err != nil { // op concluded; clear pending
						release()
						return refuse(perr.LedgerCorrupted, err.Error())
					}
					continue
				}
				gen, _ := receipt["generation"].(int)
				if gen < 1 {
					gen = 1
				}
				target, _ := receipt["target"].(string)
				binding := map[string]any{
					"resumeRunId": runID,
					"capability":  capID,
					"environment": c.Environment,
					"provider":    map[string]any{"name": prov.Name()},
					"reconciledFrom": map[string]any{
						"operationId": opID},
					"resources": []any{map[string]any{
						"id": "primary", "type": target,
						"providerId": verdict.ProviderID,
						"generation": gen}},
				}
				if err := w.Append("binding.updated",
					[]string{capID}, binding, tok); err != nil {
					release()
					return refuse(perr.LedgerCorrupted, err.Error())
				}
				res.Bindings[capID] = verdict.ProviderID
			case "update":
				// D72: the update landed — mirror apply's projection:
				// identity survives, generation increments (D46)
				pinnedID, _ := receipt["targetProviderId"].(string)
				// read the FRESH projection (D67): w.Led is re-replayed
				// under the lock on every append this run made
				if cur := w.Led.BoundProviderIDs()[capID]; cur != pinnedID {
					// the capability was rebound while the update hung —
					// the patch landed on a resource that is no longer
					// bound; surface it, never clobber the live binding
					res.Reasons = append(res.Reasons, fmt.Sprintf(
						"%s: concluded update patched %s but the "+
							"capability is bound to %s — the patched "+
							"resource is not the live binding; re-observe",
						capID, pinnedID, cur))
					if err := commitTerminal(); err != nil { // op concluded; clear pending
						release()
						return refuse(perr.LedgerCorrupted, err.Error())
					}
					continue
				}
				gen := w.Led.BoundGenerations()[capID] + 1
				if gen < 2 {
					gen = 2
				}
				target, _ := receipt["target"].(string)
				binding := map[string]any{
					"resumeRunId": runID,
					"capability":  capID,
					"environment": c.Environment,
					"provider":    map[string]any{"name": prov.Name()},
					"reconciledFrom": map[string]any{
						"operationId": opID},
					"resources": []any{map[string]any{
						"id": "primary", "type": target,
						"providerId": pinnedID,
						"generation": gen}},
				}
				// carry prior lineage forward (F4/adversarial review): an update must
				// not erase the capability's tombstone/replacement history
				if cur, ok := w.Led.Bindings[capID]; ok {
					if prior, ok := cur["lineage"].(map[string]any); ok {
						binding["lineage"] = prior
					}
				}
				if err := w.Append("binding.updated",
					[]string{capID}, binding, tok); err != nil {
					release()
					return refuse(perr.LedgerCorrupted, err.Error())
				}
				res.Bindings[capID] = pinnedID
			case "delete":
				pinnedID, _ := receipt["targetProviderId"].(string)
				pinnedGen, _ := receipt["targetGeneration"].(int)
				target, _ := receipt["target"].(string)
				// carry PRIOR lineage forward (F4): apply preserves
				// existing tombstones/replaces in the new binding body, so
				// resume must too — else a later retirement of the
				// survivor loses the deposed/replacement history. Read the
				// FRESH projection (F3), not the entry-time snapshot.
				tombstones := []any{map[string]any{
					"providerId":   pinnedID,
					"resourceType": target,
					"generation":   pinnedGen,
					"deletedAt":    ledger.FormatTs(clock),
				}}
				var replaces []any
				if cur, ok := w.Led.Bindings[capID]; ok {
					if prior, ok := cur["lineage"].(map[string]any); ok {
						if tl, ok := prior["tombstones"].([]any); ok {
							tombstones = append(tl, tombstones...)
						}
						if rp, ok := prior["replaces"].([]any); ok {
							replaces = rp
						}
					}
				}
				lineage := map[string]any{"tombstones": tombstones}
				if len(replaces) > 0 {
					lineage["replaces"] = replaces
				}
				binding := map[string]any{
					"resumeRunId": runID,
					"capability":  capID,
					"environment": c.Environment,
					// provider identity must survive (F4): a bindingless
					// provider name breaks retirement's identity pinning
					"provider": map[string]any{"name": prov.Name()},
					"reconciledFrom": map[string]any{
						"operationId": opID},
					"lineage": lineage,
				}
				// empty the binding ONLY when it still points at the
				// deleted identity (mirrors apply's replacement rule)
				if w.Led.BoundProviderIDs()[capID] == pinnedID {
					binding["resources"] = []any{}
				} else if cur, ok := w.Led.Bindings[capID]; ok {
					binding["resources"] = cur["resources"]
				}
				if err := w.Append("binding.updated",
					[]string{capID}, binding, tok); err != nil {
					release()
					return refuse(perr.LedgerCorrupted, err.Error())
				}
			}
			// the success projection is durable → NOW clear the pending intent
			// (D180): a crash before this point left the receipt pending for the
			// next resume, never an orphan
			if err := commitTerminal(); err != nil {
				release()
				return refuse(perr.LedgerCorrupted, err.Error())
			}
		}
	}
	if err := w.Append("lease.released", caps, nil, tok); err != nil {
		return refuse(perr.LedgerCorrupted, err.Error())
	}
	if stillUnknown {
		res.Status = "still-unknown"
		res.Code = perr.ReconcilePending
		res.Exit = 3
		res.Reasons = []string{
			"some outcomes remain unknown — pending receipts stay, " +
				"apply keeps refusing until they conclude"}
		return res
	}
	// D736: a receipt that CONCLUDED as a failure is not a resumed run. This reported
	// `{"status":"resumed"}` and exit 0 whenever every receipt reached a terminal state,
	// including when every one of them concluded FAILED — so an operator saw OK, moved
	// on, and the next plan proposed creates for resources that already existed.
	// Measured in the field on three budgets: the reconciler concluded `failed` for each
	// (the budget object stood but its alert notification had not landed), resume
	// answered success, and nothing was bound.
	//
	// The exit code is the whole product of this verb for a script. It now carries the
	// worst outcome among the receipts it concluded, the way apply does.
	var failed []string
	for _, r := range res.Resolved {
		if r.Status == "failed" {
			failed = append(failed, r.Capability+" ("+r.Operation+"): "+r.Reason)
		}
	}
	if len(failed) > 0 {
		sort.Strings(failed)
		res.Reasons = append(res.Reasons, append([]string{
			fmt.Sprintf("%d operation(s) CONCLUDED AS FAILURES — resume cleared their "+
				"pending receipts (which is what unblocks apply) but bound nothing, so "+
				"the resources they were creating are NOT under management. Re-apply to "+
				"heal them; until then their capability is unbound:", len(failed))},
			failed...)...)
	}
	return res
}
