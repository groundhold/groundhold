// Package perr is the machine-readable error-code registry (D64,
// spec/errors.md). The code is the CONTRACT — one code per distinct
// remediation; reasons and explanations are prose and never parsed.
package perr

import "sort"

type Code string

const (
	StructuralError      Code = "structural-error"
	NotExecutable        Code = "not-executable"
	NothingToChange      Code = "nothing-to-change"
	ObservationRequired  Code = "observation-required"
	ReconcileRequired    Code = "reconcile-required"
	ReconcilePending     Code = "reconcile-pending"
	ConsentRequired      Code = "consent-required"
	ConfirmationRequired Code = "confirmation-required"
	ReadSetMismatch      Code = "read-set-mismatch"
	StaleDecision        Code = "stale-decision"
	LeaseConflict        Code = "lease-conflict"
	ClockRegress         Code = "clock-regress"
	BindingConflict      Code = "binding-conflict"
	AdoptionMismatch     Code = "adoption-mismatch"
	ProviderRefused      Code = "provider-refused"
	UnsupportedOperation Code = "unsupported-operation"
	ApplyFailed          Code = "apply-failed"
	LedgerCorrupted      Code = "ledger-corrupted"
	// D75: permission preflight. Two distinct remediations — grant the
	// missing permissions vs. make the check itself runnable — so two codes.
	ProviderPermissionDenied Code = "provider-permission-denied"
	PreflightInconclusive    Code = "preflight-inconclusive"
	// D93: the code survey and the contract disagree about reality.
	SurveyDrift Code = "survey-drift"
	// Schema-driven mapping: the live API schema diverged inside the mapped
	// surface, so the mapping may misread it — refuse rather than reinterpret.
	MappingSchemaDrift Code = "mapping-schema-drift"
	// D226/F13: intra-plan output references. Compile-time invalidity of a
	// $ref (unknown capability/output, kind mismatch, malformed, cycle, ...)
	// vs. apply-time failure to resolve a same-plan producer's output.
	ReferenceInvalid    Code = "reference-invalid"
	ReferenceUnresolved Code = "reference-unresolved"
	// The candidate `implementation:` block is free-form (D26), but an operand
	// key no driver reads is refused rather than silently dropped — one
	// remediation: declare it under a key the driver consumes, or remove it.
	UnknownOperand Code = "unknown-operand"
	// D229: background-run state, derived purely from the ledger. Distinct codes
	// because the remediations differ: a stalled writer needs `resume`, a running
	// one needs patience, an unknown handle needs a correct id.
	RunUnknown        Code = "run-unknown"
	RunRunning        Code = "run-running"
	RunStalled        Code = "run-stalled"
	RunNeedsReconcile Code = "run-needs-reconcile"
	RunDone           Code = "run-done"
	RunFailed         Code = "run-failed"
	WaitTimeout       Code = "wait-timeout"
	// D237: a mutation was throttled (a pure rate-limit) BEFORE it could land.
	// Distinct from reconcile-required: the mutation provably did not execute, so
	// the remediation is "wait and retry the same verb", not "reconcile". A 5xx,
	// transport error, or live 403 stays reconcile-required (may have landed).
	ProviderAgainLater Code = "provider-again-later"
)

type Explanation struct {
	Summary     string `json:"summary"`
	Remediation string `json:"remediation"`
}

// RegistryEntry is one code's machine-readable remediation (D233): the exact
// pair `explain <code>` prints, keyed by the code. A consumer (the console) can
// project it verbatim so a blocked/refused figure carrying a `code` also shows
// how to fix it — one glossary, no drift.
type RegistryEntry struct {
	Code        string `json:"code"`
	Summary     string `json:"summary"`
	Remediation string `json:"remediation"`
}

// Registry returns every explained code, sorted, from the single source (the
// Explain map). Deterministic — golden-testable.
func Registry() []RegistryEntry {
	out := make([]RegistryEntry, 0, len(Explain))
	for c, ex := range Explain {
		out = append(out, RegistryEntry{Code: string(c), Summary: ex.Summary, Remediation: ex.Remediation})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Code < out[j].Code })
	return out
}

// Explain mirrors spec/errors.md — emitted only under --explain, in a
// field documented as non-contractual.
var Explain = map[Code]Explanation{
	StructuralError: {
		"The document does not parse or validate.",
		"Fix the named document; nothing was evaluated."},
	NotExecutable: {
		"Hard constraints are not proven satisfied.",
		"Fix the candidate (or revisit the contract); unknown blocks by design."},
	NothingToChange: {
		"The world already converges with the candidate.",
		"Nothing — converge reports this as success."},
	ObservationRequired: {
		"Knowledge about the bound world is missing or stale.",
		"Run `observe --record` against the ledger, then retry."},
	ReconcileRequired: {
		"In-flight operations have unsettled outcomes.",
		"Run `resume` — it asks the provider what actually happened."},
	ReconcilePending: {
		"The provider cannot answer for the outcome yet.",
		"Retry `resume` later; the receipt stays pending, nothing is guessed."},
	ProviderAgainLater: {
		"The provider throttled the mutation before it could land.",
		"Wait for the backoff (honor Retry-After when present), then re-run the same verb; no reconcile is needed — the mutation did not execute."},
	ConsentRequired: {
		"The action needs explicit consent that is absent.",
		"Add the named contract autonomy entry or flag; nothing implicit unlocks it."},
	ConfirmationRequired: {
		"A human must see and confirm this exact decision.",
		"Confirm interactively, pass --yes, or complete the MCP two-step."},
	ReadSetMismatch: {
		"The documents differ from what the plan pinned.",
		"Use the exact pinned contract/candidate, or re-seal the plan."},
	StaleDecision: {
		"Decisions moved since this plan was sealed.",
		"Re-observe and re-plan; the sealed decision no longer matches heads."},
	LeaseConflict: {
		"Another writer holds an active lease.",
		"Wait for expiry, or break the lease deliberately (audited)."},
	ClockRegress: {
		"This writer's clock is behind the ledger.",
		"Fix the clock; the ledger refuses backdated appends (D56)."},
	BindingConflict: {
		"The capability or providerId is already bound.",
		"Unadopt or retire the existing binding first."},
	AdoptionMismatch: {
		"The candidate disagrees with observed reality.",
		"Fix the candidate or the resource — adoption must not lie."},
	ProviderRefused: {
		"The driver cannot honor the request.",
		"Change the candidate's implementation block; see the reason."},
	SurveyDrift: {
		"The code survey and the contract disagree about reality.",
		"Add the capability the code now requires, or retire the one no " +
			"repo witnesses; re-crawl if the survey is stale (D93)."},
	ReferenceInvalid: {
		"An intra-plan $ref operand is invalid (D226).",
		"Fix the candidate reference: unknown capability/output, kind " +
			"mismatch (no coercion), malformed $ref, dependency cycle, or a " +
			"producer this plan retires. A stale fold is observation-required."},
	UnknownOperand: {
		"The candidate declares an implementation operand no driver reads (D26).",
		"Declare the operand under a key the driver consumes, or remove it; a " +
			"key the driver ignores would be silently dropped, so it is refused."},
	ReferenceUnresolved: {
		"A same-plan producer did not yield the referenced output (D226).",
		"Inspect the producer receipt, then `resume`; the consumer is " +
			"refused before mutating. A missing/mistyped output is a driver " +
			"contract violation — re-plan."},
	MappingSchemaDrift: {
		"The live API schema diverged inside the mapping's mapped surface.",
		"Re-author the mapping against the current schema (a mapped field " +
			"changed type, lost an enum, or vanished); the engine refuses to " +
			"reinterpret rather than misread."},
	UnsupportedOperation: {
		"Outside this version's scope.",
		"Consult the verb's documentation for the v0 boundary."},
	ApplyFailed: {
		"A provider operation failed terminally mid-flight.",
		"Inspect the reason and receipts; re-plan."},
	LedgerCorrupted: {
		"The ledger file is corrupted.",
		"Run `groundhold repair` — diagnose, then quarantine on fingerprint " +
			"consent; nothing proceeds over corruption."},
	ProviderPermissionDenied: {
		"The acting identity lacks permissions the plan requires.",
		"Grant the listed permissions to the identity, or apply as one that " +
			"has them. A preflight refusal is trustworthy; a pass is evidence, " +
			"not proof."},
	PreflightInconclusive: {
		"The permission preflight could not run.",
		"Fix what blocks the check (enable the provider's IAM API, repair the " +
			"token/scope, restore connectivity), then retry — or skip it " +
			"deliberately where strictness is not required."},
	// D330: the run codes are emitted by `runstatus`/`wait`/`runs` and travel to
	// notification hooks, so they need the same static remediation every other
	// routed code has. The context-specific prose (which receipt, whose lease)
	// stays where the invocation knows it — this is the generic answer `explain`
	// can give with no context at all.
	RunUnknown: {
		"The run's state cannot be derived from the ledger.",
		"Check the handle. A registry-only run was launched but never admitted — " +
			"it may have died before its first event; read its log."},
	RunRunning: {
		"A writer holds a live lease and the run has not concluded.",
		"Nothing — wait. `wait --handle` blocks until it concludes."},
	RunStalled: {
		"The writer's lease lapsed without concluding the run.",
		"Run `resume` — it asks the provider what actually happened."},
	RunNeedsReconcile: {
		"The run concluded leaving receipts unsettled.",
		"Run `resume` before starting another run against this ledger."},
	RunDone: {
		"The run concluded successfully.",
		"None."},
	RunFailed: {
		"The run concluded unsuccessfully; its own exit code is relayed.",
		"Read the run's refusal — this code reports the outcome, the run's own " +
			"code says why."},
	WaitTimeout: {
		"`wait` gave up before the run concluded. The run is unaffected.",
		"Re-run `wait` with a longer --timeout, or poll `runstatus` — nothing " +
			"was cancelled and no state changed."},
}
