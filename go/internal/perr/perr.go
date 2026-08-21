// Package perr is the machine-readable error-code registry (D64,
// spec/errors.md). The code is the CONTRACT — one code per distinct
// remediation; reasons and explanations are prose and never parsed.
package perr

import "sort"

// AtNow is the `--at` operand every published remediation carries when it names a
// time-sensitive verb (D693). N1 refuses a defaulted clock, so advice that names
// `observe`, `discover`, `crawl`, `resume` — any of the twenty — without one cannot
// be followed as written: the reader pastes it and gets a refusal instead of the
// help they were promised at the moment they most needed it.
//
// A shell substitution rather than a `<placeholder>`: the reader pastes it verbatim
// and it resolves. Shared from here, the package with no dependencies, so the twenty
// verbs' advice cannot drift into twenty spellings of the same operand.
//
// Pass it as an ARGUMENT (`… %s`), never concatenated into a format string: it holds
// `%F` and `%T`, which Sprintf reads as verbs. `go vet` refuses that — it caught all
// six call sites on the first draft, which is the gate this constant relies on.
const AtNow = `--at "$(date -u +%FT%TZ)"`

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
	// D1154: the ledger holds an event type this build does not know. The
	// registry rule here is "one code per DISTINCT REMEDIATION", and this one's
	// remediation is the OPPOSITE of ledger-corrupted's: run a newer build and
	// leave the file alone, rather than diagnose and quarantine it. Sharing a
	// code (and with it exit 5, whose banner is CORRUPTED) told a reader their
	// intact ledger was damaged — advice that, followed, destroys evidence.
	LedgerVersionAhead Code = "ledger-version-ahead"
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
	// D1099: the estate has a projected state-change (a hard constraint's proof
	// decays, or a live run's lease lapses with a receipt unsettled) INSIDE the
	// requested --within window. One remediation: run the advised verb before the
	// stated deadline. A future condition, so exit 2 (not a corruption/refusal class).
	HorizonActionRequired Code = "horizon-action-required"
)

type Explanation struct {
	Summary     string `json:"summary"`
	Remediation string `json:"remediation"`
}

// ExitFor is the process exit each code carries, and it is now stated ONCE (D619).
//
// It used to live only in `spec/errors.md` and, separately, at every call site as a
// literal beside the code. They drifted, which a caller cannot survive: the SAME
// condition — a plan whose decision heads moved — was refused as `structural-error`
// exit 3 on one path and `stale-decision` exit 3 on another, `structural-error` was
// emitted at exits 1, 2 AND 3, and `stale-decision` at 2 and 3. A machine reading the
// code cannot map it to an exit in either direction, which is the whole point of
// publishing both.
//
// D330's gate reconciles the code NAMES across four artefacts. The exit column had no
// gate at all, which is exactly where the drift lived.
// Markers are nouns the runtime emits that are NOT process-exit codes: per-capability
// verdicts inside a report, and compiler advisories. `explain` is published as "the
// single place to ask about any noun the runtime emits", and four of these were
// emitted as bare string literals, registered nowhere, so asking about them exited 1
// with "not an error code and not a vocabulary attribute" (D623).
//
// They are deliberately separate from Explain: those carry an exit and appear in
// spec/errors.md's table, and a marker has neither. Same lookup surface, honest
// distinction — and a gate requires every code string the runtime emits to be in one
// registry or the other.
var Markers = map[Code]Explanation{
	"capsule-coupled": {
		"A capability shares an event with one that could not be proven, so its tail " +
			"cannot be restored without fabricating that history.",
		"Supply the capsule for the coupled capability and restore again; `--partial` " +
			"marks it unknown rather than inventing the shared events.",
	},
	"capsule-trust-refused": {
		"A capsule's signatures did not verify against the trusted keys in force.",
		"Check `--trust`/`--trust-from` against the keys that signed the capsule; a " +
			"capsule that cannot be trusted is not restored from.",
	},
	"existence-not-witnessed": {
		"The plan asserts a resource exists without an observation that witnessed it.",
		"Run `observe --record` for the capability, then re-plan; existence claimed " +
			"from a declaration is not evidence.",
	},
	"hard-constraint-on-a-projection": {
		"A hard constraint's runtime bar is `static` on an attribute the vocabulary marks " +
			"as a PROJECTION, so the only evidence it can ever have is the value declared " +
			"in the candidate.",
		"Keep it if a stated assumption is what you want; raise the bar to `probe` to " +
			"demand a measurement (and be refused until one exists, which is the point); " +
			"or make it `soft`, which is what an unprovable assertion already is.",
	},
	"chargeable-component-outside-the-declared-cost": {
		"A declared attribute makes this build a component the provider bills SEPARATELY " +
			"from the resource, while cost.monthly on the same capability is the author's " +
			"own figure.",
		"Check the declared cost against the provider's rate card for the named " +
			"component. This tool prices nothing it builds and does not pretend to.",
	},
	"logs-group-has-no-producer": {
		"A log group is declared with nothing in the contract writing to it.",
		"Bind a producer to the group, or drop the group; a sink with no source " +
			"collects nothing and reads as coverage.",
	},
}

// ExitsFor is the set of process exits each code may carry, stated ONCE (D619).
//
// Most codes carry one. Three carry two by design, and `spec/errors.md` publishes them
// as "3/4" — a fact my first version of this map silently dropped, because the parser
// only matched a cell of pure digits. The gate compared the dropped map against a
// `published` map parsed the SAME WRONG WAY, so both agreed by being wrong together,
// and the missing entries surfaced only when a lookup returned the zero value and a
// refusal exited 0. Two artefacts derived by one broken parser are one artefact.
var ExitsFor = map[Code][]int{}

// ExitFor is the PRIMARY exit for a code — what a refusal uses when it has no reason
// to pick the alternate. Unknown codes give 2, the historical default; the gate
// asserts every code the source refuses with has an entry, so that is unreachable.
func ExitFor(code Code) int {
	if e := ExitsFor[code]; len(e) > 0 {
		return e[0]
	}
	return 2
}

func init() {
	for code, exits := range map[Code][]int{
		AdoptionMismatch:         {2},
		ApplyFailed:              {4},
		BindingConflict:          {2},
		ClockRegress:             {2, 3},
		HorizonActionRequired:    {2},
		ConfirmationRequired:     {2},
		ConsentRequired:          {2},
		LeaseConflict:            {3},
		LedgerCorrupted:          {5},
		LedgerVersionAhead:       {2},
		MappingSchemaDrift:       {2},
		NotExecutable:            {2},
		NothingToChange:          {2},
		ObservationRequired:      {2},
		PreflightInconclusive:    {2},
		ProviderAgainLater:       {4},
		ProviderPermissionDenied: {2},
		ProviderRefused:          {2},
		ReadSetMismatch:          {2},
		ReconcilePending:         {3},
		ReconcileRequired:        {3, 4},
		ReferenceInvalid:         {2},
		ReferenceUnresolved:      {3, 4},
		RunDone:                  {0},
		RunFailed:                {4},
		RunNeedsReconcile:        {3},
		RunRunning:               {3},
		RunStalled:               {3},
		RunUnknown:               {3},
		StaleDecision:            {3},
		StructuralError:          {1},
		SurveyDrift:              {2},
		UnknownOperand:           {2},
		UnsupportedOperation:     {2},
		WaitTimeout:              {3},
	} {
		ExitsFor[code] = exits
	}
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
	HorizonActionRequired: {
		"Something the estate depends on decays within your --within window: a hard constraint's proof expires, or a live run's lease lapses with a receipt unsettled.",
		"Run the advised verb before the stated deadline — each transition names the action (refresh before a proof decays; wait/resume before a lease lapses)."},
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
		// D730: this used to say "Unadopt or retire the existing binding first" and
		// there is no `retire` VERB. A pilot spent a quarter of an hour searching a
		// fifty-item verb list, assuming they had missed it rather than that the tool
		// was pointing at nothing. Retirement is a CONTRACT state (D47), and naming it
		// is the difference between advice and a wild-goose chase.
		"For a resource groundhold adopted, `unadopt` it. For one groundhold created, " +
			"set `state: retired` on the capability in the contract and re-plan — that " +
			"compiles a pinned delete. Removing the capability from the contract does " +
			"NOT delete anything, deliberately."},
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
	LedgerVersionAhead: {
		"The ledger holds an event type this build does not know — the event-type " +
			"registry is additive-only, so a newer groundhold wrote it.",
		"Run the newer build against this ledger, or upgrade this one. Do NOT " +
			"repair, quarantine or restore the file on account of this refusal: " +
			"the refusal says the events cannot be INTERPRETED here, and it " +
			"reports separately whether the hash chain verifies."},
	LedgerCorrupted: {
		"The ledger file is corrupted.",
		"Run `groundhold repair --ledger <file>` — diagnose, then quarantine on " +
			"fingerprint consent; nothing proceeds over corruption."},
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
	// D330: the run codes are emitted by `status`/`wait`/`runs` and travel to
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
		// D764: this said `wait --handle`, and there is no such flag — wait takes the
		// handle POSITIONALLY. A remediation that routes at a flag the binary does not
		// parse is the same failure as one routing at a verb it does not dispatch (D730).
		"Nothing — wait. `wait <handle> --ledger <l>` blocks until it concludes."},
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
		"Re-run `wait` with a longer --timeout, or poll `status` — nothing " +
			"was cancelled and no state changed."},
}
