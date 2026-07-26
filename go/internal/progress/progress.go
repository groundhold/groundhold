// Package progress is the ephemeral liveness stream for the execution loop
// (D227, spec/progress.md). It is a PROJECTION of the executor's action state
// machine, never a second source of truth: the same machine that decides to
// write receipts (the durable truth) emits these events. The stream is not in
// the sealed plan, not in the plan hash, and not a ledger event — it may be
// absent without changing apply semantics.
//
// This file is the closed vocabulary the conformance suite pins: the event
// shape, the ten action states, and the transition table. The enum is closed
// twice — here and in the suite — so a new state or edge cannot ship unpinned.
package progress

// Stream is the versioned schema tag every event carries.
const Stream = "groundhold/progress/v1"

// Kind is the event kind. Only a transition may advance k, change state, or
// move an indicator; a tick is a pure liveness heartbeat and can change
// neither state nor k (enforced by Fold, pinned by a case).
type Kind string

const (
	KindRunStart   Kind = "run-start"
	KindTransition Kind = "transition"
	KindTick       Kind = "tick"
	KindRunEnd     Kind = "run-end"
	KindBanner     Kind = "banner"
)

// ActionState is the closed per-action state (D227). Motion is a pure function
// of state: only Running and ProviderWait animate, and ProviderWait requires
// fresh evidence to remain itself (else the machine moves it to Stalled).
type ActionState string

const (
	StatePending        ActionState = "pending"         // deps unmet
	StateReady          ActionState = "ready"           // dispatchable, queued behind the concurrency budget
	StateRunning        ActionState = "running"         // our own provider calls in flight
	StateProviderWait   ActionState = "provider-wait"   // LRO handed off; polls returning fresh evidence
	StateStalled        ActionState = "stalled"         // evidence stale — poll budget missed / polls erroring; NOT terminal
	StateBlockedConsent ActionState = "blocked-consent" // awaiting a human consent gate (converge / two-step MCP)
	StateDone           ActionState = "done"            // terminal: satisfied
	StateFailed         ActionState = "failed"          // terminal: violated
	StateSkipped        ActionState = "skipped"         // terminal: cached (satisfied) or dep-failed (unknown)
	StateIndeterminate  ActionState = "indeterminate"   // terminal: gave up without knowing (unverifiable) — routes to resume
)

// terminal states end an action and increment k ("k of N resolved").
var terminal = map[ActionState]bool{
	StateDone: true, StateFailed: true, StateSkipped: true, StateIndeterminate: true,
}

// IsTerminal reports whether a state ends the action (and moves k).
func IsTerminal(s ActionState) bool { return terminal[s] }

// motion states are the ONLY ones a renderer may animate. ProviderWait's motion
// is conditional on fresh evidence — the state machine, not the renderer,
// demotes a stale ProviderWait to Stalled, so a frozen glyph is always a real
// state, never a renderer guess.
var motion = map[ActionState]bool{
	StateRunning: true, StateProviderWait: true,
}

// IsMotion reports whether a renderer may animate this state.
func IsMotion(s ActionState) bool { return motion[s] }

// transitions is the pinned edge table. A transition event whose (prev -> state)
// edge is absent here is invalid — the enum is closed by this map plus the
// conformance case that mirrors it. Every non-terminal path can reach a terminal
// state; terminal states have no out-edges.
var transitions = map[ActionState][]ActionState{
	StatePending:        {StateReady, StateSkipped},                                                    // deps met -> ready; a dep failed -> skipped
	StateReady:          {StateRunning, StateSkipped},                                                  // dispatched; or skipped (cached)
	StateRunning:        {StateProviderWait, StateDone, StateFailed, StateIndeterminate, StateStalled}, // sync-done, handed to an LRO, or lost
	StateProviderWait:   {StateStalled, StateDone, StateFailed, StateIndeterminate, StateBlockedConsent},
	StateStalled:        {StateProviderWait, StateFailed, StateIndeterminate}, // evidence returned; or gave up
	StateBlockedConsent: {StateRunning, StateProviderWait, StateSkipped, StateFailed, StateIndeterminate},
}

// CanTransition reports whether prev -> next is a legal edge. A terminal prev
// has no out-edges; an equal prev==next is not a transition (it would be a tick).
func CanTransition(prev, next ActionState) bool {
	if IsTerminal(prev) || prev == next {
		return false
	}
	for _, s := range transitions[prev] {
		if s == next {
			return true
		}
	}
	return false
}

// Outcome maps a terminal state to its four-valued action-claim verdict — the
// claim "this action's receipt concluded", NOT the contract's constraints
// (those live in verify/audit). Skipped is context-dependent (cached=satisfied,
// dep-failed=unknown), resolved by the caller via SkipWhy; the bare mapping here
// is the cached case. A non-terminal state has no outcome ("").
func Outcome(s ActionState, skipWhy string) Verdict {
	switch s {
	case StateDone:
		return Satisfied
	case StateFailed:
		return Violated
	case StateIndeterminate:
		return Unverifiable
	case StateSkipped:
		if skipWhy == SkipDepFailed {
			return Unknown // never attempted — we cannot claim it holds
		}
		return Satisfied // cached — already true
	}
	return ""
}

// Verdict is the four-valued action-claim verdict carried on terminal events.
type Verdict string

const (
	Satisfied    Verdict = "satisfied"
	Violated     Verdict = "violated"
	Unknown      Verdict = "unknown"
	Unverifiable Verdict = "unverifiable"
)

// Basis is provenance on an estimate (D227/#3). A time band is inferred (from
// own receipt history); a provider percent is declared (by the provider). No
// number is ever emitted with basis unknown.
type Basis string

const (
	BasisDeclared Basis = "declared"
	BasisInferred Basis = "inferred"
	BasisAssumed  Basis = "assumed"
	BasisUnknown  Basis = "unknown"
)

// SkipWhy values.
const (
	SkipCached    = "cached"
	SkipDepFailed = "dep-failed"
)

// ManifestAction is one action in the run-start manifest — the sealed plan's
// shape, enough for a consumer attaching at t=0 to render position without any
// other source.
type ManifestAction struct {
	ActionID   string   `json:"actionId"`
	Index      int      `json:"index"` // 1-based sealed-plan position
	Operation  string   `json:"operation"`
	Capability string   `json:"capability"`
	Target     string   `json:"target,omitempty"`
	DependsOn  []string `json:"dependsOn,omitempty"`
}

// RunManifest opens the stream (run-start only).
type RunManifest struct {
	TotalActions int              `json:"totalActions"`
	Actions      []ManifestAction `json:"actions"`
}

// ETABand is a basis-tagged forecast of an action's duration from own receipt
// history (D227). Absent unless the history justifies it; withdrawn once elapsed
// exceeds Worst (a band already beaten is a lie). Never emitted with basis
// unknown. Milliseconds throughout for a stable machine surface.
type ETABand struct {
	AtLeastMS int64 `json:"atLeastMs"` // fastest observed success
	TypicalMS int64 `json:"typicalMs"` // EWMA of successes
	WorstMS   int64 `json:"worstMs"`   // p95 of successes
	Basis     Basis `json:"basis"`     // inferred (or declared); never unknown with numbers
	Samples   int   `json:"samples"`
}

// Event is one delta on the progress stream. Fields are populated per Kind;
// zero-valued optionals are omitted so the machine surface stays tight.
type Event struct {
	Stream   string `json:"stream"`
	Seq      uint64 `json:"seq"`
	Kind     Kind   `json:"kind"`
	RunID    string `json:"runId"`
	PlanHash string `json:"planHash"`

	Manifest *RunManifest `json:"manifest,omitempty"` // run-start only

	ActionID string      `json:"actionId,omitempty"`
	State    ActionState `json:"state,omitempty"`
	Prev     ActionState `json:"prev,omitempty"` // transitions only; the edge MUST be legal
	K        int         `json:"k"`
	N        int         `json:"n"`

	StartedAt string `json:"startedAt,omitempty"` // coordination clock (D56)
	ElapsedMS int64  `json:"elapsedMs"`           // monotonic runtime clock — a duration, never freshness

	ProviderPercent *float64 `json:"providerPercent,omitempty"` // present ONLY if the provider supplied it
	ProviderPhase   string   `json:"providerPhase,omitempty"`
	RetryAfterMS    *int64   `json:"retryAfterMs,omitempty"`

	ETA *ETABand `json:"eta,omitempty"`

	Outcome Verdict `json:"outcome,omitempty"` // terminal transitions only
	SkipWhy string  `json:"skipWhy,omitempty"`
	Reason  string  `json:"reason,omitempty"`
	Code    string  `json:"code,omitempty"`
}
