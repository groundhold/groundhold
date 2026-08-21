// Package ledger implements the D31 backend semantics as an in-memory
// state machine: CAS appends over full heads, decision heads (D41),
// leases with history-derived fencing tokens, receipt tracking (D29).
// It is the single Go implementation of the rules — the scenario engine
// (D37) and the apply engine (D42) both drive THIS code, so what the
// conformance scenarios pin is what apply obeys.
//
// The clock is logical and owned by the caller: scenarios tick it,
// apply derives it from event timestamps. Nothing here reads wall time.
package ledger

import (
	"fmt"
	"sort"
	"strings"

	"groundhold/internal/canonical"
	"groundhold/internal/state"
)

// MutationTypes require an active lease + fencing token (D29).
var MutationTypes = map[string]bool{
	"binding.updated": true, "apply.started": true,
	"apply.finished": true, "apply.failed": true,
}

// NonMutatingTypes is the EXPLICIT other half of MutationTypes (D338). The
// fencing/lease requirement is driven by MutationTypes membership, so a mutating
// type omitted from it is appended with NO lease and NO fencing token — a silent
// fail-open in the concurrency control (D29). Together the two sets must cover
// state.EventTypes exactly, and a gate enforces that: a new event type cannot land
// without someone deciding, in writing, which half it belongs to.
var NonMutatingTypes = map[string]bool{
	"contract.published":   true, // authorship of a document; decision, not a world change
	"candidate.verified":   true, // a verdict about documents
	"plan.sealed":          true, // a decision; concurrency is handled by heads CAS (D41)
	"observation.recorded": true, // knowledge, never a change
	"violation.detected":   true, // knowledge derived from observations
	"violation.resolved":   true, // knowledge derived from observations
	"probe.failed":         true, // knowledge that measurement failed (never an observation, D59)
	"observation.failed":   true, // knowledge that a READ failed (D1152); never an observation
	"lease.acquired":       true, // coordination; has its own arm in the append switch
	"lease.renewed":        true, // coordination
	"lease.released":       true, // coordination
	"lease.broken":         true, // coordination
	"operation.receipt":    true, // outcome of a mutation already fenced by apply.started
	// D599: an AUTHORSHIP stamp, not a world change — spec/state-model.md §1 says so
	// in those words, and §2 enumerates the mutation set as apply.* + binding.updated.
	// It was in MutationTypes, so the runtime refused a bare claim that the reference
	// implementation accepts. `apply` stamps it while holding a lease and MAY carry a
	// token; the token is simply no longer demanded.
	"ownership.claimed": true,
	// D229: converge lifecycle markers — run-scoped, lease-free by design.
	"converge.started":       true,
	"converge.phase.entered": true,
	"converge.finished":      true,
	"converge.failed":        true,
}

// DecisionTypes advance the decision heads sealed plans pin (D41);
// knowledge and coordination events are audit-chained but neutral.
var DecisionTypes = map[string]bool{
	"binding.updated": true, "apply.started": true,
	"apply.finished": true, "apply.failed": true,
	"contract.published": true, "candidate.verified": true,
	"plan.sealed": true,
}

// ReceiptStatuses is the closed set of operation-receipt statuses, in a stable
// order. Exported because the run-state derivation folds the SAME event
// (internal/runstatus) and must be checkable against this fold rather than
// carrying its own copy of the rule — D641.
func ReceiptStatuses() []string {
	return []string{"pending", "succeeded", "failed", "unknown", "retryable"}
}

// ReceiptLeavesIntentPending is the single answer to "does a receipt with this
// status leave the operation unsettled?" — the rule the fold below applies, so
// that every other reader applies the same one. `unknown` MAY have landed and
// stays pending until adopted (D29/D180); `retryable` provably did not land and
// concludes (D241).
func ReceiptLeavesIntentPending(status string) bool {
	return status == "pending" || status == "unknown"
}

var receiptStatuses = map[string]bool{
	"pending": true, "succeeded": true, "failed": true, "unknown": true,
	// D241: a throttled mutation that provably did not land — concludes the
	// intent (clears pending, like succeeded/failed), but is neither: the verb
	// may be safely re-attempted (provider-again-later).
	"retryable": true,
}

type lease struct {
	token  int
	expiry int
	ttl    int
	ended  bool
	// seq identifies the LEASE, not the capability (D633). Tokens are per-capability
	// counters — `max(previous tokens for the affected caps) + 1` — so two leases over
	// disjoint capability sets both receive token 1, and the mutation rule ("does the
	// token equal the active token on each affected capability") was satisfied by a
	// writer mutating INTO someone else's lease. seq is a fold-time counter: it is
	// recomputed identically on every replay, never appears on the wire, and does not
	// touch token arithmetic — so no existing ledger reads differently because of it.
	seq int
	// seqUnknown marks a lease seeded from a snapshot written before lease
	// identity existed (D644). Its seq is synthetic and distinct, so the covering
	// check refuses a multi-capability mutation over it — the snapshot cannot
	// establish that one lease held them, and silence is not agreement.
	seqUnknown bool
}

type Ledger struct {
	Clock         int
	Heads         map[string]string
	DecisionHeads map[string]string
	// Bindings is the projection of binding.updated events —
	// latest body wins (D27); there is no second mutable store.
	Bindings map[string]map[string]any
	// Observations is the projection of observation.recorded bodies:
	// latest observedAt wins per (capability, path); on a tie, measured
	// beats config-intent (D45).
	Observations map[string]map[string]ObsRecord
	// ObservationsBySource retains the latest record PER SOURCE
	// (capability -> path -> source -> record), so a probe measurement is
	// not erased by a later provider-api observe (D191). audit selects the
	// freshest record whose source meets the constraint's verify.method bar
	// (D190); the single-slot Observations above stays newest-overall for
	// drift consumers (forecast, compiler) that do not method-gate.
	// Outputs (D286) is the WIRING projection: a bound resource's declared
	// typed outputs (D226/D283), keyed capability -> output NAME (the
	// "outputs." prefix is stripped). It is DELIBERATELY separate from
	// Observations: an output is an IDENTITY a consumer references, not a
	// capability SEMANTIC fact the contract constrains. Keeping them in one
	// map let wiring records answer "has this capability been observed?" —
	// a fail-open. Separate projections make that mistake structurally
	// impossible rather than a rule to remember.
	Outputs              map[string]map[string]ObsRecord
	ObservationsBySource map[string]map[string]map[string]ObsRecord
	// ViolationState: (capability \x00 constraint) -> last recorded
	// verdict; entries clear on violation.resolved (D54 transitions)
	ViolationState map[string]string
	// Environments: capability -> the environment its history declares.
	// Projected from every event EXCEPT observation.recorded —
	// observations inherit an environment, they never define one (and
	// pre-fix ledgers carried a sentinel there that must not stick).
	Environments map[string]string
	// claimed: capability -> groundhold has claimed AUTHORSHIP of the adopted
	// resource (ownership.claimed, D52 takeover). Lazily created; canonEmpty
	// nils an empty one so snapshot+tail folds match a full fold (D137).
	claimed map[string]bool
	// observed: capability -> observe was RECORDED for it (observation.recorded),
	// even when it yielded zero observable attributes. This distinguishes a bound
	// capability that was never observed (re-observe recovers) from one whose
	// observer is structurally blind/empty (re-observe cannot help) — the compiler
	// must not freeze the latter. Lazily created; canonEmpty nils an empty one so
	// snapshot+tail folds match a full fold (D137).
	observed map[string]bool
	// readFailures: capability -> the most recent observation.failed for it
	// (D1152). Deliberately NOT part of the canonical snapshot: it is a
	// DIAGNOSTIC, and putting it there would change every pinned snapshot
	// hash for a field no decision rests on. The cost is stated rather than
	// hidden — after a compaction the failures older than the snapshot are
	// no longer folded, so the refusal falls back to the freshness-only
	// wording. That degrades to LESS information, never to wrong
	// information, and the failure that matters is the most recent one,
	// which lives in the tail.
	readFailures map[string]ReadFailure
	// Lenient tolerates occurredAt regressions in EXISTING history
	// (replay); appends with Lenient false reject them (D56)
	Lenient     bool
	maxOccurred int
	leases      map[string]*lease
	maxToken    map[string]int
	leaseSeq    int // D633: identifies a lease across its capabilities
	pending     map[string]map[string]bool
	// pendingBody keeps the LAST receipt body per pending operation —
	// resume (D57) needs the intent details, not just the id
	pendingBody map[string]map[string]map[string]any
	// replaced/tombstoned accumulate across FULL history (D58): a later
	// binding-body overwrite must not hide an orphaned predecessor
	replaced   map[string]map[string]bool
	tombstoned map[string]map[string]bool
	// lastGen remembers the generation each (capability, providerId) held
	// when last bound (D71) — a deposed-delete plan pins the orphan's
	// real generation from history, never a guess. Keyed by capability
	// too (F7): the same providerId under two capabilities must not share
	// a generation.
	lastGen map[string]map[string]int
	// EventHashes records the hash of every committed event in order —
	// position-addressed identity for the anchor check (D70). After a
	// snapshot (D137) it holds only the TAIL; BaseEvents/BaseHead keep
	// positions absolute so anchors keep meaning what they always meant.
	EventHashes []string
	BaseEvents  int
	BaseHead    string
	// ledgerId (D134): genesis hash — from line 1, or carried by the
	// snapshot when the genesis line lives in the archive.
	ledgerId string
	// verifiedFrom (D137): the --trust-from boundary the snapshot's
	// rotation replay honored, per its verifiedUnder receipt.
	verifiedFrom string
	// snapshotHash (D137): identity of the fold this replay seeded
	// from — anchors cut at a compaction pin it (review fix).
	snapshotHash string
}

// LedgerId reports the identity (D134): the genesis event's hash —
// recorded from line 1 during replay, or seeded by a snapshot.
func (l *Ledger) LedgerId() string {
	if l.ledgerId != "" {
		return l.ledgerId
	}
	if l.BaseEvents == 0 && len(l.EventHashes) > 0 {
		return l.EventHashes[0]
	}
	return ""
}

// TotalEvents is the absolute event count including the compacted base.
func (l *Ledger) TotalEvents() int { return l.BaseEvents + len(l.EventHashes) }

// headAtTip: the absolute last event hash — tail's last, or the
// snapshot's baseHead when the tail is still empty.
func (l *Ledger) headAtTip() string {
	if n := len(l.EventHashes); n > 0 {
		return l.EventHashes[n-1]
	}
	if l.BaseEvents > 0 {
		return l.BaseHead
	}
	return "genesis"
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

type ObsRecord struct {
	Value      any
	ObservedAt string
	TTLSeconds int
	Derivation string
	Source     string
}

type Result struct {
	Status string // ok | conflict | rejected
	Reason string
	Token  int    // set for successful lease.acquired
	Hash   string // event hash when Status == ok
}

func New() *Ledger {
	return &Ledger{
		Heads:                map[string]string{},
		DecisionHeads:        map[string]string{},
		Bindings:             map[string]map[string]any{},
		Observations:         map[string]map[string]ObsRecord{},
		Outputs:              map[string]map[string]ObsRecord{},
		ObservationsBySource: map[string]map[string]map[string]ObsRecord{},
		Environments:         map[string]string{},
		leases:               map[string]*lease{},
		maxToken:             map[string]int{},
		pending:              map[string]map[string]bool{},
	}
}

// canonEmpty canonicalizes the lazily-initialized projections: an
// empty map and an absent one are the SAME claim, and replay must
// produce one in-memory form for both — otherwise the D137 equivalence
// (full fold vs snapshot+tail) drowns real drift in nil-vs-empty noise.
// Found by the snapshot fuzz, not by inspection.
func (l *Ledger) canonEmpty() {
	if len(l.ViolationState) == 0 {
		l.ViolationState = nil
	}
	if len(l.pendingBody) == 0 {
		l.pendingBody = nil
	}
	if len(l.replaced) == 0 {
		l.replaced = nil
	}
	if len(l.tombstoned) == 0 {
		l.tombstoned = nil
	}
	if len(l.lastGen) == 0 {
		l.lastGen = nil
	}
	if len(l.claimed) == 0 {
		l.claimed = nil
	}
	if len(l.observed) == 0 {
		l.observed = nil
	}
}

// BoundProviderIDs projects capability -> providerId from binding bodies.
func (l *Ledger) BoundProviderIDs() map[string]string {
	out := map[string]string{}
	for cap, body := range l.Bindings {
		resources, _ := body["resources"].([]any)
		for _, r := range resources {
			m, _ := r.(map[string]any)
			if pid, _ := m["providerId"].(string); pid != "" {
				out[cap] = pid
				break
			}
		}
	}
	return out
}

// AdoptedCapabilities projects capability -> was taken over by adopt (D52):
// its binding resource carries origin "adopted". These are the bindings the
// claim step (ownership.claimed) applies to; a created resource is authored
// from birth and needs no claim.
func (l *Ledger) AdoptedCapabilities() map[string]bool {
	out := map[string]bool{}
	for cap, body := range l.Bindings {
		resources, _ := body["resources"].([]any)
		for _, r := range resources {
			m, _ := r.(map[string]any)
			if o, _ := m["origin"].(string); o == "adopted" {
				out[cap] = true
				break
			}
		}
	}
	return out
}

// ClaimedCapabilities projects capability -> groundhold has claimed authorship
// (ownership.claimed recorded). The compiler emits no further claim once true.
func (l *Ledger) ClaimedCapabilities() map[string]bool {
	out := map[string]bool{}
	for cap := range l.claimed {
		out[cap] = true
	}
	return out
}

// ReadFailure is what the last failed READ of a capability said, and when it was
// attempted. It is knowledge that measurement failed — never an observation, and
// never a value (D59, D242).
type ReadFailure struct {
	Reason      string
	AttemptedAt string
}

// ReadFailures projects capability -> the most recent observation.failed. The
// compiler reads it to tell a reading that merely AGED from one whose refresh is
// failing: "re-observe first" is sound advice for the first and a loop for the
// second, and only the ledger knows which one this is.
func (l *Ledger) ReadFailures() map[string]ReadFailure {
	out := map[string]ReadFailure{}
	for cap, f := range l.readFailures {
		out[cap] = f
	}
	return out
}

// ObservedCapabilities projects capability -> observe was RECORDED for it, even
// with zero observable attributes. The compiler reads this to tell "never
// observed" (re-observe recovers) from "observed but blind" (isolate, do not
// freeze) when a bound capability has no observation for a declared attribute.
func (l *Ledger) ObservedCapabilities() map[string]bool {
	out := map[string]bool{}
	for cap := range l.observed {
		out[cap] = true
	}
	return out
}

func (l *Ledger) activeLease(cap string) *lease {
	le := l.leases[cap]
	if le != nil && !le.ended && l.Clock < le.expiry {
		return le
	}
	return nil
}

// ActiveToken returns the fencing token of the active lease on a
// capability, or 0.
func (l *Ledger) ActiveToken(cap string) int {
	if le := l.activeLease(cap); le != nil {
		return le.token
	}
	return 0
}

// BoundGenerations projects capability -> current resource generation.
func (l *Ledger) BoundGenerations() map[string]int {
	out := map[string]int{}
	for cap, body := range l.Bindings {
		resources, _ := body["resources"].([]any)
		for _, r := range resources {
			m, _ := r.(map[string]any)
			if g, ok := m["generation"].(int); ok {
				out[cap] = g
				break
			}
		}
	}
	return out
}

// BoundProviderNames projects capability -> provider name from binding
// bodies (retirement plans read identity from here, not from candidates).
func (l *Ledger) BoundProviderNames() map[string]string {
	out := map[string]string{}
	for cap, body := range l.Bindings {
		if p, ok := body["provider"].(map[string]any); ok {
			if n, _ := p["name"].(string); n != "" {
				out[cap] = n
			}
		}
	}
	return out
}

// BoundServices (D76): capability -> service token, parsed from the binding's
// resource type ("gcp.cloudsql/db" -> "cloudsql"). Retire/observe/probe
// dispatch on it when the candidate carries no extras.
func (l *Ledger) BoundServices() map[string]string {
	out := map[string]string{}
	for cap, body := range l.Bindings {
		res, _ := body["resources"].([]any)
		if len(res) == 0 {
			continue
		}
		r0, _ := res[0].(map[string]any)
		t, _ := r0["type"].(string)
		dot := strings.IndexByte(t, '.')
		slash := strings.IndexByte(t, '/')
		if dot >= 0 && slash > dot {
			out[cap] = t[dot+1 : slash]
		}
	}
	return out
}

// ObservationExpired is THE freshness predicate: at evaluation time T an
// observation is usable iff `observedAt + ttlSeconds >= T`, so it is expired iff
// its age EXCEEDS the ttl. spec/state-model.md states it in those words.
//
// D666: six places decided this and two of them used `>=` where the spec and the
// other four use `>`. `posture` and `refresh` therefore called a proof decayed one
// second before `audit`, `plan`, `apply` and `forecast` did — and `posture`'s own
// printed remediation chains exactly those three verbs, so the operator was told to
// refresh a proof the auditor still accepted, and posture kept reporting decayed
// after refresh had renewed nothing.
//
// An unreadable observedAt is EXPIRED, never fresh: a freshness decision must not
// be made against a clock nobody could read (N1).
func ObservationExpired(observedAt string, ttlSeconds, evalClock int) bool {
	obsClock, err := ParseTs(observedAt)
	if err != nil {
		return true
	}
	return evalClock-obsClock > ttlSeconds
}

// ObservationDecayInstant returns the clock at which an observation is LAST still
// fresh — the boundary ObservationExpired compares against. At the returned instant
// ObservationExpired is false; at instant+1 it is true. It is exposed so a caller that
// needs to know WHEN freshness ends (horizon projecting a future decay) reads the
// boundary from the same place the predicate does, instead of re-deriving obs+ttl and
// drifting from it (D666 — six copies of that arithmetic is the defect this prevents).
// ok is false when there is no ttl to decay from (ttlSeconds<=0) or observedAt cannot
// be read — the same clock a freshness decision must never be made against (N1).
func ObservationDecayInstant(observedAt string, ttlSeconds int) (instant int, ok bool) {
	if ttlSeconds <= 0 {
		return 0, false
	}
	obsClock, err := ParseTs(observedAt)
	if err != nil {
		return 0, false
	}
	return obsClock + ttlSeconds, true
}

// PendingCount returns the number of unresolved operation receipts on a
// capability (D29). `unknown` receipts stay pending — they are not
// terminal until explicitly adopted.
// PendingReceipts projects capability -> pending receipt bodies,
// sorted by operation id (D57).
func (l *Ledger) PendingReceipts() map[string][]map[string]any {
	out := map[string][]map[string]any{}
	for cap, ops := range l.pendingBody {
		if len(ops) == 0 {
			continue
		}
		ids := make([]string, 0, len(ops))
		for id := range ops {
			ids = append(ids, id)
		}
		sort.Strings(ids)
		for _, id := range ids {
			out[cap] = append(out[cap], ops[id])
		}
	}
	return out
}

func (l *Ledger) PendingCount(cap string) int {
	return len(l.pending[cap])
}

// Append validates the event, CAS-checks expectedHeads (nil = skip,
// absent key = must-be-genesis), applies the D29/D41 rules and commits.
// Semantic outcomes come back in Result; error means the event document
// itself is malformed.
func (l *Ledger) Append(doc map[string]any,
	expectedHeads map[string]string) (Result, error) {
	if _, err := state.ValidateEvent(doc); err != nil {
		return Result{}, err
	}
	ev, _ := doc["event"].(map[string]any)
	capsAny, _ := ev["capabilities"].([]any)
	caps := make([]string, 0, len(capsAny))
	for _, c := range capsAny {
		s, _ := c.(string)
		caps = append(caps, s)
	}

	// 1. CAS over full heads (D28)
	if expectedHeads != nil {
		for _, c := range caps {
			want, ok := expectedHeads[c]
			if !ok {
				want = "genesis"
			}
			cur, ok := l.Heads[c]
			if !ok {
				cur = "genesis"
			}
			if cur != want {
				return Result{Status: "conflict"}, nil
			}
		}
	}

	// 2. coordination clock (D56): NEW appends must not regress
	// occurredAt — a backdated write would rewind lease arithmetic and
	// resurrect expired fencing. Replay is lenient (existing history is
	// tolerated, never allowed to rewind runtime time). The clock
	// ADVANCES only after rules and hashing pass — a rejected or
	// unhashable event must not poison it (review fix).
	occurred, _ := ev["occurredAt"].(string)
	evClock, evClockErr := ParseTs(occurred)
	if evClockErr == nil && evClock < l.maxOccurred && !l.Lenient {
		return Result{Status: "rejected", Reason: fmt.Sprintf(
			"occurredAt %s regresses behind the ledger's %s — "+
				"writer clock skew; refuse, never rewind (D56)",
			occurred, FormatTs(l.maxOccurred))}, nil
	}

	// 3. rules (D29)
	rejected, token, commit := l.checkRules(ev, caps)
	if rejected != "" {
		return Result{Status: "rejected", Reason: rejected}, nil
	}

	// 4. hash BEFORE commit — an unhashable event mutates nothing
	h, err := canonical.HashEvent(doc)
	if err != nil {
		return Result{}, err
	}

	// 5. commit: rules passed, hash exists — state may now move
	commit()
	l.EventHashes = append(l.EventHashes, h)
	if evClockErr == nil && evClock > l.maxOccurred {
		l.maxOccurred = evClock
	}
	etype, _ := ev["type"].(string)
	for _, c := range caps {
		l.Heads[c] = h
		if etype != "observation.recorded" {
			if env, _ := ev["environment"].(string); env != "" {
				l.Environments[c] = env
			}
		}
		if DecisionTypes[etype] {
			l.DecisionHeads[c] = h
		}
		if etype == "binding.updated" {
			if body, ok := ev["body"].(map[string]any); ok {
				l.Bindings[c] = body
				l.accumulateLineage(c, body)
				// D192: releasing the binding (unadopt: empty resources)
				// voids any authorship claim — it was stamped on the resource
				// just released. Leaving claimed set would let a later re-adopt
				// of a DIFFERENT resource read Adopted && !Claimed == false, so
				// the compiler emits no claim and the new resource is bound but
				// never stamped (the D140 takeover hole, re-opened).
				if res, _ := body["resources"].([]any); len(res) == 0 {
					delete(l.claimed, c)
				}
			}
		}
		if etype == "observation.recorded" {
			l.projectObservations(c, ev)
			// mark the capability observed even when the body carried ZERO
			// observations (a readable-but-blind observer) — the signal the
			// compiler uses to isolate rather than freeze (re-observe won't help).
			if l.observed == nil {
				l.observed = map[string]bool{}
			}
			l.observed[c] = true
		}
		if etype == "observation.failed" {
			// LAST one wins: a later successful observe does NOT clear it, because
			// the compiler only consults this when a reading is already stale, and
			// a fresh reading never reaches that branch.
			body, _ := ev["body"].(map[string]any)
			reason, _ := body["reason"].(string)
			at, _ := body["attemptedAt"].(string)
			if l.readFailures == nil {
				l.readFailures = map[string]ReadFailure{}
			}
			l.readFailures[c] = ReadFailure{Reason: reason, AttemptedAt: at}
		}
		if etype == "ownership.claimed" {
			if l.claimed == nil {
				l.claimed = map[string]bool{}
			}
			l.claimed[c] = true
		}
		if etype == "violation.detected" || etype == "violation.resolved" {
			l.projectViolation(c, etype, ev)
		}
	}
	return Result{Status: "ok", Token: token, Hash: h}, nil
}

// accumulateLineage records every replaced and tombstoned identity
// ever mentioned (D58) — the deposed computation must survive later
// binding-body overwrites that drop the lineage block.
func (l *Ledger) accumulateLineage(cap string, body map[string]any) {
	// remember the generation every bound identity held (D71): when it
	// later turns up deposed, its delete plan pins recorded history
	if resources, ok := body["resources"].([]any); ok {
		for _, r := range resources {
			m, _ := r.(map[string]any)
			pid, _ := m["providerId"].(string)
			if g, ok := m["generation"].(int); ok && pid != "" && g >= 1 {
				if l.lastGen == nil {
					l.lastGen = map[string]map[string]int{}
				}
				if l.lastGen[cap] == nil {
					l.lastGen[cap] = map[string]int{}
				}
				l.lastGen[cap][pid] = g
			}
		}
	}
	lineage, _ := body["lineage"].(map[string]any)
	if lineage == nil {
		return
	}
	// decoupled lazy inits: after canonEmpty (D137) either map can be
	// nil independently — a coupled init here panicked on the first
	// lineage write when only one of them had been emptied (fuzz find)
	if l.replaced == nil {
		l.replaced = map[string]map[string]bool{}
	}
	if l.tombstoned == nil {
		l.tombstoned = map[string]map[string]bool{}
	}
	if reps, ok := lineage["replaces"].([]any); ok {
		for _, r := range reps {
			if id, _ := r.(string); id != "" {
				if l.replaced[cap] == nil {
					l.replaced[cap] = map[string]bool{}
				}
				l.replaced[cap][id] = true
			}
		}
	}
	if tombs, ok := lineage["tombstones"].([]any); ok {
		for _, t := range tombs {
			m, _ := t.(map[string]any)
			if id, _ := m["providerId"].(string); id != "" {
				if l.tombstoned[cap] == nil {
					l.tombstoned[cap] = map[string]bool{}
				}
				l.tombstoned[cap][id] = true
			}
		}
	}
}

// DeposedResource: a replaced identity with no tombstone — the old
// resource survived a failed create-before-destroy and is unbound but
// alive (D58). status pending-delete marks ids an in-flight delete
// already owns: resume's territory, not manual cleanup.
type DeposedResource struct {
	Capability string `json:"capability"`
	ProviderID string `json:"providerId"`
	Generation int    `json:"generation"` // last recorded while bound (D71)
	Status     string `json:"status"`     // deposed | pending-delete
}

func (l *Ledger) Deposed(includePending bool) []DeposedResource {
	// pending-delete targets are keyed per capability (F7): a pending op
	// on capability X must not suppress or re-label an orphan under Y.
	pendingTargets := map[string]map[string]bool{}
	for cap, ops := range l.pendingBody {
		for _, body := range ops {
			if id, _ := body["targetProviderId"].(string); id != "" {
				if pendingTargets[cap] == nil {
					pendingTargets[cap] = map[string]bool{}
				}
				pendingTargets[cap][id] = true
			}
		}
	}
	// an orphan is UNBOUND by definition (F2): a providerId that is the
	// current live binding of ANY capability — e.g. re-adopted after a
	// failed replacement, which resume explicitly recommends — must never
	// be reported as deposed, or plan --deposed would seal a delete of a
	// live resource.
	liveBound := map[string]bool{}
	for _, body := range l.Bindings {
		if resources, ok := body["resources"].([]any); ok {
			for _, r := range resources {
				if m, ok := r.(map[string]any); ok {
					if pid, _ := m["providerId"].(string); pid != "" {
						liveBound[pid] = true
					}
				}
			}
		}
	}
	caps := make([]string, 0, len(l.replaced))
	for c := range l.replaced {
		caps = append(caps, c)
	}
	sort.Strings(caps)
	var out []DeposedResource
	for _, c := range caps {
		ids := make([]string, 0, len(l.replaced[c]))
		for id := range l.replaced[c] {
			ids = append(ids, id)
		}
		sort.Strings(ids)
		for _, id := range ids {
			if l.tombstoned[c][id] || liveBound[id] {
				continue
			}
			gen := l.lastGen[c][id]
			if gen < 1 {
				gen = 1
			}
			switch {
			case pendingTargets[c][id] && includePending:
				out = append(out, DeposedResource{Capability: c,
					ProviderID: id, Generation: gen, Status: "pending-delete"})
			case !pendingTargets[c][id]:
				out = append(out, DeposedResource{Capability: c,
					ProviderID: id, Generation: gen, Status: "deposed"})
			}
		}
	}
	return out
}

// projectViolation tracks the RECORDED alarm state per (capability,
// constraint) — audit emits only on transitions (D54), so this
// projection is what "already alarmed" means.
func (l *Ledger) projectViolation(cap, etype string, ev map[string]any) {
	body, _ := ev["body"].(map[string]any)
	constraint, _ := body["constraint"].(string)
	if constraint == "" {
		return
	}
	if l.ViolationState == nil {
		l.ViolationState = map[string]string{}
	}
	key := cap + "\x00" + constraint
	if etype == "violation.resolved" {
		delete(l.ViolationState, key)
		return
	}
	verdict, _ := body["verdict"].(string)
	l.ViolationState[key] = verdict
}

// obsNewer compares observation recency NUMERICALLY — RFC3339 with a
// non-UTC offset string-compares wrong (review fix). On a tie,
// measured beats config-intent (D45).
//
// D667: at an equal clock with EQUAL derivations the incumbent used to win, so a
// re-observation recorded in the same second as the previous one was silently
// dropped from the projection. Reachable by construction and reproduced with the
// product: `converge` runs two observe phases under one `--at`, and any scheduler
// that pins a single `--at` per tick re-observes into the same second. The ledger
// then held the fresher reading — a different VALUE, or a shorter TTL — while every
// freshness and verdict decision used the older one.
//
// The ledger is an ordered log, so among equally-timestamped records of equal
// derivation the LATER LINE is the later fact. That is the same reading D656 gave
// two terminal events for one run.
func obsNewer(candidate, incumbent ObsRecord) bool {
	ct, cerr := ParseTs(candidate.ObservedAt)
	it, ierr := ParseTs(incumbent.ObservedAt)
	if cerr != nil || ierr != nil {
		return candidate.ObservedAt > incumbent.ObservedAt // last resort
	}
	if ct != it {
		return ct > it
	}
	if candidate.Derivation != incumbent.Derivation {
		// D45: a measurement outranks a declaration whatever the order.
		return candidate.Derivation == "measured"
	}
	return true // same instant, same basis: the later line is the later fact
}

func (l *Ledger) projectObservations(cap string, ev map[string]any) {
	body, _ := ev["body"].(map[string]any)
	list, _ := body["observations"].([]any)
	for _, it := range list {
		o, _ := it.(map[string]any)
		path, _ := o["path"].(string)
		if path == "" {
			continue
		}
		ttl, _ := o["ttlSeconds"].(int)
		rec := ObsRecord{
			Value:      o["value"],
			ObservedAt: str(o["observedAt"]),
			TTLSeconds: ttl,
			Derivation: str(o["derivation"]),
			Source:     str(o["source"]),
		}
		// D286: route the reserved WIRING namespace into its own projection.
		// A wiring record is an identity, not evidence about a constraint, so
		// it never enters Observations (nor the per-source evidence map the
		// audit method-gate reads).
		if name, isWiring := strings.CutPrefix(path, WiringPrefix); isWiring {
			if l.Outputs[cap] == nil {
				l.Outputs[cap] = map[string]ObsRecord{}
			}
			if prev, exists := l.Outputs[cap][name]; !exists || obsNewer(rec, prev) {
				l.Outputs[cap][name] = rec
			}
			continue
		}
		if l.Observations[cap] == nil {
			l.Observations[cap] = map[string]ObsRecord{}
		}
		prev, exists := l.Observations[cap][path]
		if !exists || obsNewer(rec, prev) {
			l.Observations[cap][path] = rec
		}
		// D191: retain the latest record PER SOURCE, so a probe measurement
		// survives a later provider-api observe. Newest-per-source wins.
		if l.ObservationsBySource[cap] == nil {
			l.ObservationsBySource[cap] = map[string]map[string]ObsRecord{}
		}
		if l.ObservationsBySource[cap][path] == nil {
			l.ObservationsBySource[cap][path] = map[string]ObsRecord{}
		}
		if bs, had := l.ObservationsBySource[cap][path][rec.Source]; !had || obsNewer(rec, bs) {
			l.ObservationsBySource[cap][path][rec.Source] = rec
		}
	}
}

func str(v any) string {
	s, _ := v.(string)
	return s
}

// checkRules returns (rejectionReason, token, commit).
func (l *Ledger) checkRules(ev map[string]any,
	caps []string) (string, int, func()) {
	etype, _ := ev["type"].(string)
	body, _ := ev["body"].(map[string]any)
	noop := func() {}

	switch {
	case etype == "lease.acquired":
		ttl, ok := body["ttlSeconds"].(int)
		if !ok || ttl <= 0 {
			return "lease.acquired requires body.ttlSeconds > 0", 0, noop
		}
		for _, c := range caps {
			if l.activeLease(c) != nil {
				return fmt.Sprintf("active lease exists on %s", c), 0, noop
			}
		}
		token := 0
		for _, c := range caps {
			if l.maxToken[c] > token {
				token = l.maxToken[c]
			}
		}
		token++
		return "", token, func() {
			l.leaseSeq++
			for _, c := range caps {
				l.leases[c] = &lease{token: token, expiry: l.Clock + ttl,
					ttl: ttl, ended: false, seq: l.leaseSeq}
				l.maxToken[c] = token
			}
		}

	case etype == "lease.released" || etype == "lease.renewed":
		tok, _ := ev["fencingToken"].(int)
		for _, c := range caps {
			le := l.activeLease(c)
			if le == nil || le.token != tok {
				return fmt.Sprintf(
					"no active lease with token %d on %s", tok, c), 0, noop
			}
		}
		return "", 0, func() {
			for _, c := range caps {
				if etype == "lease.released" {
					l.leases[c].ended = true
				} else {
					ttl := l.leases[c].ttl
					if t, ok := body["ttlSeconds"].(int); ok {
						ttl = t
					}
					l.leases[c].expiry = l.Clock + ttl
					l.leases[c].ttl = ttl
				}
			}
		}

	case etype == "lease.broken":
		adopt, _ := body["adoptReceipts"].(bool)
		for _, c := range caps {
			if len(l.pending[c]) > 0 && !adopt {
				return fmt.Sprintf(
					"pending operation receipts on %s — reconcile first (D29)",
					c), 0, noop
			}
		}
		return "", 0, func() {
			for _, c := range caps {
				if le := l.leases[c]; le != nil {
					le.ended = true
				}
				if adopt {
					l.pending[c] = map[string]bool{}
					delete(l.pendingBody, c) // phantom receipts must
					// not survive for resume/deposed (review fix)
				}
			}
		}

	case MutationTypes[etype]:
		tok, ok := ev["fencingToken"].(int)
		if !ok {
			return "mutation requires a fencing token (D29)", 0, noop
		}
		// D633: ONE lease must cover the whole affected set. Checking the token per
		// capability let a writer hold {a,b} and mutate {b,c} the moment an unrelated
		// worker acquired {c} and was handed the same token number.
		// D644: `covering := 0` was both the sentinel and a legal seq, so the
		// comparison was skipped for a seq-0 lease and the verdict depended on the
		// ORDER of the affected list. Seq 0 arrives from a pre-D633 snapshot, where
		// every seeded lease read back as 0 — the rule went vacuous for any ledger
		// an older binary had compacted.
		covering, haveCovering := 0, false
		for _, c := range caps {
			le := l.activeLease(c)
			if le == nil || le.token != tok {
				return fmt.Sprintf(
					"stale or missing fencing token on %s", c), 0, noop
			}
			if le.seqUnknown && len(caps) > 1 {
				return fmt.Sprintf(
					"%s is held by a lease restored from a snapshot that predates "+
						"lease identity, so nothing here can establish that ONE lease "+
						"covers this mutation — release and re-acquire the lease "+
						"before mutating more than one capability (D29)", c), 0, noop
			}
			if !haveCovering {
				covering, haveCovering = le.seq, true
			} else if le.seq != covering {
				return fmt.Sprintf(
					"the affected capabilities are held by DIFFERENT leases — %s is "+
						"under another lease that happens to carry the same token "+
						"number; one mutation must be covered by ONE lease (D29)",
					c), 0, noop
			}
		}
		return "", 0, noop

	case etype == "operation.receipt":
		op, _ := body["operationId"].(string)
		status, _ := body["status"].(string)
		if op == "" || !receiptStatuses[status] {
			return "receipt requires operationId and a valid status", 0, noop
		}
		return "", 0, func() {
			for _, c := range caps {
				switch {
				case ReceiptLeavesIntentPending(status):
					// unknown keeps the receipt pending AND refreshes
					// the stored body — the terminal-unknown receipt
					// carries providerOperation, which resume's
					// authority ladder needs after a restart
					if l.pending[c] == nil {
						l.pending[c] = map[string]bool{}
					}
					l.pending[c][op] = true
					if l.pendingBody == nil {
						l.pendingBody = map[string]map[string]map[string]any{}
					}
					if l.pendingBody[c] == nil {
						l.pendingBody[c] = map[string]map[string]any{}
					}
					l.pendingBody[c][op] = body
				default: // succeeded, failed, retryable
					// D241: retryable concludes the intent (throttled, did not
					// land) — clears pending so a re-apply is not blocked.
					delete(l.pending[c], op)
					delete(l.pendingBody[c], op)
				}
			}
		}
	}

	// contract.published, candidate.verified, plan.sealed,
	// observation.recorded, violation.detected: no extra rules
	return "", 0, noop
}

// WiringPrefix reserves the observation-path namespace for typed outputs
// (D226/D283/D286). A path under it is a WIRING fact — the identity a
// same-plan or cross-plan consumer references — routed to the Outputs
// projection and never counted as semantic knowledge of a capability. The
// vocabulary may not declare an attribute here (pinned by a vocab gate).
const WiringPrefix = "outputs."
