// Package cloudfake is the reality-anchored test double at the heart of the Layer-2
// testing strategy (docs/TESTING_STRATEGY.md). A stateless fake hides state-machine
// bugs (the Aurora scratch-cluster leak passed a fake that returned 200 for every
// delete); a fake hand-written from our heads hides MODEL bugs (it can be as wrong as
// the driver). This package is built against both failures:
//
//   - It is a state machine, not a fixed response: a resource created "creating"
//     becomes "available" only after N READS, so a driver that concludes "ready" on
//     the first read is caught. Deletes are async the same way.
//   - It enforces cross-resource CONSTRAINTS (a cluster refuses deletion while a
//     member still exists — the exact Aurora rule AWS bit us with).
//   - Every behavior rule is PROVENANCE-TAGGED (Observed = backed by a recorded trace
//     or a vendor waiter/LRO definition; Assumed = a guess). A test that concludes only
//     through Assumed transitions is suspect, not green — the runtime's own
//     declared/inferred/assumed basis, applied to test doubles.
//   - It is the authoritative WORLD: it records every resource and state, so a test
//     asserts leak-freedom (LeakCheck) and (future) diffs against the ledger — the two
//     universal postconditions, with no per-test assertions.
//
// A per-cloud adapter renders World state into that cloud's wire protocol and routes
// mutations back through the World; the adapter must fail LOUD (500) on any operation
// the World does not model, so the fake can never silently pretend.
package cloudfake

import (
	"fmt"
	"sort"
	"sync"
)

// State is a resource's lifecycle state. The strings are cloud-agnostic; adapters map
// them to each cloud's vocabulary (available→"available"/"Ready"/"ACTIVE"/"Succeeded").
type State string

const (
	Absent    State = "absent"
	Creating  State = "creating"
	Available State = "available"
	Failed    State = "failed"
	Deleting  State = "deleting"
)

// Provenance records WHY a behavior rule exists — the anti-recursion tag.
type Provenance int

const (
	Observed Provenance = iota // backed by a recorded real trace or a vendor definition
	Assumed                    // a guess — a test that relies on it is flagged, not trusted
)

func (p Provenance) String() string {
	if p == Observed {
		return "observed"
	}
	return "assumed"
}

// Resource is one modelled resource in the fake's world.
type Resource struct {
	ID    string
	Type  string // adapter-defined kind, e.g. "cluster" / "instance" — used by constraints
	State State
	Tags  map[string]string

	// settle is how many more Describes until an in-flight transition completes
	// (Creating→Available, Deleting→Absent). settle<0 means NEVER settles — the
	// adversarial "stuck provisioning / stuck deleting" case. Set it per test seed.
	settle int
	// prov of the transition currently in flight (Observed unless a test injects Assumed).
	prov Provenance
}

// Terminal reports whether the resource has reached a state that needs no cleanup.
func (r *Resource) Terminal() bool { return r.State == Absent || r.State == Failed }

// Constraint refuses a mutation the real API would refuse. reason=="" means allowed.
type Constraint struct {
	Name string
	Prov Provenance
	// Blocks reports why a delete of `id` must be refused (e.g. a member still exists),
	// or "" to allow it.
	Blocks func(w *World, id string) string
}

// Mutation is one wire mutation the World actually served — the ground truth for the
// ledger-vs-world diff. Op is "create" or "delete".
type Mutation struct {
	Op string
	ID string
}

// World is the fake's authoritative, concurrency-safe store.
type World struct {
	mu          sync.Mutex
	res         map[string]*Resource
	constraints []Constraint
	settleAfter int // default reads-until-settle for newly created/deleted resources

	usedAssumed map[string]bool // provenance audit: which Assumed rules were exercised
	mutations   []Mutation      // every create/delete the wire actually performed
}

// New makes an empty world. settleAfter is the default number of Describes before a
// Creating resource becomes Available (and a Deleting one becomes Absent). Choose it
// adversarially across seeds — including 0 (immediate) and a "never" via SetStuck — so
// a driver that happens to poll a fixed number of times is not accidentally satisfied.
func New(settleAfter int) *World {
	return &World{res: map[string]*Resource{}, settleAfter: settleAfter, usedAssumed: map[string]bool{}}
}

// AddConstraint registers a cross-resource rule (e.g. cluster-refuses-delete-while-member).
func (w *World) AddConstraint(c Constraint) { w.constraints = append(w.constraints, c) }

// Seed places a resource directly in a state (test setup — the pre-existing world).
func (w *World) Seed(r *Resource) {
	w.mu.Lock()
	defer w.mu.Unlock()
	cp := *r
	w.res[r.ID] = &cp
}

// Create records a new resource entering Creating (async) with the world's default
// settle budget, or Available immediately when settleAfter==0.
func (w *World) Create(id, typ string, tags map[string]string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	st := Creating
	if w.settleAfter == 0 {
		st = Available
	}
	w.res[id] = &Resource{ID: id, Type: typ, State: st, Tags: cloneTags(tags), settle: w.settleAfter, prov: Observed}
	w.mutations = append(w.mutations, Mutation{Op: "create", ID: id})
}

// SetStuck forces a resource to never leave its current in-flight state (adversarial
// "never ready" / "never deletes"), tagged with the given provenance.
func (w *World) SetStuck(id string, prov Provenance) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if r := w.res[id]; r != nil {
		r.settle = -1
		r.prov = prov
	}
}

// Fail forces a resource into the terminal Failed state (a create/restore that errored).
func (w *World) Fail(id string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if r := w.res[id]; r != nil {
		r.State = Failed
		r.settle = 0
	}
}

// Describe is READ-DRIVEN: each call advances an in-flight transition one tick, so a
// resource is Available only after settle reads. found=false means Absent (a clean
// "does not exist"). It records the provenance actually traversed.
func (w *World) Describe(id string) (state State, tags map[string]string, found bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	r := w.res[id]
	if r == nil || r.State == Absent {
		return Absent, nil, false
	}
	if r.settle > 0 {
		r.settle--
		if r.settle == 0 {
			switch r.State {
			case Creating:
				r.State = Available
			case Deleting:
				r.State = Absent
			}
			if r.prov == Assumed {
				w.usedAssumed["transition:"+id] = true
			}
		}
	}
	if r.State == Absent {
		return Absent, nil, false
	}
	return r.State, cloneTags(r.Tags), true
}

// Delete requests deletion. It is refused (error) if any constraint blocks it — the
// caller (adapter) renders that as the cloud's conflict error, exactly as a real API
// would, so a driver that deletes a parent before its child is caught. Otherwise the
// resource enters Deleting (async) and settles to Absent over reads.
func (w *World) Delete(id string) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	r := w.res[id]
	if r == nil || r.State == Absent {
		return nil // idempotent
	}
	for _, c := range w.constraints {
		if reason := c.Blocks(w, id); reason != "" {
			if c.Prov == Assumed {
				w.usedAssumed["constraint:"+c.Name] = true
			}
			return fmt.Errorf("%s: %s", c.Name, reason)
		}
	}
	r.State = Deleting
	r.settle = w.settleAfter
	if r.settle == 0 {
		r.State = Absent
	}
	w.mutations = append(w.mutations, Mutation{Op: "delete", ID: id})
	return nil
}

// ChildPresent reports whether any resource of the given type whose ID has the given
// prefix (and is not the parent itself) is still present — the generic "parent has a
// child" constraint. It is called from inside a Constraint.Blocks predicate, which
// runs under the World lock, so it does not re-lock.
func (w *World) ChildPresent(parentID, childType string) bool {
	for _, r := range w.res {
		if r.ID != parentID && r.Type == childType && r.State != Absent && hasPrefix(r.ID, parentID) {
			return true
		}
	}
	return false
}

// TypeOf returns the modelled type of a resource ("" if absent). For constraint
// predicates to scope themselves to the kind they guard. Called under the World lock.
func (w *World) TypeOf(id string) string {
	if r := w.res[id]; r != nil {
		return r.Type
	}
	return ""
}

// LeakCheck is the universal postcondition: it returns every resource matching the
// ownership predicate that is LIVE AND UNDELETED — Available or Creating. A resource in
// Deleting has had its delete accepted and will drain (not a leak); Absent/Failed are
// terminal. A leak is a billed resource that will PERSIST because no delete was
// successfully issued — exactly the Aurora case, where the cluster delete was REFUSED
// (constraint) so the cluster stayed Available. The fake IS the leak detector, so that
// class is caught generically with no per-test assertion.
func (w *World) LeakCheck(ours func(tags map[string]string) bool) []string {
	w.mu.Lock()
	defer w.mu.Unlock()
	var leaked []string
	for id, r := range w.res {
		if r.State != Available && r.State != Creating {
			continue // Deleting (delete issued, draining) / Absent / Failed are not leaks
		}
		if ours(r.Tags) {
			leaked = append(leaked, id+" ("+string(r.State)+")")
		}
	}
	sort.Strings(leaked)
	return leaked
}

// Mutations returns every create/delete the wire actually performed, in order — the
// ground truth for the ledger-vs-world diff.
func (w *World) Mutations() []Mutation {
	w.mu.Lock()
	defer w.mu.Unlock()
	out := make([]Mutation, len(w.mutations))
	copy(out, w.mutations)
	return out
}

// CreatedIDs returns the ids the wire actually created (deduped, sorted).
func (w *World) CreatedIDs() []string {
	w.mu.Lock()
	defer w.mu.Unlock()
	seen := map[string]bool{}
	var out []string
	for _, m := range w.mutations {
		if m.Op == "create" && !seen[m.ID] {
			seen[m.ID] = true
			out = append(out, m.ID)
		}
	}
	sort.Strings(out)
	return out
}

// LedgerWorldDiff is the second universal postcondition (ledger–wire consistency,
// invariant 7). `created` is what the wire ACTUALLY created (World.CreatedIDs); the
// caller extracts `receipts` — the resource ids the LEDGER recorded a binding for — in
// the SAME key space (strip the providerId scheme). It returns:
//
//   - phantomReceipts: a receipt whose resource was never created on the wire — the
//     D62 phantom-receipt bug (the ledger asserts a resource that does not exist).
//   - unrecorded: a wire mutation with no receipt — an orphan the ledger cannot resume
//     or clean up.
//
// A clean run returns two empty slices. A test asserts that on every apply.
func LedgerWorldDiff(created, receipts []string) (phantomReceipts, unrecorded []string) {
	cset, rset := map[string]bool{}, map[string]bool{}
	for _, c := range created {
		cset[c] = true
	}
	for _, r := range receipts {
		rset[r] = true
	}
	for r := range rset {
		if !cset[r] {
			phantomReceipts = append(phantomReceipts, r)
		}
	}
	for c := range cset {
		if !rset[c] {
			unrecorded = append(unrecorded, c)
		}
	}
	sort.Strings(phantomReceipts)
	sort.Strings(unrecorded)
	return phantomReceipts, unrecorded
}

// UsedAssumed reports which Assumed-provenance rules a test actually relied on. A test
// whose GREEN result depended on an Assumed rule is not trustworthy evidence — surface
// it, do not silently pass.
func (w *World) UsedAssumed() []string {
	w.mu.Lock()
	defer w.mu.Unlock()
	var out []string
	for k := range w.usedAssumed {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func cloneTags(t map[string]string) map[string]string {
	if t == nil {
		return nil
	}
	c := make(map[string]string, len(t))
	for k, v := range t {
		c[k] = v
	}
	return c
}

func hasPrefix(s, p string) bool { return len(s) >= len(p) && s[:len(p)] == p }
