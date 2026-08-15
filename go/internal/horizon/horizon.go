// Package horizon is posture's future tense (D1099): posture answers "what
// is true NOW", horizon answers "WHEN does the tool's own answer change, and what
// to run before then". It is a DETERMINISTIC, read-only projection — no network, no
// ledger writes, no heuristics (invariant #6).
//
// The load-bearing decision: horizon does NOT re-derive the freshness/lease
// arithmetic (that is the D666 sibling-drift trap — six sites comparing one boundary
// disagreed by a second). Instead it collects the finite set of BREAKPOINTS at which
// a re-run of the real verbs could differ (an observation's ttl boundary, a lease's
// ttl boundary), re-runs `audit` and `status` AT each breakpoint (both pure functions
// of (ledger, clock)), and diffs consecutive evaluations. So horizon can never
// disagree with what audit/status will actually say at T — because at T it IS them.
//
// Honesty scope: it projects what blocks execution across the --within window — the
// tool's own VERDICTS changing as evidence and leases already in the ledger expire,
// PLUS anything already blocking at the instant the window opens (a --within gate that
// counted only future changes would go green over a block apply already refuses) —
// never new drift, new failures, or the world itself. Every deadline is CONDITIONAL on
// no intervention; the advised action is the one that falsifies the prediction, which
// is the product, not a caveat.
package horizon

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"

	"groundhold/internal/audit"
	"groundhold/internal/contract"
	"groundhold/internal/ledger"
	"groundhold/internal/perr"
	"groundhold/internal/runstatus"
	"groundhold/internal/vocab"
)

const (
	apiVersion       = "horizon/v0.1"
	projectsSentence = "what blocks execution across the --within window: this tool's own verdicts changing as ledger evidence and leases expire, plus anything already blocking at the instant the window opens — never new drift, new failures, or the state of the world itself"
	assumesSentence  = "no intervention and no new ledger events before each projected instant"
)

// blockingVerdict: a hard constraint in one of these states blocks execution (#1).
func blockingVerdict(v string) bool {
	return v == "unknown" || v == "unverifiable" || v == "violated"
}

type Advice struct {
	Action string   `json:"action"`
	Before string   `json:"before"`
	Steps  []string `json:"steps,omitempty"`
}

type Transition struct {
	At           string `json:"at"`
	FreshThrough string `json:"freshThrough,omitempty"`
	Kind         string `json:"kind"` // constraint-decay | lease-lapse | evidence-arrives
	Capability   string `json:"capability,omitempty"`
	Constraint   string `json:"constraint,omitempty"`
	Path         string `json:"path,omitempty"`
	Severity     string `json:"severity,omitempty"`
	Run          string `json:"run,omitempty"`
	From         string `json:"from"`
	To           string `json:"to"`
	Effect       string `json:"effect"`
	Advice       Advice `json:"advice"`
	blocking     bool   // not serialized: drives the gate (only a HARD block or needs-reconcile)
	sortKey      string
}

type Examined struct {
	Constraints       int  `json:"constraints"`
	BoundCapabilities int  `json:"boundCapabilities"`
	LiveRuns          int  `json:"liveRuns"`
	ContractsGiven    bool `json:"contractsGiven"`
}

type Summary struct {
	HardBlocking      int    `json:"hardBlocking"`
	Advisory          int    `json:"advisory"`
	FirstHardDeadline string `json:"firstHardDeadline,omitempty"`
}

type Document struct {
	APIVersion    string       `json:"apiVersion"`
	Kind          string       `json:"kind"`
	At            string       `json:"at"`
	WindowSeconds *int         `json:"windowSeconds,omitempty"`
	Horizon       string       `json:"horizon,omitempty"`
	Projects      string       `json:"projects"`
	Assumes       string       `json:"assumes"`
	Examined      Examined     `json:"examined"`
	Transitions   []Transition `json:"transitions"`
	Summary       Summary      `json:"summary"`
	Code          perr.Code    `json:"code,omitempty"`
	HorizonHash   string       `json:"horizonHash"`

	haveWindow bool
}

// ExitCode: a windowed run that found a HARD block or a needs-reconcile lapse inside
// the window is the cron's early warning (exit 2). Without a window horizon is a pure
// reporter (exit 0). Advisory-only transitions never gate — the HardOnly discipline
// (audit) extended forward. Decided once, here, testably (the D958/D1079 rule).
func (d *Document) ExitCode() int {
	if d.haveWindow && d.Summary.HardBlocking > 0 {
		return 2
	}
	return 0
}

// Project computes the horizon deterministically. contracts may be empty (then only
// lease-lapse is projected; examined.contractsGiven says so). window<0 means "open"
// (no upper bound); haveWindow gates the exit code.
func Project(led *ledger.Ledger, evs []runstatus.RunEvent, contracts []*contract.Contract,
	vocabs map[string]vocab.Vocabulary, atClock, window int, haveWindow bool) (*Document, error) {

	upper := atClock + window
	inWindow := func(t int) bool {
		return t > atClock && (!haveWindow || t <= upper)
	}

	// 1. collect breakpoints — the finite instants a re-evaluation could differ.
	bpSet := map[int]bool{}
	add := func(t int) {
		if inWindow(t) {
			bpSet[t] = true
		}
	}
	for _, paths := range led.ObservationsBySource {
		for _, sources := range paths {
			for _, rec := range sources {
				oc, err := ledger.ParseTs(rec.ObservedAt)
				if err != nil {
					continue // an unparseable time is audit's refusal, not a horizon event
				}
				// the decay boundary comes from ledger, never re-derived here (D666).
				if inst, ok := ledger.ObservationDecayInstant(rec.ObservedAt, rec.TTLSeconds); ok {
					add(inst)     // last fresh instant (freshThrough)
					add(inst + 1) // first expired instant — where audit will flip
				}
				if oc > atClock { // a future-dated record becomes eligible at its own stamp (D189)
					add(oc - 1)
					add(oc)
				}
			}
		}
	}
	for _, e := range evs {
		if e.Type == "lease.acquired" {
			if ttl := intOf(e.Body, "ttlSeconds"); ttl > 0 {
				add(e.Clock + ttl - 1) // last live instant
				add(e.Clock + ttl)     // first lapsed instant (runstatus.go:294)
			}
		}
	}
	bps := make([]int, 0, len(bpSet))
	for t := range bpSet {
		bps = append(bps, t)
	}
	sort.Ints(bps)

	// snap: re-run the REAL verbs at clock T (pure; record=false, ledgerPath="").
	snap := func(T int) (map[string]audit.Verdict, map[string]runstatus.State, error) {
		vs := map[string]audit.Verdict{}
		for ci, c := range contracts {
			ar, err := audit.Run(c, led, "", ledger.FormatTs(T), false, vocabs)
			if err != nil {
				return nil, nil, err
			}
			for _, v := range ar.Verdicts {
				vs[fmt.Sprintf("%d\x00%s", ci, v.Constraint)] = v
			}
		}
		rs := map[string]runstatus.State{}
		for _, r := range runstatus.ListRuns(evs, T, nil) {
			rs[r.Handle] = r.State
		}
		return vs, rs, nil
	}

	// 2. baseline at atClock, then evaluate each breakpoint and diff consecutive.
	baseV, baseR, err := snap(atClock)
	if err != nil {
		return nil, err
	}
	transitions := []Transition{} // never nil — marshals as [], schema wants an array

	// present blocks: a hard constraint ALREADY unknown/violated at atClock, or a run
	// ALREADY needs-reconcile. No CHANGE projects them — they predate the window — but
	// the window OPENS on them, so a --within gate that counted only future transitions
	// would exit 0 while apply/converge refuse RIGHT NOW (a false-secure gate, the
	// D1069 class). They are stamped at atClock, the head of the timeline, and they gate.
	for _, k := range sortedStrKeys(baseV) {
		if v := baseV[k]; v.Severity == "hard" && blockingVerdict(v.Verdict) {
			transitions = append(transitions, presentConstraintBlock(atClock, v))
		}
	}
	for _, h := range sortedStateKeys(baseR) {
		if baseR[h] == runstatus.StateNeedsReconcile {
			transitions = append(transitions, presentLeaseBlock(atClock, h))
		}
	}

	prevV, prevR := baseV, baseR
	for _, T := range bps {
		curV, curR, err := snap(T)
		if err != nil {
			return nil, err
		}
		for _, k := range sortedStrKeys(curV) {
			cur := curV[k]
			prev, ok := prevV[k]
			if !ok || prev.Verdict == cur.Verdict {
				continue
			}
			transitions = append(transitions, constraintTransition(T, prev, cur))
		}
		for _, h := range sortedStateKeys(curR) {
			cur := curR[h]
			prev, ok := prevR[h]
			if !ok || prev == cur {
				continue
			}
			if tr, ok := leaseTransition(T, h, prev, cur); ok {
				transitions = append(transitions, tr)
			}
		}
		prevV, prevR = curV, curR
	}

	sort.SliceStable(transitions, func(i, j int) bool {
		if transitions[i].At != transitions[j].At {
			return transitions[i].At < transitions[j].At
		}
		return transitions[i].sortKey < transitions[j].sortKey
	})

	// examined + summary (baseV/baseR are the atClock snapshot captured above)
	live := 0
	for _, r := range runstatus.ListRuns(evs, atClock, nil) {
		if r.Lease.Live {
			live++
		}
	}
	doc := &Document{
		APIVersion: apiVersion, Kind: "Horizon", At: ledger.FormatTs(atClock),
		Projects: projectsSentence, Assumes: assumesSentence,
		Examined: Examined{
			Constraints:       len(baseV),
			BoundCapabilities: len(led.Bindings),
			LiveRuns:          live,
			ContractsGiven:    len(contracts) > 0,
		},
		Transitions: transitions,
		haveWindow:  haveWindow,
	}
	if haveWindow {
		w := window
		doc.WindowSeconds = &w
		doc.Horizon = ledger.FormatTs(upper)
	}
	for _, t := range transitions {
		if t.blocking {
			doc.Summary.HardBlocking++
			if doc.Summary.FirstHardDeadline == "" {
				doc.Summary.FirstHardDeadline = t.At
			}
		} else {
			doc.Summary.Advisory++
		}
	}
	// The routing `code` is the errors.md contract (horizon-action-required = exit 2),
	// so it fires ONLY when the process actually gates. In reporter mode (no --within)
	// the summary still reports the projected hardBlocking count honestly, but a consumer
	// routing on `code` must never see a remediation contract the exit code contradicts.
	if doc.ExitCode() != 0 {
		doc.Code = perr.HorizonActionRequired
	}
	doc.HorizonHash = hashTransitions(transitions)
	return doc, nil
}

func constraintTransition(T int, prev, cur audit.Verdict) Transition {
	worsening := prev.Verdict == "satisfied" && cur.Verdict != "satisfied"
	improving := prev.Verdict != "satisfied" && cur.Verdict == "satisfied"
	kind := "constraint-decay"
	if improving {
		kind = "evidence-arrives"
	}
	hard := cur.Severity == "hard"
	blocking := worsening && hard && blockingVerdict(cur.Verdict)
	t := Transition{
		At: ledger.FormatTs(T), FreshThrough: ledger.FormatTs(T - 1), Kind: kind,
		Capability: cur.Capability, Constraint: cur.Constraint, Path: cur.Path,
		Severity: cur.Severity, From: prev.Verdict, To: cur.Verdict,
		blocking: blocking,
		sortKey:  "constraint\x00" + cur.Capability + "\x00" + cur.Constraint,
	}
	switch {
	case blocking:
		t.Effect = "audit blocks (observation-required); apply and converge refuse — " +
			"unknown/unverifiable on a hard constraint blocks, no flag bypasses it (#1)"
		t.Advice = Advice{Action: "refresh", Before: t.At, Steps: []string{
			"groundhold refresh --ledger <l> --provider <p> --at <ts>  (before the deadline)",
			"groundhold audit <contract> --ledger <l> --at <ts>",
		}}
	case improving:
		t.Effect = "a future-dated observation becomes eligible; audit unblocks — no action needed"
		t.Advice = Advice{Action: "none", Before: t.At}
	default:
		t.Effect = "a soft constraint's proof expires — advisory only, execution is not blocked"
		t.Advice = Advice{Action: "refresh", Before: t.At, Steps: []string{
			"groundhold refresh --ledger <l> --provider <p> --at <ts>  (optional; soft)",
		}}
	}
	return t
}

// leaseTransition emits only for a lease LAPSE (running -> stalled/needs-reconcile);
// other state changes (done/failed) come from fixed past terminal events, never a
// future lease-ttl boundary. Only needs-reconcile BLOCKS: a bare stalled lease
// auto-releases and enables the next writer (skeptic's correction), a needs-reconcile
// leaves a pending receipt unsettled that refuses the next apply until resume (D57).
func leaseTransition(T int, handle string, prev, cur runstatus.State) (Transition, bool) {
	if prev != runstatus.StateRunning {
		return Transition{}, false
	}
	if cur != runstatus.StateStalled && cur != runstatus.StateNeedsReconcile {
		return Transition{}, false
	}
	blocking := cur == runstatus.StateNeedsReconcile
	t := Transition{
		At: ledger.FormatTs(T), FreshThrough: ledger.FormatTs(T - 1), Kind: "lease-lapse",
		Run: handle, From: string(prev), To: string(cur),
		blocking: blocking,
		sortKey:  "lease\x00" + handle,
	}
	if blocking {
		t.Effect = "the writer's lease lapses with a receipt unsettled; the next run against " +
			"this ledger is refused until resume concludes it (D935)"
		t.Advice = Advice{Action: "wait", Before: t.At, Steps: []string{
			"groundhold wait " + handle + " --ledger <l>  (let it conclude before the deadline)",
			"if it has not concluded by then: groundhold resume <contract> --ledger <l> --provider <p> --at <ts>",
		}}
	} else {
		t.Effect = "the writer's lease lapses with no outcome and nothing pending — the lease " +
			"auto-releases and the next writer may proceed; the dead run needs no cleanup"
		t.Advice = Advice{Action: "none", Before: t.At}
	}
	return t, true
}

// presentConstraintBlock stamps a hard constraint ALREADY blocking at atClock as an
// already-blocking entry at the window's start. There is no freshThrough — the proof
// expired before the window opened — and the deadline is now. Without this, a --within
// gate would report exit 0 over a constraint apply/converge already refuse (false-secure).
func presentConstraintBlock(atClock int, v audit.Verdict) Transition {
	at := ledger.FormatTs(atClock)
	return Transition{
		At: at, Kind: "already-blocking",
		Capability: v.Capability, Constraint: v.Constraint, Path: v.Path,
		Severity: v.Severity, From: v.Verdict, To: v.Verdict, blocking: true,
		sortKey: "\x00present-constraint\x00" + v.Capability + "\x00" + v.Constraint,
		Effect: "audit ALREADY blocks: the proof is " + v.Verdict + " now, so apply and " +
			"converge refuse until it is renewed — this predates the window, not a future risk",
		Advice: Advice{Action: "refresh", Before: at, Steps: []string{
			"groundhold refresh --ledger <l> --provider <p> --at <ts>  (now)",
			"groundhold audit <contract> --ledger <l> --at <ts>",
		}},
	}
}

// presentLeaseBlock stamps a run ALREADY needs-reconcile at atClock — a lease that
// lapsed with a receipt unsettled before the window opened, which refuses the next
// apply now (D935). Symmetric to presentConstraintBlock on the run side.
func presentLeaseBlock(atClock int, handle string) Transition {
	at := ledger.FormatTs(atClock)
	nr := string(runstatus.StateNeedsReconcile)
	return Transition{
		At: at, Kind: "already-blocking", Run: handle, From: nr, To: nr, blocking: true,
		sortKey: "\x00present-lease\x00" + handle,
		Effect: "this run ALREADY needs reconcile (a lease lapsed with a receipt unsettled) — " +
			"the next apply against this ledger is refused now until resume concludes it (D935)",
		Advice: Advice{Action: "resume", Before: at, Steps: []string{
			"groundhold resume <contract> --ledger <l> --provider <p> --at <ts>  (now)",
		}},
	}
}

func hashTransitions(ts []Transition) string {
	var b strings.Builder
	for _, t := range ts {
		// identity of the projection: instant, kind, subject, direction — never prose.
		fmt.Fprintf(&b, "%s|%s|%s|%s|%s|%s\n", t.At, t.Kind, t.sortKey, t.From, t.To, t.FreshThrough)
	}
	sum := sha256.Sum256([]byte(b.String()))
	return "sha256:" + hex.EncodeToString(sum[:])
}

func intOf(m map[string]any, key string) int {
	switch v := m[key].(type) {
	case int:
		return v
	case float64:
		return int(v)
	}
	return 0
}

func sortedStrKeys(m map[string]audit.Verdict) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	return ks
}

func sortedStateKeys(m map[string]runstatus.State) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	return ks
}
