// Package audit evaluates a contract's constraints against RECORDED
// REALITY (D54): the latest ledger observations, not the candidate's
// declarations. Verify asks "does the proposal satisfy the contract";
// audit asks "does the world still". Verdicts keep the four-valued
// semantics (D2): no observation or a stale one is unknown, an
// incomparable pair is unverifiable — never a silent false. With
// --record, hard-constraint violations and unknowns append
// violation.detected knowledge events carrying everything an alert
// needs without re-reading the ledger.
package audit

import (
	"fmt"
	"groundhold/internal/perr"
	"sort"

	"groundhold/internal/contract"
	"groundhold/internal/ledger"
	"groundhold/internal/scalars"
	"groundhold/internal/verify"
	"groundhold/internal/vocab"
)

type Verdict struct {
	Constraint string `json:"constraint"`
	Capability string `json:"capability"`
	Path       string `json:"path"`
	Severity   string `json:"severity"`
	Verdict    string `json:"verdict"` // satisfied|violated|unknown|unverifiable
	Reason     string `json:"reason,omitempty"`
	Observed   any    `json:"observed,omitempty"`
	ObservedAt string `json:"observedAt,omitempty"`
	Derivation string `json:"derivation,omitempty"`
}

type Result struct {
	Status string `json:"status"` // clean | violations-found
	// Code (D624): `spec/errors.md` states the coverage rule — "every JSON-emitting
	// verb carries `code`" — and this report had none, so a caller was pushed back
	// to regexing prose the same document declares unparseable. The condition has a
	// published code; naming it is all that was missing.
	Code       perr.Code `json:"code,omitempty"`
	Verdicts   []Verdict `json:"verdicts"`
	Violations int       `json:"violations"` // hard: violated + unknown + unverifiable (all block, #1)
	// Events is always present: an empty list on a failing world SAYS
	// "already alarmed, nothing new" (D54 transitions)
	Events []string `json:"events"`
}

// Run audits every constraint with a subject and a comparable op.
// evalClock gates staleness exactly like the compiler does (D46).
func Run(c *contract.Contract, led *ledger.Ledger, ledgerPath, at string,
	record bool, vocabs map[string]vocab.Vocabulary) (*Result, error) {
	clock, err := ledger.ParseTs(at)
	if err != nil {
		return nil, fmt.Errorf("bad --at: %v", err)
	}
	res := &Result{Status: "clean", Verdicts: []Verdict{}, Events: []string{}}

	ordered := make([]contract.Constraint, len(c.Constraints))
	copy(ordered, c.Constraints)
	sort.Slice(ordered, func(i, j int) bool {
		return ordered[i].ID < ordered[j].ID
	})

	for _, cn := range ordered {
		isPresence := cn.Op == "exists" || cn.Op == "absent"
		if cn.Expected == nil && !isPresence {
			// Only the budget/objective forms (an Objective — no operand, not a
			// presence op) are out of audit scope; they are forced soft at load, so
			// they never block. D964: presence forms (exists/absent) carry no Expected
			// but ARE audit material.
			//
			// D1019: a SUBJECTLESS constraint is no longer skipped here. It used to be
			// dropped into a clean verdict — but `verify` BLOCKS it (unknown) and
			// `validate` counts it hard, so a hard constraint that verify refuses became
			// invisible at audit, the alerting surface (exit code + violation.detected
			// export). Now it flows through: latestSufficient finds no observation for
			// the empty subject and returns `unknown`, which blocks a hard constraint
			// exactly as verify does. audit never certifies `clean` over a constraint it
			// could not evaluate.
			continue
		}
		v := Verdict{Constraint: cn.ID, Capability: cn.Subject,
			Path: cn.Path, Severity: cn.Severity}
		// D190/D191: select the observation to judge against — the most-
		// recent NON-FUTURE per-source record whose source meets the
		// constraint's verify.method bar. This honors the author's evidence
		// bar (a probe-method OUTCOME cannot be judged by a provider-api
		// config read) AND retains a probe measurement that a later observe
		// would otherwise erase from the single-slot projection.
		rec, sel, reason := latestSufficient(
			led.ObservationsBySource[cn.Subject][cn.Path], cn.RuntimeMethod, clock)
		if sel != "" {
			v.Verdict, v.Reason = sel, reason
		} else {
			v.Observed = rec.Value
			v.ObservedAt = rec.ObservedAt
			v.Derivation = rec.Derivation
			obsClock, err := ledger.ParseTs(rec.ObservedAt)
			switch {
			case err != nil || clock-obsClock > rec.TTLSeconds:
				v.Verdict = "unknown"
				v.Reason = "observation is stale — re-observe first"
			default:
				if isPresence {
					// D964: a fresh sufficient observation means the attribute is
					// PRESENT — exists→satisfied, absent→violated. A missing or stale
					// observation cannot PROVE absence, so it stays unknown above and
					// blocks a hard constraint; audit never certifies absence it did
					// not see.
					if cn.Op == "exists" {
						v.Verdict = "satisfied"
						v.Reason = fmt.Sprintf("path %s is present", cn.Path)
					} else {
						v.Verdict = "violated"
						v.Reason = fmt.Sprintf(
							"path %s is present — the constraint requires it absent", cn.Path)
					}
					break
				}
				sc, perr := scalars.Parse(rec.Value)
				if perr != nil {
					v.Verdict = "unverifiable"
					v.Reason = "observation unparseable"
					break
				}
				// D660: a SET attribute (unordered:true) must compare order-
				// independently against recorded reality, exactly as verify does for
				// the candidate — canonicalize BOTH the observation and the operand,
				// or `not-equals` reports SATISFIED against the very forbidden set.
				lhs := verify.SortIfUnordered(sc, cn.Subject, cn.Path, c, vocabs)
				rhs := verify.SortIfUnordered(cn.Expected, cn.Subject, cn.Path, c, vocabs)
				okOp, cerr := scalars.Operators[cn.Op](lhs, rhs)
				if cerr != nil {
					v.Verdict = "unverifiable"
					v.Reason = "observation incomparable with the required value"
					break
				}
				if okOp {
					v.Verdict = "satisfied"
				} else {
					v.Verdict = "violated"
					v.Reason = fmt.Sprintf("reality %v fails %s %v",
						rec.Value, cn.Op, cn.Expected.Raw)
				}
			}
		}
		res.Verdicts = append(res.Verdicts, v)
		// the alerting bar: HARD constraints that are violated,
		// unknown OR UNVERIFIABLE — the non-negotiable is "unknown OR
		// unverifiable on a hard constraint blocks" (non-negotiable invariant #1), and
		// the banner already treats hard unverifiable as BLOCKED, so the
		// machine surface (exit + status) MUST agree or a currency-
		// mismatch silently escapes a cron that alerts on exit != 0
		// (review fix). soft is advisory. Ledger writes happen on
		// TRANSITIONS only (review verdict, D54).
		key := cn.Subject + "\x00" + cn.ID
		recorded := led.ViolationState[key]
		failing := cn.Severity == "hard" &&
			(v.Verdict == "violated" || v.Verdict == "unknown" ||
				v.Verdict == "unverifiable")
		if failing {
			res.Violations++
			if record && recorded != v.Verdict {
				if err := emit(led, ledgerPath, "violation.detected",
					c, cn, v, clock); err != nil {
					return nil, err
				}
				res.Events = append(res.Events, "violation.detected")
			}
		} else if record && recorded != "" && v.Verdict == "satisfied" {
			if err := emit(led, ledgerPath, "violation.resolved",
				c, cn, v, clock); err != nil {
				return nil, err
			}
			res.Events = append(res.Events, "violation.resolved")
		}
	}
	if res.Violations > 0 {
		res.Status = "violations-found"
		res.Code = auditCode(res.Verdicts)
	}
	return res, nil
}

// auditCode names WHY the audit is blocking, from the verdicts themselves (D624).
// An `unknown` verdict means the evidence is missing or stale — the operator's next
// step is `observe --record`, which is what observation-required publishes. Anything
// else that blocks is a constraint the world genuinely fails.
// HardOnly is the ONE place "which verdicts decide" is answered (D755). Run returns
// every constraint's verdict with its severity, and two callers had to know that soft is
// advisory: the exit code, which knew, and posture's class fold, which did not — so an
// advisory violation rendered as drift with the sentence "a hard constraint is violated",
// and an advisory PASS rendered as managed-ok, whose published meaning is that every hard
// verdict is satisfied. A set with two homes has no home (D311).
func HardOnly(vs []Verdict) []Verdict {
	out := make([]Verdict, 0, len(vs))
	for _, v := range vs {
		if v.Severity == "hard" {
			out = append(out, v)
		}
	}
	return out
}

func auditCode(vs []Verdict) perr.Code {
	blocking := false
	for _, v := range HardOnly(vs) {
		switch v.Verdict {
		case "unknown", "unverifiable":
			return perr.ObservationRequired
		case "violated":
			blocking = true
		}
	}
	if blocking {
		return perr.NotExecutable
	}
	return ""
}

// emit appends one violation.detected / violation.resolved — knowledge
// events (audit-chained, decision-neutral) whose bodies carry enough
// for an alert to act on without re-reading the ledger: constraint,
// severity, verdict, required op+value, observed value+time+derivation.
func emit(led *ledger.Ledger, path, etype string, c *contract.Contract,
	cn contract.Constraint, v Verdict, clock int) error {
	if clock > led.Clock {
		led.Clock = clock
	}
	w := &ledger.Writer{Path: path, Led: led, Env: c.Environment,
		Clock: clock, Actor: "groundhold-audit"}
	body := map[string]any{
		"constraint": cn.ID,
		"capability": cn.Subject,
		"path":       cn.Path,
		"severity":   cn.Severity,
		"verdict":    v.Verdict,
		"reason":     v.Reason,
		"required":   map[string]any{"op": cn.Op, "value": cn.Value},
		"contract":   map[string]any{"id": c.ID, "version": c.Version},
	}
	if v.Observed != nil {
		body["observed"] = map[string]any{
			"value": v.Observed, "observedAt": v.ObservedAt,
			"derivation": v.Derivation,
		}
	}
	return w.Append(etype, []string{cn.Subject}, body, 0)
}

// methodRank / sourceRank encode the D190 evidence lattice: a constraint's
// verify.method is the required evidence bar, an observation's source is the
// evidence gathered. Monotone — stronger evidence satisfies a weaker
// requirement. Gating is on SOURCE (machine-honest: set by observe/probe, not
// per-observation driver self-report), never on derivation.
//
//	probe (2)  >  provider-api (1)  >  anything else (0)
//
// method static ranks 0: any observation may audit it (compile-time verify
// stays authoritative for whether it is provable at all).
// latestSufficient selects the observation audit judges a constraint against
// (D190/D191): among the per-source records for a (capability, path), the
// most-recent NON-FUTURE one whose source meets the constraint's verify.method
// bar. It returns a terminal verdict+reason when no such record exists,
// distinguishing three cases — no observation at all, evidence too weak for the
// method (probe first), and a sufficient reading that is only future-dated
// (invalid, not fresh — the D189 time-travel guard).
func latestSufficient(bySource map[string]ledger.ObsRecord, method string,
	evalClock int) (ledger.ObsRecord, string, string) {
	if len(bySource) == 0 {
		return ledger.ObsRecord{}, "unknown", "no recorded observation"
	}
	need := methodRank(method)
	var best ledger.ObsRecord
	found, sufficient, future := false, false, false
	for src, r := range bySource {
		if evidenceRank(src, r.Derivation) < need {
			continue
		}
		sufficient = true
		if bt, err := ledger.ParseTs(r.ObservedAt); err == nil && bt > evalClock {
			future = true
			continue // a future reading did not exist at the evaluated instant
		}
		if !found || obsMoreRecent(r, best) {
			best, found = r, true
		}
	}
	switch {
	case !sufficient:
		return ledger.ObsRecord{}, "unknown", fmt.Sprintf(
			"evidence weaker than the required verify.method %q — probe first",
			method)
	case !found && future:
		return ledger.ObsRecord{}, "unverifiable",
			"observation is dated after the evaluation time — invalid, not fresh"
	case !found:
		return ledger.ObsRecord{}, "unknown", "no recorded observation"
	}
	return best, "", ""
}

func obsMoreRecent(a, b ledger.ObsRecord) bool {
	at, aerr := ledger.ParseTs(a.ObservedAt)
	bt, berr := ledger.ParseTs(b.ObservedAt)
	if aerr != nil || berr != nil {
		return a.ObservedAt > b.ObservedAt
	}
	return at > bt
}

func methodRank(method string) int {
	switch method {
	case "probe":
		return 2
	case "provider-api":
		return 1
	default: // static
		return 0
	}
}

func sourceRank(source string) int {
	switch source {
	case "probe":
		return 2
	case "provider-api":
		return 1
	default:
		return 0
	}
}

// evidenceRank is sourceRank corrected by what the reading actually WITNESSED (D722).
//
// The ladder used to key on source alone, so a provider-api read ranked 1 whether it
// measured the property or merely reported the setting the resource stores. That is
// the whole difference `Derivation` was introduced to record: `config-intent` means
// the resource HOLDS this value and does not itself enforce it. Measured in the field:
// `egress.restricted: true, derivation: config-intent` ruled a hard constraint
// SATISFIED on a network whose security groups allowed everything outbound — the tool
// carried the marker and threw it away at the one moment it decided anything.
//
// A config-intent reading is evidence at the STATIC bar and no higher: an author who
// wrote `verify: {method: static}` accepted the document's own word, and one who asked
// for provider-api or probe asked for something this reading is not. It does not
// become false — it becomes `unknown`, which on a hard constraint blocks, which is
// what the reporter asked for in preference to a sealed plan resting on a declaration.
// D759 puts `platform-invariant` at the same bar as config-intent, deliberately. It is
// tempting to rank a provider guarantee HIGH — it cannot be otherwise, after all — and
// the record says otherwise: D752, D753 and D754 were each an author asserting a
// platform guarantee that was not one ("GCP vaults are immutable by construction", "one
// write region is across zones", "every Fargate service is regional"). All three were
// wrong, and all three would have ranked at the provider-api bar under the generous
// reading. Nothing about THIS resource was read, so the static bar is what it earns; the
// new value buys honest PROVENANCE, not more trust.
func evidenceRank(source, derivation string) int {
	r := sourceRank(source)
	if (derivation == "config-intent" || derivation == "platform-invariant") && r > 0 {
		return 0
	}
	return r
}
