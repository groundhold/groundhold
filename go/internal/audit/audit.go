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
	"sort"

	"groundhold/internal/contract"
	"groundhold/internal/ledger"
	"groundhold/internal/scalars"
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
	Status     string    `json:"status"` // clean | violations-found
	Verdicts   []Verdict `json:"verdicts"`
	Violations int       `json:"violations"` // hard: violated + unknown + unverifiable (all block, #1)
	// Events is always present: an empty list on a failing world SAYS
	// "already alarmed, nothing new" (D54 transitions)
	Events []string `json:"events"`
}

// Run audits every constraint with a subject and a comparable op.
// evalClock gates staleness exactly like the compiler does (D46).
func Run(c *contract.Contract, led *ledger.Ledger, ledgerPath, at string,
	record bool) (*Result, error) {
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
		if cn.Subject == "" || cn.Expected == nil {
			continue // budget/presence forms are not audit material yet
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
			led.ObservationsBySource[cn.Subject][cn.Path], cn.VerifyMethod, clock)
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
				sc, perr := scalars.Parse(rec.Value)
				if perr != nil {
					v.Verdict = "unverifiable"
					v.Reason = "observation unparseable"
					break
				}
				okOp, cerr := scalars.Operators[cn.Op](sc, cn.Expected)
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
	}
	return res, nil
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
		if sourceRank(src) < need {
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
