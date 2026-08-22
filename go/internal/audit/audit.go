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
	"strings"

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
		// Systemic cure for the false-secure class (D1003/D1040/D1041/D1069/D1070): a
		// SECURITY control must be WITNESSED, never accepted on the candidate's own word.
		// adopt fills a MISSING observation (a driver that emitted nothing for the
		// dangerous state) with the declared value at the `candidate-declared` source,
		// which ranks at the static bar — so a hard security constraint left at the
		// default `static` runtime bar was SATISFIED by that intent, certifying a control
		// the resource may lack. Raise the effective runtime bar for a hard security path
		// to provider-api, so declared intent (rank 0) is insufficient and blocks. A real
		// measured reading still satisfies/violates; only intent is refused. The floor is
		// keyed on a fail-closed Go namespace predicate (survives --no-vocab). It is still
		// a hand-maintained list, but no longer an unguarded one:
		// TestSecurityFloorCoversEverySecurityPostureAttr reads the whole vocabulary and
		// fails the build if a security-posture attribute is neither floored nor explicitly
		// waived — the forcing function that D1072/D1074/D1075 needed, because the list was
		// under-filled three times before it existed.
		method := cn.RuntimeMethod
		raised := false
		if cn.Severity == "hard" && isSecurityPath(cn.Path) && methodRank(method) < methodRank("provider-api") {
			method, raised = "provider-api", true
		}
		rec, sel, reason := latestSufficient(
			led.ObservationsBySource[cn.Subject][cn.Path], method, clock)
		if sel != "" && raised {
			// surface that audit enforced a HIGHER bar than the constraint declares, so
			// an operator reading `verify.method: static` is not surprised (Codex review).
			// The escape for a control genuinely unwitnessable on this provider is to
			// declare the constraint SOFT (advisory) — the floor bites hard constraints
			// only, and a soft one records the gap without blocking.
			reason += " (a hard security control must be witnessed, not taken on the " +
				"candidate's own word; declare it soft if it is genuinely unobservable here)"
		}
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

// securityNamespaces are the vocabulary paths whose value carries a SECURITY posture —
// one value is secure, the other dangerous. A hard constraint on such a path must be
// WITNESSED (provider-api or better), never satisfied by the candidate's own declared
// word (the D1003/D1040/D1071 false-secure). This Go predicate is the FAIL-CLOSED
// authority: it is present even under --no-vocab (a vocab-only marker would fail open,
// Codex review). It is HAND-MAINTAINED and pinned by TestIsSecurityPath. There is still
// no vocab `security:` marker and so no PARITY lint between a marker and this list —
// that was assessed low-value, because a per-path marker only syncs docs for paths
// already floored and cannot force a new namespace unless the author volunteers it.
//
// D1181: this paragraph used to end there, and it read as "nothing guards this list but
// vigilance". That describes the state before D1075. A KEYWORD lint does guard it —
// `TestSecurityFloorCoversEverySecurityPostureAttr`, named thirty lines below, which
// scans every vocabulary and FAILS THE BUILD on a security-posture attribute missing
// here. It found a dozen the hand-enumeration had missed, and D1076 widened it after
// two more dodged every keyword. Saying so here is not decoration: a maintainer reading
// the register learns from this comment whether adding an attribute is guarded, and the
// answer changed without the sentence changing.
//
// What the keyword lint cannot do is see a control whose NAME matches nothing — the
// caveat D1076 patched by hand, which is the shape that says the mechanism is wrong
// rather than incomplete. The stronger forcing function is an EXHAUSTIVE classification:
// require every vocabulary attribute to be either here or in an explicit not-a-security-
// posture list, so a new attribute cannot be added without a decision. Measured for
// feasibility rather than guessed: 145 unique attribute paths across the 57
// vocabularies, of which this list already classifies these. That is a one-time
// classification of about a hundred paths, and it overturns the assessment recorded
// above on DIFFERENT grounds (forced, not volunteered), so it is proposed rather than
// done here.
//
// So the discipline is: EVERY capability's security-posture attributes must be listed
// here, and an omission is a silently-reopened false-secure. The identity paths below were exactly such an omission,
// found by the D323/D325-class hunt — worst-case, because the identity capabilities are
// declared-ONLY (no observer driver), so a hard identity security constraint could ONLY
// ever be satisfied by intent, i.e. it was ALWAYS false-secure without this floor.
var securityNamespaces = []string{
	"encryption.",            // customerManagedKeys, atRest, inTransit
	"network.publicExposure", // public reachability
	"tls.",                   // tls.enforced / plaintext-refused
	"rotation.",              // rotation.enabled / rotation.period (key rotation)
	"retention.locked",       // WORM / compliance immutability
	"protection.level",       // HSM vs software key protection
	"deletion.protection",    // delete-guard on a stateful resource
	"access.privileged",      // over-privileged identity
	// identity.sso (D55) — declared-only, no observer:
	"sso.enforced",      // no local-password bypass
	"mfa.required",      // a second factor is required
	"assertions.signed", // SAML assertions are signed
	// identity.oauth-client (D55) — declared-only, no observer:
	"pkce.required",              // PKCE on the authorization-code flow
	"client.authentication",      // confidential vs `none` (public) client
	"redirects.exactMatch",       // redirect URIs matched exactly
	"redirects.wildcardsAllowed", // open-redirect surface
	"token.asymmetricSigning",    // asymmetric (not shared-secret) token signing
	"grants.implicit",            // the deprecated, token-leaking implicit grant
	"refreshToken.rotation",      // replay detection on refresh-token reuse (declared-only)
	// more security-posture paths a completeness sweep found the list omitted (D1072
	// proved the hand-list is gap-prone). Two are declared-only worst-cases:
	"sourceProvenance",    // compute.image: a signed build attestation (declared-only)
	"network.apiExposure", // cluster.kubernetes: a public API-server endpoint
	"authentication.dkim", // email.sending: the sending domain is DKIM-signed
	"retention.lockMode",  // backup.vault: WORM/compliance immutability of backups
	// D1075: the keyword lint (TestSecurityFloorCoversEverySecurityPostureAttr) found a
	// dozen more the hand-enumeration still missed — the whole reason the lint exists.
	"security.podSecurity",    // cluster.namespace: pod-security enforcement level
	"dnssec.enabled",          // dns.zone: DNSSEC signing of the zone
	"image.signedProvenance",  // workload.container: signed build provenance
	"ingress.public",          // network.private: a public ingress path
	"egress.internet",         // network.private: unrestricted egress to the internet
	"serviceAccess.private",   // network.private: private service endpoints
	"interconnect.private",    // network.private: private (non-internet) interconnect
	"access.mutating",         // authorization.role: a role that can mutate, not just read
	"role.permissions",        // authorization.role: the permission set (least-privilege crown)
	"immutable.tags",          // registry.image: tag immutability (supply-chain)
	"viewer.protocol",         // cdn.distribution: HTTPS-only vs plaintext viewer access
	"integrity.logValidation", // audit.trail: tamper-evident log-file validation
	// D1076: found by a self-review of the D1075 lint's own caveat — two security
	// controls whose names dodged every keyword, so the regex was widened to reach them.
	"key.exportable",      // identity.serviceaccount: a DOWNLOADABLE long-lived private key
	"audience.restricted", // identity.oauth-client: tokens carry an audience restriction
	// D1190: the keyword lint floored SOME members of a security block and not their
	// siblings, because it matches names and not concepts. Both cases are inside one
	// capability, which is what makes them worth listing rather than just adding:
	//
	//   authorization.grant   `access.privileged` was floored (the regex has "privileg")
	//                         while WHO the grant is for and WHICH role it carries were
	//                         not. So an audit witnessed "this grant is not privileged"
	//                         and took "the principal is a named user, not allUsers" on
	//                         the candidate's own word — the D1179 public-access shape,
	//                         one attribute over.
	//   identity.oauth-client `grants.implicit` was floored (the regex has "implicit
	//                         grant") and its two siblings in the same block were not.
	//
	// Listed as exact paths rather than a `grant.` prefix on purpose: a prefix would
	// floor a future sibling by default, which is the safer direction, but it would also
	// decide for whoever adds it. These five are each a posture in the floor's own terms
	// — one value is secure, the other dangerous — and a sixth deserves the same reading
	// rather than inheriting one.
	"grant.principal",          // authorization.grant: allUsers vs a named principal
	"grant.role",               // authorization.grant: owner vs viewer (least privilege)
	"access.scope",             // authorization.grant: how wide the grant reaches
	"grants.clientCredentials", // identity.oauth-client: machine-to-machine grant enabled
	"grants.authorizationCode", // identity.oauth-client: the code grant enabled
	// D1194: the same query that found D1190, asked of every capability rather than
	// the one that raised it — where does the floor cover part of a family and not the
	// rest? Seven more, each a sibling of something already floored, and none of them
	// on the reviewed-non-security waiver list, so none had been judged.
	//
	// The clearest is `trust.principals` — "WHO may assume this identity, and UNDER
	// WHAT CONDITION" — which is `grant.principal` (D1190) one capability over.
	//
	// One candidate is deliberately NOT here: `egress.restricted`. Its own description
	// calls it "DESTINATION DISCIPLINE (orthogonal to egress.internet)", naming the
	// floored sibling it stands beside, so on the family test it belongs. Flooring it
	// broke two tests that use it as their example of a NON-security static constraint
	// — one pinning that `config-intent` still satisfies a static bar, the other that
	// `platform-invariant` is honest provenance and not extra trust. Those fixtures
	// encode a decision: for a path whose enforcement IS the provider's configuration,
	// a config-intent reading may be the control itself rather than a weaker claim
	// about it. Flooring it says config-intent is never enough there, which is a
	// semantic call about egress evidence and not a gap to close while sweeping. It is
	// recorded in the entry and left to the owner, not resolved by editing the tests
	// that stand in the way — those tests are the argument, not the obstacle.
	"trust.principals",    // identity.serviceaccount: who may assume it, on what condition
	"security.scanOnPush", // registry.image: vulnerability scan at push (supply chain)
	"flowLogs.enabled",    // network.private: network flow logging for audit
	"cors.allowedOrigins", // storage.object: the browser origins granted cross-origin
	"scopes.granted",      // identity.oauth-client: the scopes this client may request
	"secret.maxAge",       // identity.oauth-client: enforced client-secret age bound
	// The last two have NO observer in any driver, so a hard constraint on them now
	// BLOCKS instead of passing on the candidate's word. Said out loud rather than
	// slipped in: that is the fail-closed answer and it is the precedent this list
	// already set with `grants.implicit`, which is equally unobserved and floored.
}

// isSecurityPath reports whether a constraint path names a security control that must be
// witnessed rather than accepted on declared intent.
func isSecurityPath(path string) bool {
	for _, ns := range securityNamespaces {
		if path == ns || strings.HasPrefix(path, ns+".") || (strings.HasSuffix(ns, ".") && strings.HasPrefix(path, ns)) {
			return true
		}
	}
	return false
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
