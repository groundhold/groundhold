// Package apply implements executor v0 (D42, spec/executor.md).
//
// Refuse-before-mutate: preconditions (re-verified from the pinned
// documents), read-set hash checks, decision-heads CAS (D41), the v0
// effect-model limit and pending-receipt reconciliation are ALL checked
// before the first mutation. Execution follows write-ahead discipline:
// an operation.receipt(pending) lands in the ledger BEFORE the provider
// call, the terminal receipt after — a resumed run finds its intent.
// Every apply-scoped event carries applyRunId; the run id derives from
// (planHash, evaluationTime), so a retry of the same logical run is
// recognizable.
//
// The rules are internal/ledger — the same code the conformance
// scenarios pin (D37). Nothing here reads wall time.
package apply

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"time"

	"groundhold/internal/canonical"
	"groundhold/internal/contract"
	"groundhold/internal/ledger"
	"groundhold/internal/perr"
	"groundhold/internal/policy"
	"groundhold/internal/progress"
	"groundhold/internal/provider"
	"groundhold/internal/verify"
	"groundhold/internal/vocab"
)

type Result struct {
	Status  string    `json:"status"`         // applied|refused|failed|corrupted
	Code    perr.Code `json:"code,omitempty"` // spec/errors.md (D64)
	RunID   string    `json:"runId,omitempty"`
	Reasons []string  `json:"reasons,omitempty"`
	// RetryAfterSeconds (D243): the provider's Retry-After hint on a throttle
	// (provider-again-later), when a driver captured it — converge honors it as
	// the backoff delay. 0 = no hint.
	RetryAfterSeconds int               `json:"retryAfterSeconds,omitempty"`
	Events            []string          `json:"events"`
	Bindings          map[string]string `json:"bindings,omitempty"`
	// Outputs (Layer 1 reachability) surfaces each succeeded create's declared
	// typed outputs, keyed capability -> output name -> value. It is a
	// projection of the create results already computed for the terminal
	// receipts — NOT a new provider read — so the apply VERB can derive a
	// public-edge URL (domainName/functionUrl, D316) for the post-apply
	// reachability probe WITHOUT the deterministic executor doing any network.
	Outputs map[string]map[string]any `json:"outputs,omitempty"`
	// Outcomes (Part A) is the per-action outcome for a fail-isolated run
	// (succeeded|failed|unknown|throttled|skipped), keyed by action id. Present
	// only when at least one action did not succeed — a clean run stays quiet.
	Outcomes  map[string]string `json:"outcomes,omitempty"`
	Preflight *PreflightResult  `json:"preflight,omitempty"` // D75
	// Reachability (Layer 1) is the four-valued post-apply edge verdict, set by
	// the apply VERB (never the executor): reachable | denied | unknown | skipped
	// (or "" when there is no public edge). A machine field so a script can tell
	// "up and serving" from "up but the edge 403s".
	Reachability string `json:"reachability,omitempty"`
	Exit         int    `json:"-"`
	// D230: raw structured facts a refusal SITE uniquely knows, so main can
	// build an advisory `next` WITHOUT the engine importing perrnext (advisory
	// stays out of the execution path). Not serialized — the permissions are
	// already in Reasons; these carry the machine shape.
	Denied     []string `json:"-"` // provider-permission-denied: the exact denied set
	Capability string   `json:"-"` // consent-required: the stateful capability
}

// PreflightResult (D75, D78) surfaces the permission preflight on a SUCCESSFUL
// apply — passed (with the checked set), inconclusive (the provider check could
// not attest some permissions; the apply itself remains the authorization
// oracle), or skipped (with why). A preflight REFUSAL (authoritative denial, or
// inconclusive under --require-preflight) returns a refused Result carrying the
// code instead.
type PreflightResult struct {
	Status     string   `json:"status"` // passed | inconclusive | skipped
	Checked    []string `json:"checked,omitempty"`
	Unattested []string `json:"unattested,omitempty"`
	Reason     string   `json:"reason,omitempty"`
}

// serviceOf parses the SERVICE token from a plan action target
// "provider.service/capability" (e.g. "gcp.cloudsql/app-db" -> "cloudsql").
// "unbound/cap" or a malformed target yields "" — which the driver's
// dispatch refuses, never defaults (D76).
func serviceOf(target string) string {
	dot := strings.IndexByte(target, '.')
	slash := strings.IndexByte(target, '/')
	if dot < 0 || slash < 0 || slash < dot {
		return ""
	}
	return target[dot+1 : slash]
}

// requiredUnion is the deduped, sorted union of the permissions every action
// needs: the executor's OWN current derivation, per-service (D76) and
// attribute-aware (D75) — never trust ONLY the plan's self-declared list, a
// stale sealing driver could understate it — unioned with each action's
// declared requiredPermissions.
func requiredUnion(actions []any, providerName string, c *contract.Contract,
	cand *contract.Candidate, vocabs map[string]vocab.Vocabulary) []string {
	set := map[string]bool{}
	for _, it := range actions {
		a, _ := it.(map[string]any)
		op, _ := a["operation"].(string)
		target, _ := a["target"].(string)
		capID, _ := a["capability"].(string)
		for _, p := range provider.PermissionsFor(providerName, serviceOf(target), op, attributesRaw(c, cand, vocabs, capID)) {
			set[p] = true
		}
		decl, _ := a["requiredPermissions"].([]any)
		for _, d := range decl {
			if s, ok := d.(string); ok {
				set[s] = true
			}
		}
	}
	out := make([]string, 0, len(set))
	for p := range set {
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}

// actionPerms is one action's required permissions: the executor's own
// derivation (per-service, attribute-aware) unioned with the action's declared
// set — the same rule requiredUnion applies, per action rather than flattened.
func actionPerms(a map[string]any, providerName string, c *contract.Contract,
	cand *contract.Candidate, vocabs map[string]vocab.Vocabulary) []string {
	op, _ := a["operation"].(string)
	target, _ := a["target"].(string)
	capID, _ := a["capability"].(string)
	set := map[string]bool{}
	for _, p := range provider.PermissionsFor(providerName, serviceOf(target), op, attributesRaw(c, cand, vocabs, capID)) {
		set[p] = true
	}
	decl, _ := a["requiredPermissions"].([]any)
	for _, d := range decl {
		if s, ok := d.(string); ok {
			set[s] = true
		}
	}
	out := make([]string, 0, len(set))
	for p := range set {
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}

// scopedPreflight checks each action's permissions at the RIGHT scope (D80):
// an action on an existing resource (a pinned targetProviderId — update/delete/
// deposed) against that resource's own AUTHORITATIVE testIamPermissions; a
// create (no providerId) and any no-resource-surface service against the
// project surface (D78 classification: attested omission = denied, else
// unattested). A resource check that cannot read the surface (missing resource,
// network) yields unattested, NEVER denied. Returns the authoritative denials,
// the unattested set, and a fatal error only if the PROJECT check could not run.
func scopedPreflight(pf provider.Preflighter, prov provider.Provider,
	project string, actions []any, providerName string, c *contract.Contract,
	cand *contract.Candidate, vocabs map[string]vocab.Vocabulary) (denied, unattested []string, err error) {

	rpf, hasRPF := prov.(provider.ResourcePreflighter)
	projectSet := map[string]bool{}
	type grp struct {
		service, providerID string
		perms               map[string]bool
	}
	groups := map[string]*grp{}

	for _, it := range actions {
		a, _ := it.(map[string]any)
		perms := actionPerms(a, providerName, c, cand, vocabs)
		if len(perms) == 0 {
			continue
		}
		pid, _ := a["targetProviderId"].(string)
		target, _ := a["target"].(string)
		if pid != "" && hasRPF {
			g := groups[pid]
			if g == nil {
				g = &grp{service: serviceOf(target), providerID: pid, perms: map[string]bool{}}
				groups[pid] = g
			}
			for _, p := range perms {
				g.perms[p] = true
			}
		} else {
			for _, p := range perms {
				projectSet[p] = true
			}
		}
	}

	deniedSet, unattSet := map[string]bool{}, map[string]bool{}
	for _, g := range groups {
		d, u, rerr := rpf.CheckResourcePermissions(g.service, g.providerID, sortedKeys(g.perms))
		switch {
		case errors.Is(rerr, provider.ErrNoResourceSurface):
			for p := range g.perms { // no per-resource surface: use the project check
				projectSet[p] = true
			}
		case rerr != nil:
			for p := range g.perms { // surface unreadable: inconclusive, never denied
				unattSet[p] = true
			}
		default:
			for _, p := range d { // AUTHORITATIVE resource-level denial
				deniedSet[p] = true
			}
			for _, p := range u { // D720: the provider could not stand behind these
				unattSet[p] = true
			}
		}
	}
	if len(projectSet) > 0 {
		d, u, perr := pf.CheckPermissions(project, sortedKeys(projectSet))
		if perr != nil {
			return nil, nil, perr
		}
		for _, p := range d {
			deniedSet[p] = true
		}
		for _, p := range u {
			unattSet[p] = true
		}
	}
	return sortedKeys(deniedSet), sortedKeys(unattSet), nil
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func refused(code perr.Code, exit int, reasons ...string) *Result {
	return &Result{Status: "refused", Code: code, Reasons: reasons,
		Events: []string{}, Exit: exit}
}

func corrupted(reason string) *Result {
	return &Result{Status: "corrupted", Code: perr.LedgerCorrupted,
		Reasons: []string{reason}, Events: []string{}, Exit: 5}
}

// Option configures optional apply behaviour without churning the signature
// (existing callers stay unchanged). Progress (D227) is the first use.
type Option func(*config)

type config struct {
	progMode progress.Mode
	progOut  io.Writer
	nowMS    func() int64 // monotonic runtime clock for progress elapsed
}

// WithProgress enables the ephemeral progress stream (D227). out defaults to
// stderr; nowMS defaults to the wall clock (injected in tests for determinism).
// It CANNOT touch the evaluation clock (N1) or the ledger — progress is a
// projection, never a source of truth.
func WithProgress(mode progress.Mode, out io.Writer, nowMS func() int64) Option {
	return func(c *config) {
		c.progMode = mode
		if out != nil {
			c.progOut = out
		}
		if nowMS != nil {
			c.nowMS = nowMS
		}
	}
}

func wallMS() int64 { return time.Now().UnixMilli() }

func runIDFrom(planHash, at string) string {
	sum := sha256.Sum256([]byte(planHash + "|" + at))
	return hex.EncodeToString(sum[:])[:12]
}

// RunID computes the apply run handle for a plan + clock WITHOUT running — the
// detach launcher (D229) needs the handle before it forks the child, and it must
// be byte-identical to what the child writes (applyRunId). Both inputs are known
// at invocation, so the handle exists before the fork; it cryptographically
// embeds the explicit --at, so a handle cannot exist for a defaulted clock.
func RunID(planDoc map[string]any, at string) (string, error) {
	planHash, err := canonical.HashPlan(planDoc)
	if err != nil {
		return "", err
	}
	return runIDFrom(planHash, at), nil
}

func Apply(c *contract.Contract, cand *contract.Candidate,
	vocabs map[string]vocab.Vocabulary, planDoc map[string]any,
	ledgerPath string, prov provider.Provider, at string,
	requirePreflight bool, opts ...Option) *Result {

	cfg := config{progMode: progress.ModeNone, progOut: os.Stderr, nowMS: wallMS}
	for _, o := range opts {
		o(&cfg)
	}

	p, _ := planDoc["plan"].(map[string]any)
	reads, _ := p["reads"].(map[string]any)
	env, _ := p["environment"].(string)

	// ---- replay: reconstruct state through the SAME rules (D42) ----
	led, err := ledger.ReplayFile(ledgerPath)
	if err != nil {
		return corrupted(err.Error())
	}
	// tail tamper-evidence on the execution path (review): if the
	// operator armed an anchor, a truncated/rewritten tail refuses here,
	// before any provider call
	if err := ledger.EnforceAnchor(ledgerPath, led); err != nil {
		return corrupted(err.Error())
	}

	// ---- refuse-before-mutate preflight ----
	report, verr := verify.Verify(c, cand, vocabs)
	if verr != nil {
		return refused(perr.NotExecutable, 2, verr.Error())
	}

	// read-set identity first: verdicts about other documents are noise
	contractHash, candidateHash := report.ContractHash, report.CandidateHash
	if h, _ := reads["contractHash"].(string); h != contractHash {
		return refused(perr.ReadSetMismatch, 2, "contract does not match the plan's read-set")
	}
	if h, _ := reads["candidateHash"].(string); h != candidateHash {
		return refused(perr.ReadSetMismatch, 2, "candidate does not match the plan's read-set")
	}

	// D325: invariant 1 is UNCONDITIONAL. It used to be enforced only when the
	// plan happened to carry a report-executable precondition — so a hand-authored
	// plan opted out of the project's first rule ("unknown or unverifiable on a
	// hard constraint blocks execution — no exceptions, no flags to bypass it")
	// simply by omitting one line. apply already re-verifies the candidate and
	// holds the report; it must act on it whether or not the plan asks.
	//
	// This is the same discipline D47/D48 state for the autonomy and replacement
	// gates: "a hand-authored plan must not bypass compiler policy". Invariant 1
	// was the one gate that still took its instructions from the plan.
	if !report.Executable {
		return refused(perr.NotExecutable, 2, append([]string{
			"candidate is not executable against the contract (invariant 1 is " +
				"unconditional — a plan cannot opt out of it)"},
			report.BlockingReasons...)...)
	}
	preAny, _ := p["preconditions"].([]any)
	sawExecutable := false
	for _, it := range preAny {
		pc, _ := it.(map[string]any)
		switch t, _ := pc["type"].(string); t {
		case "report-executable":
			sawExecutable = true
			if !report.Executable {
				return refused(perr.NotExecutable, 2, append([]string{
					"precondition report-executable failed"},
					report.BlockingReasons...)...)
			}
		case "no-assumed-basis":
			if report.Summary.VerdictsOnAssumedValues > 0 {
				return refused(perr.NotExecutable, 2, "precondition no-assumed-basis failed")
			}
		case "no-assumed-hard-basis":
			// D195: the D5 gate made reachable — a HARD constraint may not
			// seal on an ASSUMED candidate value (a guess). hard violated/
			// unknown/unverifiable already blocked via report-executable, so
			// the only bite here is satisfied-hard-on-assumed. inferred stays
			// reportable (assumed-only); soft-assumed is advisory (hard-only).
			var offenders []string
			for _, v := range report.Verdicts {
				if v.Severity != "hard" || v.Basis == nil || *v.Basis != "assumed" {
					continue
				}
				if v.Verdict == "satisfied" || v.Verdict == "violated" {
					offenders = append(offenders, v.Constraint)
				}
			}
			if len(offenders) > 0 {
				return refused(perr.NotExecutable, 2, append([]string{
					"precondition no-assumed-hard-basis failed: hard " +
						"constraint(s) rest on an assumed value, not proven " +
						"reality — probe/observe to prove them (D59)"},
					offenders...)...)
			}
		default:
			// fail-closed: a precondition we cannot evaluate refuses
			return refused(perr.UnsupportedOperation, 2, fmt.Sprintf(
				"precondition %s is not evaluable in executor v0", t))
		}
	}
	// D325: the compiler makes report-executable MANDATORY (D195), so a plan
	// without it was not produced by this compiler. The check above already
	// enforces the invariant, but a plan missing the line is a plan whose
	// provenance is wrong — refuse it rather than silently accept a shape the
	// compiler never emits.
	if !sawExecutable {
		return refused(perr.NotExecutable, 2,
			"the plan carries no report-executable precondition — every compiled "+
				"plan declares it (D195); a plan without it was not sealed by this "+
				"compiler and is refused rather than executed on trust")
	}

	writes := writeSet(p)
	bound := led.BoundProviderIDs()
	actions, _ := p["actions"].([]any)
	for _, it := range actions {
		a, _ := it.(map[string]any)
		capID, _ := a["capability"].(string)
		// D959: the plan's field-reclaim consent (D699) is RE-DERIVED from the pinned
		// contract here, not trusted from the plan's bool. Sealing it defeats granting the
		// consent AFTER a plan is sealed, but a hand-authored or stale plan can still assert
		// fieldReclaim=true for a capability the contract never scoped — force-taking fields
		// another manager owns. Re-check on the same unconditional-gate principle as the
		// delete/replace consents above.
		if reclaim, _ := a["fieldReclaim"].(bool); reclaim && !policy.AllowsFieldReclaim(c, capID) {
			r := refused(perr.ConsentRequired, 2, fmt.Sprintf(
				"action %v reclaims fields on %s (force over another manager) without "+
					"autonomy.allow_field_reclaim consent", a["id"], capID))
			r.Capability = capID // D230
			return r
		}
		// D1034/D1037: the emission-adopt grant is re-derived from the pinned contract AND
		// candidate at apply — BOTH halves, not just the consent. apply anchors only the
		// contract and candidate hashes (above), never the plan's action set, so a
		// hand-authored plan can assert emissionAdopt=true with a LITERAL foreign
		// log_group and cross the ownership-tag gate onto a group it never emitted
		// (D1037, found by audit). So:
		//   - CONSENT: the live contract must scope allow_emission_adopt to this cap.
		//   - PROVENANCE: the pinned candidate's log_group must be a $ref to a certified
		//     emission (mirror mintEmissionAdopt) — the forgeable plan folds are NOT
		//     trusted. A literal group, or a $ref to a non-emission output, refuses.
		// This is the D959 discipline applied to the half that PICKS THE TARGET, which for
		// emission-adopt (unlike fieldReclaim's owned-resource fields) is a foreign group.
		if adopt, _ := a["emissionAdopt"].(bool); adopt {
			if !policy.AllowsEmissionAdopt(c, capID) {
				r := refused(perr.ConsentRequired, 2, fmt.Sprintf(
					"action %v adopts a provider-created log group on %s without "+
						"autonomy.allow_emission_adopt consent", a["id"], capID))
				r.Capability = capID // D230
				return r
			}
			if !emissionAdoptProvenanceOK(cand, prov, capID) {
				r := refused(perr.ConsentRequired, 2, fmt.Sprintf(
					"action %v asserts emissionAdopt on %s but its log_group is not a $ref "+
						"to a certified emission — refusing to adopt a group whose "+
						"provenance the pinned candidate does not carry", a["id"], capID))
				r.Capability = capID // D230
				return r
			}
		}
		switch op, _ := a["operation"].(string); op {
		case "create":
			// D76: the service comes from the SEALED plan target, cross-
			// checked against the candidate — a hand-edited plan must not
			// re-route a database candidate into the Cloud Run builder.
			target, _ := a["target"].(string)
			svc := serviceOf(target)
			if cs := candidateService(cand, capID); cs != "" && cs != svc {
				return refused(perr.ProviderRefused, 2, fmt.Sprintf(
					"action %v target service %q disagrees with candidate "+
						"service %q", a["id"], svc, cs))
			}
			// D43: the driver's refuse-before-mutate hook — an attribute
			// the driver cannot honor refuses here, never by silent drop.
			// D275: an action consuming intra-plan references (D226) cannot
			// validate up front — its operand values do not exist until the
			// producer runs. Its Validate is deferred to resolution time
			// (still before ITS write-ahead intent and driver call); no
			// placeholder is ever passed, because a made-up operand would
			// make Validate's answer a lie.
			// D283: compile-FOLDED operands are literals already — they
			// substitute here, so a fold-only consumer validates up front
			// like any other action.
			if len(actionRefs(a)) == 0 {
				if err := prov.Validate(svc, capID, env, attributesRaw(c, cand, vocabs, capID),
					foldedImplementation(a, cand, capID),
					actionGeneration(a)); err != nil {
					return refused(perr.ProviderRefused, 2, fmt.Sprintf(
						"provider cannot honor action %v: %v", a["id"], err))
				}
			}
			// D48: a replacement (create+delete of the same capability)
			// of a stateful capability needs explicit contract consent —
			// checked here too, so a hand-authored plan cannot bypass it
			if planDeletes(actions, capID) &&
				policy.StatefulOf(c, capID, vocabs) &&
				!policy.AllowsReplaceStateful(c, capID) {
				r := refused(perr.ConsentRequired, 2, fmt.Sprintf(
					"action %v replaces stateful %s without "+
						"autonomy.allow_replace_stateful consent", a["id"], capID))
				r.Capability = capID // D230: main builds the allow_replace_stateful edit
				return r
			}
		case "delete":
			// D47: autonomy is an UNCONDITIONAL executor gate — a
			// hand-authored plan must not bypass compiler policy
			if policy.ForbidsDeleteStateful(c) && policy.StatefulOf(c, capID, vocabs) {
				return refused(perr.ConsentRequired, 2, fmt.Sprintf(
					"action %v deletes stateful %s and the pinned contract "+
						"forbids delete_stateful", a["id"], capID))
			}
			// D959: deleting a protection: capability switches a security CONTROL off
			// (GuardDuty/WAF/SCC/Defender). The compiler refuses this without
			// autonomy.allow_protection_lift (D698) — re-check here on the SAME
			// unconditional-gate principle, so a hand-authored or stale plan cannot lift a
			// control the pinned contract never consented to lift. A protection cap is
			// stateful:false, so the delete_stateful gate above never catches it; without
			// this the D698 consent lived only at compile.
			if policy.ProtectionOf(c, capID, vocabs) && !policy.AllowsProtectionLift(c, capID) {
				r := refused(perr.ConsentRequired, 2, fmt.Sprintf(
					"action %v deletes protection %s (its delete removes a control, not a "+
						"resource) without autonomy.allow_protection_lift consent", a["id"], capID))
				r.Capability = capID // D230: main builds the allow_protection_lift edit
				return r
			}
			// D1038: refuse a delete the compiler never emits. It deletes a capability only
			// on RETIRE (the contract declares it `state: retired`), as the destroy half of
			// a REPLACE (paired with a create for the same cap), or as a deposed-orphan
			// cleanup (ledger-validated below). A hand-authored plan asserting a bare delete
			// of a capability the pinned contract declares LIVE (not retired), with no create
			// replacing it, would destroy a live resource on the plan's word — the D959
			// threat model, at the operation itself. The `state` read is from the hash-pinned
			// contract, so it cannot be forged without changing contractHash; the paired
			// create, if forged to dodge this, makes it a REPLACE gated by the stateful
			// consent above.
			if raw, stillDeclared := c.Capabilities[capID]; stillDeclared {
				state, _ := raw["state"].(string)
				dep, _ := a["deposed"].(bool)
				if state != "retired" && !dep && !planCreates(actions, capID) {
					r := refused(perr.NotExecutable, 2, fmt.Sprintf(
						"action %v deletes %s, which the contract declares live (not retired) "+
							"and no create in this plan replaces — a non-retire, non-replace delete "+
							"is not a plan this compiler seals; refusing to destroy a live resource "+
							"on the plan's word", a["id"], capID))
					r.Capability = capID // D230
					return r
				}
			}
			pinnedID, _ := a["targetProviderId"].(string)
			pinnedGen, _ := a["targetGeneration"].(int)
			if dep, _ := a["deposed"].(bool); dep {
				// D71: an orphan's capability is bound to its SUCCESSOR,
				// so the pin validates against the deposed projection —
				// and consent mirrors replacement (D48), checked now
				if policy.StatefulOf(c, capID, vocabs) &&
					!policy.AllowsReplaceStateful(c, capID) {
					r := refused(perr.ConsentRequired, 2, fmt.Sprintf(
						"action %v deletes deposed stateful %s without "+
							"autonomy.allow_replace_stateful consent",
						a["id"], capID))
					r.Capability = capID // D230
					return r
				}
				if !isDeposed(led, capID, pinnedID, pinnedGen) {
					return refused(perr.StaleDecision, 3, fmt.Sprintf(
						"action %v pinned deposed %s gen %d of %s but the "+
							"ledger no longer records it as deposed — "+
							"re-plan", a["id"], pinnedID, pinnedGen, capID))
				}
				break
			}
			// the pinned identity must match the CURRENT binding — a
			// rebind between seal and apply must not redirect a delete
			if bound[capID] == "" {
				return refused(perr.StaleDecision, 3, fmt.Sprintf(
					"action %v deletes %s, which has no binding", a["id"], capID))
			}
			curGen := led.BoundGenerations()[capID]
			if bound[capID] != pinnedID || curGen != pinnedGen {
				return refused(perr.StaleDecision, 3, fmt.Sprintf(
					"action %v pinned %s gen %d but the binding is %s gen %d "+
						"— re-observe and re-seal", a["id"], pinnedID,
					pinnedGen, bound[capID], curGen))
			}
		case "update":
			if bound[capID] == "" {
				return refused(perr.StaleDecision, 3, fmt.Sprintf(
					"action %v updates %s, which has no binding", a["id"], capID))
			}
			// D46: every change must be honorable in place — preflight
			for _, path := range changePaths(a) {
				pv := cand.Capabilities[capID][path]
				var desired any
				if pv.Scalar != nil {
					desired = pv.Scalar.Raw
				}
				class, note := prov.ClassifyChange(serviceOf(asStr(a["target"])), path, nil, desired,
					implementationOf(cand, capID))
				if class != "mutable" && class != "caveated" {
					return refused(perr.ProviderRefused, 2, fmt.Sprintf(
						"action %v: %s cannot be honored in place: %s",
						a["id"], path, note))
				}
			}
		case "claim":
			// D52 takeover: stamp authorship on an adopted resource. It must
			// still be bound, and the driver must be able to take ownership.
			if bound[capID] == "" {
				return refused(perr.StaleDecision, 3, fmt.Sprintf(
					"action %v claims %s, which has no binding", a["id"], capID))
			}
			if _, ok := prov.(provider.Claimer); !ok {
				return refused(perr.UnsupportedOperation, 2, fmt.Sprintf(
					"action %v is a claim but provider %s cannot take ownership",
					a["id"], prov.Name()))
			}
		default:
			return refused(perr.UnsupportedOperation, 2, fmt.Sprintf(
				"executor supports create, update, delete and claim, action %v is %v",
				a["id"], a["operation"]))
		}
	}

	for _, cap := range writes {
		if led.PendingCount(cap) > 0 {
			return refused(perr.ReconcileRequired, 3, fmt.Sprintf(
				"in-flight operations on %s must be reconciled first (D29)",
				cap))
		}
	}

	// decision-heads CAS, pre-lease (D41)
	if reason := staleReason(led, reads); reason != "" {
		// D619: the SAME condition was refused as stale-decision on the writer
		// path below; the documents are fine, the world moved.
		return refused(perr.StaleDecision, 3, reason)
	}

	// ---- evaluation clock (explicit, never wall time) ----
	evalClock, err := parseTs(at)
	if err != nil {
		return refused(perr.StructuralError, 1, fmt.Sprintf("bad evaluation time: %v", err))
	}
	if evalClock < led.Clock {
		return refused(perr.ClockRegress, 2, "evaluation time precedes ledger history")
	}
	led.Clock = evalClock

	// D283: a compile-folded operand is appliable only while its backing
	// "outputs.<name>" observation is still the OPERATIVE one (the ledger's
	// latest record carries the same value) and still FRESH at THIS --at — a
	// fold sealed fresh must not apply against a decayed or superseded
	// reading. Either way the remedy is re-observe + re-seal, the stale-plan
	// class (exit 3), checked pre-lease like the decision heads above.
	if reason := foldStaleReason(led, actions, evalClock); reason != "" {
		return refused(perr.StaleDecision, 3, reason)
	}
	if reason := changeStaleReason(led, actions, evalClock); reason != "" {
		return refused(perr.StaleDecision, 3, reason)
	}
	// D634: the vocabulary the plan was compiled against decides whether a delete is
	// forbidden by the contract's own autonomy block. `spec/sealed-plan.md` step 3
	// says apply re-checks the read-set's vocabulary versions; it never did — and the
	// pin was a version STRING, so an edited file with an untouched version changed
	// the meaning of the plan invisibly.
	if reason := vocabDriftReason(planDoc, vocabs); reason != "" {
		return refused(perr.ReadSetMismatch, 2, reason)
	}

	planHash, err := canonical.HashPlan(planDoc)
	if err != nil {
		return corrupted(err.Error())
	}
	runID := runIDFrom(planHash, at)

	res := &Result{Status: "applied", RunID: runID,
		Events: []string{}, Bindings: map[string]string{}}
	w := &writer{runID: runID, lw: ledger.Writer{
		Path: ledgerPath, Led: led, Env: env, Clock: evalClock,
		Actor: "groundhold-apply", Events: &res.Events}}

	// ---- permission preflight (D75): a live provider-permission check,
	// after every deterministic refusal, before the lease and before any
	// mutation. Best-effort fail-fast — a refusal is trustworthy, a pass is
	// evidence not proof (deny policies, IAM conditions, propagation lag,
	// org policy, VPC-SC and OAuth scope can diverge at call time). Never
	// held under the lease; not re-checked (permission truth is not CAS-able). ----
	provInfo, _ := reads["provider"].(map[string]any)
	provName, _ := provInfo["name"].(string)
	provProject, _ := provInfo["project"].(string)
	if needed := requiredUnion(actions, provName, c, cand, vocabs); len(needed) > 0 {
		if pf, ok := prov.(provider.Preflighter); ok {
			denied, unattested, cerr := scopedPreflight(pf, prov, provProject, actions, provName, c, cand, vocabs)
			switch {
			case cerr != nil:
				// the check could not run at all (API disabled, scope, network)
				return refused(perr.PreflightInconclusive, 2, fmt.Sprintf(
					"permission preflight could not run: %v", cerr))
			case len(denied) > 0:
				// AUTHORITATIVE negative only — the surface attests these absent
				sort.Strings(denied)
				r := refused(perr.ProviderPermissionDenied, 2, append(
					[]string{"the acting identity lacks required permissions"},
					denied...)...)
				r.Denied = denied // D230: main builds the grant `next`
				return r
			case len(unattested) > 0:
				// the provider could not ATTEST these (an allowlist omission) —
				// NOT a denial (D78). Fail-fast would be a lie; proceed and let
				// the mutation be the authorization oracle (receipts recover a
				// real mid-apply denial), unless the operator demanded certainty.
				sort.Strings(unattested)
				if requirePreflight {
					return refused(perr.PreflightInconclusive, 2, append(
						[]string{"the provider cannot attest these permissions " +
							"and --require-preflight is set"}, unattested...)...)
				}
				res.Preflight = &PreflightResult{Status: "inconclusive",
					Checked: needed, Unattested: unattested,
					Reason: "the provider permission check does not attest these " +
						"permissions (a non-authoritative omission, not a denial); " +
						"the apply itself is the authorization oracle"}
			default:
				res.Preflight = &PreflightResult{Status: "passed", Checked: needed}
			}
		} else if requirePreflight {
			return refused(perr.PreflightInconclusive, 2, fmt.Sprintf(
				"provider %s cannot preflight permissions and --require-preflight is set",
				prov.Name()))
		} else {
			res.Preflight = &PreflightResult{Status: "skipped",
				Reason: "provider " + prov.Name() + " cannot check permissions"}
		}
	}

	// ---- execution ----
	// D665: a plan with nothing to write has nothing to apply. This used to take the
	// empty set into appendLease, where the ledger's own document validator refused
	// ("event.capabilities must be a non-empty list of ids") — and that refusal was
	// reported as a LEASE CONFLICT, exit 3, with the validator's internal text in the
	// reasons. The published remediation for lease-conflict is "wait for expiry, or
	// break the lease deliberately"; there is no lease, so the operator waits for
	// nothing and every retry produces the same empty plan.
	//
	// Reachable from the documented quickstart with no credentials: a candidate
	// declaring an attribute the provider cannot witness converges once, and D249
	// then correctly isolates that attribute as unverifiable, so the second plan
	// carries no actions at all.
	if len(writes) == 0 {
		return refused(perr.NothingToChange, 2,
			"the sealed plan carries no actions — the world already matches the "+
				"candidate on everything this run can compare, so there is nothing "+
				"to apply")
	}
	tok, err := w.appendLease(writes)
	if err != nil {
		code := perr.LeaseConflict
		if strings.Contains(err.Error(), "regresses") {
			code = perr.ClockRegress
		}
		return refused(code, 3, err.Error())
	}
	// re-check freshness under the lease before declaring the apply (D42).
	// MUST read the FRESH post-lease ledger (w.lw.Led), not the entry-time
	// snapshot `led`: the whole point of this re-check is to catch a decision
	// head a concurrent executor moved during the preflight window (between the
	// pre-lease check and appendLease sits a live permission-preflight network
	// round-trip). Re-checking the stale `led` here is a no-op — the lost-update
	// guard the lease exists to provide (CAS-under-lease) would never fire.
	if reason := staleReason(w.lw.Led, reads); reason != "" {
		// trailing best-effort: nothing is appended after this within
		// the run, so a lost release cannot orphan a prev hash — the
		// lease simply expires by TTL in the file (D65)
		_ = w.append("lease.released", writes, nil, tok)
		return refused(perr.StaleDecision, 3, reason)
	}
	if err := w.append("apply.started", writes,
		map[string]any{"applyRunId": runID, "plan": planHash}, tok); err != nil {
		return corrupted(err.Error())
	}

	// D227: the ephemeral progress stream. Built from the sealed plan's actions
	// in execution order; emits run-start (the manifest), per-action transitions,
	// and run-end. It writes to its own sink and never touches the ledger below.
	order := topoOrder(actions)
	pe := progress.New(cfg.progOut, cfg.progMode, runID, planHash)
	pe.Start(progressManifest(actions, order))

	// D275 (D226 apply slice): typed outputs of this run's succeeded creates,
	// keyed by action id — the in-run source consumers resolve references from.
	// The same values land in the producer's terminal receipt, so the ledger
	// remains the durable record and this map is only a projection of it.
	runOutputs := map[string]map[string]any{}

	// Part A — fail-isolated execution (Acme field report #2). A failed action
	// fails only its TRANSITIVE dependents (via the DAG's dependsOn); INDEPENDENT
	// branches still run. Write-ahead discipline is untouched — every action that
	// reaches its driver call still brackets it with a pending then a terminal
	// receipt, so per-capability pending/reconcile semantics are identical. The
	// lease and the ONE run-level terminal marker are written after the whole DAG
	// is walked; the run's exit code is the worst action outcome's.
	outcome := map[string]int{} // aid -> clXxx
	var reasons []string
	worst := clSucceeded
	var worstCode perr.Code
	maxRetryAfter := 0
	// depFailed reports the first dependency of `a` that did not succeed — its
	// dependents then skip (transitively: a skipped dep is itself not succeeded).
	depFailed := func(a map[string]any) string {
		deps, _ := a["dependsOn"].([]any)
		for _, d := range deps {
			s, _ := d.(string)
			if s != "" && outcome[s] != clSucceeded {
				return s
			}
		}
		return ""
	}
	// fail records a non-success and keeps the worst (highest-severity, first at
	// that tier) code for the run.
	fail := func(cls int, code perr.Code, reason string, retryAfter int) {
		if cls > worst {
			worst, worstCode = cls, code
		}
		if retryAfter > maxRetryAfter {
			maxRetryAfter = retryAfter
		}
		if reason != "" {
			reasons = append(reasons, reason)
		}
	}

	for _, aid := range order {
		a := actionByID(actions, aid)
		capID, _ := a["capability"].(string)
		target, _ := a["target"].(string)
		key, _ := a["idempotencyKey"].(string)
		// a dependency that did not succeed transitively skips this action — a
		// failed producer must not have its consumer mutate on a phantom operand,
		// and a replacement's delete must not run when its create failed.
		if dep := depFailed(a); dep != "" {
			outcome[aid] = clSkipped
			why := fmt.Sprintf("action %s skipped — dependency %s did not succeed", aid, dep)
			pe.Transition(aid, progress.StatePending, progress.StateSkipped,
				progress.Detail{SkipWhy: progress.SkipDepFailed, Reason: why})
			fail(clSkipped, "", why, 0)
			continue
		}
		actionStart := cfg.nowMS()
		// actionState tracks the action's live progress state so the terminal
		// transition rides a legal edge — running, or provider-wait once a driver
		// LRO poll begins (Part D).
		actionState := progress.StateRunning
		pe.Transition(aid, progress.StatePending, progress.StateReady, progress.Detail{})
		pe.Transition(aid, progress.StateReady, progress.StateRunning,
			progress.Detail{StartedAt: ts(w.lw.Clock)})
		// intent id keys the pending set; the provider's REAL operation
		// name (unknown until the call returns) rides in the terminal
		// receipt body as providerOperation (D43)
		intentID := "intent-" + key

		// refuseBeforeIntent isolates a PRE-INTENT refusal (D275): no write-ahead
		// intent was written and no driver call was made for this action, so there
		// is nothing pending to reconcile. It records the failure (its dependents
		// then skip) and the loop moves on; the run-level terminal marker is
		// written once, after the DAG. Refusal-is-not-failure, but mid-run this is
		// a non-success for THIS action.
		refuseBeforeIntent := func(code perr.Code, reason string) {
			emitTerminal(pe, aid, progress.StateRunning, "failed", cfg.nowMS()-actionStart, reason)
			outcome[aid] = clFailed
			fail(clFailed, code, reason, 0)
		}

		// D275: resolve intra-plan references (D226) from producer receipts of
		// THIS run, before the write-ahead intent — refuse-before-mutate. The
		// consumer's operand map is a copy: the candidate document is never
		// mutated. Kind is re-checked at the point of use (fail-closed), and
		// the deferred driver Validate runs on the RESOLVED operands.
		// D283: compile-folded literals substitute first; same-run references
		// overlay on top of them.
		implArgs := foldedImplementation(a, cand, capID)
		if refs := actionRefs(a); len(refs) > 0 {
			resolved, why := resolveActionRefs(refs, implArgs, runOutputs)
			if why != "" {
				refuseBeforeIntent(perr.ReferenceUnresolved, fmt.Sprintf(
					"action %s: %s — no intent written, no driver call made", aid, why))
				continue
			}
			implArgs = resolved
			svc := serviceOf(asStr(a["target"]))
			if err := prov.Validate(svc, capID, env, attributesRaw(c, cand, vocabs, capID),
				implArgs, actionGeneration(a)); err != nil {
				refuseBeforeIntent(perr.ProviderRefused, fmt.Sprintf(
					"provider cannot honor action %s (validated on resolved "+
						"references): %v", aid, err))
				continue
			}
		}

		// write-ahead intent: the pending receipt lands BEFORE the call
		receipt := map[string]any{"applyRunId": runID,
			"operationId": intentID, "idempotencyKey": key,
			"target": target, "status": "pending"}
		if op, _ := a["operation"].(string); op != "" {
			receipt["operation"] = op // resume (D57) keys behavior on it
		} else {
			receipt["operation"] = "create"
		}
		if op, _ := a["operation"].(string); op != "delete" {
			receipt["generation"] = actionGeneration(a)
		}
		if op, _ := a["operation"].(string); op == "delete" {
			// D48: a failed replacement-delete must leave the orphan
			// discoverable — the receipt names exactly what it targeted
			receipt["targetProviderId"] = a["targetProviderId"]
			receipt["targetGeneration"] = a["targetGeneration"]
			if dep, _ := a["deposed"].(bool); dep {
				receipt["deposed"] = true
			}
		}
		if op, _ := a["operation"].(string); op == "update" {
			// D72: the receipt carries a VERIFIABLE target shape — the
			// bound identity and the exact desired values — so resume
			// can conclude a lost update against reality, not a guess
			receipt["targetProviderId"] = bound[capID]
			receipt["changes"] = desiredChanges(a)
		}
		if err := w.append("operation.receipt",
			[]string{capID}, receipt, 0); err != nil {
			return corrupted(err.Error())
		}

		// D257/Part D: wire the driver's intra-action heartbeat so a long LRO poll
		// (a Lambda ENI provision, a cluster upgrade, a node-group roll) reports
		// the phase it is waiting on LIVE instead of a multi-minute silence. The
		// FIRST beat is the LRO handoff: it moves the action running -> provider-wait
		// (the D227 state gated until a driver polled — D257 drivers now do), once;
		// subsequent beats tick within provider-wait, carrying the provider phase
		// and MEASURED elapsed. Cleared after the call so a phase never leaks onto
		// the next action's id. The heartbeat is a projection — it never touches the
		// ledger or the mutation semantics.
		if pr, ok := prov.(provider.ProgressReporter); ok {
			pr.SetProgress(func(phase string) {
				d := progress.Detail{ProviderPhase: phase, ElapsedMS: cfg.nowMS() - actionStart}
				if actionState == progress.StateRunning {
					actionState = progress.StateProviderWait
					pe.Transition(aid, progress.StateRunning, progress.StateProviderWait, d)
				} else {
					pe.Tick(aid, actionState, d)
				}
			})
		}

		// D699: the sealed field-reclaim consent, per action. Set from the PLAN so an
		// operator cannot widen it after sealing, and cleared after the call so it
		// never leaks onto the next action.
		if fr, ok := prov.(provider.FieldReclaimer); ok {
			reclaim, _ := a["fieldReclaim"].(bool)
			fr.SetFieldReclaim(reclaim)
		}
		// D1036: the sealed emission-adopt grant (D1034), same discipline — set from the
		// PLAN so it cannot be widened after sealing, cleared after the call below.
		if ea, ok := prov.(provider.EmissionAdopter); ok {
			adopt, _ := a["emissionAdopt"].(bool)
			ea.SetEmissionAdopt(adopt)
		}

		var cr provider.CreateResult
		op, _ := a["operation"].(string)
		svc := serviceOf(asStr(a["target"]))
		switch op {
		case "update":
			// implArgs carries the action's D283/D961 compile-folded operand literals
			// (foldedImplementation), so a driver that re-pushes a full body (Lambda's
			// UpdateFunctionConfiguration) sees the RESOLVED wired operand — not the raw
			// $ref, which the builder drops, STRIPPING it as collateral (D962). Same
			// folded map the create branch below feeds prov.Create.
			cr = prov.Update(svc, capID, env, bound[capID],
				attributesRaw(c, cand, vocabs, capID), implArgs,
				changePaths(a), key)
		case "delete":
			// D48: delete acts on the PINNED identity, never on the
			// binding projection — which a replacement-create in this
			// very run may already have moved
			pinnedID, _ := a["targetProviderId"].(string)
			cr = prov.Delete(svc, capID, env, pinnedID, key)
		case "claim":
			cr = prov.(provider.Claimer).Claim(svc, capID, env, bound[capID])
		default:
			// implArgs carries D275-resolved reference operands when the
			// action consumes them; otherwise it IS the candidate's map.
			cr = prov.Create(svc, capID, env, attributesRaw(c, cand, vocabs, capID),
				implArgs, key, actionGeneration(a))
			// D723: a replacement's create must not come back holding the identity it
			// is replacing. Several drivers adopt an existing resource by ownership
			// tags before creating (D253, so a lost ledger does not mint a duplicate),
			// and those tags do not carry the generation — so the generation-2 create
			// of a replacement could find the generation-1 resource, return ITS id with
			// zero mutations, and the delete that follows, pinned to that same id,
			// destroys it. Both actions report success and the capability is left
			// unbound with its resource gone.
			//
			// This is the provider-independent backstop: whatever a driver's scan does,
			// a create that returns the identity being replaced did not create anything,
			// and continuing would write a binding to a resource this run is about to
			// delete. Refuse before that binding is written.
			if rep, ok := a["replaces"].(map[string]any); ok && cr.Status == "succeeded" {
				if old, _ := rep["providerId"].(string); old != "" && cr.ProviderID == old {
					cr = provider.CreateResult{Status: "failed", Reason: fmt.Sprintf(
						"the replacement create returned the identity it is replacing "+
							"(%s) — it adopted the resource the following delete would "+
							"destroy; nothing was created and nothing has been deleted",
						old)}
				}
			}
		}
		// D257: detach the heartbeat — a phase must never leak onto the next action.
		if pr, ok := prov.(provider.ProgressReporter); ok {
			pr.SetProgress(nil)
		}
		if fr, ok := prov.(provider.FieldReclaimer); ok {
			fr.SetFieldReclaim(false)
		}
		if ea, ok := prov.(provider.EmissionAdopter); ok {
			ea.SetEmissionAdopt(false)
		}

		// D275: a succeeded create's declared outputs are filtered through the
		// driver's typed OutputsFor contract and land in the terminal receipt —
		// the durable record consumers resolve references from. A missing or
		// wrong-kinded DECLARED output demotes the outcome to unknown at
		// receipt-write time (the driver broke its own contract; nothing
		// downstream may start on a value that failed its type).
		if op == "create" && cr.Status == "succeeded" {
			if outs, why := declaredOutputs(prov, svc, cr.Outputs); why != "" {
				cr.Status = "unknown"
				cr.Reason = fmt.Sprintf(
					"create succeeded but its declared outputs are unusable: %s "+
						"— concluding unknown, reconcile before retrying", why)
			} else if len(outs) > 0 {
				receipt["outputs"] = outs
				runOutputs[aid] = outs
				// Layer 1: surface the applied outputs per capability so the apply
				// verb can derive a public-edge URL for the reachability probe. A
				// projection of already-computed values; no extra provider read.
				if res.Outputs == nil {
					res.Outputs = map[string]map[string]any{}
				}
				res.Outputs[capID] = outs
			}
		}

		receipt["status"] = cr.Status
		if cr.Retryable {
			// D241: a pure throttle (provider-again-later) provably did NOT land —
			// the mutation was rejected at the rate limiter, not executed. Conclude
			// the write-ahead intent as `retryable`, which CLEARS the pending set
			// (unlike `unknown`, which keeps it pending for reconcile): there is no
			// resource to reconcile, so a re-apply — or converge's backoff-retry —
			// is clean. This is the receipt-level twin of the exit code.
			receipt["status"] = "retryable"
		}
		if cr.OperationID != "" {
			receipt["providerOperation"] = cr.OperationID
		}
		if cr.Reason != "" {
			receipt["reason"] = cr.Reason
		}
		// D227: the action's terminal progress transition, keyed on the same
		// receipt status the ledger records — one source, two projections. An
		// `unknown` outcome is `indeterminate` (routes to resume), never a
		// silent success. Emitted before the success path's binding writes and
		// before the failure path's early return, so it covers every exit.
		emitTerminal(pe, aid, actionState, cr.Status, cfg.nowMS()-actionStart, cr.Reason)
		// D57: an UNKNOWN create that DID compute a provider id (a deterministic name,
		// or a server-assigned id captured before the response was lost) persists it so
		// resume/reconcile can read live state by identity — the id must survive a lost
		// response rather than be thrown away. This is the ONLY way to conclude a
		// server-assigned-id resource with no list/tag-scan path (vpc, kms, cloudfront,
		// apigateway...). succeeded clears the receipt (D180); failed has no resource.
		if cr.Status == "unknown" && !cr.Retryable && cr.ProviderID != "" {
			receipt["targetProviderId"] = cr.ProviderID
		}
		// The terminal receipt records the OUTCOME and, when succeeded, CLEARS the
		// pending intent (D180). On the SUCCESS path it must land AFTER the durable
		// binding/ownership written below: a crash in the gap then leaves the
		// receipt PENDING for resume to reconcile against the already-written
		// state, never an orphan (resource created, pending cleared, no binding →
		// a re-plan double-creates). On the failure path there is no state to write
		// first, and `unknown` must KEEP its pending intent (only a succeeded
		// receipt clears it), so it is committed here.
		commitTerminal := func() error {
			return w.append("operation.receipt", []string{capID}, receipt, 0)
		}
		if cr.Status != "succeeded" {
			// The terminal receipt records this action's outcome: `failed`/
			// `retryable` clear the pending intent, `unknown` keeps it (only a
			// succeeded receipt clears an ambiguous outcome, D180). Identical
			// per-capability discipline to before — Part A only stops one failed
			// action from aborting the INDEPENDENT branches. A commit error is the
			// one thing that still escalates to CORRUPTED and stops: a hash citing
			// an event the file does not contain cannot be isolated.
			if err := commitTerminal(); err != nil {
				return corrupted(err.Error())
			}
			switch {
			case cr.Status == "unknown" && cr.Retryable:
				// D237: a pure throttle did NOT land — retry the same verb after a
				// backoff, no reconcile (the retryable receipt cleared pending).
				outcome[aid] = clThrottled
				fail(clThrottled, perr.ProviderAgainLater, fmt.Sprintf(
					"action %s throttled — wait and retry (the mutation did not land)",
					aid), cr.RetryAfterSeconds)
			case cr.Status == "unknown":
				// every other unknown (5xx, transport, live 403) MAY have landed —
				// reconcile before retrying; the pending receipt stays (D29).
				outcome[aid] = clUnknown
				fail(clUnknown, perr.ReconcileRequired, fmt.Sprintf(
					"action %s outcome unknown — reconcile before retrying", aid), 0)
			default:
				outcome[aid] = clFailed
				fail(clFailed, perr.ApplyFailed, fmt.Sprintf(
					"action %s failed: %s", aid, cr.Reason), 0)
			}
			continue
		}

		// D52 takeover: a claim stamps authorship, it does not change the
		// binding body — record ownership.claimed and move on, leaving the
		// binding projection untouched. The next compile sees Claimed and
		// emits no further claim, so a converged no-op now means BOTH reality
		// matches AND groundhold owns the object.
		if op == "claim" {
			if err := w.append("ownership.claimed", []string{capID},
				map[string]any{"applyRunId": runID, "capability": capID,
					"providerId": bound[capID]}, tok); err != nil {
				return corrupted(err.Error())
			}
			// ownership is durable → now clear the pending intent (D180)
			if err := commitTerminal(); err != nil {
				return corrupted(err.Error())
			}
			res.Bindings[capID] = bound[capID]
			outcome[aid] = clSucceeded
			continue
		}

		// full binding projection — latest body wins, so never partial;
		// updates increment the generation (D46); deletes tombstone the
		// PINNED identity (D47/D48) and empty resources ONLY when the
		// binding still points at the deleted resource — after a
		// replacement-create in this run it already points at the
		// successor, which must survive
		generation := 1
		var tombstones, replacesList []any
		curResources := []any{}
		curID := ""
		// read the FRESH binding (D67): a create-before-destroy's create
		// was committed under lock earlier in this run and moved the
		// binding to the successor; the local preflight ledger is stale
		if cur, ok := w.lw.Led.Bindings[capID]; ok {
			if prior, ok := cur["lineage"].(map[string]any); ok {
				if tl, ok := prior["tombstones"].([]any); ok {
					tombstones = append(tombstones, tl...)
				}
				if rp, ok := prior["replaces"].([]any); ok {
					replacesList = append(replacesList, rp...)
				}
			}
			if resources, ok := cur["resources"].([]any); ok {
				curResources = resources
				if len(resources) > 0 {
					if m, ok := resources[0].(map[string]any); ok {
						curID, _ = m["providerId"].(string)
						if g, ok := m["generation"].(int); ok {
							generation = g + 1
						}
					}
				}
			}
		}
		if g, ok := a["targetGeneration"].(int); ok && g >= 1 {
			generation = g // the plan's explicit generation wins (D48)
		}
		binding := map[string]any{
			"applyRunId":  runID,
			"capability":  capID,
			"environment": env,
			"provider":    map[string]any{"name": prov.Name()},
		}
		if op == "delete" {
			pinnedID, _ := a["targetProviderId"].(string)
			pinnedGen, _ := a["targetGeneration"].(int)
			tombstones = append(tombstones, map[string]any{
				"providerId":          pinnedID,
				"resourceType":        target,
				"generation":          pinnedGen,
				"deletedAt":           ts(w.lw.Clock),
				"deletionOperationId": cr.OperationID,
			})
			if curID == "" || curID == pinnedID {
				binding["resources"] = []any{} // plain retirement
				delete(res.Bindings, capID)
			} else {
				binding["resources"] = curResources // replacement survivor
			}
			lineage := map[string]any{"tombstones": tombstones}
			if len(replacesList) > 0 {
				lineage["replaces"] = replacesList
			}
			binding["lineage"] = lineage
		} else {
			binding["resources"] = []any{map[string]any{
				"id": "primary", "type": target,
				"providerId": cr.ProviderID, "generation": generation}}
			if rep, ok := a["replaces"].(map[string]any); ok {
				if old, _ := rep["providerId"].(string); old != "" {
					replacesList = append(replacesList, old)
				}
			}
			if len(tombstones) > 0 || len(replacesList) > 0 {
				lineage := map[string]any{}
				if len(tombstones) > 0 {
					lineage["tombstones"] = tombstones
				}
				if len(replacesList) > 0 {
					lineage["replaces"] = replacesList
				}
				binding["lineage"] = lineage
			}
			res.Bindings[capID] = cr.ProviderID
		}
		if err := w.append("binding.updated",
			[]string{capID}, binding, tok); err != nil {
			return corrupted(err.Error())
		}
		// binding is durable → now the pending-clearing terminal receipt (D180):
		// a crash between the two leaves the receipt pending, and resume
		// reconciles it against this binding rather than orphaning the resource.
		if err := commitTerminal(); err != nil {
			return corrupted(err.Error())
		}
		outcome[aid] = clSucceeded
	}
	pe.End()

	// Part A — one run-level terminal marker and one lease release, AFTER the
	// whole DAG. All-success writes apply.finished (exit 0); any non-success
	// writes apply.failed (exit 4) so status derivation and resume see a failed
	// run, while each unknown's pending receipt still routes reconcile per
	// capability. The worst action outcome picks the run's code/status; the
	// per-action reasons (in DAG order) name every non-success.
	if worst == clSucceeded {
		if err := w.append("apply.finished", writes,
			map[string]any{"applyRunId": runID}, tok); err != nil {
			return corrupted(err.Error())
		}
		if err := w.append("lease.released", writes, nil, tok); err != nil {
			return corrupted(err.Error())
		}
		return res
	}
	if err := w.append("apply.failed", writes,
		map[string]any{"applyRunId": runID, "exitCode": 4}, tok); err != nil {
		return corrupted("failure-path append lost: " + err.Error())
	}
	if err := w.append("lease.released", writes, nil, tok); err != nil {
		return corrupted("failure-path append lost: " + err.Error())
	}
	res.Exit = 4
	res.Code = worstCode
	res.RetryAfterSeconds = maxRetryAfter
	res.Reasons = reasons
	res.Outcomes = outcomeNames(outcome)
	switch worst {
	case clUnknown, clThrottled:
		res.Status = "unknown" // ambiguous/throttled — never a fabricated success
	default:
		res.Status = "failed"
	}
	return res
}

// outcomeNames renders the per-action outcome map with stable class names for
// the machine Result (Part A: succeeded|failed|unknown|throttled|skipped).
func outcomeNames(outcome map[string]int) map[string]string {
	out := make(map[string]string, len(outcome))
	for aid, cl := range outcome {
		switch cl {
		case clSucceeded:
			out[aid] = "succeeded"
		case clSkipped:
			out[aid] = "skipped"
		case clThrottled:
			out[aid] = "throttled"
		case clUnknown:
			out[aid] = "unknown"
		default:
			out[aid] = "failed"
		}
	}
	return out
}

// progressManifest builds the run-start manifest from the sealed plan's actions
// in execution order (D227).
func progressManifest(actions []any, order []string) progress.RunManifest {
	m := progress.RunManifest{TotalActions: len(order)}
	for i, aid := range order {
		a := actionByID(actions, aid)
		op, _ := a["operation"].(string)
		capID, _ := a["capability"].(string)
		target, _ := a["target"].(string)
		var deps []string
		if raw, ok := a["dependsOn"].([]any); ok {
			for _, d := range raw {
				if s, ok := d.(string); ok {
					deps = append(deps, s)
				}
			}
		}
		m.Actions = append(m.Actions, progress.ManifestAction{
			ActionID: aid, Index: i + 1, Operation: op,
			Capability: capID, Target: target, DependsOn: deps,
		})
	}
	return m
}

// emitTerminal maps a receipt status to the action's terminal progress state
// (D227). unknown is indeterminate — an honest "gave up without knowing" that
// routes to resume, never a silent success. `prev` is the action's current
// progress state (running, or provider-wait once a driver LRO poll started,
// D227/D257) so the terminal transition rides a legal edge.
func emitTerminal(pe *progress.Emitter, aid string, prev progress.ActionState, status string, elapsedMS int64, reason string) {
	d := progress.Detail{ElapsedMS: elapsedMS, Reason: reason}
	switch status {
	case "succeeded":
		pe.Transition(aid, prev, progress.StateDone, d)
	case "failed":
		pe.Transition(aid, prev, progress.StateFailed, d)
	default: // unknown
		d.Code = string(perr.ReconcileRequired)
		pe.Transition(aid, prev, progress.StateIndeterminate, d)
	}
}

// Part A action outcome classes, ordered by SEVERITY: the run's exit code is
// the worst action's. A possibly-landed unknown (needs reconcile) outranks a
// terminal failure outranks a clean throttle (did not land) outranks a
// dependency-skip outranks success.
const (
	clSucceeded = iota
	clSkipped
	clThrottled
	clFailed
	clUnknown
)

// ---- helpers ---------------------------------------------------------------

func staleReason(led *ledger.Ledger, reads map[string]any) string {
	heads, _ := reads["heads"].(map[string]any)
	for cap, pinnedAny := range heads {
		pinned, _ := pinnedAny.(string)
		cur, ok := led.DecisionHeads[cap]
		if !ok {
			cur = "genesis"
		}
		if cur != pinned {
			return fmt.Sprintf(
				"stale plan: decision head of %s moved (pinned %s)", cap, pinned)
		}
	}
	return ""
}

func writeSet(p map[string]any) []string {
	writesAny, _ := p["writes"].([]any)
	out := make([]string, 0, len(writesAny))
	for _, wc := range writesAny {
		s, _ := wc.(string)
		out = append(out, s)
	}
	return out
}

func actionGeneration(a map[string]any) int {
	if g, ok := a["targetGeneration"].(int); ok && g >= 1 {
		return g
	}
	return 1
}

// isDeposed: the pinned orphan must be CURRENTLY deposed in the fresh
// projection (D71) — replaced, never tombstoned, no in-flight delete.
func isDeposed(led *ledger.Ledger, capID, pinnedID string,
	pinnedGen int) bool {
	for _, d := range led.Deposed(false) {
		if d.Capability == capID && d.ProviderID == pinnedID &&
			d.Generation == pinnedGen && d.Status == "deposed" {
			return true
		}
	}
	return false
}

func planDeletes(actions []any, capID string) bool {
	for _, it := range actions {
		a, _ := it.(map[string]any)
		if a["capability"] == capID && a["operation"] == "delete" {
			return true
		}
	}
	return false
}

// planCreates reports whether the plan carries a create for capID — the paired create
// that makes a same-cap delete a REPLACE rather than a bare destroy (D1038).
func planCreates(actions []any, capID string) bool {
	for _, it := range actions {
		a, _ := it.(map[string]any)
		if a["capability"] == capID && a["operation"] == "create" {
			return true
		}
	}
	return false
}

// desiredChanges compacts an update action's change-set to what a
// reconciler can verify: path and desired value (D72). `from` is a
// decision record, not a target — it stays in the plan.
func desiredChanges(a map[string]any) []any {
	changes, _ := a["changes"].([]any)
	out := make([]any, 0, len(changes))
	for _, chAny := range changes {
		ch, _ := chAny.(map[string]any)
		p, _ := ch["path"].(string)
		if p == "" {
			continue
		}
		out = append(out, map[string]any{"path": p, "to": ch["to"]})
	}
	return out
}

func changePaths(a map[string]any) []string {
	changes, _ := a["changes"].([]any)
	out := make([]string, 0, len(changes))
	for _, chAny := range changes {
		ch, _ := chAny.(map[string]any)
		if p, _ := ch["path"].(string); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func actionByID(actions []any, id string) map[string]any {
	for _, it := range actions {
		a, _ := it.(map[string]any)
		if a["id"] == id {
			return a
		}
	}
	return nil
}

// topoOrder: dependency order, stable on the document order (the plan
// loader already proved acyclicity).
func topoOrder(actions []any) []string {
	done := map[string]bool{}
	var order []string
	for len(order) < len(actions) {
		for _, it := range actions {
			a, _ := it.(map[string]any)
			aid, _ := a["id"].(string)
			if done[aid] {
				continue
			}
			ready := true
			if deps, ok := a["dependsOn"].([]any); ok {
				for _, d := range deps {
					s, _ := d.(string)
					if !done[s] {
						ready = false
					}
				}
			}
			if ready {
				done[aid] = true
				order = append(order, aid)
			}
		}
	}
	return order
}

// PreflightCap is one capability's driver refuse-before-mutate outcome.
type PreflightCap struct {
	Capability string `json:"capability"`
	Service    string `json:"service"`
	OK         bool   `json:"ok"`
	Refusal    string `json:"refusal,omitempty"`
	// References lists operand slots this capability wires from same-plan
	// outputs (D226), as "slot <- capability.output". The report judged the
	// REMAINING operands with these slots assumed wired; apply validates them
	// again on the truly resolved values (D275).
	References []string `json:"references,omitempty"`
}

// PreflightReport is the whole-contract operand/attribute preflight.
type PreflightReport struct {
	Ready        bool           `json:"ready"`
	Missing      int            `json:"missing"`
	Capabilities []PreflightCap `json:"capabilities"`
}

// Preflight runs the driver refuse-before-mutate hook (Validate) for EVERY
// capability the candidate declares and collects ALL refusals in one pass —
// unlike apply, which fails fast on the first. It surfaces the complete set of
// missing implementation.* operands and unsatisfiable attributes across the whole
// contract, so an operator fixes them in ONE round-trip instead of discovering
// them one apply at a time (F3/F7). Pure and deterministic: Validate makes no
// network call. Generation is 1 (a refusal for a missing operand or an
// unsatisfiable attribute is generation-independent); the report is sorted by
// capability for a stable, diffable output.
func Preflight(c *contract.Contract, cand *contract.Candidate,
	vocabs map[string]vocab.Vocabulary, prov provider.Provider) PreflightReport {
	env := ""
	if c != nil {
		env = c.Environment
	}
	caps := make([]string, 0, len(cand.Capabilities))
	for capID := range cand.Capabilities {
		caps = append(caps, capID)
	}
	sort.Strings(caps)

	report := PreflightReport{Ready: true}
	for _, capID := range caps {
		svc := candidateService(cand, capID)
		cap := PreflightCap{Capability: capID, Service: svc, OK: true}
		impl, wired := preflightImpl(cand, capID, prov)
		cap.References = wired
		if err := prov.Validate(svc, capID, env, attributesRaw(c, cand, vocabs, capID),
			impl, 1); err != nil {
			cap.OK = false
			cap.Refusal = err.Error()
			report.Ready = false
			report.Missing++
		}
		report.Capabilities = append(report.Capabilities, cap)
	}
	return report
}

// preflightImpl returns the capability's operand map with each well-formed
// intra-plan $ref slot (D226) replaced by a typed stand-in, so the report can
// judge the REST of the operands (presence, honorability) in one round-trip
// (F3/F14) instead of refusing on values that by design do not exist yet. The
// stand-in never reaches a driver call — Preflight is pure, and apply
// validates on truly resolved values (D275). A $ref whose producer or output
// the driver does not declare is left in place, so the driver's refusal
// surfaces it in the report rather than being masked by a stand-in.
func preflightImpl(cand *contract.Candidate, capID string,
	prov provider.Provider) (map[string]any, []string) {
	impl := implementationOf(cand, capID)
	op, isProducer := prov.(provider.OutputProducer)
	if impl == nil || !isProducer {
		return impl, nil
	}
	var out map[string]any
	var wired []string
	slots := make([]string, 0, len(impl))
	for k := range impl {
		slots = append(slots, k)
	}
	sort.Strings(slots)
	for _, slot := range slots {
		m, ok := impl[slot].(map[string]any)
		if !ok || len(m) != 1 {
			continue
		}
		rm, ok := m["$ref"].(map[string]any)
		if !ok {
			continue
		}
		refCap, _ := rm["capability"].(string)
		refOut, _ := rm["output"].(string)
		if refCap == "" || refOut == "" {
			continue
		}
		refSvc, _ := cand.Extras[refCap]["service"].(string)
		kind := ""
		var sample any
		for _, s := range op.OutputsFor(refSvc) {
			if s.Name == refOut {
				kind, sample = s.Kind, s.Sample
				break
			}
		}
		// D289: prefer the producer driver's own FORMAT-PLAUSIBLE sample. A
		// generic placeholder fails the shape checks real drivers apply (an ARN
		// prefix, an id pattern), which made preflight report a wired slot as a
		// missing operand — a false negative that reads as "not ready" for a
		// candidate that applies cleanly. A driver that declares no sample keeps
		// the generic stand-in: still better than refusing to judge at all, and
		// its failure direction stays safe (it can only over-report work).
		var standIn any
		switch {
		case sample != nil:
			standIn = sample
		case kind == "string":
			standIn = "groundhold-preflight-ref"
		case kind == "list":
			standIn = []any{"groundhold-preflight-ref-a", "groundhold-preflight-ref-b"}
		default:
			continue // undeclared output: leave the $ref so the refusal names it
		}
		if out == nil {
			out = make(map[string]any, len(impl))
			for k, v := range impl {
				out[k] = v
			}
		}
		out[slot] = standIn
		wired = append(wired, fmt.Sprintf("%s <- %s.%s", slot, refCap, refOut))
	}
	if out == nil {
		return impl, nil
	}
	return out, wired
}

// attributesRaw is the boundary between the contract and a driver: the declared
// attribute values a builder is handed.
//
// D311: attributes the vocabulary marks as NOT resource state — a projection
// (cost.monthly) or a probe outcome (recovery.rto) — are dropped HERE rather than
// carried into every driver. A builder refuses any attribute it cannot map (so a
// silent drop is impossible), which used to force ~130 no-op `case "cost.monthly":`
// arms across the drivers: the same fact, re-encoded by hand once per service.
// Filtering at the boundary makes the vocabulary the single source, so a new
// attribute of this class needs zero driver changes (D23/D55).
//
// A nil contract or an unknown capability type yields the zero Vocabulary, which
// classifies everything as resource state — the pre-D311 behaviour.
func attributesRaw(c *contract.Contract, cand *contract.Candidate,
	vocabs map[string]vocab.Vocabulary, capID string) map[string]any {
	voc := vocabs[capTypeOf(c, capID)]
	out := map[string]any{}
	for p, pv := range cand.Capabilities[capID] {
		if pv.Scalar == nil {
			continue
		}
		if voc.NotResourceState(p) {
			continue // a forecast or a probe target — nothing for a builder to configure
		}
		out[p] = pv.Scalar.Raw
	}
	return out
}

// capTypeOf resolves a capability's declared TYPE — the key the vocabulary map is
// indexed by.
func capTypeOf(c *contract.Contract, capID string) string {
	if c == nil {
		return ""
	}
	raw, ok := c.Capabilities[capID]
	if !ok {
		return ""
	}
	typ, _ := raw["type"].(string)
	return typ
}

func implementationOf(cand *contract.Candidate, capID string) map[string]any {
	impl, _ := cand.Extras[capID]["implementation"].(map[string]any)
	return impl
}

// foldedImplementation overlays an action's compile-folded literals (D283)
// onto the candidate's operand map — copied, never mutated in place. Folds
// substitute before references: a fold is a sealed decision, a reference
// resolves live in this run.
func foldedImplementation(a map[string]any, cand *contract.Candidate, capID string) map[string]any {
	impl := implementationOf(cand, capID)
	folds, _ := a["folds"].([]any)
	if len(folds) == 0 {
		return impl
	}
	out := make(map[string]any, len(impl)+len(folds))
	for k, v := range impl {
		out[k] = v
	}
	for _, fi := range folds {
		f, _ := fi.(map[string]any)
		slot, _ := f["slot"].(string)
		if slot == "" {
			continue
		}
		// a dotted slot folds INTO a copy of the map operand's value (D226/D283).
		if base, sub, nested := strings.Cut(slot, "."); nested {
			out[base] = withMapEntry(out[base], sub, f["value"])
		} else {
			out[slot] = f["value"]
		}
	}
	return out
}

// foldStaleReason (D283) re-judges every folded operand against the REPLAYED
// ledger at apply's own --at: the backing "outputs.<name>" record must still
// exist, still carry the folded value (a moved value means the plan was
// sealed against superseded knowledge), and still be within its TTL. Any
// miss is the stale-plan class — re-observe + re-seal — never a silent apply
// of a decayed literal.
// changeStaleReason re-checks the EVIDENCE a change set rests on (D632).
//
// `plan` refuses to seal against a decayed observation; `apply` never re-judged it.
// Its only freshness check was foldStaleReason, which covers folded operands and
// nothing else — so the change set's own `from:` value, the assertion about current
// reality that justifies the mutation, was trusted from the plan however old the plan
// was. Measured: an observation with ttl 3600 recorded at 01:00:00Z, a plan sealed one
// second later, and
//
//	plan  … --at 2030-01-01T00:00:00Z   exit 2  "observation is stale — re-observe first"
//	apply … --at 2030-01-01T00:00:00Z   exit 0  APPLIED
//
// with a real receipt in the ledger: a mutation justified by a proof that died four
// years earlier. `converge` was safe only because it re-plans; the hole is reachable
// exactly through the seal-now-apply-later review workflow that D36/D89 promote.
//
// D42/D47/D325 say apply re-derives rather than trusts. Freshness was the one thing it
// still took on the plan's word.
// vocabDriftReason compares the vocabularies the plan pinned against the ones this
// process loaded (D634). The pin is "<version> <canonical-hash-of-the-model>", so a
// version bump AND a same-version content edit both surface; a comment or a reordering
// does not, because the hash covers the model the runtime reads rather than the bytes.
func vocabDriftReason(planDoc map[string]any, vocabs map[string]vocab.Vocabulary) string {
	plan, _ := planDoc["plan"].(map[string]any)
	reads, _ := plan["reads"].(map[string]any)
	pinned, _ := reads["vocabularies"].(map[string]any)
	for typ, want := range pinned {
		w, _ := want.(string)
		if w == "" {
			continue
		}
		voc, ok := vocabs[typ]
		if !ok {
			return fmt.Sprintf("the plan was compiled against vocabulary %s and this "+
				"run has no vocabulary for it — re-plan against the vocabulary you "+
				"intend to execute with", typ)
		}
		h, err := canonical.HashVocabulary(voc)
		if err != nil {
			return fmt.Sprintf("cannot identify vocabulary %s: %v", typ, err)
		}
		got := voc.Version + " " + h
		// A plan sealed before D634 pins the bare version; compare what it pinned.
		if !strings.Contains(w, " ") {
			got = voc.Version
		}
		if got != w {
			return fmt.Sprintf("vocabulary %s changed since the plan was sealed "+
				"(pinned %q, loaded %q) — the vocabulary decides statefulness and "+
				"therefore which deletes the contract forbids; re-plan", typ, w, got)
		}
	}
	return ""
}

func changeStaleReason(led *ledger.Ledger, actions []any, evalClock int) string {
	for _, it := range actions {
		a, _ := it.(map[string]any)
		capID, _ := a["capability"].(string)
		changes, _ := a["changes"].([]any)
		for _, ci := range changes {
			c, _ := ci.(map[string]any)
			path, _ := c["path"].(string)
			if path == "" {
				continue
			}
			// An attribute with NO observation is not this check's business: the
			// compiler derives changes from bindings as well as observations, and a
			// legitimate seeded binding carries no observation.recorded at all
			// (conformance: apply-updates-a-bound-capability). Refusing those was an
			// over-reach of mine that the suite caught — this check is about evidence
			// that EXPIRED, not evidence that was never of this kind.
			rec, ok := led.Observations[capID][path]
			if !ok {
				continue
			}
			obsClock, err := ledger.ParseTs(rec.ObservedAt)
			if err != nil {
				return fmt.Sprintf("stale plan: action %v changes %s.%s and its "+
					"observation carries an unreadable time %q",
					a["id"], capID, path, rec.ObservedAt)
			}
			// D967: judge freshness like ledger.ObservationExpired and foldStaleReason
			// below — NOT with a `TTLSeconds > 0` conjunct (that let a ttl==0
			// observation, which every sibling calls stale at any age, justify a
			// mutation), and WITH the D189 future guard (an observation dated after the
			// evaluation time is invalid, never fresh). Both holes let apply re-seal a
			// change on evidence nothing currently witnesses — the D632 gate the
			// conjunct claimed to close, left open for ttl==0 and future dates.
			if evalClock-obsClock > rec.TTLSeconds {
				return fmt.Sprintf("stale plan: action %v changes %s.%s, and the "+
					"observation that justifies it expired %ds ago — the plan asserts "+
					"a `from` value nothing currently witnesses; re-observe and re-seal",
					a["id"], capID, path, evalClock-obsClock-rec.TTLSeconds)
			}
			if evalClock-obsClock < 0 {
				return fmt.Sprintf("stale plan: action %v changes %s.%s, and the "+
					"observation that justifies it is dated after the evaluation time — "+
					"invalid, cannot re-seal against it (D189)",
					a["id"], capID, path)
			}
		}
	}
	return ""
}

func foldStaleReason(led *ledger.Ledger, actions []any, evalClock int) string {
	for _, it := range actions {
		a, _ := it.(map[string]any)
		folds, _ := a["folds"].([]any)
		for _, fi := range folds {
			f, _ := fi.(map[string]any)
			capID, _ := f["capability"].(string)
			out, _ := f["output"].(string)
			slot, _ := f["slot"].(string)
			rec, ok := led.Outputs[capID][out]
			if !ok {
				return fmt.Sprintf("stale plan: folded operand %v.%s — the ledger "+
					"no longer carries outputs.%s of %s; re-observe and re-seal",
					a["id"], slot, out, capID)
			}
			if fmt.Sprint(rec.Value) != fmt.Sprint(f["value"]) {
				return fmt.Sprintf("stale plan: folded operand %v.%s — outputs.%s "+
					"of %s has moved since sealing; re-seal against the fresh observation",
					a["id"], slot, out, capID)
			}
			obsClock, err := ledger.ParseTs(rec.ObservedAt)
			if err != nil || evalClock-obsClock > rec.TTLSeconds {
				return fmt.Sprintf("stale plan: folded operand %v.%s — outputs.%s "+
					"of %s is beyond its TTL at this evaluation time; re-observe and re-seal",
					a["id"], slot, out, capID)
			}
			if evalClock-obsClock < 0 {
				return fmt.Sprintf("stale plan: folded operand %v.%s — outputs.%s "+
					"of %s is dated after the evaluation time — invalid",
					a["id"], slot, out, capID)
			}
		}
	}
	return ""
}

// planRef is an action's intra-plan reference as sealed by the compiler
// (D226 OperandRef), read back from the plan document at apply time.
type planRef struct{ Slot, ProducerAction, Capability, Output, Kind string }

// actionRefs parses an action's references array from the sealed plan (D275).
// A malformed entry is dropped; its slot then still holds the raw $ref map, so
// the driver refuses the unknown operand shape — fail-closed, never a guess.
func actionRefs(a map[string]any) []planRef {
	raw, _ := a["references"].([]any)
	out := make([]planRef, 0, len(raw))
	for _, it := range raw {
		m, _ := it.(map[string]any)
		r := planRef{
			Slot:           asStr(m["slot"]),
			ProducerAction: asStr(m["producerAction"]),
			Capability:     asStr(m["capability"]),
			Output:         asStr(m["output"]),
			Kind:           asStr(m["kind"]),
		}
		if r.Slot != "" && r.ProducerAction != "" && r.Output != "" {
			out = append(out, r)
		}
	}
	return out
}

// resolveActionRefs substitutes each reference slot with the producer's
// receipted output value (D275). The candidate's operand map is copied, never
// mutated. Any failure — producer receipt absent from this run, output
// missing, kind mismatch — returns a reason and the caller refuses before the
// write-ahead intent: zero mutation, nothing pending.
func resolveActionRefs(refs []planRef, impl map[string]any,
	runOutputs map[string]map[string]any) (map[string]any, string) {
	resolved := make(map[string]any, len(impl))
	for k, v := range impl {
		resolved[k] = v
	}
	for _, r := range refs {
		outs, ok := runOutputs[r.ProducerAction]
		if !ok {
			return nil, fmt.Sprintf("reference %s <- %s.%s is unresolved: "+
				"producer %s has no succeeded receipt with outputs in this run",
				r.Slot, r.Capability, r.Output, r.ProducerAction)
		}
		v, ok := outs[r.Output]
		if !ok {
			return nil, fmt.Sprintf("reference %s <- %s.%s is unresolved: "+
				"the producer receipt carries no output %q",
				r.Slot, r.Capability, r.Output, r.Output)
		}
		got, kindErr := provider.OutputValueOfKind(v, r.Kind)
		if kindErr != "" {
			return nil, fmt.Sprintf("reference %s <- %s.%s: %s",
				r.Slot, r.Capability, r.Output, kindErr)
		}
		// a dotted slot (e.g. environment.DATABASE_HOST) resolves INTO a copy of
		// the map operand's value, never mutating the candidate document (D226).
		if base, sub, nested := strings.Cut(r.Slot, "."); nested {
			resolved[base] = withMapEntry(resolved[base], sub, got)
		} else {
			resolved[r.Slot] = got
		}
	}
	return resolved, ""
}

// withMapEntry returns a COPY of the map operand at `cur` with entry sub=val
// set. A non-map (or absent) current value yields a fresh single-entry map, so
// a map-value reference resolves cleanly even when the operand was declared with
// only $ref values. The candidate document is never mutated.
func withMapEntry(cur any, sub string, val any) map[string]any {
	m, _ := cur.(map[string]any)
	cp := make(map[string]any, len(m)+1)
	for k, v := range m {
		cp[k] = v
	}
	cp[sub] = val
	return cp
}

// declaredOutputs filters a create result's raw outputs through the driver's
// typed OutputsFor contract (D226/D275): only declared names pass, every
// declared name must be present, and each value must match its declared kind.
// A driver without the OutputProducer interface — or with an empty table for
// this service — produces nothing, and that is not an error.
func declaredOutputs(prov provider.Provider, service string,
	raw map[string]any) (map[string]any, string) {
	op, ok := prov.(provider.OutputProducer)
	if !ok {
		return nil, ""
	}
	specs := op.OutputsFor(service)
	if len(specs) == 0 {
		return nil, ""
	}
	outs := make(map[string]any, len(specs))
	for _, s := range specs {
		v, ok := raw[s.Name]
		if !ok {
			return nil, fmt.Sprintf(
				"declared output %q is missing from the driver result", s.Name)
		}
		got, kindErr := provider.OutputValueOfKind(v, s.Kind)
		if kindErr != "" {
			return nil, fmt.Sprintf("declared output %q: %s", s.Name, kindErr)
		}
		outs[s.Name] = got
	}
	return outs, ""
}

func asStr(v any) string { s, _ := v.(string); return s }

// candidateService is the service the candidate DECLARES for a capability —
// used to cross-check the sealed plan's target service (D76).
func candidateService(cand *contract.Candidate, capID string) string {
	if cand == nil {
		return ""
	}
	s, _ := cand.Extras[capID]["service"].(string)
	return s
}

// emissionAdoptProvenanceOK re-derives, from the HASH-PINNED candidate (never the
// forgeable plan folds), that capID's log_group operand is a $ref to a certified
// emission a monitoring.logs governs (D1037). This is the apply-side twin of
// mintEmissionAdopt's provenance check: a literal log_group, a $ref to a
// non-emission output, or a provider that certifies no emissions all fail closed —
// so a hand-authored plan asserting emissionAdopt over a foreign group is refused.
func emissionAdoptProvenanceOK(cand *contract.Candidate, prov provider.Provider, capID string) bool {
	m, ok := implementationOf(cand, capID)["log_group"].(map[string]any)
	if !ok {
		return false // a literal (or absent) log_group carries no emission provenance
	}
	rm, ok := m["$ref"].(map[string]any)
	if !ok {
		return false
	}
	refCap, _ := rm["capability"].(string)
	refOut, _ := rm["output"].(string)
	if refCap == "" || refOut == "" {
		return false
	}
	ec, ok := prov.(provider.EmissionCertifier)
	if !ok {
		return false
	}
	for _, comp := range ec.EmittedCompanions()[candidateService(cand, refCap)] {
		if comp.NameOutput == refOut && comp.GovernedBy == "capability.monitoring.logs" {
			return true
		}
	}
	return false
}

func parseTs(s string) (int, error) { return ledger.ParseTs(s) }

func ts(clock int) string {
	return time.Unix(int64(clock), 0).UTC().Format("2006-01-02T15:04:05Z")
}

type writer struct {
	lw    ledger.Writer
	runID string
}

func (w *writer) appendLease(caps []string) (int, error) {
	return w.lw.AppendLease(caps,
		map[string]any{"ttlSeconds": 300, "applyRunId": w.runID})
}

func (w *writer) append(etype string, caps []string, body map[string]any,
	token int) error {
	return w.lw.Append(etype, caps, body, token)
}
