// Package converge is the porcelain (D51): verify → plan → forecast →
// confirm → apply → observe → convergence check, stitched over the
// D22-frozen CLI protocol by exec'ing our own binary. Porcelain hides
// keystrokes, never information: refusals, risk vectors, unknowns and
// delete targets pass through verbatim (D49).
package converge

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"groundhold/internal/contract"
	"groundhold/internal/ledger"
	"groundhold/internal/perr"
	"groundhold/internal/reach"
	"groundhold/internal/render"
)

// RunID computes a converge run handle (and the contract's environment for the
// lifecycle events) WITHOUT running — the detach launcher (D229) needs the handle
// before it forks, and it must equal what Converge writes as convergeRunId. It is
// domain-prefixed so it can never collide with an applyRunId of the same inputs,
// and it embeds the explicit --at, so a handle cannot exist for a defaulted clock.
// D656: the CANDIDATE and the PROJECT are part of a run's identity. They were not
// in the handle, so editing the candidate — the file an operator edits to fix an
// implementation — and re-running at the same --at reused it. The ledger then held
// converge.finished{exitCode:0} and converge.failed{exitCode:2} under one id, and
// `status`/`wait` reported the first: exit 0 for a deploy that was refused.
func RunID(contractPath, candidatePath, at, project string) (runID, env string, caps []string, err error) {
	raw, err := os.ReadFile(contractPath)
	if err != nil {
		return "", "", nil, err
	}
	ch := sha256.Sum256(raw)
	kh := [32]byte{} // an absent candidate path stays distinguishable from an empty one
	if candidatePath != "" {
		kraw, kerr := os.ReadFile(candidatePath)
		if kerr != nil {
			return "", "", nil, kerr
		}
		kh = sha256.Sum256(kraw)
	}
	sum := sha256.Sum256([]byte("converge:" + hex.EncodeToString(ch[:]) +
		"|" + hex.EncodeToString(kh[:]) + "|" + at + "|" + project))
	runID = hex.EncodeToString(sum[:])[:12]
	// the contract's capabilities scope the lifecycle events (the ledger requires
	// non-empty caps); status derives from the body's convergeRunId, not caps.
	if c, cerr := contract.LoadContract(contractPath); cerr == nil {
		env = c.Environment
		for id := range c.Capabilities {
			caps = append(caps, id)
		}
		sort.Strings(caps)
	}
	return runID, env, caps, nil
}

// planPathFor names the plan file for ONE run. D656: it was a fixed
// `.groundhold/converge-plan.yaml`, so two converges in one directory clobbered it
// and each applied whichever plan was written last — measured 8 times in 8, with
// one run creating resources in the other's project at exit 0. The two plans
// differed only in `project`, which is not in the read-set, so apply's own
// mismatch check could not see it.
func planPathFor(runID string) string {
	name := "converge-plan.yaml"
	if runID != "" {
		name = "converge-plan-" + runID + ".yaml"
	}
	return filepath.Join(".groundhold", name)
}

type Options struct {
	Contract, Candidate string
	Ledger, Vocab       string
	// D612: the SECURITY policy of the run. converge executes plan/observe/apply as
	// child PROCESSES, so an in-process trust set does not reach them — the flags
	// have to travel on argv. They did not, and the consequences ran both ways:
	// `converge --trust <key>` read AND WROTE a ledger whose events were signed by a
	// foreign key while `plan`, `export` and `audit` all refused it (exit 5), and
	// `converge --sign-key` produced a history where the child observe's events are
	// UNSIGNED — which, because history is append-only, permanently breaks
	// `--trust` verification of that ledger.
	AllowExposure bool // D630: consent for a provable increase in exposure
	// D638: the CLUSTER SELECTOR. Same shape as D612's security policy: converge runs
	// its children as separate processes, so a flag that names WHICH cluster has to
	// travel on argv. It did not — so `converge --kubeconfig <other> --context <other>`
	// created objects on the DEFAULT cluster while the operator named another, at exit
	// 0 and with a CONVERGED banner. Every other verb refuses an unknown context.
	Kubeconfig  string
	KubeContext string
	// D638: the rest of what a child needs to see the same world and do the same
	// work. Each was classified "forwarded" by the flag-forwarding gate and was not
	// travelling; the injection keys are why converge's own partial-apply path (D379,
	// D387, D241) could not be exercised from the command line at all.
	Region                string
	Bindings              string
	Observations          string
	TTL                   string
	Budget                string
	RequirePreflight      bool
	FailKey               string
	UnknownKey            string
	RetryableKey          string
	Trust                 []string
	TrustFrom             string
	SignKey               string
	NoVocab               bool   // force the empty vocabulary in sub-commands
	Currency              string // reporting currency for the cost estimate (D202)
	Project, Provider, At string
	Yes, AllowDataLoss    bool
	JSON                  bool
	// NoReachability opts out of the post-apply reachability probe (Layer 1).
	// Default OFF (the probe runs); when set the probe is skipped LOUDLY (a
	// printed "reachability skipped", never silent).
	NoReachability bool
	// Getter is the reachability HTTP getter (injectable for tests/conformance);
	// nil uses reach.DefaultGetter (real HTTPS, or the env-driven fake).
	Getter reach.Getter
	In     io.Reader
	Out    io.Writer
	// Enrich attaches the advisory remediation fields to a refusal that already
	// carries a machine code, exactly as every other verb's refusal gets them
	// (D1108). converge writes its own JSON from this package, so without a hook
	// it silently skipped the enrichment the CLI's machine contract promises for
	// `--explain`. nil means no enrichment, which is only correct for callers with
	// no code registry — the CLI always sets it.
	Enrich func(m map[string]any)
	Run    Runner      // injectable for tests
	Render render.Mode // presentation (D89/D90); zero value = plain
	// ConvergeRunID (D229) is the run handle, precomputed by the launcher so
	// `status`/`wait` can find this converge run in the ledger. When set (and a
	// ledger is configured), converge writes its own lifecycle events; empty
	// leaves the ledger untouched (a foreground converge needs no run markers).
	ConvergeRunID string
	Env           string   // environment for lifecycle events (from the contract)
	Caps          []string // capabilities scoping the lifecycle events
	// D241 apply backoff: a throttled apply (provider-again-later) provably did
	// not land, so converge waits and re-applies rather than surfacing it. Bounded
	// exponential; Sleep is injectable for tests (nil = time.Sleep). Zero values
	// take the defaults in the accessors below.
	MaxApplyRetries int
	BaseBackoff     time.Duration
	MaxBackoff      time.Duration
	Sleep           func(time.Duration)
	// checklist (D232) is the live phase roadmap, rendered to stderr. Set up in
	// Converge; nil in JSON/non-interactive mode (no human region).
	checklist *Checklist
}

// maxApplyRetries is the bounded number of throttle backoffs before converge
// surfaces provider-again-later (never an infinite loop). Default 4.
func (o Options) maxApplyRetries() int {
	if o.MaxApplyRetries > 0 {
		return o.MaxApplyRetries
	}
	return 4
}

// backoffDelay is bounded exponential: base<<attempt, capped. Retry-After
// honoring is deferred (apply does not yet carry the provider's hint).
func (o Options) backoffDelay(attempt int) time.Duration {
	base := o.BaseBackoff
	if base <= 0 {
		base = time.Second
	}
	cap := o.MaxBackoff
	if cap <= 0 {
		cap = 30 * time.Second
	}
	d := base << attempt
	if d <= 0 || d > cap { // <=0 guards the shift overflowing at large attempts
		d = cap
	}
	return d
}

func (o Options) sleep(d time.Duration) {
	if o.Sleep != nil {
		o.Sleep(d)
		return
	}
	time.Sleep(d)
}

// backoffFor picks the throttle delay (D243): the provider's Retry-After hint when
// it gave one (capped at MaxBackoff so a hostile/huge value cannot stall converge
// unbounded), else the blind exponential. Returns whether the hint was honored.
func (o Options) backoffFor(attempt, retryAfterSeconds int) (time.Duration, bool) {
	if retryAfterSeconds > 0 {
		cap := o.MaxBackoff
		if cap <= 0 {
			cap = 30 * time.Second
		}
		d := time.Duration(retryAfterSeconds) * time.Second
		if d > cap {
			d = cap
		}
		return d, true
	}
	return o.backoffDelay(attempt), false
}

// planArgs builds the `plan` sub-command invocation — used for the initial plan
// and for the D241 re-plan on a throttle backoff (the retryable receipt moved
// decision heads, so the sealed plan must be regenerated against current heads).
func (o Options) planArgs() []string {
	args := append([]string{"plan", o.Contract, o.Candidate}, o.vocabArgs()...)
	args = append(args, "--at", o.At)
	if o.Currency != "" {
		args = append(args, "--currency", o.Currency)
	}
	if o.Project != "" {
		args = append(args, "--project", o.Project)
	}
	if o.Ledger != "" {
		args = append(args, "--ledger", o.Ledger)
	}
	return append(args, o.policyArgs()...)
}

// policyArgs are the trust/signing flags every child must carry (D612). A child that
// does not carry them enforces nothing and signs nothing, which is worse than a child
// that was never run: the run reports success and the ledger records it.
// targetArgs are the flags that name WHAT the run acts on — the cluster selector today.
// They travel with policyArgs for the same reason (D638): a child process inherits
// neither, and a child pointed at the wrong world is worse than a child with no policy.
func (o Options) targetArgs() []string {
	var a []string
	if o.Kubeconfig != "" {
		a = append(a, "--kubeconfig", o.Kubeconfig)
	}
	if o.KubeContext != "" {
		a = append(a, "--context", o.KubeContext)
	}
	for _, kv := range [][2]string{
		{"--region", o.Region}, {"--bindings", o.Bindings},
		{"--observations", o.Observations}, {"--ttl", o.TTL},
		{"--budget", o.Budget}, {"--fail-key", o.FailKey},
		{"--unknown-key", o.UnknownKey}, {"--retryable-key", o.RetryableKey},
	} {
		if kv[1] != "" {
			a = append(a, kv[0], kv[1])
		}
	}
	if o.RequirePreflight {
		a = append(a, "--require-preflight")
	}
	return a
}

func (o Options) policyArgs() []string {
	var a []string
	for _, t := range o.Trust {
		a = append(a, "--trust", t)
	}
	if o.TrustFrom != "" {
		a = append(a, "--trust-from", o.TrustFrom)
	}
	if o.SignKey != "" {
		a = append(a, "--sign-key", o.SignKey)
	}
	return append(a, o.targetArgs()...)
}

// ledgerPhase maps a checklist row id to the stable ledger phase name (the two
// observes share the ledger name "observe"); the checklist keeps them distinct.
func ledgerPhase(rowID string) string {
	if i := strings.Index(rowID, "-"); i > 0 && strings.HasPrefix(rowID, "observe-") {
		return "observe"
	}
	return rowID
}

// ledgerEvent appends a converge lifecycle marker to the ledger (D229), lease-free
// (token 0) and best-effort — a run marker must NEVER fail the run. No-op unless a
// run id and ledger are set. It carries the contract's caps (the ledger requires
// non-empty caps); status derives from the body's convergeRunId, not the caps.
func (o *Options) ledgerEvent(etype string, body map[string]any) {
	if o.ConvergeRunID == "" || o.Ledger == "" {
		return
	}
	led, err := ledger.ReplayFile(o.Ledger)
	if err != nil {
		return
	}
	clk, _ := ledger.ParseTs(o.At)
	if clk < led.Clock {
		clk = led.Clock
	}
	w := ledger.Writer{Path: o.Ledger, Led: led, Env: o.Env, Clock: clk, Actor: "groundhold-converge"}
	_ = w.Append(etype, o.Caps, body, 0)
}

func (o *Options) convergeBody(extra map[string]any) map[string]any {
	b := map[string]any{"convergeRunId": o.ConvergeRunID}
	for k, v := range extra {
		b[k] = v
	}
	return b
}

// pendingBlocker names the first in-scope capability that still carries an
// unresolved (unknown-outcome) receipt, if any.
//
// D935: apply refuses while a capability has pending receipts (apply.go, "must be
// reconciled first (D29)"), but that loop iterates ONLY the plan's write set —
// capabilities that carry an action. A converge whose plan carries NO actions
// (e.g. a retire over a create that stayed `unknown`: the create wrote no binding,
// so the retire diffs to nothing) never enters apply, so the guard never runs, and
// converge would declare "converged" — the world clean — while the resource the
// pending receipt names may be live and billing. That is the fail-open the freeze
// admits: a person acting on "converged" is worse off than if the tool said
// nothing. The deterministic providerId sits in the pending receipt the whole time
// (recoverable via `resume`); the fix is to refuse the converged verdict until it
// concludes.
func (o *Options) pendingBlocker() (string, bool) {
	if o.Ledger == "" {
		return "", false
	}
	led, err := ledger.ReplayFile(o.Ledger)
	if err != nil {
		return "", false
	}
	for _, cap := range o.Caps {
		if led.PendingCount(cap) > 0 {
			return cap, true
		}
	}
	return "", false
}

// refuseIfPending turns a would-be "converged" verdict into a ReconcileRequired
// refusal when any in-scope capability has an outstanding unknown receipt (D935).
func (o *Options) refuseIfPending(phases []string) (result, bool) {
	cap, pending := o.pendingBlocker()
	if !pending {
		return result{}, false
	}
	return result{Status: "refused", Code: perr.ReconcileRequired, Exit: 3,
		Phases: phases, Reasons: []string{fmt.Sprintf(
			"cannot report converged: capability %q has an in-flight operation whose "+
				"outcome is still unknown — the resource it names may exist. Run `resume` "+
				"to conclude it before trusting this result (D935)", cap)}}, true
}

// witnessReality re-checks recorded reality against the contract with a read-only
// `audit` at o.At and returns a blocking result if any HARD constraint is not
// witnessed as satisfied (violated | unknown | unverifiable). Converge's own
// convergence check runs the compiler's reconcile, which carries a non-observable
// or intent-only attribute as "unverified" (D249) and does NOT implement the D1071
// security floor — that floor lives only in `audit`. So a hard control backed by
// nothing but the candidate's own word paints the world converged at exit 0, green,
// while `audit` and `posture` (D965) exit 2 on the identical ledger. Invariant #1
// says unknown/unverifiable on a hard constraint blocks, "no exceptions"; this is the
// D1020/D965/D966 shape — an honest machine FIELD (convergence: inconclusive) beside
// a LYING exit code — applied to the porcelain a CI gates on. Converge RELAYS audit's
// verdict (rollup + code) rather than re-deriving the floor: one canon, no sibling
// re-derivation (the trap D965/D966 name). record=false — it never writes, so the
// alarm-transition channel stays `audit --record` (D54) and there is no D935 pending
// interaction. finish() paints BLOCKED/VIOLATED from the rollup (D194); the caller
// sets Status. Clean (no hard failure) -> ({}, false).
func (o *Options) witnessReality() (result, bool) {
	if o.Ledger == "" {
		return result{}, false
	}
	args := append([]string{"audit", o.Contract, "--ledger", o.Ledger, "--at", o.At},
		o.vocabArgs()...)
	// D638: a ledger-touching child carries the run's full policy (trust to verify a
	// signed ledger, plus the cluster/region selector) — the flag-forwarding gate
	// enforces this for every child, this one included.
	args = append(args, o.policyArgs()...)
	code, stdout, stderr := o.Run(args...)
	switch code {
	case 0:
		return result{}, false
	case 2:
		roll, reasons, ac := parseAuditVerdicts(stdout)
		if len(reasons) == 0 {
			// audit exits 2 only when a HARD verdict fails (audit.go), so an
			// unparsed report is a broken child, not a soft advisory — fail CLOSED
			// rather than certify converged over a report we could not read.
			reasons = []string{"audit refused (exit 2) but its report could not be read"}
		}
		return result{Exit: 2, Code: ac, Rollup: roll, Convergence: "inconclusive",
			Reasons: append([]string{"a hard constraint is not witnessed by recorded reality:"}, reasons...)}, true
	case 5:
		return result{Status: "corrupted", Exit: 5,
			Reasons: append([]string{"post-apply audit: ledger corrupted"}, lines(stderr)...)}, true
	default:
		// a killed/failed audit child must not let converge claim converged (the
		// same fail-closed reading the verify phase uses on an unexpected code).
		return result{Exit: 2,
			Reasons: append([]string{fmt.Sprintf(
				"post-apply audit exited %d — cannot certify the world converged", code)}, lines(stderr)...)}, true
	}
}

// parseAuditVerdicts reads a read-only audit report into the HARD non-satisfied
// verdicts as a banner rollup (D194), human reasons, and audit's own blocking code
// (D624). Converge relays these verbatim — the security floor is not re-implemented
// here.
func parseAuditVerdicts(stdout string) (render.Rollup, []string, perr.Code) {
	var rep struct {
		Code     perr.Code `json:"code"`
		Verdicts []struct {
			Constraint string `json:"constraint"`
			Path       string `json:"path"`
			Severity   string `json:"severity"`
			Verdict    string `json:"verdict"`
			Reason     string `json:"reason"`
		} `json:"verdicts"`
	}
	_ = json.Unmarshal([]byte(stdout), &rep)
	var roll render.Rollup
	var reasons []string
	for _, v := range rep.Verdicts {
		if v.Severity != "hard" {
			continue
		}
		switch v.Verdict {
		case "violated":
			roll.Violated = append(roll.Violated, v.Constraint)
		case "unknown":
			roll.Unknown = append(roll.Unknown, v.Constraint)
		case "unverifiable":
			roll.Unverifiable = append(roll.Unverifiable, v.Constraint)
		default:
			continue
		}
		r := fmt.Sprintf("%s (%s): %s", v.Constraint, v.Path, v.Verdict)
		if v.Reason != "" {
			r += " — " + v.Reason
		}
		reasons = append(reasons, r)
	}
	return roll, reasons, rep.Code
}

// vocabArgs mirrors the CLI's vocabulary selection into a child invocation:
// --no-vocab (empty), --vocab DIR (custom), or nothing (the binary's built-in
// embedded vocabulary — the default a downloaded groundhold uses).
func (o *Options) vocabArgs() []string {
	switch {
	case o.NoVocab:
		return []string{"--no-vocab"}
	case o.Vocab != "":
		return []string{"--vocab", o.Vocab}
	default:
		return nil
	}
}

type Runner func(args ...string) (int, string, string)

func SelfRunner(bin string) Runner {
	return func(args ...string) (int, string, string) {
		cmd := exec.Command(bin, args...)
		// Orphan guard: isolate the child (plan/apply/observe) into its own
		// process group and, on Linux, ask the kernel to SIGKILL it if THIS converge
		// process dies for any reason. A terminated CronJob pod, a SIGKILL, or a crash
		// must not leave an `apply` mutating headless while still holding the lease.
		// A hard kill is safe: apply is write-ahead + resumable (D42/D57), so an
		// interrupted child is reconciled by resume, never left corrupt.
		cmd.SysProcAttr = childProcAttr()
		var so, se strings.Builder
		cmd.Stdout, cmd.Stderr = &so, &se
		err := cmd.Run()
		code := 0
		if ee, ok := err.(*exec.ExitError); ok {
			code = ee.ExitCode()
		} else if err != nil {
			code = -1
		}
		return code, so.String(), se.String()
	}
}

type result struct {
	Status string `json:"status"` // applied|converged|refused|stale-or-conflict|failed|corrupted
	// Convergence (D136): what the post-apply check actually proved —
	// verified | inconclusive | unverified. Only "verified" (or the
	// no-op converged status) earns the CONVERGED banner.
	Convergence string `json:"convergence,omitempty"`
	// Reachability (Layer 1) is the four-valued post-apply edge verdict:
	// reachable | denied | unknown | skipped (or "" when there is no public
	// edge to probe). A machine field so a script can tell "up and serving"
	// (reachable, exit 0) from "up but the edge 403s" (denied, exit 2).
	Reachability string    `json:"reachability,omitempty"`
	Code         perr.Code `json:"code,omitempty"` // spec/errors.md (D64)
	Reasons      []string  `json:"reasons,omitempty"`
	Phases       []string  `json:"phases"`
	Exit         int       `json:"-"`
	// Rollup carries the hard-constraint verdicts so the banner distinguishes
	// a VIOLATED / BLOCKED world from a plain policy REFUSED (D194) — an empty
	// rollup used to collapse a blocked verify into a benign blue refusal.
	Rollup render.Rollup `json:"-"`
}

// printCostBlock forwards the cost estimate the plan child wrote to its stderr
// (D202) — reusing the child's provenance-aware computation rather than
// recomputing it here without provenance.
func (o *Options) printCostBlock(childStderr string) {
	inBlock := false
	for _, ln := range strings.Split(childStderr, "\n") {
		if strings.HasPrefix(ln, "Estimated cost") {
			inBlock = true
			o.say("  %s", ln)
			continue
		}
		if inBlock {
			if strings.HasPrefix(ln, "  ") {
				o.say("%s", ln)
			} else {
				return
			}
		}
	}
}

// printSuggestHint forwards the plan child's one-line hardening hint (D203) — the
// same advisory pointer plan prints on its stderr — so converge surfaces it too.
// Advisory only: it never changes the exit code or blocks.
func (o *Options) printSuggestHint(childStderr string) {
	for _, ln := range strings.Split(childStderr, "\n") {
		if strings.Contains(ln, "hardening suggestion(s) — run") {
			o.say("  %s", strings.TrimSpace(ln))
			return
		}
	}
}

func (o *Options) say(format string, a ...any) {
	if !o.JSON {
		fmt.Fprintf(o.Out, format+"\n", a...)
	}
}

// finish is the single exit point — and therefore where the banner
// lands (D90): last line of the human stdout, or stderr when stdout
// carried the JSON result. Reasons print first; the banner never
// replaces information, it concludes it.
func (o *Options) finish(r result) int {
	// D232: freeze the checklist BEFORE the banner (the region becomes ordinary
	// scrollback, then the banner is emitted once, last). A refusal marks the
	// active phase `refused` (refusal-is-not-failure); any early exit resolves
	// pending rows to skipped(loop ended) — never dangling, never failed.
	refused := r.Status == "refused" || r.Exit == 2
	endReason := "loop ended"
	if refused && len(r.Phases) > 0 {
		endReason = "loop ended: " + r.Phases[len(r.Phases)-1] + " refused"
	}
	o.checklist.Freeze(refused, endReason)

	// D229: the run's terminal marker — done on a clean exit, failed otherwise.
	// Best-effort and lease-free; a marker never changes the run's outcome.
	if r.Exit == 0 {
		o.ledgerEvent("converge.finished", o.convergeBody(map[string]any{
			"outcome": r.Status, "exitCode": r.Exit}))
	} else {
		o.ledgerEvent("converge.failed", o.convergeBody(map[string]any{
			"exitCode": r.Exit}))
	}
	word, color := render.Pick("converge", r.Exit, string(r.Code), r.Rollup)
	// D136: CONVERGED is a claim about verified reality. An apply whose
	// convergence check came back inconclusive or unverified earned
	// APPLIED — true, and exactly as much as was checked.
	if r.Exit == 0 && r.Status == "applied" && r.Convergence != "verified" {
		word = "APPLIED"
	}
	if o.JSON {
		raw, _ := json.MarshalIndent(r, "", "  ")
		if o.Enrich != nil {
			var m map[string]any
			if flat, err := json.Marshal(r); err == nil && json.Unmarshal(flat, &m) == nil {
				if code, _ := m["code"].(string); code != "" {
					o.Enrich(m)
					if out, err := json.MarshalIndent(m, "", "  "); err == nil {
						raw = out
					}
				}
			}
		}
		fmt.Fprintln(o.Out, string(raw))
		fmt.Fprintf(os.Stderr, "%s\n", o.Render.Paint(color, word))
	} else {
		for _, reason := range r.Reasons {
			o.say("  %s", reason)
		}
		o.say("%s", o.Render.Paint(color, word))
	}
	return r.Exit
}

func exitStatus(code int) (string, int) {
	switch code {
	case 1, 2:
		return "refused", 2
	case 3:
		return "stale-or-conflict", 3
	case 4:
		return "failed", 4
	case 5:
		return "corrupted", 5
	}
	// a signal-killed or unexecable apply may have mutated — "refused"
	// would promise nothing happened (review fix)
	return "failed", 4
}

func Converge(o Options) int {
	var phases []string
	// D232: the live phase checklist on stderr — a sticky region on a TTY, an
	// append-only transition line otherwise, disabled in JSON mode (the machine
	// result carries the phases). It NEVER renders a loop verdict; the banner is
	// the sole verdict carrier.
	if !o.JSON {
		sticky := o.Render.Color // color only on a TTY, so it proxies "interactive"
		o.checklist = NewChecklist(os.Stderr, o.Render, sticky)
	}
	o.ledgerEvent("converge.started", o.convergeBody(map[string]any{"at": o.At}))
	phase := func(rowID string) {
		p := ledgerPhase(rowID)
		phases = append(phases, p)
		o.checklist.Enter(rowID)
		o.ledgerEvent("converge.phase.entered", o.convergeBody(map[string]any{"phase": p}))
	}

	// ---- 1. verify: permission first, verbatim on refusal ----
	phase("verify")
	o.say("→ verify")
	code, stdout, stderr := o.Run(append([]string{"verify", o.Contract,
		o.Candidate, "--json"}, o.vocabArgs()...)...)
	if code != 0 && code != 2 {
		// fail-closed: a killed or missing verify subprocess must not
		// let an unverified candidate reach apply (review fix)
		return o.finish(result{Status: "refused", Exit: 2, Phases: phases,
			Reasons: append([]string{fmt.Sprintf(
				"verify exited with unexpected code %d", code)},
				lines(stderr)...)})
	}
	if code == 2 {
		var rep struct {
			BlockingReasons []string `json:"blockingReasons"`
			Verdicts        []struct {
				Constraint string `json:"constraint"`
				Severity   string `json:"severity"`
				Verdict    string `json:"verdict"`
				// D566: the two fields that tell an evidence GAP from a contract
				// that can never be satisfied at create time.
				Subject      string `json:"subject"`
				VerifyMethod string `json:"verifyMethod"`
			} `json:"verdicts"`
		}
		_ = json.Unmarshal([]byte(stdout), &rep)
		// D194: carry the hard-constraint verdicts into the banner so a
		// proven-false world reads VIOLATED (red) and a hard evidence-gap
		// reads BLOCKED (yellow) — not a benign blue REFUSED. Mirrors the
		// standalone verify verb's verdictRollup.
		var roll render.Rollup
		for _, v := range rep.Verdicts {
			if v.Severity != "hard" {
				continue
			}
			switch v.Verdict {
			case "violated":
				roll.Violated = append(roll.Violated, v.Constraint)
			case "unknown":
				roll.Unknown = append(roll.Unknown, v.Constraint)
			case "unverifiable":
				roll.Unverifiable = append(roll.Unverifiable, v.Constraint)
			}
		}
		// D566: a hard provider-api constraint over a capability that is NOT BOUND
		// can never resolve — no observation can exist before the resource does
		// (D290 named this "the natural mistake a first-time author makes with a
		// four-valued verifier"). verify's sentence covers that and "bound but not
		// yet observed" alike, and their remedies are opposite: one is fixed by
		// `observe --record`, the other by a different contract. verify cannot tell
		// them apart — it is a pure function of the two documents, which is why it
		// is dual-implemented and conformance-pinned. Converge HAS the ledger.
		for _, c := range unresolvableAtCreate(rep.Verdicts, o.Ledger) {
			o.say("  %s cannot resolve by observing: no observation can exist before "+
				"the resource does, and %q is not bound. A create-time contract states "+
				"what the candidate declares (method: static) and lets the convergence "+
				"check supply the measured half.", c.constraint, c.subject)
		}
		return o.finish(result{Status: "refused", Code: perr.NotExecutable,
			Exit: 2, Phases: phases, Rollup: roll,
			Reasons: append([]string{"not executable:"}, rep.BlockingReasons...)})
	}
	o.say("  executable: true")

	// ---- 2. plan (with one auto-observe retry on staleness) ----
	planPath := planPathFor(o.ConvergeRunID)
	observed := false
	var planBody string
	for {
		phase("plan")
		o.say("→ plan")
		code, stdout, stderr = o.Run(o.planArgs()...)
		if code == 0 {
			planBody = stdout
			break
		}
		reason := strings.TrimSpace(stderr)
		rcode := childCode(stdout)
		switch {
		case rcode == perr.NothingToChange:
			// for converge, a converged world is the GOAL, not a refusal —
			// unless a pending unknown receipt means the world is NOT known clean (D935)
			if r, blocked := o.refuseIfPending(phases); blocked {
				o.say("  ✗ cannot claim converged — an in-flight operation is unresolved")
				return o.finish(r)
			}
			if g, blocked := o.witnessReality(); blocked {
				if g.Status == "" {
					g.Status = "refused"
				}
				g.Phases = phases
				o.say("  ✗ cannot certify converged — a hard constraint is not witnessed by recorded reality")
				return o.finish(g)
			}
			o.say("  ✓ converged — the world already matches the candidate")
			return o.finish(result{Status: "converged", Exit: 0,
				Phases: phases})
		case code == 2 && rcode == perr.ObservationRequired &&
			!observed && o.Ledger != "":
			// observe is read-only (L2) — porcelain may weave it in, once
			observed = true
			phase("observe-refresh")
			o.say("→ observe (stale knowledge — refreshing, read-only)")
			obsArgs := append([]string{"observe", "--ledger", o.Ledger,
				"--provider", o.Provider, "--at", o.At, "--record"},
				o.policyArgs()...)
			c2, obsOut, e2 := o.Run(obsArgs...)
			if c2 != 0 {
				return o.finish(result{Status: "refused", Exit: 2,
					Phases: phases, Reasons: append(lines(reason), lines(e2)...)})
			}
			// D558: the child's account of what it could NOT measure went to `_`,
			// and its stderr was read only on failure — so the case that matters
			// most was the one dropped: observe SUCCEEDED and, while succeeding,
			// said it could not read something. Same relay D202 does for the plan
			// child's cost estimate: a child's report is not noise because it
			// exited 0.
			for _, d := range observeDiagnostics(obsOut) {
				o.say("  note: %s", d)
			}
			continue
		}
		status, exit := exitStatus(code)
		return o.finish(result{Status: status, Code: rcode, Exit: exit,
			Phases: phases, Reasons: append(lines(reason), applyNext(stdout)...)})
	}
	_ = os.MkdirAll(filepath.Dir(planPath), 0o755)
	if err := os.WriteFile(planPath, []byte(planBody), 0o600); err != nil {
		return o.finish(result{Status: "failed", Exit: 4,
			Phases: phases, Reasons: []string{err.Error()}})
	}
	// D202: the plan child rendered the cost estimate to its stderr; surface it
	// here, before apply, so converge shows the price of the change too.
	o.printCostBlock(stderr)
	o.printSuggestHint(stderr)

	// D232: we passed the stale-refresh decision without needing it — resolve the
	// conditional row honestly (skipped: evidence fresh), not left dangling.
	o.checklist.Skip("observe-refresh", "evidence fresh")

	// D249: the plan may (a) BLOCK a bound capability it cannot reconcile at all
	// (unwired change class, incomparable observation) — held back, never
	// converged; or (b) mark one UNVERIFIED — it reconciled its observable attrs
	// but declares non-observable ones (taken as declared, D136 inconclusive). The
	// other capabilities still apply below. Surface both now; the final verdict
	// refuses the clean "converged" while either stands.
	blockedCaps := planBlockedCaps(planBody)
	if len(blockedCaps) > 0 {
		o.say("  %d capability(ies) BLOCKED — held back, not converged:", len(blockedCaps))
		for _, b := range blockedCaps {
			o.say("    %s", b)
		}
	}
	unverifiedCaps := planUnverifiedCaps(planBody)
	if len(unverifiedCaps) > 0 {
		o.say("  %d capability(ies) reconciled but UNVERIFIED (non-observable attrs, taken as declared):", len(unverifiedCaps))
		for _, u := range unverifiedCaps {
			o.say("    %s", u)
		}
	}
	// Part B: name every converged no-op so "converge did nothing" for a bound
	// capability is never a mystery — one honest line each (bound, observed==
	// declared | no diff | unwitnessed).
	for _, n := range planNoOpCaps(planBody) {
		o.say("  %s", n)
	}

	// D251: a plan that is ENTIRELY creates across several capabilities is the
	// signature of a first deployment OR a LOST/wrong ledger (the ledger holds the
	// bindings; without it converge cannot see what already exists and plans to
	// create it all). A genuine first deploy is fine, so this is an advisory, not a
	// refusal — but a loud one, because applying it against already-existing infra
	// risks duplicates. The remedy is discover + adopt to rebuild state first.
	if creates, total := planCreateSummary(planBody); total >= 3 && creates == total {
		o.say("  ⚠ this plan CREATES all %d capabilities and the ledger records no "+
			"existing bindings.", total)
		o.say("    If this is a FIRST deployment, proceed. If these resources may " +
			"ALREADY EXIST (a lost or wrong ledger), applying will try to create " +
			"duplicates — STOP and rebuild state with `discover` + `adopt` first " +
			"(docs/onboarding.md).")
	}

	// ---- 3. forecast + the decision, never hidden (D49) ----
	phase("forecast")
	o.say("→ forecast")
	fArgs := append([]string{"forecast", planPath, o.Candidate,
		"--ledger", o.Ledger, "--at", o.At}, o.policyArgs()...)
	fcode, fout, ferr := o.Run(fArgs...)
	if fcode != 0 {
		// D291: the forecast is ADVISORY — apply independently re-checks the
		// read-set, the clock and the ledger, so a preview that cannot be
		// produced must not block a correct deploy. But it must not pass
		// SILENTLY either: this phase exists to show a human what will happen
		// immediately before they consent, and until now its exit code was
		// discarded — the row rendered done and the transcript looked like a
		// preview had been shown. Say it, mark the row failed (not done), and
		// carry on with LESS certainty stated out loud.
		o.checklist.Fail("forecast", "no preview produced")
		o.say("!  forecast did not produce a preview (exit %d) — continuing "+
			"WITHOUT it; the destructive check below still reads the sealed "+
			"plan's own risk vectors, and apply re-validates everything", fcode)
		if line := firstLine(ferr); line != "" {
			o.say("   forecast said: %s", line)
		}
	}
	destructive, exposing := describePlan(o, planBody, fout)

	// ---- 4. confirm: --yes skips prompts for already-permitted actions
	// only; destructive plans need their own explicit consent.
	// --json is non-interactive by definition — flags, never prompts ----
	phase("confirm")
	interactive := !o.JSON && o.In != nil
	// D630: a plan that provably OPENS something up needs its own consent. D628 made
	// `securityExposure: certain` derivable — a boolean security attribute weakened,
	// or public exposure switched on — and nothing consumed it, so an update that
	// exposes a database to the internet rode on plain `--yes` exactly as before.
	// It is a separate flag rather than a fold into --allow-data-loss: the two are
	// different harms, and a consent flag whose name does not describe what it
	// permits is not consent.
	if exposing && !o.AllowExposure {
		if o.Yes || !interactive {
			return o.finish(result{Status: "refused",
				Code: perr.ConsentRequired, Exit: 2, Phases: phases,
				Reasons: []string{"plan contains actions that provably increase " +
					"security exposure (a security attribute weakened, or public " +
					"access switched on) — --yes does not cover exposure; add " +
					"--allow-exposure or confirm interactively"}})
		}
		if !prompt(o, "type 'expose' to accept increased exposure: ", "expose") {
			return o.finish(result{Status: "refused", Code: perr.ConsentRequired,
				Exit: 2, Phases: phases,
				Reasons: []string{"exposure not confirmed"}})
		}
	}
	if destructive && !o.AllowDataLoss {
		if o.Yes || !interactive {
			return o.finish(result{Status: "refused",
				Code: perr.ConsentRequired, Exit: 2, Phases: phases,
				Reasons: []string{"plan contains dataLoss/identity-replacing " +
					"actions — --yes does not cover destruction; add " +
					"--allow-data-loss or confirm interactively"}})
		}
		if !prompt(o, "type 'delete' to accept data loss: ", "delete") {
			return o.finish(result{Status: "refused", Exit: 2, Phases: phases,
				Reasons: []string{"not confirmed"}})
		}
	} else if !o.Yes {
		if !interactive {
			return o.finish(result{Status: "refused",
				Code: perr.ConfirmationRequired, Exit: 2, Phases: phases,
				Reasons: []string{"confirmation required — non-interactive " +
					"run; pass --yes to skip the prompt"}})
		}
		if !prompt(o, "type 'apply' to execute this plan: ", "apply") {
			return o.finish(result{Status: "refused",
				Code: perr.ConfirmationRequired, Exit: 2, Phases: phases,
				Reasons: []string{"not confirmed"}})
		}
	}

	// ---- 5. apply: exit codes pass through ----
	phase("apply")
	o.say("→ apply")
	applyArgs := append([]string{"apply", o.Contract, o.Candidate, planPath,
		"--ledger", o.Ledger}, o.vocabArgs()...)
	applyArgs = append(applyArgs, "--provider", o.Provider, "--at", o.At)
	// The porcelain runs its OWN reachability phase after the post-apply observe
	// (where the ledger's Outputs projection is populated). Suppress the apply
	// child's probe so its denied/unknown exit is not misread as an apply failure
	// — one probe per converge, folded into finish().
	applyArgs = append(applyArgs, "--no-reachability")
	applyArgs = append(applyArgs, o.policyArgs()...)
	// D241: a throttled apply (provider-again-later) provably did not land — the
	// receipt concludes as `retryable` (clears pending), so a re-apply is clean.
	// Back off (bounded exponential) and retry rather than surfacing a transient
	// throttle as a converge failure. Any other non-zero code passes through.
	for attempt := 0; ; attempt++ {
		code, stdout, stderr = o.Run(applyArgs...)
		if code == 0 {
			break
		}
		rcode := childCode(stdout)
		if rcode == perr.ProviderAgainLater && attempt < o.maxApplyRetries() {
			d, honored := o.backoffFor(attempt, childRetryAfter(stdout))
			src := "backing off"
			if honored {
				src = "honoring Retry-After"
			}
			o.say(fmt.Sprintf("  throttled (provider-again-later) — %s %s, retry %d/%d",
				src, d, attempt+1, o.maxApplyRetries()))
			o.ledgerEvent("converge.apply.backoff", o.convergeBody(map[string]any{
				"attempt": attempt + 1, "backoffMs": d.Milliseconds(), "retryAfterHonored": honored}))
			o.sleep(d)
			// The throttle wrote a `retryable` receipt (cleared pending) — but that
			// event moved the capability's decision head, so the sealed plan is now
			// stale. Re-plan against current heads before re-applying.
			pcode, pout, perr2 := o.Run(o.planArgs()...)
			if pcode != 0 {
				prc := childCode(pout)
				if prc == perr.NothingToChange {
					if r, blocked := o.refuseIfPending(phases); blocked {
						return o.finish(r)
					}
					if g, blocked := o.witnessReality(); blocked {
						if g.Status == "" {
							g.Status = "applied"
						}
						g.Phases = phases
						return o.finish(g)
					}
					o.say("  ✓ converged during backoff")
					return o.finish(result{Status: "converged", Exit: 0, Phases: phases})
				}
				status, exit := exitStatus(pcode)
				return o.finish(result{Status: status, Code: prc, Exit: exit,
					Phases: phases, Reasons: lines(strings.TrimSpace(perr2))})
			}
			if err := os.WriteFile(planPath, []byte(pout), 0o600); err != nil {
				return o.finish(result{Status: "failed", Exit: 4,
					Phases: phases, Reasons: []string{err.Error()}})
			}
			continue
		}
		// D665: apply refuses a plan with no actions, and for converge a converged
		// world is the GOAL, not a refusal — the same reading the plan phase above
		// already gives this code. A plan can carry zero actions and still be a real
		// plan: the compiler seals one when a capability converged on everything it
		// can compare and left an unobservable attribute unverified (D249).
		if childCode(stdout) == perr.NothingToChange {
			if r, blocked := o.refuseIfPending(phases); blocked {
				return o.finish(r)
			}
			if g, blocked := o.witnessReality(); blocked {
				if g.Status == "" {
					g.Status = "applied"
				}
				g.Phases = phases
				return o.finish(g)
			}
			o.say("  ✓ converged — nothing to apply; the world already matches on " +
				"every attribute this run can compare")
			return o.finish(result{Status: "converged", Exit: 0, Phases: phases,
				Reasons: applyReasons(stdout)})
		}
		status, exit := exitStatus(code)
		// D379: what APPLIED goes first. A run that stopped part-way has already
		// changed the world, and the refusal that stopped it says nothing about that.
		reasons := append(lines(stderr), appliedSummary(stdout)...)
		reasons = append(reasons, applyReasons(stdout)...)
		// Part C: a STALE/reconcile/observation refusal carries a `next` — surface
		// the exact remedy command (resume/observe with --at) instead of a dead end.
		reasons = append(reasons, applyNext(stdout)...)
		return o.finish(result{Status: status, Code: rcode,
			Exit: exit, Phases: phases, Reasons: reasons})
	}
	o.say("  applied")

	// ---- 6. post-apply observe + convergence check, best effort ----
	convergence := ""
	phase("observe-evidence")
	o.say("→ observe (recording reality)")
	postArgs := append([]string{"observe", "--ledger", o.Ledger,
		"--provider", o.Provider, "--at", o.At, "--record"}, o.policyArgs()...)
	if c2, _, _ := o.Run(postArgs...); c2 == 0 {
		phase("convergence-check")
		ccArgs := append([]string{"plan", o.Contract, o.Candidate},
			o.vocabArgs()...)
		ccArgs = append(ccArgs, "--ledger", o.Ledger, "--at", o.At)
		ccArgs = append(ccArgs, o.policyArgs()...)
		pcode, pout, _ := o.Run(ccArgs...)
		pRcode := childCode(pout)
		switch {
		case pcode == 2 && pRcode == perr.NothingToChange:
			o.say("  ✓ converged — verified against observed reality")
			convergence = "verified"
		case pcode == 2 && pRcode == perr.ObservationRequired:
			o.say("  applied; convergence check inconclusive " +
				"(observations do not cover every attribute)")
			convergence = "inconclusive"
		case len(planUnverifiedCaps(pout)) > 0:
			// D249: the just-applied capability reconciled, but declares an
			// attribute the driver cannot observe — the apply SUCCEEDED (we set the
			// declared value), only the post-hoc verification is incomplete. That is
			// D136 inconclusive.
			o.say("  applied; convergence check inconclusive " +
				"(some attributes are not observable)")
			convergence = "inconclusive"
		default:
			o.say("  applied; a further pass may be needed")
			convergence = "unverified"
		}
	} else {
		o.say("  applied; observe unavailable — convergence unverified")
		convergence = "unverified"
	}
	if len(blockedCaps) > 0 {
		// applied what was reconcilable, but a BLOCKED capability means the run did
		// NOT fully converge — a non-zero exit so automation never reads it as green.
		return o.finish(result{Status: "applied", Exit: 2, Phases: phases,
			Convergence: "blocked",
			Reasons: append([]string{"applied the reconcilable capabilities; " +
				"these are BLOCKED (an unwired change class or an incomparable " +
				"observation — fix the driver or the contract):"}, blockedCaps...)})
	}
	if len(unverifiedCaps) > 0 && convergence != "inconclusive" {
		// reconciled everything reconcilable, but a non-observable attribute was
		// taken as declared — honest exit 0, convergence inconclusive (never a
		// green "converged" claim about an attribute we could not see).
		convergence = "inconclusive"
	}

	// ---- 7. reachability probe (Layer 1): an APPLIED public edge that silently
	// 403s is not clean success. The post-apply observe above populated the
	// ledger's Outputs projection (domainName/functionUrl, D316); derive the edge
	// URL from it, GET it, and classify. Only 2xx/3xx is clean; a 401/403 or a
	// transport failure is unknown (BLOCKED) — it does NOT retroactively fail the
	// apply (the resources DID apply), and it does NOT accuse a cause. ----
	// D939: the D935 fail-open has a fourth emitter here — the post-apply exit-0
	// "applied / verified" path, which finish() paints CONVERGED. A MIXED plan
	// reaches it while a receipt is still unknown: one capability carries a real
	// action, a second is retired-unbound with a pending `unknown` receipt. The
	// compiler drops the retired-unbound capability from the plan (compiler.go: the
	// `Bindings[capID] == "" → continue`), so apply's write-set-gated pending guard
	// never sees it, and the plan is NON-empty, so the three whole-empty-plan guards
	// cannot fire either. Gate the post-apply success the same way: refuse
	// (reconcile-required) if any in-scope capability still holds an unresolved
	// receipt — reporting the world converged while that resource may be live is the
	// same fail-open D935 closed for the empty-plan case.
	if r, blocked := o.refuseIfPending(phases); blocked {
		o.say("  ✗ applied, but cannot report converged — an in-flight operation is unresolved")
		return o.finish(r)
	}
	// D1079: witness invariant #1 before painting the world converged. The
	// plan-based convergence check above cannot see a hard constraint left
	// unverifiable (the compiler carries it as "unverified"; the D1071 floor is
	// audit-only), so a hard control witnessed by nothing but the candidate's word
	// would reach exit 0 here — green — while `audit` on this same ledger exits 2.
	if g, blocked := o.witnessReality(); blocked {
		if g.Status == "" {
			g.Status = "applied"
		}
		g.Phases = phases
		o.say("  ✗ applied, but a hard constraint is not witnessed by recorded reality — not converged")
		return o.finish(g)
	}
	final := result{Status: "applied", Exit: 0, Phases: phases, Convergence: convergence}
	o.reachability(&final)
	return o.finish(final)
}

// reachability runs the Layer-1 post-apply reachability probe and folds its
// verdict into the converge result: reachable stays clean (exit 0,
// CONVERGED/APPLIED); every other outcome — a 401/403 anonymous denial or a
// transport failure — is unknown -> BLOCKED (exit 2) with a named, non-accusatory
// cause. Skipped LOUDLY under --no-reachability. No public edge is silent.
func (o *Options) reachability(r *result) {
	if o.NoReachability {
		r.Phases = append(r.Phases, "reachability")
		o.checklist.Enter("reachability")
		o.say("→ reachability")
		o.say("  reachability skipped (--no-reachability) — the public edge was " +
			"NOT probed; an APPLIED edge that 403s will read as clean success")
		r.Reachability = string(reach.Skipped)
		return
	}
	// derive edge targets from the ledger Outputs projection + contract types
	led, err := ledger.ReplayFile(o.Ledger)
	if err != nil {
		return
	}
	c, err := contract.LoadContract(o.Contract)
	if err != nil {
		return
	}
	capTypes := map[string]string{}
	for id, raw := range c.Capabilities {
		if t, _ := raw["type"].(string); t != "" {
			capTypes[id] = t
		}
	}
	outputs := map[string]map[string]any{}
	providerIDs := led.BoundProviderIDs()
	for capID, byName := range led.Outputs {
		m := map[string]any{}
		for name, rec := range byName {
			m[name] = rec.Value
		}
		outputs[capID] = m
	}
	// public-exposure gate for edge types whose URL output exists even when
	// private (Cloud Run): from the candidate's declared network.publicExposure.
	// nil vocabs skips the vocab check — a lightweight read for the gate only.
	public := map[string]bool{}
	if cand, cerr := contract.LoadCandidate(o.Candidate, nil, nil); cerr == nil {
		public = cand.PublicExposureByCap()
	}
	targets := reach.Targets(capTypes, outputs, public)
	if len(targets) == 0 {
		return // no public edge to probe — nothing measured, nothing emitted
	}
	r.Phases = append(r.Phases, "reachability")
	o.checklist.Enter("reachability")
	o.say("→ reachability (probing the public edge)")

	g := o.Getter
	if g == nil {
		g = reach.DefaultGetter()
	}
	results := reach.Probe(g, targets)
	if _, err := reach.Record(led, o.Ledger, o.Env, o.At, o.Provider,
		providerIDs, reach.Observations(results)); err != nil {
		o.say("  reachability observations could not be recorded: %v", err)
	}
	o.foldReach(r, results)
}

// foldReach turns per-edge results into human lines, the machine reachability
// verdict and the banner rollup/exit. Only reachable is clean; every other
// outcome — a 401/403 anonymous denial or a transport failure — is unknown
// (BLOCKED, missing knowledge), which prevents a clean success claim WITHOUT
// accusing a cause. A 401/403 carries the multi-cause anonymous-reachability
// remediation; a transport failure names its own cause.
func (o *Options) foldReach(r *result, results []reach.CapResult) {
	for _, cr := range results {
		switch {
		case cr.Verdict == reach.Reachable:
			o.say("  ✓ %s reachable: GET %s — %s", cr.Capability, cr.URL, cr.Cause)
		case cr.Verdict == reach.Failing:
			// D696: not folded into unknown. This edge was measured and it failed;
			// a reader must not have to tell that apart from "we could not tell".
			o.say("  ✗ %s reachability FAILING: GET %s — %s", cr.Capability, cr.URL, cr.Cause)
		case reach.IsAnonymousDenied(cr):
			o.say("  ? %s reachability unknown: GET %s — %s", cr.Capability, cr.URL, cr.Cause)
			o.say("    %s", reach.AnonymousRemediation)
		default: // unknown: transport failure or an unexpected status
			o.say("  ? %s reachability unknown (from here): GET %s — %s",
				cr.Capability, cr.URL, cr.Cause)
		}
	}
	if len(results) > 0 {
		// The scope of what was measured, once, next to the verdicts (D696): a
		// reader keying on "reachable" must be able to see what it did not cover.
		o.say("  checked: %s", reach.Checked)
	}
	violated, unknown, verdict := reach.Fold(results)
	r.Rollup.Violated = append(r.Rollup.Violated, violated...)
	r.Rollup.Unknown = append(r.Rollup.Unknown, unknown...)
	switch verdict {
	case reach.Failing:
		r.Reachability, r.Exit = string(reach.Failing), 2
	case reach.Unknown:
		r.Reachability, r.Exit = string(reach.Unknown), 2
	default:
		r.Reachability = string(reach.Reachable)
	}
}

// planCreateSummary (D251) counts a plan's actions and how many are creates —
// an all-creates plan across several capabilities is the lost-ledger signature.
func planCreateSummary(planBody string) (creates, total int) {
	var p struct {
		Plan struct {
			Actions []struct {
				Operation string `json:"operation"`
			} `json:"actions"`
		} `json:"plan"`
	}
	if json.Unmarshal([]byte(planBody), &p) != nil {
		return 0, 0
	}
	for _, a := range p.Plan.Actions {
		total++
		if a.Operation == "create" {
			creates++
		}
	}
	return creates, total
}

// planUnverifiedCaps (D249) extracts "capability: attr, attr" for every capability
// that reconciled but declares non-observable attributes (taken as declared).
func planUnverifiedCaps(planBody string) []string {
	var p struct {
		Plan struct {
			Unverified []struct {
				Capability string   `json:"capability"`
				Attributes []string `json:"attributes"`
			} `json:"unverified"`
		} `json:"plan"`
	}
	if json.Unmarshal([]byte(planBody), &p) != nil {
		return nil
	}
	out := make([]string, 0, len(p.Plan.Unverified))
	for _, u := range p.Plan.Unverified {
		out = append(out, u.Capability+": "+strings.Join(u.Attributes, ", "))
	}
	return out
}

// planBlockedCaps (D249) extracts the "capability: reason" of every capability the
// plan held back as un-reconcilable. Empty on a clean plan or an unparseable one
// (the risk gate in describePlan is the fail-closed guard; this is display-only).
func planBlockedCaps(planBody string) []string {
	var p struct {
		Plan struct {
			Blocked []struct {
				Capability string `json:"capability"`
				Reason     string `json:"reason"`
			} `json:"blocked"`
		} `json:"plan"`
	}
	if json.Unmarshal([]byte(planBody), &p) != nil {
		return nil
	}
	out := make([]string, 0, len(p.Plan.Blocked))
	for _, b := range p.Plan.Blocked {
		out = append(out, b.Capability+": "+b.Reason)
	}
	return out
}

// planNoOpCaps (Part B) extracts "capability: no-op (reason)" for every bound
// capability the plan produced no action for. Display-only, like the cost block.
func planNoOpCaps(planBody string) []string {
	var p struct {
		Plan struct {
			NoOp []struct {
				Capability string `json:"capability"`
				Reason     string `json:"reason"`
			} `json:"noop"`
		} `json:"plan"`
	}
	if json.Unmarshal([]byte(planBody), &p) != nil {
		return nil
	}
	out := make([]string, 0, len(p.Plan.NoOp))
	for _, n := range p.Plan.NoOp {
		out = append(out, n.Capability+": no-op ("+n.Reason+")")
	}
	return out
}

// describePlan surfaces the decision: actions, risk vectors, delete
// targets, drift. Returns whether the plan is destructive.
func describePlan(o Options, planBody, forecastOut string) (bool, bool) {
	destructive := false
	exposing := false
	var plan struct {
		Plan struct {
			Actions []struct {
				ID               string `json:"id"`
				Operation        string `json:"operation"`
				TargetProviderID string `json:"targetProviderId"`
				Risk             struct {
					Reversibility       string `json:"reversibility"`
					DataLoss            string `json:"dataLoss"`
					Downtime            string `json:"downtime"`
					SecurityExposure    string `json:"securityExposure"`
					IdentityReplacement bool   `json:"identityReplacement"`
				} `json:"risk"`
			} `json:"actions"`
		} `json:"plan"`
	}
	if err := json.Unmarshal([]byte(planBody), &plan); err != nil {
		// fail-CLOSED on the consent gate: if the plan cannot be parsed for
		// risk, converge cannot rule out data loss / identity replacement, so
		// it must treat the plan as destructive and demand explicit consent
		// (--allow-data-loss) rather than skip the gate on an empty Actions.
		// Unreachable while `plan` always emits valid JSON on exit 0, but the
		// gate must not depend on that contract holding forever (D51).
		o.say("  plan output could not be parsed for risk — treating as " +
			"destructive (fail-closed)")
		return true, true
	}
	o.say("  plan:")
	for _, a := range plan.Plan.Actions {
		// D630: securityExposure is printed too. It became derivable in D628 and
		// nothing showed it, so the line a human reads before consenting omitted the
		// one field that says "this action opens something up".
		line := fmt.Sprintf("    %s %s [%s dataLoss=%s downtime=%s exposure=%s]",
			a.Operation, a.ID, a.Risk.Reversibility, a.Risk.DataLoss,
			a.Risk.Downtime, a.Risk.SecurityExposure)
		if a.TargetProviderID != "" {
			line += " target=" + a.TargetProviderID
		}
		o.say("%s", line)
		if a.Risk.DataLoss == "certain" || a.Risk.IdentityReplacement {
			destructive = true
		}
		if a.Risk.SecurityExposure == "certain" {
			exposing = true
		}
	}
	var fc struct {
		Forecast struct {
			Rollup map[string]int `json:"rollup"`
		} `json:"forecast"`
	}
	if json.Unmarshal([]byte(forecastOut), &fc) == nil &&
		len(fc.Forecast.Rollup) > 0 {
		// human channel: sorted, nonzero counts only — never a raw map
		keys := make([]string, 0, len(fc.Forecast.Rollup))
		for k, v := range fc.Forecast.Rollup {
			if v != 0 {
				keys = append(keys, k)
			}
		}
		sort.Strings(keys)
		parts := make([]string, len(keys))
		for i, k := range keys {
			parts[i] = fmt.Sprintf("%s %d", k, fc.Forecast.Rollup[k])
		}
		if len(parts) == 0 {
			parts = []string{"no effects"}
		}
		o.say("  forecast rollup: %s", strings.Join(parts, ", "))
	}
	return destructive, exposing
}

// firstLine lifts the first non-empty line of a child's stderr for the human
// channel — the whole stream would drown the transcript, and none of it is
// parsed (D89: prose is never a contract).
func firstLine(s string) string {
	for _, l := range strings.Split(s, "\n") {
		if t := strings.TrimSpace(l); t != "" {
			return t
		}
	}
	return ""
}

func prompt(o Options, msg, expected string) bool {
	if o.In == nil {
		return false
	}
	fmt.Fprint(o.Out, msg)
	line, err := bufio.NewReader(o.In).ReadString('\n')
	if err != nil && line == "" {
		return false
	}
	return strings.TrimSpace(line) == expected
}

// childCode lifts the machine code out of a child verb's JSON result
// so porcelain refusals stay routable (D64).
func childCode(stdout string) perr.Code {
	var res struct {
		Code string `json:"code"`
	}
	if json.Unmarshal([]byte(stdout), &res) == nil {
		return perr.Code(res.Code)
	}
	return ""
}

// childRetryAfter reads the provider's Retry-After hint (seconds) from an apply
// result (D243); 0 when absent (converge then uses its own backoff).
func childRetryAfter(stdout string) int {
	var res struct {
		RetryAfterSeconds int `json:"retryAfterSeconds"`
	}
	if json.Unmarshal([]byte(stdout), &res) == nil {
		return res.RetryAfterSeconds
	}
	return 0
}

func applyReasons(stdout string) []string {
	var res struct {
		Reasons []string `json:"reasons"`
	}
	if json.Unmarshal([]byte(stdout), &res) == nil {
		return res.Reasons
	}
	return nil
}

// appliedSummary lifts apply's PER-ACTION outcomes (Part A `outcomes`) and folds
// them into one advisory line naming what actually happened (D379).
//
// apply has emitted this map since fail-isolation landed; nothing read it. So a
// partially-applied run reported only its refusal, and the operator could not
// tell from the status that a sibling action had already changed production —
// which is how a field partner deployed a bad image and found the outage by
// hand. `reasons` names every non-success; the SUCCESSES were nowhere.
//
// Advisory only: it never changes the status or the exit code. Those stay the
// machine contract; this is the sentence a human needed and did not get.
func appliedSummary(stdout string) []string {
	var res struct {
		Outcomes map[string]string `json:"outcomes"`
	}
	if json.Unmarshal([]byte(stdout), &res) != nil || len(res.Outcomes) == 0 {
		return nil
	}
	byOutcome := map[string][]string{}
	for id, oc := range res.Outcomes {
		byOutcome[oc] = append(byOutcome[oc], id)
	}
	total := len(res.Outcomes)
	succeeded := byOutcome["succeeded"]
	sort.Strings(succeeded)

	// An UNKNOWN outcome is not a "did not apply" (D529, from the field). If the
	// run does not know how an action ended, it does not know how many actions
	// applied either, and "nothing was changed" reads as a confirmation that the
	// world is untouched — a partner met exactly that line while the Lambda it
	// described had been created. Three states, not two: applied / not applied /
	// NOT KNOWN, and the third may not be dressed as the second. This is D29's rule
	// (a transient outcome is `unknown`, never a terminal answer) in the sentence a
	// human reads, which had been saying the opposite of the machine contract.
	unknown := byOutcome["unknown"]
	sort.Strings(unknown)

	// The line leads with what CHANGED, because that is the fact an operator
	// needs first when a run did not finish cleanly.
	var out []string
	switch {
	case len(succeeded) > 0:
		out = append(out, fmt.Sprintf(
			"%d of %d actions applied before the run stopped — the world HAS changed: %s",
			len(succeeded), total, strings.Join(succeeded, ", ")))
	case len(unknown) > 0:
		out = append(out, fmt.Sprintf(
			"0 of %d actions confirmed applied, %d UNKNOWN — the world MAY have changed; "+
				"run `resume` before retrying, or a retry may duplicate: %s",
			total, len(unknown), strings.Join(unknown, ", ")))
	default:
		out = append(out, fmt.Sprintf(
			"0 of %d actions applied — nothing was changed", total))
	}
	// A confirmed change leads, but the uncertainty behind it must survive.
	if len(succeeded) > 0 && len(unknown) > 0 {
		out = append(out, fmt.Sprintf(
			"%d further action(s) UNKNOWN — the world MAY have changed beyond that; "+
				"run `resume` before retrying: %s", len(unknown), strings.Join(unknown, ", ")))
	}
	for _, oc := range []string{"failed", "unknown", "throttled", "skipped"} {
		ids := byOutcome[oc]
		if len(ids) == 0 {
			continue
		}
		sort.Strings(ids)
		out = append(out, fmt.Sprintf("  %s: %s", oc, strings.Join(ids, ", ")))
	}
	return out
}

// applyNext lifts the advisory `next` (D230) the apply/plan child emitted for a
// refusal — the exact remediation command plus its note — so converge surfaces
// the pointer (e.g. `groundhold resume <contract> --ledger ... --at <clock>` on a
// STALE/reconcile refusal) instead of leaving the operator with no way forward
// (Acme field report #4). Advisory only: never parsed for control flow, never
// changes the exit code (that stays the machine `code`).
func applyNext(stdout string) []string {
	var res struct {
		Next *struct {
			Command string `json:"command"`
			Note    string `json:"note"`
		} `json:"next"`
	}
	if json.Unmarshal([]byte(stdout), &res) != nil || res.Next == nil || res.Next.Command == "" {
		return nil
	}
	out := []string{"next: " + res.Next.Command}
	if res.Next.Note != "" {
		out = append(out, "      "+res.Next.Note)
	}
	return out
}

func lines(s string) []string {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	return strings.Split(s, "\n")
}

// observeDiagnostics pulls the diagnostics out of an observe child's JSON. A body
// that does not parse yields none rather than an error: converge is mid-run and a
// malformed child report must not turn a successful refresh into a failure. The
// child's exit code already governs whether the refresh worked.
func observeDiagnostics(stdout string) []string {
	var doc struct {
		Diagnostics []string `json:"diagnostics"`
	}
	if json.Unmarshal([]byte(stdout), &doc) != nil {
		return nil
	}
	return doc.Diagnostics
}

// unresolvableAtCreate returns the hard, unknown, provider-api constraints whose
// subject has no binding — the ones observing can never settle. A ledger that
// cannot be read yields NOTHING rather than everything: claiming a capability is
// unbound because the ledger was unreadable would tell an author to rewrite a
// correct contract, and a wrong remedy is worse than none (D75 skip-loudly applies
// to advice too).
func unresolvableAtCreate(verdicts []struct {
	Constraint   string `json:"constraint"`
	Severity     string `json:"severity"`
	Verdict      string `json:"verdict"`
	Subject      string `json:"subject"`
	VerifyMethod string `json:"verifyMethod"`
}, ledgerPath string) []struct{ constraint, subject string } {
	var out []struct{ constraint, subject string }
	if ledgerPath == "" {
		return out
	}
	led, err := ledger.ReplayFile(ledgerPath)
	if err != nil {
		return out
	}
	bound := led.BoundProviderIDs()
	for _, v := range verdicts {
		if v.Severity != "hard" || v.Verdict != "unknown" ||
			v.VerifyMethod != "provider-api" || v.Subject == "" {
			continue
		}
		if _, ok := bound[v.Subject]; ok {
			continue // observing WILL resolve this one
		}
		out = append(out, struct{ constraint, subject string }{v.Constraint, v.Subject})
	}
	return out
}
