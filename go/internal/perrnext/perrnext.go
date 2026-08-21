// Package perrnext builds an ADVISORY "next step" for a refusal (D230): the
// exact command to run, contract/candidate edit to make, or permission to grant
// that would unblock THIS invocation. It is invocation-specific where the static
// perr.Explain remediation is generic. Two hard properties:
//
//   - Advisory by construction: nothing in the runtime reads a Next. The type
//     lives here beside perr; engine packages (compiler, apply, ...) never import
//     it, so a `next` can never change control flow. The machine `code` stays the
//     contract.
//   - Omit over guess (the honesty rule): a `command` is emitted iff EVERY
//     argument the target verb requires is known verbatim — echoed from the
//     operator's own inputs or from facts the refusal itself established. A
//     required-but-unknown argument means no command (the static remediation
//     stands); an optional-unknown flag is omitted, never placeholdered. Values
//     are never normalized, defaulted, or reformatted — rewriting an input is a
//     guess. Placeholders are allowed only for arguments the runtime cannot know
//     (operator identity/choice); they force runnable=false.
package perrnext

import (
	"sort"
	"strings"

	"groundhold/internal/perr"
)

// Kind discriminates the remediation shape. Only `command` is executable.
type Kind string

const (
	KindCommand Kind = "command" // a runnable groundhold invocation
	KindEdit    Kind = "edit"    // a contract/candidate change a human must make
	KindGrant   Kind = "grant"   // permissions to grant via the operator's IAM tooling
)

// Edit is a document change (kind=edit) — there is nothing to execute, which
// preserves gates like consent structurally.
type Edit struct {
	Path    string `json:"path"`             // the file to edit (the operator's own path)
	Pointer string `json:"pointer"`          // dotted location within it
	Insert  string `json:"insert,omitempty"` // the snippet to add (verbatim)
}

// Grant names permissions to grant (kind=grant) — never a provider CLI command
// (the operator's role model and org policy are unknowable to the runtime).
type Grant struct {
	Principal   string   `json:"principal"`
	Permissions []string `json:"permissions"` // sorted, the authoritative denied set
}

// Next is the advisory remediation. Optional sibling of code/reasons; absent
// when nothing honest can be said (the static remediation then stands).
type Next struct {
	Kind         Kind     `json:"kind"`
	Argv         []string `json:"argv,omitempty"`         // kind=command; argv[0]=="groundhold", executable as-is
	Command      string   `json:"command,omitempty"`      // display string derived from Argv by the one quoter
	Edit         *Edit    `json:"edit,omitempty"`         // kind=edit
	Grant        *Grant   `json:"grant,omitempty"`        // kind=grant
	Placeholders []string `json:"placeholders,omitempty"` // present iff any arg is templated
	Runnable     bool     `json:"runnable,omitempty"`     // kind=command AND no placeholders
	Retry        []string `json:"retry,omitempty"`        // the operator's own invocation, to run AFTER the fix
	Note         string   `json:"note,omitempty"`
}

// Invocation is the operator's own inputs, packaged once at the CLI boundary.
// Values are echoed verbatim — relative paths stay relative (correct in the
// operator's cwd; absolutizing them would be a rewrite).
type Invocation struct {
	Verb      string
	Contract  string
	Candidate string
	Ledger    string
	Provider  string
	Project   string
	At        string
	Argv      []string // the process argv, for `retry`
}

// Detail carries the facts a refusal SITE uniquely knows. Zero value is fine for
// command builders that need only the invocation.
type Detail struct {
	Capability  string   // consent-required, reference-invalid
	Principal   string   // provider-permission-denied
	Permissions []string // provider-permission-denied
	RefPointer  string   // reference-invalid: the $ref's location in the candidate
	Note        string   // reference-invalid: the structured "what's wrong" prose
}

// retryOf echoes the operator's own invocation with argv[0] normalized.
func retryOf(inv Invocation) []string {
	if len(inv.Argv) == 0 {
		return nil
	}
	out := append([]string(nil), inv.Argv...)
	out[0] = "groundhold"
	return out
}

func commandNext(argv []string, inv Invocation, note string) *Next {
	return &Next{Kind: KindCommand, Argv: argv, Command: quote(argv),
		Runnable: true, Retry: retryOf(inv), Note: note}
}

func observationRequired(inv Invocation, _ Detail) (*Next, bool) {
	// observe --record needs a ledger + a clock; provider is optional (omit if
	// unknown, never placeholdered).
	if inv.Ledger == "" || inv.At == "" {
		return nil, false
	}
	argv := []string{"groundhold", "observe", "--ledger", inv.Ledger}
	if inv.Provider != "" {
		argv = append(argv, "--provider", inv.Provider)
	}
	argv = append(argv, "--at", inv.At, "--record")
	return commandNext(argv, inv,
		"re-observe against the ledger with the same clock (or a fresher --at), then re-run"), true
}

func reconcileRequired(inv Invocation, _ Detail) (*Next, bool) {
	if inv.Contract == "" || inv.Ledger == "" || inv.At == "" {
		return nil, false
	}
	argv := []string{"groundhold", "resume", inv.Contract, "--ledger", inv.Ledger}
	if inv.Provider != "" {
		argv = append(argv, "--provider", inv.Provider)
	}
	argv = append(argv, "--at", inv.At)
	return commandNext(argv, inv,
		"resume asks the provider what actually happened, then re-run"), true
}

func consentRequired(inv Invocation, d Detail) (*Next, bool) {
	// a contract EDIT, never a command — consent is a human decision (D48).
	if inv.Contract == "" || d.Capability == "" {
		return nil, false
	}
	return &Next{
		Kind: KindEdit,
		Edit: &Edit{Path: inv.Contract, Pointer: "autonomy.allow_replace_stateful",
			Insert: "autonomy:\n  allow_replace_stateful:\n    - " + d.Capability},
		Retry: retryOf(inv),
		Note: "consent is a human decision recorded in the contract (D48, scoped at " +
			"compile AND apply); do not apply this edit autonomously — then re-run",
	}, true
}

func permissionDenied(inv Invocation, d Detail) (*Next, bool) {
	if len(d.Permissions) == 0 {
		return nil, false
	}
	perms := append([]string(nil), d.Permissions...)
	sort.Strings(perms)
	principal := d.Principal
	if principal == "" {
		principal = "the acting identity"
	}
	return &Next{
		Kind:  KindGrant,
		Grant: &Grant{Principal: principal, Permissions: perms},
		Retry: retryOf(inv),
		Note:  "grant these exact permissions via your IAM tooling; a preflight pass is evidence, not proof",
	}, true
}

func candidateEditNext(inv Invocation, d Detail) (*Next, bool) {
	// a candidate EDIT — the compiler must have surfaced the operand's location
	// (a $ref's slot for reference-invalid, the offending operand key for
	// unknown-operand). Both point the operator at exactly one line to fix.
	if inv.Candidate == "" || d.RefPointer == "" {
		return nil, false
	}
	return &Next{
		Kind:  KindEdit,
		Edit:  &Edit{Path: inv.Candidate, Pointer: d.RefPointer},
		Retry: retryOf(inv),
		Note:  d.Note,
	}, true
}

var nextBuilders = map[perr.Code]func(Invocation, Detail) (*Next, bool){
	perr.ObservationRequired:      observationRequired,
	perr.ReconcileRequired:        reconcileRequired,
	perr.ConsentRequired:          consentRequired,
	perr.ProviderPermissionDenied: permissionDenied,
	perr.ReferenceInvalid:         candidateEditNext,
	perr.UnknownOperand:           candidateEditNext,
}

// noNext is the EXPLICIT set of remediable codes that deliberately get no
// actionable next — either the fix is situational (wait, re-author) or a wrong
// command could deepen damage. Together with nextBuilders it must cover every
// code in perr.Explain (the completeness test enforces this): a new code cannot
// land without a decision here.
var noNext = map[perr.Code]bool{
	perr.StructuralError:      true, // fix the document by hand; no single command
	perr.NotExecutable:        true, // fix the candidate/contract; situational
	perr.NothingToChange:      true, // success, nothing to do
	perr.ReconcilePending:     true, // retry resume LATER — no better command now
	perr.ProviderAgainLater:   true, // D237: wait for the backoff, then re-run the SAME verb — no better command now
	perr.ConfirmationRequired: true, // a human must confirm interactively
	perr.ReadSetMismatch:      true, // pinned-doc paths are unknown to the runtime
	perr.StaleDecision:        true, // re-observe/re-plan; situational
	perr.LeaseConflict:        true, // wait or break deliberately — the break hint could be destructive
	perr.ClockRegress:         true, // fix the writer clock; environmental
	perr.BindingConflict:      true, // unadopt/retire first; situational
	perr.AdoptionMismatch:     true, // fix candidate OR resource; a human judges which
	perr.ProviderRefused:      true, // change the implementation block; situational
	perr.SurveyDrift:          true, // reconcile contract vs survey; a human decides
	perr.ReferenceUnresolved:  true, // apply-time; inspect the producer receipt, then resume (situational)
	perr.MappingSchemaDrift:   true, // re-author the mapping; situational
	perr.UnsupportedOperation: true, // out of scope
	perr.ApplyFailed:          true, // inspect receipts, re-plan; situational
	perr.LedgerCorrupted:      true, // repair flow; any command may deepen damage
	// D1154: the remediation is to run a DIFFERENT BUILD, which is not a command
	// this runtime can offer — it is the one thing a next-step suggestion cannot
	// hand over. And it must not fall back to a groundhold command: every verb this
	// build has will refuse the same file for the same reason, and the two that
	// would happily act on it (`repair --quarantine`) destroy the history that is
	// intact. Silence is the honest answer here.
	perr.LedgerVersionAhead:    true,
	perr.PreflightInconclusive: true, // fix the check environment; situational
	// D330: the background-run family. `resume` is the right remediation for two
	// of these, but it takes the CONTRACT and the run verbs (`wait`, `runs`) never
	// do — so the command is not derivable from the operator's own inputs, and the
	// honesty rule says omit rather than guess a path.
	perr.RunUnknown:        true, // check the handle / read the run's log; environmental
	perr.RunRunning:        true, // nothing to do — wait
	perr.RunStalled:        true, // resume, but the contract is not among this verb's inputs
	perr.RunNeedsReconcile: true, // same: resume needs a contract the run verbs never take
	perr.RunDone:           true, // success, nothing to do
	perr.RunFailed:         true, // inspect the run's own refusal; situational
	perr.WaitTimeout:       true, // a longer --timeout is the operator's choice; `retry` already echoes the invocation
	// D1099: horizon's remediation is not a single command — its document already carries
	// per-transition `advice` (a different verb and deadline for each projected decay or
	// lapse: refresh, resume, wait). A single `next` would flatten a list of distinct,
	// differently-timed actions into one, so it is honestly omitted here.
	perr.HorizonActionRequired: true,
}

// NextFor returns the advisory next for a refusal, or nil when none is honest.
func NextFor(inv Invocation, code perr.Code, d Detail) *Next {
	if b, ok := nextBuilders[code]; ok {
		if n, ok := b(inv, d); ok {
			return n
		}
	}
	return nil
}

// Codes returns the codes with a builder and the explicit no-next set — the
// completeness test asserts their union covers perr.Explain.
func Codes() (builders, none []perr.Code) {
	for c := range nextBuilders {
		builders = append(builders, c)
	}
	for c := range noNext {
		none = append(none, c)
	}
	return
}

// quote renders argv as a copy-pasteable command, single-quoting any element
// that contains a space or shell metacharacter. Deterministic (no environment).
func quote(argv []string) string {
	var b strings.Builder
	for i, a := range argv {
		if i > 0 {
			b.WriteByte(' ')
		}
		b.WriteString(shellQuote(a))
	}
	return b.String()
}

func shellQuote(s string) string {
	if s == "" {
		return "''"
	}
	if !strings.ContainsAny(s, " \t\n'\"\\$`&|;<>()*?![]{}#~") {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
