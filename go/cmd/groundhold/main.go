// groundhold — Go runtime of the Infrastructure Contract spec v0.1.
// Passes the same conformance suite as the Python reference, through
// its own binary (D22, D24): `make conformance-go`.
package main

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"time"

	"gopkg.in/yaml.v3"

	"sort"
	"strings"

	"groundhold/internal/adopt"
	"groundhold/internal/apireq"
	"groundhold/internal/apiver"
	"groundhold/internal/apply"
	"groundhold/internal/audit"
	"groundhold/internal/aws"
	"groundhold/internal/azure"
	"groundhold/internal/backup"
	"groundhold/internal/canonical"
	"groundhold/internal/cloudflare"
	"groundhold/internal/collector"
	"groundhold/internal/compiler"
	"groundhold/internal/compose"
	"groundhold/internal/contract"
	"groundhold/internal/converge"
	"groundhold/internal/costproj"
	"groundhold/internal/crawl"
	"groundhold/internal/detach"
	"groundhold/internal/discover"
	"groundhold/internal/docio"
	"groundhold/internal/edgecanary"
	"groundhold/internal/export"
	"groundhold/internal/forecast"
	"groundhold/internal/gcp"
	"groundhold/internal/hetzner"
	"groundhold/internal/importer"
	"groundhold/internal/k8s"
	"groundhold/internal/ledger"
	"groundhold/internal/mcp"
	"groundhold/internal/notify"
	"groundhold/internal/observe"
	"groundhold/internal/pace"
	"groundhold/internal/pair"
	"groundhold/internal/parity"
	"groundhold/internal/perr"
	"groundhold/internal/perrnext"
	"groundhold/internal/plan"
	"groundhold/internal/planview"
	"groundhold/internal/posture"
	"groundhold/internal/probe"
	"groundhold/internal/progress"
	"groundhold/internal/provider"
	"groundhold/internal/publish"
	"groundhold/internal/reach"
	"groundhold/internal/react"
	"groundhold/internal/refresh"
	"groundhold/internal/render"
	"groundhold/internal/restore"
	"groundhold/internal/resume"
	"groundhold/internal/runstatus"
	"groundhold/internal/scalars"
	"groundhold/internal/scenario"
	"groundhold/internal/state"
	"groundhold/internal/suggest"
	"groundhold/internal/survey"
	"groundhold/internal/upstash"
	"groundhold/internal/verify"
	"groundhold/internal/vocab"
)

const usage = `groundhold — Go runtime of the Infrastructure Contract spec v0.1

Usage:
  groundhold validate <contract.yaml>
  groundhold verify   <contract.yaml> <candidate.yaml> [--json] [--vocab <dir>]
  groundhold plan     <contract.yaml> <candidate.yaml> [--vocab <dir>] [--project <p>]
                   [--ledger <f>] [--bindings <f>] [--observations <f>] [--at <ts>]
  groundhold preflight <contract.yaml> <candidate.yaml> --provider <aws|gcp|azure|k8s>
                   [--project <p>]  (every capability's missing implementation
                    operands + unsatisfiable attributes in ONE pass; exit 2 if any)
  groundhold forecast <plan.yaml> <candidate.yaml> [--ledger <file>]
                   [--heads <f>] [--bindings <f>] [--observations <f>] [--at <ts>]
  groundhold apply    <contract.yaml> <candidate.yaml> <plan.yaml>
                   --ledger <file> [--provider fake|gcp|aws|k8s] [--at <ts>]
                   [--vocab <dir>] [--require-preflight] [--no-reachability]
                   [--detach] [--fail-key <k>] [--unknown-key <k>]
  groundhold observe  (--ledger <file> | --bindings <file>)
                   [--provider fake|gcp|aws] [--at <ts>] [--ttl <s>] [--record]
  groundhold example  <contract|candidate> [<contract.yaml>]
                   (print a valid starter document; "candidate <contract.yaml>"
                    scaffolds one entry per capability with its vocab attributes)
  groundhold compose  <base.yaml> [overlay.yaml ...]
                   (merge a base contract with per-environment overlays into ONE
                    flat contract — dev/staging/prod DRY without inheritance;
                    constraints/capabilities union by id, later overlays win)
  groundhold diff     <a.yaml> <b.yaml> [--json]
                   (constraint/capability delta + whether a's invariants are a
                    subset of b's — the dev ⊆ staging ⊆ prod promotion proof)
  groundhold cost     <plan.yaml> <candidate.yaml> [--currency <ISO>] [--json]
                   (authoritative cost.monthly rollup week/month/year for a plan
                    — the number plan/converge show; --json for the console)
  groundhold suggest  <contract.yaml> [<candidate.yaml>] [--json] [--as hard|soft]
                   (deterministic, cited hardening advisor: recommended-but-
                    absent constraints as ready-to-paste snippets — ADVISORY,
                    never gates; --json for the console)
  groundhold hash     <document.yaml>
  groundhold keygen   <keyfile>  (new ed25519 signing seed, hex, 0600;
                    prints the public key — hand THAT to verifiers)
  groundhold explain  <error-code | vocab-path> [--vocab <dir>]
                   (one place to ask about any noun the system emits:
                    machine error codes and vocabulary attributes)
  groundhold apiver   [--live <snapshot>] [--json]
                   (the API-version pins each driver targets; --live compares
                    against a canary-fetched version list and surfaces
                    newer/deprecated drift — exit 2 on actionable drift)
  groundhold apireq   [--provider aws|gcp|azure] [--json]
                   (the KNOWN provider API-requirement registry (D329) the
                    functional canary iterates as data — server-side authz/
                    protocol facts a version pin and shape fixture cannot see)
  groundhold [--provider aws|gcp] apireq classify --applied <b> --deployed <b>
                   --http-status <n> [--transport]  (edge-canary verdict core: an
                    observed public-edge outcome (AWS CloudFront-OAC->Function-URL,
                    or GCP public Cloud Run with --provider gcp) -> class + exit
                    0 green / 10 provider-drift / 20 regression / 30 flake,
                    citing the apireq entry on drift where one exists (AWS);
                    used by canary-aws.sh / canary-gcp.sh)
  groundhold parity   [capability.type] [--json]
                   (cross-cloud capability matrix: for each cloud, does it
                    FULFIL a capability, STRUCTURALLY cannot (gap), or lacks a
                    driver (unbuilt)? the bake-off's deterministic vendor map)
  groundhold survey   <contract.yaml> --survey <s.json> [--survey ...]
                   [--complete]  (code-survey coverage vs the contract,
                    spec/survey.md: uncovered required dependencies are
                    drift; unwitnessed capabilities harden into drift
                    only under --complete)
  groundhold scenario <scenario.yaml>
  groundhold mcp      [--print-config] (MCP server over stdio;
                    GROUNDHOLD_MCP_ALLOW_APPLY=1 enables the two-step apply tool;
                    --print-config prints the .mcp.json + one-liner to wire it
                    into an agent — no server is started)
  groundhold converge <contract.yaml> <candidate.yaml> --ledger <file>
                   [--provider fake|gcp|aws] [--vocab <dir>] [--project <p>]
                   [--at <ts>] [--yes] [--allow-data-loss] [--json] [--detach]
                   [--no-reachability]  (skip the post-apply public-edge probe)
  groundhold discover [--provider fake|gcp|aws|azure|k8s] [--project <p>] [--region <r>]
                   [--at <ts>]  (read-only; never writes the ledger)
                   (k8s: --region is the namespace, empty = cluster-wide)
  groundhold k8s-skeleton <group>/<version>/<Kind> --capability <cap>
                   [--kubeconfig <f>] [--context <c>]  (offline mapping
                   scaffolding: emits the machine half only, authors no
                   semantics; use "core" for the core group)
  groundhold pair <provider> --cred-ref <kind>:<value> [--scope <s>] [--verify-ref]
                   (register a credential REFERENCE for the gentle crawler,
                   never a secret; gcp|aws|azure|k8s only, OAuth deferred D141)
  groundhold connections   (list pairings; references only, never secrets)
  groundhold unpair <provider> [--scope <s>]
  groundhold crawl --at <ts> [--budget <n>] [--out <dir>] [--pairings <f>]
                   (gentle read-only context crawl over the paired providers;
                   rate-limited + backoff, partiality is recorded not hidden)
  groundhold refresh --ledger <f> --at <ts> [--window <s>] [--provider <p>]
                   [--budget <n>]  (gentle sweep: re-observe bound resources
                   whose proof is stale or decaying within --window, keeping
                   evidence fresh so verdicts never rest on a decayed proof)
  groundhold backup --ledger <f> --out <dir> [--documents <store>]
                   (disaster recovery: bundle the anchor + one capsule per
                   capability + the pinned contract blobs into one directory)
  groundhold restore --out <ledger> --check <anchor.json> [--partial] [--documents <dir>] <capsule.json>...
                   (disaster recovery: rebuild a ledger from a verified capsule
                   set + its off-host anchor; refuses a set that does not hold.
                   --partial restores the sound capabilities and marks the rest
                   unknown+code; --documents re-verifies the backup's contract blobs)
  groundhold react --event <file> --ledger <f> --at <ts> [--crawl <base.json>]
                   [--contract <f>...] [--out <dir>]  (event-driven ingress:
                   map one cloud change or k8s watch event to a scope, re-list it,
                   splice, reclassify posture — the opt-in real-time path over polling)
  groundhold posture --ledger <f> --at <ts> [--crawl <crawl.json>]
                   [--contract <f>...] [--out <dir>]  (proactive classifier:
                   managed-ok/drifted/shadow/decayed/unknown with adopt/converge/
                   observe recipes; exit 2 on shadow or drift; writes nothing)
  groundhold adopt    <contract.yaml> <candidate.yaml> --ledger <file>
                   --map <cap=providerId> [--map ...] [--provider fake|gcp]
                   [--project <p>] [--vocab <dir>] [--at <ts>]
                   [--discovery <file>]
                   (binds existing resources; mutates the ledger, never
                    the cloud; refuses when reality disagrees)
  groundhold unadopt  <contract.yaml> <capability> --ledger <file> [--at <ts>]
                   (removes the binding, never the resource)
  groundhold hints    <state-file> [--format auto|tfstate|pulumi]
                   (terraform/pulumi state -> adoption hints; pure
                    translation — hints, never a contract)
  groundhold export   --ledger <file> [--since <index>] [--type <t> ...]
                   [--from <ts>] [--to <ts>] [--format ndjson|cloudevents]
                   (deterministic ledger fold to stdout; --from/--to window the
                   emitted events by occurredAt — the 4D DR primitive; transport and
                    cursor belong to the operator)
  groundhold publish  <contract.yaml> --ledger <file> --actor <id> [--at <ts>]
                   (records contract authorship: appends
                    contract.published with the canonical hash and a
                    HUMAN actor — the ledger answers "who approved this")
  groundhold audit    <contract.yaml> --ledger <file> [--at <ts>] [--record]
                   (constraints vs recorded REALITY; --record appends
                    violation.detected; exit 2 when hard constraints
                    are violated or unknown)
  groundhold resume   <contract.yaml> --ledger <file> [--provider fake|gcp]
                   [--project <p>] [--at <ts>] [--fail-key <k>]
                   [--unknown-key <k>]  (concludes pending receipts
                    read-only; exit 3 while any outcome stays unknown)
  groundhold status   <handle> --ledger <file> --at <ts>  (a background run's
                    state from the ledger: running/stalled/needs-reconcile/
                    done/failed; exit 0 — reporting is not judging)
  groundhold runs     --ledger <file> --at <ts>  (every run in the ledger with
                    its derived state, most-recent-first; a per-state count
                    line, no health rollup)
  groundhold wait     <handle> --ledger <file> [--poll <s>] [--timeout <s>]
                   [--notify-url <u>] [--notify-cmd <argv>]  (block until the
                    run is terminal, then relay its exit code)
  groundhold probe    <contract.yaml> --ledger <file> [--provider fake|gcp]
                   [--project <p>] [--capability <id>] [--at <ts>]
                   [--allow-intrusive] [--record] [--fail-key <k>]
                   (outcome probes: measured reality into the
                    observation stream; never implicit)
  groundhold deposed  --ledger <file> [--all]
                   (replaced identities with no tombstone — orphans of
                    failed replacements; --all includes pending-delete;
                    plan --deposed compiles their pinned deletes)
  groundhold repair   --ledger <file> [--quarantine --fingerprint <fp>]
                   (diagnose a corrupt ledger: findings, valid prefix,
                    fingerprint; --quarantine renames the corrupt file
                    aside and restores the valid prefix — two-step,
                    gated on the diagnosed fingerprint; run with
                    writers stopped)
  groundhold attest   --ledger <file> --at <ts>
                   (deterministic integrity/provenance report: ledger
                    identity, compaction state, signature coverage —
                    facts of PRESENCE, verified against each key's OWN
                    claim, NEVER a trust verdict — and anchor presence.
                    A read-only consumer projects it; D139)
  groundhold anchor   --ledger <file> [--check <anchor.json>]
                   (emit the tail anchor — store it OUTSIDE the file;
                    --check verifies the ledger still extends the
                    anchored prefix: truncation/divergence exit 5)
  groundhold snapshot --ledger <file>
                   (compact: replay-verify, write <ledger>.snapshot,
                    ARCHIVE the file (never deleted), start a fresh
                    tail; prints the new anchor — store it off-host;
                    signs the snapshot when --sign-key is armed, D137)
  groundhold capsule  <capability> --ledger <file>
                   (emit a SELF-CONTAINED evidence capsule: the
                    capability's event subchain verbatim + tip hash;
                    hand it across a boundary, D103)
  groundhold capsule  --verify <capsule.json> [--trust <hex-pub>]
                   [--check <anchor.json>]
                   (standalone verification, no ledger needed: linkage,
                    hashes, signatures under --trust; --check pins the
                    tip against a receiver-held anchor — the omission
                    countermeasure; refusals exit 5)
  groundhold certify-capsule <capsule.json>
                   (witness-side collector self-cert + import-time check,
                    spec/collector.md: structure/signatures PLUS the honesty
                    shape — D53 secrets scan, derivation vocab, freshness;
                    rejected exits 5)

Discovering what you can express (no external files needed):
  1. groundhold parity                     — the capability map: every type, and
                                          which cloud fulfils it
  2. groundhold explain <capability.type>  — that type's attributes (kind, enum)
  3. groundhold explain <attribute-path>   — one attribute in full (allowed values,
                                          per-cloud mapping)
  4. groundhold example candidate <contract.yaml>
                                        — scaffold a candidate for a contract,
                                          pre-filled with each capability's attrs
  Author a contract, then: verify -> plan -> apply. Never guess a schema.

Cost: plan and converge print an estimated cost.monthly rollup over
        week/month/year at the end (stderr, before apply). Reporting currency
        defaults to EUR; override with --currency <ISO> or GROUNDHOLD_CURRENCY.
        It is a projection, never FX: costs in other currencies are shown
        separately, never converted (invariant #2).

Global: the full attribute vocabulary is compiled into this binary and
        used by default (no external files needed). --vocab <dir> EXTENDS
        it with your own documents (custom entries override the built-in
        per capability); --no-vocab forces the empty vocabulary.
        --explain attaches remediation (spec/errors.md) to JSON
        refusals; the "code" field is the machine contract.
        --color auto|never|always and --ascii control human rendering
        (spec/presentation.md); banners and glyphs are never a machine
        interface — route on exit codes and "code".
        Time-sensitive verbs (plan/apply/audit/probe/observe/forecast/
        adopt/converge/resume) REQUIRE an explicit --at (RFC3339): a
        safety clock never defaults to a value that makes stale
        observations look fresh (N1).
        Provider verbs (discover/apply/adopt/observe/converge/probe/
        resume/repair/anchor/react/refresh/crawl/preflight) REQUIRE an
        explicit --provider (aws|gcp|azure|k8s|fake): the fake driver
        fabricates reality, so it is chosen deliberately, never defaulted,
        and an unknown provider name is refused, not silently faked (F4).
        Per-verb detail: groundhold <verb> --help (or: groundhold help
        <verb>) prints that verb's arguments, then how to drill deeper.
        Workspace-context flags default from the environment when absent
        (the flag always wins): --ledger from GROUNDHOLD_LEDGER, --provider
        from GROUNDHOLD_PROVIDER, --project from GROUNDHOLD_PROJECT, --region
        from GROUNDHOLD_REGION, --vocab from GROUNDHOLD_VOCAB, --actor from
        GROUNDHOLD_ACTOR, --kubeconfig from GROUNDHOLD_KUBECONFIG or KUBECONFIG,
        --context from GROUNDHOLD_KUBECONTEXT (provider k8s; static token or
        client-cert auth only — exec/auth-provider plugins are refused). These are just location/identity — safe operator
        context, set once per workspace and omitted per command. The
        clock is NOT among them: --at is a safety invariant (N1) and
        never defaults, nor do the consent flags (--allow-data-loss,
        --allow-intrusive, --require-preflight, --yes) — those must be
        typed each time, on purpose.
        --sign-key <keyfile> signs every event this process appends
        (ed25519, detached, D102). --trust <hex-pub> (REPEATABLE) makes
        every ledger-reading verb require a signature by ANY key in the
        set on every event — unsigned or foreign lines refuse like a
        broken chain. Rotation is receiver policy (D133): trust both
        keys during the overlap, drop the old one after.
        --trust-from <event-hash> pins where signing became mandatory:
        lines before it may be unsigned, from it (inclusive) every line
        must verify; a stream lacking the boundary refuses.
        Signing is opt-in; unsigned history stays valid forever.

Exit codes:
  0  ok / executable / applied
  1  structural error in a document
  2  refused: not executable / precondition / read-set mismatch
  3  refused: stale plan or lease conflict
  4  apply failed mid-flight
  5  corrupted ledger
`

// buildVersion is stamped at release time via
// -ldflags "-X main.buildVersion=<tag>"; a plain `go build` reports "dev".
var buildVersion = "dev"

func main() {
	exit := run(os.Args[1:])
	emitBanner(exit)
	os.Exit(exit)
}

// bannerState collects what the final banner needs (D90). The banner is
// presentation only (spec/presentation.md) — never a machine interface.
var bannerState struct {
	verb      string
	colorFlag string
	ascii     bool
	code      string        // last machine code seen in a result
	rollup    render.Rollup // hard-constraint verdicts, when the verb has them
	done      bool          // the verb rendered its own banner (verify text, converge)
	suppress  bool          // --progress=ndjson: keep stderr a pure machine stream (D227)
}

// silentOnSuccess: stdout is the product, or a green word would claim
// health the verb does not assert — probe records measured reality, it
// does not pronounce it healthy. Banner only on failure.
var silentOnSuccess = map[string]bool{
	"hash": true, "export": true, "hints": true, "scenario": true,
	"discover": true, "forecast": true, "explain": true, "deposed": true,
	"observe": true, "probe": true, "validate": true, "survey": true,
	"keygen": true, "capsule": true, "snapshot": true, "attest": true,
	"suggest": true, "apiver": true,
}

// timeSensitiveVerbs is the CLOSED set of verbs whose decision depends on a
// safety clock (N1): each MUST refuse a missing --at rather than default to the
// 1970 epoch (which would make every observation infinitely fresh and silently
// disable the staleness gate). It is a package var, not a local literal, so a
// membership test can pin it — a verb silently DROPPED from this set is a
// fail-open regression on the most safety-critical invariant, and a new
// time-sensitive verb ADDED without gating is the same hole. The test forces
// either change to be a conscious one. (restore is deliberately absent: it
// linearizes events by their own occurredAt, it does not gate freshness.)
// helpDrillDown is the recursion tail appended to every per-verb --help: it names
// the NEXT levels of detail an agent can reach without any external file. This is
// the mechanism the whole CLI is meant to be learnable by drilling: --help ->
// <verb> --help -> explain <code|type|path>.
const helpDrillDown = `
Drill down (no external files needed):
  groundhold <verb> --help                 — this block for any verb (or: groundhold help <verb>)
  groundhold explain <error-code>          — remediation for a refusal's "code" field (spec/errors.md)
  groundhold explain <capability.type>     — a capability's attributes (kind, enum, per-cloud)
  groundhold explain <attribute-path>      — one attribute in full
  groundhold parity                        — the full capability map (every type + which cloud)
Machine contract: route on the process exit code and the JSON "code" field, never
on banner text; --explain attaches remediation to JSON refusals.
`

// verbHelp extracts a single verb's block from the usage text (its `groundhold
// <verb> …` line plus the indented continuation lines beneath it), so
// `groundhold <verb> --help` returns just that verb — the per-verb rung of the
// self-documentation ladder. Returns false for an unknown verb (the caller then
// prints the full usage). Parsing the one usage source keeps the per-verb help and
// the overview from ever drifting apart.
func verbHelp(verb string) (string, bool) {
	if verb == "" {
		return "", false
	}
	const vpfx = "  groundhold "
	var out []string
	collecting := false
	for _, ln := range strings.Split(usage, "\n") {
		if strings.HasPrefix(ln, vpfx) {
			rest := strings.TrimPrefix(ln, vpfx)
			w := rest
			if i := strings.IndexAny(rest, " \t"); i >= 0 {
				w = rest[:i]
			}
			if w == verb {
				collecting = true
				out = append(out, ln)
				continue
			}
			if collecting {
				break // the next verb's block begins — done
			}
			continue
		}
		if collecting {
			// continuation lines are deeply indented; a blank line or a
			// left-flush section header ends the block.
			if strings.TrimSpace(ln) == "" || !strings.HasPrefix(ln, "   ") {
				break
			}
			out = append(out, ln)
		}
	}
	if len(out) == 0 {
		return "", false
	}
	return strings.Join(out, "\n"), true
}

var timeSensitiveVerbs = map[string]bool{
	"plan": true, "apply": true, "audit": true, "probe": true,
	"observe": true, "forecast": true, "adopt": true, "unadopt": true,
	"converge": true, "resume": true, "publish": true,
	"attest": true, "crawl": true, "refresh": true, "posture": true, "react": true,
	// D229: status judges lease-TTL liveness against the clock — a defaulted
	// clock is exactly the stale-freshness lie N1 forbids. `wait` is exempt (it
	// IS the live clock).
	"status": true,
	// D231: runs evaluates the identical lease predicate for EVERY run — a
	// defaulted clock is the N1 lie multiplied by N, and runs is the verb you
	// invoke after time has passed ("what happened while I was away"), where a
	// stale clock is most likely to flip stalled back to running.
	"runs": true,
}

// providerVerbs is the CLOSED set of verbs that OBSERVE or MUTATE real
// infrastructure through a provider driver. Each MUST refuse when the provider
// resolves to the FAKE driver by DEFAULT (F4 fail-closed, the N1 sibling): fake
// fabricates reality, so running a real-infra verb against it by accident would
// observe/adopt/apply nothing real while reporting success. fake must be a
// deliberate choice (--provider fake), never a silent default, and an unknown
// provider name is an error, not a silent fake fallthrough. Package var so a
// membership test pins it: a provider verb DROPPED here is a fail-open regression.
var providerVerbs = map[string]bool{
	"discover": true, "apply": true, "adopt": true, "observe": true,
	"converge": true, "probe": true, "resume": true, "repair": true,
	"anchor": true, "react": true, "refresh": true, "crawl": true,
	"preflight": true,
}

// knownProviders is the closed set of provider names the CLI accepts (a typo must
// be an error, not a silent fake fallthrough).
var knownProviders = map[string]bool{
	"aws": true, "gcp": true, "azure": true, "k8s": true, "fake": true,
	"upstash": true, "hetzner": true, "cloudflare": true,
}

// emitBanner: one banner word, last, on stderr — the prose channel; the
// machine stdout of these verbs stays untouched. converge and text-mode
// verify render their own banner on their human stdout instead.
func emitBanner(exit int) {
	v := bannerState.verb
	if v == "" || v == "mcp" || bannerState.done || bannerState.suppress {
		return
	}
	if exit == 0 && silentOnSuccess[v] {
		return
	}
	word, color := render.Pick(v, exit, bannerState.code, bannerState.rollup)
	m := render.Detect(bannerState.colorFlag, bannerState.ascii, os.Stderr)
	culprit := ""
	var ids []string
	switch word {
	case "VIOLATED":
		ids = bannerState.rollup.Violated
	case "BLOCKED":
		ids = append(append([]string{}, bannerState.rollup.Unknown...),
			bannerState.rollup.Unverifiable...)
	}
	if len(ids) > 0 {
		culprit = ": " + ids[0]
		if len(ids) > 1 {
			culprit += fmt.Sprintf(" (+%d more)", len(ids)-1)
		}
	}
	fmt.Fprintf(os.Stderr, "%s%s\n", m.Paint(color, word), culprit)
}

// planRefusalCode maps the compiler's refusal sentinels to registry
// codes (D65); unmapped refusals carry no code — additive, never
// guessed.
// resolveProgress maps the --progress flag to a sink mode (D227). auto is quiet
// off a TTY (clig.dev's christmas-tree rule keeps CI logs clean) and shows plain
// liveness lines on a terminal; the TTY sticky region is T1.
func resolveProgress(flag string) progress.Mode {
	switch flag {
	case "ndjson":
		return progress.ModeNDJSON
	case "tty":
		return progress.ModeTTY
	case "plain":
		return progress.ModePlain
	case "none":
		return progress.ModeNone
	default: // auto: sticky region on a terminal, quiet off it (CI stays clean)
		if fi, err := os.Stderr.Stat(); err == nil && fi.Mode()&os.ModeCharDevice != 0 {
			return progress.ModeTTY
		}
		return progress.ModeNone
	}
}

// invocation holds the operator's own inputs for the current run, so a refusal
// can build an invocation-specific advisory `next` (D230). Set once in run().
var invocation perrnext.Invocation

// refusalDetail carries the site-level facts a verb handler extracts from its
// typed result (denied permissions, the stateful capability) so the emitter can
// build edit/grant nexts — the engine never imports perrnext (D230).
var refusalDetail perrnext.Detail

func posAt(pos []string, i int) string {
	if i < len(pos) {
		return pos[i]
	}
	return ""
}

func planRefusalCode(reason string) perr.Code {
	switch {
	case reason == compiler.ErrNothingToChange,
		reason == compiler.ErrNothingDeposed:
		return perr.NothingToChange
	case strings.HasSuffix(reason, "— re-observe first") ||
		strings.Contains(reason, "no observation —"):
		return perr.ObservationRequired
	case strings.Contains(reason, "not executable"):
		return perr.NotExecutable
	case strings.Contains(reason, "forbids delete_stateful") ||
		strings.Contains(reason, "allow_replace_stateful"):
		return perr.ConsentRequired
	case strings.Contains(reason, "retired capability"):
		return perr.StructuralError
	case strings.Contains(reason, "(D226)"):
		return perr.ReferenceInvalid
	case strings.Contains(reason, "(unknown-operand)"):
		return perr.UnknownOperand
	}
	return ""
}

// printResult emits a verb's JSON result; with --explain it attaches
// the registry's remediation under the NON-CONTRACTUAL explain field
// (D64: `code` is the contract; prose is never parsed).
func printResult(v any, explain bool) {
	raw, err := json.Marshal(v)
	if err == nil {
		var m map[string]any
		if json.Unmarshal(raw, &m) == nil {
			if code, _ := m["code"].(string); code != "" {
				bannerState.code = code
				if explain {
					if ex, ok := perr.Explain[perr.Code(code)]; ok {
						m["explain"] = ex
					}
				}
				// D230: an invocation-specific advisory next step, when one is
				// derivable from the operator's own inputs (always emitted — an
				// agent is a first-class consumer, no --explain gate). Command
				// kinds need only the invocation; edit/grant kinds need site
				// facts and are attached at their refusal sites.
				if n := perrnext.NextFor(invocation, perr.Code(code), refusalDetail); n != nil {
					m["next"] = n
				}
			}
			out, _ := json.MarshalIndent(m, "", "  ")
			fmt.Println(string(out))
			return
		}
	}
	out, _ := json.MarshalIndent(v, "", "  ")
	fmt.Println(string(out))
}

// envOr returns the environment value for key, or def when it is unset/empty.
// Used to default workspace-context flags (provider/project/region/...) from
// GROUNDHOLD_* — the flag always overrides during parsing.
func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func run(args []string) int {
	jsonMode := false
	suggestAs := "hard"
	// Workspace-context flags default from the environment (GROUNDHOLD_*); the
	// flag always overrides during parsing below. Unlike the clock (--at,
	// N1) or the consent flags, these are just location/identity — safe as
	// env-provided operator context, set once per workspace. The clock
	// still refuses to default: a hidden clock corrupts freshness (N1).
	vocabDir := os.Getenv("GROUNDHOLD_VOCAB")
	noVocab := false
	headsPath := ""
	ledgerPath := os.Getenv("GROUNDHOLD_LEDGER")
	bindingsPath := ""
	observationsPath := ""
	evalTime := "1970-01-01T00:00:00Z"
	atProvided := false
	providerName := envOr("GROUNDHOLD_PROVIDER", "fake")
	providerProvided := os.Getenv("GROUNDHOLD_PROVIDER") != ""
	project := os.Getenv("GROUNDHOLD_PROJECT")
	region := os.Getenv("GROUNDHOLD_REGION")
	kubeconfigPath := envOr("GROUNDHOLD_KUBECONFIG", os.Getenv("KUBECONFIG"))
	kubeContext := os.Getenv("GROUNDHOLD_KUBECONTEXT")
	ttl := 0
	record := false
	yes := false
	allowDataLoss := false
	adoptMap := map[string]string{}
	discoveryPath := ""
	format := "auto"
	since := 0
	showAll := false
	partialRestore := false
	documentsPath := ""
	explainFlag := false
	helpFlag := false
	allowIntrusive := false
	printConfig := false
	// reporting currency for the cost estimate (D202): env default, --currency
	// wins. Never an FX target — foreign-currency costs are shown uncoerced.
	reportingCurrency := os.Getenv("GROUNDHOLD_CURRENCY")
	onlyCap := ""
	actor := os.Getenv("GROUNDHOLD_ACTOR")
	deposedPlan := false
	requirePreflight := false
	noReachability := false // Layer 1: opt out of the post-apply reachability probe
	progressFlag := "auto"  // D227: auto=plain on a TTY, none off it (CI stays quiet)
	pollSeconds := 2        // D229: wait poll cadence
	timeoutSeconds := 0     // D229: wait timeout, 0 = none
	notifyURL := ""         // D229: fire-and-forget terminal doorbell
	notifyCmd := ""
	detachFlag := false // D229: run in the background, return a handle
	quarantine := false
	fingerprintArg := ""
	checkPath := ""
	credRefArg := ""
	scopeArg := ""
	pairingsPath := ""
	verifyPairing := false
	budgetArg := 0
	crawlOut := ""
	windowArg := 0
	contextPath := ""
	eventPath := ""
	var contractPaths []string
	var typeFilters []string
	fromTime := ""
	toTime := ""
	failKeys := map[string]bool{}
	unknownKeys := map[string]bool{}
	retryableKeys := map[string]bool{} // D241: inject a throttled (retryable) outcome
	var pos []string
	colorFlag := "auto"
	asciiFlag := false
	var surveyPaths []string
	completeFlag := false
	signKeyPath := ""
	liveVersionsPath := "" // D236: apiver --live snapshot
	var trustArgs []string
	trustFromArg := ""
	verifyPath := ""
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--help", "-h":
			helpFlag = true
		case "--json":
			jsonMode = true
		case "--color":
			if i+1 >= len(args) {
				fmt.Fprintln(os.Stderr, "--color requires auto|never|always")
				return 1
			}
			colorFlag = args[i+1]
			i++
		case "--ascii":
			asciiFlag = true
		case "--survey":
			if i+1 >= len(args) {
				fmt.Fprintln(os.Stderr, "--survey requires a file")
				return 1
			}
			surveyPaths = append(surveyPaths, args[i+1])
			i++
		case "--complete":
			completeFlag = true
		case "--print-config":
			printConfig = true
		case "--as":
			if i+1 >= len(args) {
				fmt.Fprintln(os.Stderr, "--as requires hard|soft")
				return 1
			}
			suggestAs = args[i+1]
			i++
		case "--currency":
			if i+1 >= len(args) {
				fmt.Fprintln(os.Stderr, "--currency requires a 3-letter code (e.g. EUR)")
				return 1
			}
			reportingCurrency = args[i+1]
			i++
		case "--vocab":
			if i+1 >= len(args) {
				fmt.Fprintln(os.Stderr, "--vocab requires a directory")
				return 1
			}
			vocabDir = args[i+1]
			i++
		case "--no-vocab":
			// force the empty vocabulary (D23) — overrides the compiled-in
			// default. Used by the conformance harness to preserve the
			// exact vocab-absent semantics of cases that ship no vocab.
			noVocab = true
		case "--live":
			// apiver: a canary-fetched live version snapshot to compare the
			// pins against (D236). Offline, the pins report cannot-verify.
			if i+1 >= len(args) {
				fmt.Fprintln(os.Stderr, "--live requires a file (a fetched live-versions snapshot)")
				return 1
			}
			liveVersionsPath = args[i+1]
			i++
		case "--heads":
			if i+1 >= len(args) {
				fmt.Fprintln(os.Stderr, "--heads requires a file")
				return 1
			}
			headsPath = args[i+1]
			i++
		case "--at":
			if i+1 >= len(args) {
				fmt.Fprintln(os.Stderr, "--at requires a timestamp")
				return 1
			}
			evalTime = args[i+1]
			atProvided = true
			i++
		case "--ledger":
			if i+1 >= len(args) {
				fmt.Fprintln(os.Stderr, "--ledger requires a file")
				return 1
			}
			ledgerPath = args[i+1]
			i++
		case "--fail-key":
			if i+1 >= len(args) {
				fmt.Fprintln(os.Stderr, "--fail-key requires a key")
				return 1
			}
			failKeys[args[i+1]] = true
			i++
		case "--unknown-key":
			if i+1 >= len(args) {
				fmt.Fprintln(os.Stderr, "--unknown-key requires a key")
				return 1
			}
			unknownKeys[args[i+1]] = true
			i++
		case "--retryable-key":
			if i+1 >= len(args) {
				fmt.Fprintln(os.Stderr, "--retryable-key requires a key")
				return 1
			}
			retryableKeys[args[i+1]] = true
			i++
		case "--provider":
			if i+1 >= len(args) {
				fmt.Fprintln(os.Stderr, "--provider requires a name")
				return 1
			}
			providerName = args[i+1]
			providerProvided = true
			i++
		case "--project":
			if i+1 >= len(args) {
				fmt.Fprintln(os.Stderr, "--project requires an id")
				return 1
			}
			project = args[i+1]
			i++
		case "--kubeconfig":
			if i+1 >= len(args) {
				fmt.Fprintln(os.Stderr, "--kubeconfig requires a path")
				return 1
			}
			kubeconfigPath = args[i+1]
			i++
		case "--context":
			if i+1 >= len(args) {
				fmt.Fprintln(os.Stderr, "--context requires a name")
				return 1
			}
			kubeContext = args[i+1]
			i++
		case "--region":
			if i+1 >= len(args) {
				fmt.Fprintln(os.Stderr, "--region requires a name")
				return 1
			}
			region = args[i+1]
			i++
		case "--map":
			if i+1 >= len(args) || !strings.Contains(args[i+1], "=") {
				fmt.Fprintln(os.Stderr, "--map requires cap=providerId")
				return 1
			}
			kv := strings.SplitN(args[i+1], "=", 2)
			adoptMap[kv[0]] = kv[1]
			i++
		case "--discovery":
			if i+1 >= len(args) {
				fmt.Fprintln(os.Stderr, "--discovery requires a file")
				return 1
			}
			discoveryPath = args[i+1]
			i++
		case "--format":
			if i+1 >= len(args) {
				fmt.Fprintln(os.Stderr, "--format requires a name")
				return 1
			}
			format = args[i+1]
			i++
		case "--since":
			if i+1 >= len(args) {
				fmt.Fprintln(os.Stderr, "--since requires an index")
				return 1
			}
			_, _ = fmt.Sscanf(args[i+1], "%d", &since)
			i++
		case "--type":
			if i+1 >= len(args) {
				fmt.Fprintln(os.Stderr, "--type requires an event type")
				return 1
			}
			typeFilters = append(typeFilters, args[i+1])
			i++
		case "--from":
			if i+1 >= len(args) {
				fmt.Fprintln(os.Stderr, "--from requires an RFC3339 time")
				return 1
			}
			fromTime = args[i+1]
			i++
		case "--to":
			if i+1 >= len(args) {
				fmt.Fprintln(os.Stderr, "--to requires an RFC3339 time")
				return 1
			}
			toTime = args[i+1]
			i++
		case "--bindings":
			if i+1 >= len(args) {
				fmt.Fprintln(os.Stderr, "--bindings requires a file")
				return 1
			}
			bindingsPath = args[i+1]
			i++
		case "--observations":
			if i+1 >= len(args) {
				fmt.Fprintln(os.Stderr, "--observations requires a file")
				return 1
			}
			observationsPath = args[i+1]
			i++
		case "--ttl":
			if i+1 >= len(args) {
				fmt.Fprintln(os.Stderr, "--ttl requires seconds")
				return 1
			}
			_, _ = fmt.Sscanf(args[i+1], "%d", &ttl)
			i++
		case "--record":
			record = true
		case "--all":
			showAll = true
		case "--partial":
			partialRestore = true
		case "--deposed":
			deposedPlan = true
		case "--require-preflight":
			requirePreflight = true
		case "--no-reachability":
			noReachability = true
		case "--progress":
			if i+1 >= len(args) {
				fmt.Fprintln(os.Stderr, "--progress requires a mode (auto|plain|ndjson|none)")
				return 1
			}
			progressFlag = args[i+1]
			i++
		case "--detach":
			detachFlag = true
		case "--poll":
			if i+1 >= len(args) {
				fmt.Fprintln(os.Stderr, "--poll requires seconds")
				return 1
			}
			pollSeconds = atoiOr(args[i+1], 2)
			i++
		case "--timeout":
			if i+1 >= len(args) {
				fmt.Fprintln(os.Stderr, "--timeout requires seconds")
				return 1
			}
			timeoutSeconds = atoiOr(args[i+1], 0)
			i++
		case "--notify-url":
			if i+1 >= len(args) {
				fmt.Fprintln(os.Stderr, "--notify-url requires a URL")
				return 1
			}
			notifyURL = args[i+1]
			i++
		case "--notify-cmd":
			if i+1 >= len(args) {
				fmt.Fprintln(os.Stderr, "--notify-cmd requires a command")
				return 1
			}
			notifyCmd = args[i+1]
			i++
		case "--quarantine":
			quarantine = true
		case "--fingerprint":
			if i+1 >= len(args) {
				fmt.Fprintln(os.Stderr, "--fingerprint requires a value")
				return 1
			}
			fingerprintArg = args[i+1]
			i++
		case "--check":
			if i+1 >= len(args) {
				fmt.Fprintln(os.Stderr, "--check requires a file")
				return 1
			}
			checkPath = args[i+1]
			i++
		case "--documents":
			if i+1 >= len(args) {
				fmt.Fprintln(os.Stderr, "--documents requires a directory")
				return 1
			}
			documentsPath = args[i+1]
			i++
		case "--explain":
			explainFlag = true
		case "--allow-intrusive":
			allowIntrusive = true
		case "--capability":
			if i+1 >= len(args) {
				fmt.Fprintln(os.Stderr, "--capability requires an id")
				return 1
			}
			onlyCap = args[i+1]
			i++
		case "--cred-ref":
			if i+1 >= len(args) {
				fmt.Fprintln(os.Stderr, "--cred-ref requires <kind>:<value>")
				return 1
			}
			credRefArg = args[i+1]
			i++
		case "--scope":
			if i+1 >= len(args) {
				fmt.Fprintln(os.Stderr, "--scope requires a value")
				return 1
			}
			scopeArg = args[i+1]
			i++
		case "--pairings":
			if i+1 >= len(args) {
				fmt.Fprintln(os.Stderr, "--pairings requires a path")
				return 1
			}
			pairingsPath = args[i+1]
			i++
		case "--verify-ref":
			verifyPairing = true
		case "--budget":
			if i+1 >= len(args) {
				fmt.Fprintln(os.Stderr, "--budget requires a request count")
				return 1
			}
			_, _ = fmt.Sscanf(args[i+1], "%d", &budgetArg)
			i++
		case "--out":
			if i+1 >= len(args) {
				fmt.Fprintln(os.Stderr, "--out requires a directory")
				return 1
			}
			crawlOut = args[i+1]
			i++
		case "--window":
			if i+1 >= len(args) {
				fmt.Fprintln(os.Stderr, "--window requires seconds")
				return 1
			}
			_, _ = fmt.Sscanf(args[i+1], "%d", &windowArg)
			i++
		case "--crawl":
			if i+1 >= len(args) {
				fmt.Fprintln(os.Stderr, "--crawl requires a crawl document file")
				return 1
			}
			contextPath = args[i+1]
			i++
		case "--contract":
			if i+1 >= len(args) {
				fmt.Fprintln(os.Stderr, "--contract requires a file")
				return 1
			}
			contractPaths = append(contractPaths, args[i+1])
			i++
		case "--event":
			if i+1 >= len(args) {
				fmt.Fprintln(os.Stderr, "--event requires a file")
				return 1
			}
			eventPath = args[i+1]
			i++
		case "--actor":
			if i+1 >= len(args) {
				fmt.Fprintln(os.Stderr, "--actor requires an id")
				return 1
			}
			actor = args[i+1]
			i++
		case "--verify":
			if i+1 >= len(args) {
				fmt.Fprintln(os.Stderr, "--verify requires a capsule file path")
				return 1
			}
			verifyPath = args[i+1]
			i++
		case "--sign-key":
			if i+1 >= len(args) {
				fmt.Fprintln(os.Stderr, "--sign-key requires a key file path")
				return 1
			}
			signKeyPath = args[i+1]
			i++
		case "--trust":
			if i+1 >= len(args) {
				fmt.Fprintln(os.Stderr, "--trust requires a hex ed25519 public key")
				return 1
			}
			trustArgs = append(trustArgs, args[i+1])
			i++
		case "--trust-from":
			if i+1 >= len(args) {
				fmt.Fprintln(os.Stderr, "--trust-from requires a canonical event hash")
				return 1
			}
			trustFromArg = args[i+1]
			i++
		case "--yes":
			yes = true
		case "--allow-data-loss":
			allowDataLoss = true
		default:
			pos = append(pos, args[i])
		}
	}
	if len(pos) < 1 {
		// an explicit --help/-h is a successful help request (exit 0); a bare
		// invocation with no command is a usage error (exit 1).
		fmt.Print(usage)
		if helpFlag {
			return 0
		}
		return 1
	}
	cmd := pos[0]
	// D230: package the operator's own inputs ONCE, so a refusal can offer an
	// invocation-specific `next`. --at is echoed only when the operator actually
	// supplied it (never the epoch default), so a command builder that needs a
	// clock omits itself rather than fabricating one.
	atLiteral := ""
	if atProvided {
		atLiteral = evalTime
	}
	// echo --provider only when the operator supplied it (never the defaulted
	// "fake") — an optional-unknown flag is omitted, never guessed (D230).
	provLiteral := ""
	if providerProvided {
		provLiteral = providerName
	}
	invocation = perrnext.Invocation{
		Verb: cmd, Contract: posAt(pos, 1), Candidate: posAt(pos, 2),
		Ledger: ledgerPath, Provider: provLiteral, Project: project, At: atLiteral,
		Argv: append([]string{"groundhold"}, args...),
	}
	if cmd == "version" || cmd == "--version" || cmd == "-v" {
		fmt.Printf("groundhold %s\n", buildVersion)
		return 0
	}
	// Recursive self-documentation for agents (bootstrap from --help, then drill
	// down): `groundhold <verb> --help` and `groundhold help <verb>` print that
	// verb's usage block plus the pointers to the next level of detail. Runs before
	// every guard/dispatch so --help is never eaten by a fail-closed refusal.
	if helpFlag || cmd == "help" {
		target := cmd
		if cmd == "help" {
			target = ""
			if len(pos) > 1 {
				target = pos[1]
			}
		}
		if h, ok := verbHelp(target); ok {
			fmt.Println(h)
			fmt.Print(helpDrillDown)
			return 0
		}
		fmt.Print(usage)
		return 0
	}
	if cmd == "parity" {
		return runParity(pos[1:], jsonMode)
	}
	if cmd == "apireq" {
		// Registry-wide (no positional) or the `classify` subcommand. Returns
		// before the banner is armed: the classify exit codes (10/20/30) are the
		// canary taxonomy, not the presentation-layer exit set.
		return runAPIReq(pos, providerName, providerProvided, jsonMode)
	}
	bannerState.verb = cmd
	// D102: arm signing/verification before ANY verb touches a ledger —
	// a bad key refuses up front, never half-signs a session.
	if signKeyPath != "" {
		if err := ledger.LoadSignKey(signKeyPath); err != nil {
			fmt.Fprintf(os.Stderr, "sign-key error: %v\n", err)
			return 1
		}
	}
	for _, t := range trustArgs {
		if err := ledger.AddTrust(t); err != nil {
			fmt.Fprintf(os.Stderr, "trust error: %v\n", err)
			return 1
		}
	}
	if trustFromArg != "" {
		if len(trustArgs) == 0 {
			fmt.Fprintln(os.Stderr, "trust error: --trust-from without --trust "+
				"names a boundary with no keys to enforce past it")
			return 1
		}
		if err := ledger.SetTrustFrom(trustFromArg); err != nil {
			fmt.Fprintf(os.Stderr, "trust error: %v\n", err)
			return 1
		}
	}
	// D135: a trust-carrying anchor beside the ledger arms verification
	// for EVERY verb that reads it — the receiver's held artifact brings
	// the policy; forgetting --trust no longer downgrades anything.
	if ledgerPath != "" {
		if a, err := ledger.LoadAnchorFile(ledger.AnchorPath(ledgerPath)); err == nil && a != nil {
			if err := ledger.ApplyAnchorPolicy(a); err != nil {
				fmt.Fprintf(os.Stderr, "trust error: %v\n", err)
				return 1
			}
		}
	}
	bannerState.colorFlag = colorFlag
	bannerState.ascii = asciiFlag
	// N1 fail-closed: a verb whose decision depends on time must not
	// default to the 1970 epoch, which would make every observation
	// infinitely fresh and silently disable the staleness gate. Require
	// an explicit --at rather than inventing a wall clock (determinism).
	if timeSensitiveVerbs[cmd] && !atProvided {
		fmt.Fprintf(os.Stderr, "%s requires an explicit --at "+
			"(RFC3339 timestamp): a safety clock must not default to "+
			"the epoch and make stale observations look fresh\n", cmd)
		return 1
	}
	// D323: PRESENT is not the same as PARSES. Every downstream site reads the
	// clock with the error discarded (`atSec, _ := ledger.ParseTs(at)`), so an
	// unparseable --at becomes epoch — and at epoch the decay test
	// `observedAt+ttl <= atSec` is false for every real observation, so nothing is
	// ever stale and a capability whose proof expired years ago reports
	// managed-ok. That is exactly the lie the message above promises to prevent,
	// reached by malforming the flag instead of omitting it. The gate now enforces
	// what it has always claimed.
	if timeSensitiveVerbs[cmd] && atProvided {
		if _, terr := ledger.ParseTs(evalTime); terr != nil {
			fmt.Fprintf(os.Stderr, "%s: --at %q is not an RFC3339 timestamp "+
				"(want e.g. 2026-07-25T10:00:00Z): a clock that does not parse "+
				"becomes the epoch downstream, which makes every stale proof look "+
				"fresh\n", cmd, evalTime)
			return 1
		}
	}
	// F4 fail-closed (the N1 sibling): a verb that touches real infrastructure must
	// not silently run against the FAKE provider. fake is a deliberate choice, never
	// a default, and an unknown provider name is an error rather than a silent fake
	// fallthrough that would observe/adopt/apply nothing real while reporting success.
	if providerVerbs[cmd] {
		if !providerProvided && providerName == "fake" {
			fmt.Fprintf(os.Stderr, "%s requires an explicit --provider "+
				"(aws|gcp|azure|k8s|fake): fake fabricates reality, so it must be chosen "+
				"deliberately (--provider fake) rather than defaulted\n", cmd)
			return 1
		}
		if !knownProviders[providerName] {
			fmt.Fprintf(os.Stderr, "unknown provider %q (want aws|gcp|azure|k8s|fake)\n", providerName)
			return 1
		}
	}
	if cmd == "example" {
		return runExample(pos)
	}
	if cmd == "compose" {
		return runCompose(pos)
	}
	if cmd == "cost" {
		if len(pos) < 3 {
			fmt.Fprintln(os.Stderr,
				"usage: groundhold cost <plan.yaml> <candidate.yaml> [--currency <ISO>] [--json]")
			return 1
		}
		return runCost(pos[1], pos[2], reportingCurrency, jsonMode)
	}
	if cmd == "suggest" {
		if len(pos) < 2 {
			fmt.Fprintln(os.Stderr,
				"usage: groundhold suggest <contract.yaml> [<candidate.yaml>] [--json] [--as hard|soft]")
			return 1
		}
		candPath := ""
		if len(pos) > 2 {
			candPath = pos[2]
		}
		return runSuggest(pos[1], candPath, vocabDir, noVocab, suggestAs, jsonMode)
	}
	if cmd == "diff" {
		return runDiff(pos, jsonMode)
	}
	if cmd == "mcp" {
		self, err := os.Executable()
		if err != nil {
			fmt.Fprintf(os.Stderr, "mcp error: %v\n", err)
			return 1
		}
		if printConfig {
			// Wiring the server into an agent is the step a bare binary cannot
			// do for you (it lives in the agent's own config). So make it one
			// obvious copy-paste instead of something to reverse-engineer.
			printMCPConfig(self)
			return 0
		}
		if err := mcp.New(os.Stdin, os.Stdout, self).Serve(); err != nil {
			fmt.Fprintf(os.Stderr, "mcp error: %v\n", err)
			return 1
		}
		return 0
	}
	if cmd != "observe" && cmd != "discover" && cmd != "export" &&
		cmd != "deposed" && cmd != "repair" && cmd != "anchor" &&
		cmd != "capsule" && cmd != "snapshot" && cmd != "attest" &&
		cmd != "connections" && cmd != "crawl" && cmd != "refresh" && cmd != "posture" && cmd != "react" &&
		cmd != "backup" && cmd != "runs" && // D231: runs takes no positional (ledger-wide)
		cmd != "explain" && // D233: explain --json (no term) dumps the error registry
		cmd != "apiver" && // D236: apiver takes no positional (registry-wide)
		len(pos) < 2 {
		fmt.Print(usage)
		return 1
	}
	if cmd == "snapshot" {
		if ledgerPath == "" {
			fmt.Fprintln(os.Stderr, "snapshot requires --ledger")
			return 1
		}
		snap, anchor, err := ledger.Rotate(ledgerPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "snapshot error: %v\n", err)
			if strings.Contains(err.Error(), "ledger line") ||
				strings.Contains(err.Error(), "unsigned") ||
				strings.Contains(err.Error(), "anchor") {
				return 5
			}
			return 1
		}
		out, _ := json.MarshalIndent(map[string]any{
			"status": "compacted", "baseEvents": snap.BaseEvents,
			"baseHead": snap.BaseHead, "ledgerId": snap.LedgerId,
			"archive":  ledger.ArchivePath(ledgerPath, snap.BaseEvents),
			"snapshot": ledger.SnapshotPath(ledgerPath),
			"anchor":   anchor,
		}, "", "  ")
		fmt.Println(string(out))
		return 0
	}
	if cmd == "capsule" {
		capability := ""
		if len(pos) > 1 {
			capability = pos[1]
		}
		return runCapsule(capability, ledgerPath, verifyPath, checkPath)
	}
	if cmd == "certify-capsule" {
		// witness-side collector self-cert + import-time check (spec/collector.md):
		// VerifyCapsule's structure/signature/linkage proof PLUS the honesty shape a
		// third-party collector must produce — D53 secrets scan, derivation vocab,
		// observedAt/asOf discipline. Rejected is corruption-class (5).
		if len(pos) < 2 {
			fmt.Fprintln(os.Stderr, "usage: groundhold certify-capsule <capsule.json>")
			return 1
		}
		c, err := collector.Load(pos[1])
		if err != nil {
			fmt.Fprintf(os.Stderr, "certify-capsule: %v\n", err)
			return 1
		}
		rep := collector.Certify(c)
		b, _ := json.MarshalIndent(rep, "", "  ")
		fmt.Println(string(b))
		if rep.Status != "certified" {
			return 5
		}
		return 0
	}
	if cmd == "repair" {
		return runRepair(ledgerPath, quarantine, fingerprintArg, explainFlag)
	}
	if cmd == "attest" {
		if ledgerPath == "" {
			fmt.Fprintln(os.Stderr, "attest requires --ledger")
			return 1
		}
		rep, err := ledger.Attest(ledgerPath, evalTime)
		if err != nil {
			fmt.Fprintf(os.Stderr, "attest error: %v\n", err)
			return 5
		}
		out, _ := json.MarshalIndent(rep, "", "  ")
		fmt.Println(string(out))
		return 0
	}
	if cmd == "anchor" {
		return runAnchor(ledgerPath, checkPath)
	}
	if cmd == "converge" {
		if len(pos) < 3 {
			fmt.Print(usage)
			return 1
		}
		self, err := os.Executable()
		if err != nil {
			fmt.Fprintf(os.Stderr, "converge error: %v\n", err)
			return 1
		}
		crunID, cenv, ccaps, cerr := converge.RunID(pos[1], evalTime)
		if cerr != nil {
			fmt.Fprintf(os.Stderr, "converge error: %v\n", cerr)
			return 1
		}
		if detachFlag {
			return detachRun(crunID, "converge", ledgerPath, evalTime, args, jsonMode)
		}
		bannerState.done = true // the converge package renders its own
		return converge.Converge(converge.Options{
			Render:   render.Detect(colorFlag, asciiFlag, os.Stdout),
			Contract: pos[1], Candidate: pos[2],
			Ledger: ledgerPath, Vocab: vocabDir, NoVocab: noVocab,
			Currency: reportingCurrency,
			Project:  project,
			Provider: providerName, At: evalTime,
			Yes: yes, AllowDataLoss: allowDataLoss, JSON: jsonMode,
			NoReachability: noReachability,
			In:             os.Stdin, Out: os.Stdout,
			Run:           converge.SelfRunner(self),
			ConvergeRunID: crunID, Env: cenv, Caps: ccaps,
		})
	}

	if cmd == "observe" {
		return runObserve(ledgerPath, bindingsPath, providerName,
			evalTime, ttl, record, kubeconfigPath, kubeContext)
	}
	if cmd == "discover" {
		var prov provider.Provider
		if providerName == "gcp" {
			prov = gcp.NewDriver(project)
		} else if providerName == "aws" {
			prov = aws.NewDriver(region)
		} else if providerName == "azure" {
			prov = azure.NewDriver(project)
		} else if providerName == "k8s" {
			kd, kerr := k8sDriver(kubeconfigPath, kubeContext)
			if kerr != nil {
				fmt.Fprintln(os.Stderr, kerr.Error())
				return 1
			}
			prov = kd
		} else {
			prov = &provider.Fake{}
		}
		res, err := discover.Run(prov, project, region, evalTime)
		if err != nil {
			fmt.Fprintf(os.Stderr, "discover error: %v\n", err)
			return 1
		}
		out, _ := json.MarshalIndent(res, "", "  ")
		fmt.Println(string(out))
		return 0
	}
	if cmd == "k8s-skeleton" {
		// offline scaffolding: crawl a GVK's machine contract (discovery +
		// OpenAPI) and emit the machine-authoritative half of a mapping. It
		// writes nothing to the cluster and authors no semantics.
		parts := strings.Split(pos[1], "/")
		if len(parts) != 3 {
			fmt.Fprintln(os.Stderr, "k8s-skeleton: expected <group>/<version>/<Kind> "+
				"(use \"core\" for the core group, e.g. core/v1/ResourceQuota)")
			return 1
		}
		group, version, kind := parts[0], parts[1], parts[2]
		if group == "core" {
			group = ""
		}
		if onlyCap == "" {
			fmt.Fprintln(os.Stderr, "k8s-skeleton: --capability is required "+
				"(the vocabulary this resource will map to)")
			return 1
		}
		path := kubeconfigPath
		if path == "" {
			if home, herr := os.UserHomeDir(); herr == nil {
				path = filepath.Join(home, ".kube", "config")
			}
		}
		kd, kerr := k8s.NewFromKubeconfig(path, kubeContext)
		if kerr != nil {
			fmt.Fprintln(os.Stderr, "k8s-skeleton:", kerr)
			return 1
		}
		out, gerr := kd.SkeletonFor(group, version, kind, "k8s."+strings.ToLower(kind), onlyCap)
		if gerr != nil {
			fmt.Fprintln(os.Stderr, "k8s-skeleton:", gerr)
			return 1
		}
		fmt.Print(out)
		return 0
	}
	if cmd == "pair" {
		// register a credential REFERENCE for the gentle crawler (D141) — never a
		// secret; only delegated-credential providers, OAuth deferred.
		if len(pos) < 2 || credRefArg == "" {
			fmt.Fprintln(os.Stderr, "usage: groundhold pair <provider> --cred-ref <kind>:<value> "+
				"[--scope <s>] [--verify-ref] [--at <ts>]\n  kinds: env:NAME | aws-profile:NAME | "+
				"gcloud-config:NAME | kubeconfig:PATH[#context]")
			return 1
		}
		ref, err := pair.ParseCredentialRef(credRefArg)
		if err != nil {
			fmt.Fprintln(os.Stderr, "pair:", err)
			return 1
		}
		conn := pair.Connection{Provider: pos[1], Scope: scopeArg, Credential: ref, PairedAt: evalTime}
		if err := conn.Validate(); err != nil {
			fmt.Fprintln(os.Stderr, "pair:", err)
			return 1
		}
		if verifyPairing {
			if err := ref.Resolves(); err != nil {
				fmt.Fprintln(os.Stderr, "pair: credential reference does not resolve:", err)
				return 1
			}
		}
		ppath := pairingsPath
		if ppath == "" {
			ppath = pair.DefaultPath()
		}
		reg, err := pair.Load(ppath)
		if err != nil {
			fmt.Fprintln(os.Stderr, "pair:", err)
			return 1
		}
		reg.Upsert(conn)
		if err := reg.Save(ppath); err != nil {
			fmt.Fprintln(os.Stderr, "pair:", err)
			return 1
		}
		out, _ := json.MarshalIndent(map[string]any{
			"status": "paired", "provider": conn.Provider, "scope": conn.Scope,
			"credentialRef": ref.String(), "pairings": ppath,
		}, "", "  ")
		fmt.Println(string(out))
		return 0
	}
	if cmd == "connections" {
		ppath := pairingsPath
		if ppath == "" {
			ppath = pair.DefaultPath()
		}
		reg, err := pair.Load(ppath)
		if err != nil {
			fmt.Fprintln(os.Stderr, "connections:", err)
			return 1
		}
		rows := []map[string]string{}
		for _, c := range reg.Pairings {
			rows = append(rows, map[string]string{
				"provider": c.Provider, "scope": c.Scope,
				"credentialRef": c.Credential.String(), "pairedAt": c.PairedAt,
			})
		}
		out, _ := json.MarshalIndent(map[string]any{"pairings": rows}, "", "  ")
		fmt.Println(string(out))
		return 0
	}
	if cmd == "unpair" {
		if len(pos) < 2 {
			fmt.Fprintln(os.Stderr, "usage: groundhold unpair <provider> [--scope <s>]")
			return 1
		}
		ppath := pairingsPath
		if ppath == "" {
			ppath = pair.DefaultPath()
		}
		reg, err := pair.Load(ppath)
		if err != nil {
			fmt.Fprintln(os.Stderr, "unpair:", err)
			return 1
		}
		if !reg.Remove(pos[1], scopeArg) {
			fmt.Fprintf(os.Stderr, "unpair: no pairing for provider %q scope %q\n", pos[1], scopeArg)
			return 1
		}
		if err := reg.Save(ppath); err != nil {
			fmt.Fprintln(os.Stderr, "unpair:", err)
			return 1
		}
		fmt.Println(`{"status":"unpaired"}`)
		return 0
	}
	if cmd == "crawl" {
		// gentle read-only context crawl over the paired providers (D141). N1: --at
		// is required (enforced above). Sits outside the verifier.
		ppath := pairingsPath
		if ppath == "" {
			ppath = pair.DefaultPath()
		}
		reg, err := pair.Load(ppath)
		if err != nil {
			fmt.Fprintln(os.Stderr, "crawl:", err)
			return 1
		}
		if len(reg.Pairings) == 0 {
			fmt.Fprintln(os.Stderr, "crawl: no pairings — run `groundhold pair <provider> --cred-ref ...` first")
			return 1
		}
		doc, err := runLiveCrawl(reg, budgetArg, evalTime, kubeconfigPath, kubeContext)
		if err != nil {
			fmt.Fprintln(os.Stderr, "crawl:", err)
			return 1
		}
		out, _ := json.MarshalIndent(doc, "", "  ")
		if crawlOut != "" {
			if err := os.MkdirAll(crawlOut, 0o755); err != nil {
				fmt.Fprintln(os.Stderr, "crawl:", err)
				return 1
			}
			if err := os.WriteFile(filepath.Join(crawlOut, "context.json"), append(out, '\n'), 0o600); err != nil {
				fmt.Fprintln(os.Stderr, "crawl:", err)
				return 1
			}
		}
		fmt.Println(string(out))
		return 0
	}
	if cmd == "refresh" {
		// the freshness agent (D141 family): gently re-observe bound resources whose
		// proof is stale or decaying within --window, keeping evidence alive. N1: --at
		// required (enforced above). Writes observation.recorded like `observe --record`.
		if ledgerPath == "" {
			fmt.Fprintln(os.Stderr, "refresh requires --ledger")
			return 1
		}
		led, lerr := ledger.ReplayFile(ledgerPath)
		if lerr != nil {
			fmt.Fprintf(os.Stderr, "ledger error: %v\n", lerr)
			return 5
		}
		prov := crawlProvider(providerName, "", kubeconfigPath, kubeContext)
		if prov == nil {
			fmt.Fprintf(os.Stderr, "refresh: unknown provider %q\n", providerName)
			return 1
		}
		pol := pace.DefaultPolicy()
		if budgetArg > 0 {
			pol.Budget = budgetArg
		}
		sched := pace.New(pol, pace.Clock{Now: time.Now, Sleep: time.Sleep, Jitter: rand.Float64})
		rep, rerr := refresh.Run(led, ledgerPath, prov, sched, pol.Budget, evalTime, windowArg, ttl)
		if rerr != nil {
			fmt.Fprintf(os.Stderr, "refresh error: %v\n", rerr)
			return 1
		}
		out, _ := json.MarshalIndent(rep, "", "  ")
		fmt.Println(string(out))
		return 0
	}
	if cmd == "posture" {
		// the proactive classifier (candidate D142): fold a crawl (--context) + the
		// ledger + audit (--contract) into managed-ok/drifted/shadow/decayed/unknown
		// with on-a-plate remediation. Pure + deterministic; N1 --at. Writes nothing.
		if ledgerPath == "" {
			fmt.Fprintln(os.Stderr, "posture requires --ledger")
			return 1
		}
		led, lerr := ledger.ReplayFile(ledgerPath)
		if lerr != nil {
			fmt.Fprintf(os.Stderr, "ledger error: %v\n", lerr)
			return 5
		}
		// discovered resources -> shadow. A prior crawl (--crawl <doc>) is folded
		// offline; otherwise, when providers are paired, posture runs the gentle
		// crawl itself (one cron entry: pair -> posture does crawl + classify).
		var ctx *crawl.Document
		if contextPath != "" {
			raw, rerr := docio.ReadDoc(contextPath)
			if rerr != nil {
				fmt.Fprintf(os.Stderr, "context error: %v\n", rerr)
				return 1
			}
			var loaded crawl.Document
			if json.Unmarshal(raw, &loaded) != nil {
				fmt.Fprintln(os.Stderr, "context: not a crawl document")
				return 1
			}
			ctx = &loaded
		} else {
			ppath := pairingsPath
			if ppath == "" {
				ppath = pair.DefaultPath()
			}
			if reg, perr2 := pair.Load(ppath); perr2 == nil && len(reg.Pairings) > 0 {
				live, cerr := runLiveCrawl(reg, budgetArg, evalTime, kubeconfigPath, kubeContext)
				if cerr != nil {
					fmt.Fprintf(os.Stderr, "posture: live crawl failed: %v\n", cerr)
					return 1
				}
				ctx = live
			}
		}
		doc, cerr := classifyPosture(led, ledgerPath, ctx, contractPaths, evalTime)
		if cerr != nil {
			fmt.Fprintln(os.Stderr, "posture:", cerr)
			return 1
		}
		out, _ := json.MarshalIndent(doc, "", "  ")
		if crawlOut != "" {
			if err := os.MkdirAll(crawlOut, 0o755); err == nil {
				_ = os.WriteFile(filepath.Join(crawlOut, "posture.json"), append(out, '\n'), 0o600)
			}
		}
		fmt.Println(string(out))
		// exit 2 on findings that demand action; decayed alone does not fail (renew)
		if doc.Summary.Shadow > 0 || doc.Summary.Drifted > 0 {
			return 2
		}
		return 0
	}
	if cmd == "react" {
		// event-driven ingress (D143): map ONE change event to (provider, scope),
		// re-list just that scope, splice into the base crawl, reclassify posture.
		// N1 --at. The event is a hint — only its coordinates route the re-read.
		if eventPath == "" || ledgerPath == "" {
			fmt.Fprintln(os.Stderr, "usage: groundhold react --event <file> --ledger <f> --at <ts> "+
				"[--crawl <base.json>] [--contract <f>...] [--out <dir>]")
			return 1
		}
		raw, rerr := docio.ReadDoc(eventPath)
		if rerr != nil {
			fmt.Fprintf(os.Stderr, "event error: %v\n", rerr)
			return 1
		}
		ev, perr2 := react.ParseEvent(raw)
		if perr2 != nil {
			// an unmapped event is ignored LOUDLY, never a crash loop
			fmt.Fprintln(os.Stderr, "react: event ignored —", perr2)
			return 0
		}
		// the pairing is the consent: an event cannot conjure credentials (D141)
		ppath := pairingsPath
		if ppath == "" {
			ppath = pair.DefaultPath()
		}
		reg, _ := pair.Load(ppath)
		paired := false
		for _, c := range reg.Pairings {
			if c.Provider == ev.Provider {
				paired = true
			}
		}
		if !paired {
			fmt.Fprintf(os.Stderr, "react: provider %q is not paired — pair it first (an event cannot conjure credentials)\n", ev.Provider)
			return 1
		}
		// targeted, paced-in-spirit read-only re-list of just the changed scope
		prov := crawlProvider(ev.Provider, ev.Scope, kubeconfigPath, kubeContext)
		if prov == nil {
			fmt.Fprintf(os.Stderr, "react: cannot build a discoverer for %q\n", ev.Provider)
			return 1
		}
		res, derr := discover.Run(prov, ev.Scope, ev.Scope, evalTime)
		if derr != nil {
			fmt.Fprintf(os.Stderr, "react: scope re-list failed: %v\n", derr)
			return 1
		}
		stamp := time.Now().UTC().Format(time.RFC3339)
		fresh := crawl.ScopeContext{Scope: ev.Scope, Status: "complete", Resources: []crawl.Resource{}}
		for _, r := range res.Discovery.Resources {
			fresh.Resources = append(fresh.Resources, crawl.Resource{
				ProviderID: r.ProviderID, ResourceType: r.ResourceType,
				Observations: r.Observations, ObservedAt: stamp})
		}
		// splice the fresh scope into the last full crawl (--crawl), if any
		var base *crawl.Document
		if contextPath != "" {
			if braw, berr := docio.ReadDoc(contextPath); berr == nil {
				var b crawl.Document
				if json.Unmarshal(braw, &b) == nil {
					base = &b
				}
			}
		}
		spliced, serr := react.Splice(base, ev.Provider, ev.Scope, evalTime, fresh)
		if serr != nil {
			fmt.Fprintln(os.Stderr, "react:", serr)
			return 1
		}
		led, lerr := ledger.ReplayFile(ledgerPath)
		if lerr != nil {
			fmt.Fprintf(os.Stderr, "ledger error: %v\n", lerr)
			return 5
		}
		doc, cerr := classifyPosture(led, ledgerPath, spliced, contractPaths, evalTime)
		if cerr != nil {
			fmt.Fprintln(os.Stderr, "react:", cerr)
			return 1
		}
		if crawlOut != "" {
			if err := os.MkdirAll(crawlOut, 0o755); err == nil {
				cb, _ := json.MarshalIndent(spliced, "", "  ")
				_ = os.WriteFile(filepath.Join(crawlOut, "context.json"), append(cb, '\n'), 0o600)
				pb, _ := json.MarshalIndent(doc, "", "  ")
				_ = os.WriteFile(filepath.Join(crawlOut, "posture.json"), append(pb, '\n'), 0o600)
			}
		}
		out, _ := json.MarshalIndent(doc, "", "  ")
		fmt.Println(string(out))
		if doc.Summary.Shadow > 0 || doc.Summary.Drifted > 0 {
			return 2
		}
		return 0
	}
	if cmd == "restore" {
		// capsule disaster-recovery (slice 1): rebuild a ledger from a verified
		// capsule set + its off-host anchor. --trust is already armed above; the
		// anchor's own D135 policy arms inside restore.Run. Refusals are
		// corruption-class (5); bad inputs are operator errors (1).
		if crawlOut == "" || checkPath == "" || len(pos) < 2 {
			fmt.Fprintln(os.Stderr, "usage: groundhold restore --out <ledger> --check <anchor.json> [--partial] <capsule.json>...")
			return 1
		}
		rep, code := restore.Run(restore.Options{
			Out: crawlOut, AnchorPath: checkPath, CapsulePaths: pos[1:],
			Partial: partialRestore})
		b, _ := json.MarshalIndent(rep, "", "  ")
		fmt.Println(string(b))
		// --documents: after the ledger rebuilds, re-verify the backup's
		// content-addressed document blobs (D103 slice 4). A tampered blob
		// escalates to corruption (5), even if the ledger itself restored.
		if code == restore.ExitOK && documentsPath != "" {
			vrep, vcode := backup.VerifyDocuments(documentsPath)
			vb, _ := json.MarshalIndent(vrep, "", "  ")
			fmt.Println(string(vb))
			if vcode != restore.ExitOK {
				return vcode
			}
		}
		return code
	}
	if cmd == "backup" {
		// capsule disaster-recovery (slice 4): bundle a ledger's full recovery
		// set — anchor + one capsule per capability + (with --documents) the
		// content-addressed contract blobs it pins. Feeds `groundhold restore`.
		if ledgerPath == "" || crawlOut == "" {
			fmt.Fprintln(os.Stderr, "usage: groundhold backup --ledger <file> --out <dir> [--documents <store>]")
			return 1
		}
		rep, code := backup.Run(backup.Options{
			LedgerPath: ledgerPath, Out: crawlOut, DocumentsStore: documentsPath})
		b, _ := json.MarshalIndent(rep, "", "  ")
		fmt.Println(string(b))
		return code
	}
	if cmd == "hash" {
		return runHash(pos[1])
	}
	if cmd == "keygen" {
		return runKeygen(pos[1])
	}
	if cmd == "explain" {
		term := ""
		if len(pos) > 1 {
			term = pos[1]
		}
		return runExplain(term, vocabDir, jsonMode)
	}
	if cmd == "apiver" {
		return runAPIVer(liveVersionsPath, jsonMode)
	}
	if cmd == "deposed" {
		if ledgerPath == "" {
			fmt.Fprintln(os.Stderr, "deposed requires --ledger")
			return 1
		}
		led, err := ledger.ReplayFile(ledgerPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "ledger error: %v\n", err)
			return 5
		}
		list := led.Deposed(showAll)
		if list == nil {
			list = []ledger.DeposedResource{}
		}
		out, _ := json.MarshalIndent(
			map[string]any{"deposed": list}, "", "  ")
		fmt.Println(string(out))
		return 0
	}
	if cmd == "export" {
		if ledgerPath == "" {
			fmt.Fprintln(os.Stderr, "export requires --ledger")
			return 1
		}
		f := format
		if f == "auto" {
			f = "ndjson"
		}
		if _, err := export.Run(export.Options{
			LedgerPath: ledgerPath, Since: since, Format: f,
			Types: typeFilters, From: fromTime, To: toTime, Out: os.Stdout,
		}); err != nil {
			fmt.Fprintf(os.Stderr, "export error: %v\n", err)
			// corruption-class evidence: a torn tail, an unparseable
			// line, or a --trust refusal (D102) — same channel as replay
			if strings.Contains(err.Error(), "torn final line") ||
				strings.Contains(err.Error(), "ledger line") {
				return 5
			}
			return 1
		}
		return 0
	}
	if cmd == "hints" {
		raw, err := docio.ReadDoc(pos[1])
		if err != nil {
			fmt.Fprintf(os.Stderr, "state error: %v\n", err)
			return 1
		}
		var doc map[string]any
		if err := json.Unmarshal(raw, &doc); err != nil {
			fmt.Fprintf(os.Stderr, "state error: not JSON: %v\n", err)
			return 1
		}
		res, err := importer.Map(doc, format)
		if err != nil {
			fmt.Fprintf(os.Stderr, "state error: %v\n", err)
			return 1
		}
		out, _ := json.MarshalIndent(res, "", "  ")
		fmt.Println(string(out))
		return 0
	}
	if cmd == "scenario" {
		return runScenario(pos[1])
	}
	if cmd == "show" {
		// Plan preview (D89): render a SAVED plan to a scannable text review
		// surface. No contract needed — the reviewed object is the plan itself.
		// Presentation only; the JSON stays the machine contract, and the plan
		// hash is bound in the header so reviewed == applied is provable.
		if len(pos) < 2 {
			fmt.Print(usage)
			return 1
		}
		raw, err := os.ReadFile(pos[1])
		if err != nil {
			fmt.Fprintf(os.Stderr, "plan error: %v\n", err)
			return 1
		}
		planDoc, err := plan.LoadPlan(pos[1])
		if err != nil {
			fmt.Fprintf(os.Stderr, "plan error: %v\n", err)
			return 1
		}
		hash, _ := canonical.HashPlan(planDoc)
		out, rerr := planview.Render(raw, hash)
		if rerr != nil {
			fmt.Fprintf(os.Stderr, "plan error: %v\n", rerr)
			return 1
		}
		fmt.Print(out)
		return 0
	}
	if cmd == "status" {
		// D229: a background run's state, derived PURELY from the ledger + the
		// explicit clock (N1 family — enforced above). No second status store.
		if len(pos) < 2 {
			fmt.Print(usage)
			return 1
		}
		if ledgerPath == "" {
			fmt.Fprintln(os.Stderr, "status requires --ledger <file>")
			return 1
		}
		return runStatus(pos[1], ledgerPath, evalTime, jsonMode)
	}
	if cmd == "runs" {
		// D231: list every run in the ledger with its derived state — the
		// "what needs my attention" dashboard. Ledger is the census (D229);
		// --at is mandatory (N1, enforced above).
		if ledgerPath == "" {
			fmt.Fprintln(os.Stderr, "runs requires --ledger <file>")
			return 1
		}
		return runRuns(ledgerPath, evalTime, jsonMode)
	}
	if cmd == "wait" {
		// D229: block until a run reaches a terminal state, then relay its code.
		// wait IS the live clock, so it is exempt from --at (it samples now each
		// poll and calls the same derivation the honesty lives in).
		if len(pos) < 2 {
			fmt.Print(usage)
			return 1
		}
		if ledgerPath == "" {
			fmt.Fprintln(os.Stderr, "wait requires --ledger <file>")
			return 1
		}
		var notifier notify.Notifier
		if notifyURL != "" {
			notifier = notify.URL(notifyURL)
		} else if notifyCmd != "" {
			notifier = notify.Cmd(strings.Fields(notifyCmd))
		}
		return runWait(pos[1], ledgerPath, pollSeconds, timeoutSeconds, jsonMode, notifier)
	}
	if cmd == "forecast" {
		if len(pos) < 3 {
			fmt.Print(usage)
			return 1
		}
		return runForecast(pos[1], pos[2], headsPath, ledgerPath,
			bindingsPath, observationsPath, evalTime)
	}

	vocabs, verr := loadVocabs(vocabDir, noVocab)
	if verr != nil {
		fmt.Fprintf(os.Stderr, "vocab error: %v\n", verr)
		return 1
	}

	c, err := contract.LoadContract(pos[1])
	if err != nil {
		fmt.Fprintf(os.Stderr, "contract error: %v\n", err)
		return 1
	}

	switch cmd {
	case "validate":
		hard := 0
		for _, cn := range c.Constraints {
			if cn.Severity == "hard" {
				hard++
			}
		}
		fmt.Printf("OK  contract %s v%d: %d capabilities, %d constraints (%d hard)\n",
			c.ID, c.Version, len(c.Capabilities), len(c.Constraints), hard)
		return 0

	case "survey":
		if len(surveyPaths) == 0 {
			fmt.Fprintln(os.Stderr, "survey requires at least one --survey <file>")
			return 1
		}
		docs := make([]*survey.Doc, 0, len(surveyPaths))
		for _, p := range surveyPaths {
			d, err := survey.Load(p)
			if err != nil {
				fmt.Fprintf(os.Stderr, "survey error: %v\n", err)
				return 1
			}
			docs = append(docs, d)
		}
		res := survey.Run(c, docs, completeFlag)
		printResult(res, explainFlag)
		return res.Exit

	case "verify":
		if len(pos) < 3 {
			fmt.Print(usage)
			return 1
		}
		cand, err := contract.LoadCandidate(pos[2], c, vocabs)
		if err != nil {
			fmt.Fprintf(os.Stderr, "candidate error: %v\n", err)
			return 1
		}
		report, verr := verify.Verify(c, cand, vocabs)
		if verr != nil {
			fmt.Fprintf(os.Stderr, "candidate error: %v\n", verr)
			return 1
		}
		bannerState.code = report.Code
		bannerState.rollup = verdictRollup(report)
		if jsonMode {
			out, err := json.MarshalIndent(report, "", "  ")
			if err != nil {
				fmt.Fprintf(os.Stderr, "report error: %v\n", err)
				return 1
			}
			fmt.Println(string(out))
		} else {
			bannerState.done = true
			exit := 0
			if !report.Executable {
				exit = 2
			}
			printText(report, c, vocabs, render.Detect(colorFlag, asciiFlag, os.Stdout), exit)
		}
		if report.Executable {
			return 0
		}
		return 2

	case "probe":
		if ledgerPath == "" {
			fmt.Fprintln(os.Stderr, "probe requires --ledger")
			return 1
		}
		led, err := ledger.ReplayFile(ledgerPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "ledger error: %v\n", err)
			return 5
		}
		var prov provider.Provider
		if providerName == "gcp" {
			prov = gcp.NewDriver(project)
		} else if providerName == "aws" {
			prov = aws.NewDriver(region)
		} else if providerName == "azure" {
			prov = azure.NewDriver(project)
		} else if providerName == "k8s" {
			kd, kerr := k8sDriver(kubeconfigPath, kubeContext)
			if kerr != nil {
				fmt.Fprintln(os.Stderr, kerr.Error())
				return 1
			}
			prov = kd
		} else {
			prov = &provider.Fake{FailKeys: failKeys,
				UnknownKeys: unknownKeys, RetryableKeys: retryableKeys}
		}
		res := probe.Run(c, led, ledgerPath, prov, evalTime, onlyCap,
			allowIntrusive, record)
		printResult(res, explainFlag)
		return res.Exit

	case "resume":
		if ledgerPath == "" {
			fmt.Fprintln(os.Stderr, "resume requires --ledger")
			return 1
		}
		led, err := ledger.ReplayFile(ledgerPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "ledger error: %v\n", err)
			return 5
		}
		var prov provider.Provider
		if providerName == "gcp" {
			prov = gcp.NewDriver(project)
		} else if providerName == "aws" {
			prov = aws.NewDriver(region)
		} else if providerName == "azure" {
			prov = azure.NewDriver(project)
		} else if providerName == "k8s" {
			kd, kerr := k8sDriver(kubeconfigPath, kubeContext)
			if kerr != nil {
				fmt.Fprintln(os.Stderr, kerr.Error())
				return 1
			}
			prov = kd
		} else {
			prov = &provider.Fake{FailKeys: failKeys,
				UnknownKeys: unknownKeys, RetryableKeys: retryableKeys}
		}
		res := resume.Run(c, led, ledgerPath, prov, evalTime)
		printResult(res, explainFlag)
		return res.Exit

	case "publish":
		if ledgerPath == "" {
			fmt.Fprintln(os.Stderr, "publish requires --ledger")
			return 1
		}
		res := publish.Run(c, ledgerPath, actor, evalTime)
		printResult(res, explainFlag)
		return res.Exit

	case "audit":
		if ledgerPath == "" {
			fmt.Fprintln(os.Stderr, "audit requires --ledger")
			return 1
		}
		led, err := ledger.ReplayFile(ledgerPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "ledger error: %v\n", err)
			return 5
		}
		res, err := audit.Run(c, led, ledgerPath, evalTime, record)
		if err != nil {
			fmt.Fprintf(os.Stderr, "audit error: %v\n", err)
			return 1
		}
		for _, v := range res.Verdicts {
			if v.Severity != "hard" {
				continue
			}
			switch v.Verdict {
			case "violated":
				bannerState.rollup.Violated = append(bannerState.rollup.Violated, v.Constraint)
			case "unknown":
				bannerState.rollup.Unknown = append(bannerState.rollup.Unknown, v.Constraint)
			case "unverifiable":
				bannerState.rollup.Unverifiable = append(bannerState.rollup.Unverifiable, v.Constraint)
			}
		}
		out, _ := json.MarshalIndent(res, "", "  ")
		fmt.Println(string(out))
		if res.Violations > 0 {
			return 2
		}
		return 0

	case "adopt":
		if len(pos) < 3 {
			fmt.Print(usage)
			return 1
		}
		if ledgerPath == "" {
			fmt.Fprintln(os.Stderr, "adopt requires --ledger")
			return 1
		}
		// F5 fail-loud: adopt confirms every candidate-declared attribute against a
		// LIVE observation only — an operator cannot attest their way into an
		// adoption (D52, adoption must not lie). Rather than silently ignoring a
		// supplied --observations file, refuse it so the guarantee is explicit.
		if observationsPath != "" {
			fmt.Fprintln(os.Stderr, "adopt does not accept --observations: adoption "+
				"confirms declared attributes against LIVE observation only (an operator "+
				"cannot attest their way into an adoption) — remove --observations")
			return 1
		}
		cand, err := contract.LoadCandidate(pos[2], c, vocabs)
		if err != nil {
			fmt.Fprintf(os.Stderr, "candidate error: %v\n", err)
			return 1
		}
		report, verr := verify.Verify(c, cand, vocabs)
		if verr != nil {
			fmt.Fprintf(os.Stderr, "candidate error: %v\n", verr)
			return 1
		}
		led, err := ledger.ReplayFile(ledgerPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "ledger error: %v\n", err)
			return 5
		}
		discoveryHash := ""
		if discoveryPath != "" {
			raw, err := docio.ReadDoc(discoveryPath)
			if err != nil {
				fmt.Fprintf(os.Stderr, "discovery error: %v\n", err)
				return 1
			}
			var d struct {
				DiscoveryHash string `yaml:"discoveryHash"`
			}
			if err := yaml.Unmarshal(raw, &d); err != nil ||
				d.DiscoveryHash == "" {
				fmt.Fprintln(os.Stderr,
					"discovery error: no discoveryHash in the document")
				return 1
			}
			discoveryHash = d.DiscoveryHash
		}
		var prov provider.Provider
		if providerName == "gcp" {
			prov = gcp.NewDriver(project)
		} else if providerName == "aws" {
			prov = aws.NewDriver(region)
		} else if providerName == "azure" {
			prov = azure.NewDriver(project)
		} else if providerName == "k8s" {
			kd, kerr := k8sDriver(kubeconfigPath, kubeContext)
			if kerr != nil {
				fmt.Fprintln(os.Stderr, kerr.Error())
				return 1
			}
			prov = kd
		} else {
			prov = &provider.Fake{}
		}
		res, code := adopt.Run(c, cand, report, adoptMap, prov, led,
			ledgerPath, evalTime, discoveryHash)
		// D322: an adoption can succeed and still have something to SAY — an
		// assumed declaration the live reading contradicts. JSON alone would bury
		// it, so it also goes to the human channel (stderr, never stdout: the
		// result document stays machine-clean).
		for _, n := range res.Notes {
			fmt.Fprintf(os.Stderr, "note: %s\n", n)
		}
		printResult(res, explainFlag)
		return code

	case "unadopt":
		if len(pos) < 3 {
			fmt.Print(usage)
			return 1
		}
		if ledgerPath == "" {
			fmt.Fprintln(os.Stderr, "unadopt requires --ledger")
			return 1
		}
		led, err := ledger.ReplayFile(ledgerPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "ledger error: %v\n", err)
			return 5
		}
		res, code := adopt.Unadopt(pos[2], led, ledgerPath,
			c.Environment, evalTime)
		printResult(res, explainFlag)
		return code

	case "plan":
		if len(pos) < 3 {
			fmt.Print(usage)
			return 1
		}
		cand, err := contract.LoadCandidate(pos[2], c, vocabs)
		if err != nil {
			fmt.Fprintf(os.Stderr, "candidate error: %v\n", err)
			return 1
		}
		// D173: the parity matrix governs — a candidate binding a service to a
		// capability TYPE that service does not fulfil refuses before compile.
		if err := checkParityBindings(c, cand); err != nil {
			fmt.Fprintf(os.Stderr, "candidate error: %v\n", err)
			return 1
		}
		report, verr := verify.Verify(c, cand, vocabs)
		if verr != nil {
			fmt.Fprintf(os.Stderr, "candidate error: %v\n", verr)
			return 1
		}
		in := compiler.Inputs{
			Heads:        map[string]string{},
			Bindings:     map[string]string{},
			Observations: map[string]map[string]ledger.ObsRecord{},
		}
		if ledgerPath != "" {
			led, err := ledger.ReplayFile(ledgerPath)
			if err != nil {
				fmt.Fprintf(os.Stderr, "ledger error: %v\n", err)
				return 5
			}
			in.Heads = led.DecisionHeads
			in.Bindings = led.BoundProviderIDs()
			in.BindingProviders = led.BoundProviderNames()
			in.BindingServices = led.BoundServices()
			in.Generations = led.BoundGenerations()
			in.Observations = led.Observations
			in.Outputs = led.Outputs // D286: the wiring projection, kept apart
			in.Deposed = led.Deposed(false)
			in.Adopted = led.AdoptedCapabilities()
			in.Claimed = led.ClaimedCapabilities()
			in.Observed = led.ObservedCapabilities()
		}
		if bindingsPath != "" {
			if in.Bindings, err = loadStringMap(bindingsPath, "bindings"); err != nil {
				fmt.Fprintf(os.Stderr, "bindings error: %v\n", err)
				return 1
			}
		}
		if observationsPath != "" {
			if in.Observations, in.Outputs, err = loadObservations(observationsPath); err != nil {
				fmt.Fprintf(os.Stderr, "observations error: %v\n", err)
				return 1
			}
		}
		if in.EvalClock, err = ledger.ParseTs(evalTime); err != nil {
			fmt.Fprintf(os.Stderr, "plan error: bad --at: %v\n", err)
			return 1
		}
		// classification is pure provider knowledge (D46), dispatched
		// per-capability by provider name (D186)
		in.Providers = classifyProviders(cand)
		var doc *compiler.Document
		if deposedPlan {
			if ledgerPath == "" {
				fmt.Fprintln(os.Stderr,
					"plan --deposed requires --ledger (the deposed "+
						"projection is ledger history)")
				return 1
			}
			doc, err = compiler.CompileDeposed(c, cand, vocabs, report,
				project, in)
		} else {
			doc, err = compiler.Compile(c, cand, vocabs, report, project, in)
		}
		if err != nil {
			fmt.Fprintf(os.Stderr, "plan refused: %v\n", err)
			for _, r := range report.BlockingReasons {
				fmt.Fprintf(os.Stderr, "  %s\n", r)
			}
			// D65: machine-readable refusal on stdout — exactly one
			// JSON object plus newline (stdout was empty on exit 2
			// before, so nothing breaks; the success document is
			// self-discriminating via its top-level "plan" key)
			refusal := map[string]any{
				"status": "refused",
				"reasons": append([]string{err.Error()},
					report.BlockingReasons...),
			}
			if code := planRefusalCode(err.Error()); code != "" {
				refusal["code"] = string(code)
				bannerState.code = string(code)
				// D230: an invocation-specific advisory next step. A typed
				// compiler.RefusalError carries the site facts (the stateful
				// capability for a consent edit, the $ref location for a reference
				// edit); plain errors get command/generic nexts only.
				detail := perrnext.Detail{}
				var re *compiler.RefusalError
				if errors.As(err, &re) {
					detail.Capability = re.Capability
					detail.RefPointer = re.RefPointer
					detail.Note = re.Note
				}
				if n := perrnext.NextFor(invocation, code, detail); n != nil {
					refusal["next"] = n
				}
			}
			raw, _ := json.Marshal(refusal)
			fmt.Println(string(raw))
			return 2
		}
		out, err := json.MarshalIndent(doc, "", "  ")
		if err != nil {
			fmt.Fprintf(os.Stderr, "plan error: %v\n", err)
			return 1
		}
		fmt.Println(string(out))
		// D202: cost estimate on stderr (stdout stays the pure, hashed plan),
		// at the end of the dry run, before any apply.
		if ccy, cerr := resolveCurrency(reportingCurrency); cerr != nil {
			fmt.Fprintf(os.Stderr, "currency error: %v\n", cerr)
			return 1
		} else {
			renderCostProjection(os.Stderr, doc, cand, ccy)
		}
		// D203: advisory hardening hint on stderr (never gates, never touches
		// the hashed plan) — the same channel as the cost estimate.
		renderSuggestHint(os.Stderr, c, vocabs, cand)
		// Part B: name every converged no-op on stderr (the prose channel), so a
		// plan that changes some capabilities and leaves others alone says WHY it
		// left them alone. The hashed plan on stdout already carries plan.noop.
		renderNoOp(os.Stderr, doc)
		return 0

	case "preflight":
		// F7/F3: run the driver refuse-before-mutate hook for EVERY capability in
		// one pass, so the complete set of missing implementation.* operands and
		// unsatisfiable attributes surfaces at once — not one apply at a time.
		if len(pos) < 3 {
			fmt.Print(usage)
			return 1
		}
		cand, err := contract.LoadCandidate(pos[2], c, vocabs)
		if err != nil {
			fmt.Fprintf(os.Stderr, "candidate error: %v\n", err)
			return 1
		}
		prov := crawlProvider(providerName, project, kubeconfigPath, kubeContext)
		if prov == nil {
			fmt.Fprintf(os.Stderr, "unknown provider %q\n", providerName)
			return 1
		}
		report := apply.Preflight(c, cand, vocabs, prov)
		out, err := json.MarshalIndent(report, "", "  ")
		if err != nil {
			fmt.Fprintf(os.Stderr, "preflight error: %v\n", err)
			return 1
		}
		fmt.Println(string(out))
		if !report.Ready {
			fmt.Fprintf(os.Stderr,
				"preflight: %d of %d capabilities cannot be honored yet — "+
					"supply the named implementation operands and re-run\n",
				report.Missing, len(report.Capabilities))
			return 2
		}
		return 0

	case "apply":
		if len(pos) < 4 {
			fmt.Print(usage)
			return 1
		}
		if ledgerPath == "" {
			fmt.Fprintln(os.Stderr, "apply requires --ledger <file>")
			return 1
		}
		cand, err := contract.LoadCandidate(pos[2], c, vocabs)
		if err != nil {
			fmt.Fprintf(os.Stderr, "candidate error: %v\n", err)
			return 1
		}
		planDoc, err := plan.LoadPlan(pos[3])
		if err != nil {
			fmt.Fprintf(os.Stderr, "plan error: %v\n", err)
			return 1
		}
		var prov provider.Provider
		switch providerName {
		case "fake":
			prov = &provider.Fake{FailKeys: failKeys,
				UnknownKeys: unknownKeys, RetryableKeys: retryableKeys}
		case "gcp":
			// D28: provider identity comes from the plan's read-set
			p, _ := planDoc["plan"].(map[string]any)
			reads, _ := p["reads"].(map[string]any)
			pr, _ := reads["provider"].(map[string]any)
			pinned, _ := pr["project"].(string)
			if pinned == "" {
				fmt.Fprintln(os.Stderr,
					"apply error: plan does not pin reads.provider.project")
				return 1
			}
			if project != "" && project != pinned {
				fmt.Fprintf(os.Stderr, "apply error: --project %s does "+
					"not match the plan's pinned project %s\n",
					project, pinned)
				return 1
			}
			prov = gcp.NewDriver(pinned)
		case "aws":
			prov = aws.NewDriver("")
		case "azure":
			// like gcp (D28): a create generates the providerId from the
			// driver's subscription, so apply must pin it from the plan's
			// read-set. Azure carries the subscription in the Project field
			// (verbs take it via --project), same as every other azure verb.
			p, _ := planDoc["plan"].(map[string]any)
			reads, _ := p["reads"].(map[string]any)
			pr, _ := reads["provider"].(map[string]any)
			pinned, _ := pr["project"].(string)
			if pinned == "" {
				fmt.Fprintln(os.Stderr,
					"apply error: plan does not pin reads.provider.project (the azure subscription)")
				return 1
			}
			if project != "" && project != pinned {
				fmt.Fprintf(os.Stderr, "apply error: --project %s does "+
					"not match the plan's pinned subscription %s\n",
					project, pinned)
				return 1
			}
			prov = azure.NewDriver(pinned)
		case "k8s":
			kd, kerr := k8sDriver(kubeconfigPath, kubeContext)
			if kerr != nil {
				fmt.Fprintln(os.Stderr, kerr.Error())
				return 1
			}
			prov = kd
		default:
			fmt.Fprintf(os.Stderr, "unknown provider %q\n", providerName)
			return 1
		}
		// D229: detach before any parent-side output — the child re-runs
		// without --detach and prints the recap/progress itself.
		if detachFlag {
			handle, herr := apply.RunID(planDoc, evalTime)
			if herr != nil {
				fmt.Fprintf(os.Stderr, "plan error: %v\n", herr)
				return 1
			}
			return detachRun(handle, "apply", ledgerPath, evalTime, args, jsonMode)
		}
		// D228: the last thing a human sees before mutation is the destructive
		// recap they reviewed with `show` — same vocabulary, on stderr (never
		// stdout, never parsed). Silent when the plan destroys nothing.
		if raw, rerr := os.ReadFile(pos[3]); rerr == nil {
			if recap := planview.Recap(raw); recap != "" {
				fmt.Fprint(os.Stderr, recap)
			}
		}
		pmode := resolveProgress(progressFlag)
		// ndjson keeps stderr a pure machine stream: the human banner is
		// suppressed (it rides the stream as a kind:banner event instead, D227).
		bannerState.suppress = pmode == progress.ModeNDJSON
		res := apply.Apply(c, cand, vocabs, planDoc, ledgerPath,
			prov, evalTime, requirePreflight,
			apply.WithProgress(pmode, os.Stderr, nil))
		// D230: surface the refusal's site facts so the emitter can build a
		// grant (denied permissions) or edit (stateful capability) `next`.
		refusalDetail = perrnext.Detail{Permissions: res.Denied, Capability: res.Capability}
		// Layer 1: post-apply reachability probe. Only after a CLEAN apply (the
		// resources stand); a denied/unknown edge does NOT retroactively fail the
		// apply — it downgrades the exit/banner so an APPLIED edge that 403s is
		// never reported as clean success. Network side-effect, outside the
		// deterministic executor (apply.Apply did no GET).
		if res.Exit == 0 && res.Status == "applied" {
			applyReachability(c, cand, res, ledgerPath, providerName, evalTime, noReachability)
		}
		printResult(res, explainFlag)
		return res.Exit
	}
	fmt.Print(usage)
	return 1
}

// applyReachability runs the Layer-1 post-apply reachability probe for the
// apply verb and folds its four-valued verdict into res: reachable stays clean;
// a 401/403 or a transport failure is unknown -> exit 2 + BLOCKED rollup (a
// named, non-accusatory cause) so an APPLIED public edge that 403s is never
// reported as clean success. The GET is a network side-effect OUTSIDE apply.Apply (the executor
// stayed network-free); its result is recorded as a measured observation. The
// human prose rides stderr (the apply stdout is the JSON machine payload).
func applyReachability(c *contract.Contract, cand *contract.Candidate, res *apply.Result, ledgerPath,
	providerName, at string, noReachability bool) {
	say := func(format string, a ...any) {
		if !bannerState.suppress {
			fmt.Fprintf(os.Stderr, format+"\n", a...)
		}
	}
	if noReachability {
		say("reachability skipped (--no-reachability) — the public edge was NOT " +
			"probed; an APPLIED edge that 403s will read as clean success")
		res.Reachability = "skipped"
		return
	}
	capTypes := map[string]string{}
	for id, raw := range c.Capabilities {
		if t, _ := raw["type"].(string); t != "" {
			capTypes[id] = t
		}
	}
	public := map[string]bool{}
	if cand != nil {
		public = cand.PublicExposureByCap()
	}
	targets := reach.Targets(capTypes, res.Outputs, public)
	if len(targets) == 0 {
		return // no public edge to probe — nothing measured, nothing emitted
	}
	results := reach.Probe(reach.DefaultGetter(), targets)
	if led, err := ledger.ReplayFile(ledgerPath); err == nil {
		if _, rerr := reach.Record(led, ledgerPath, c.Environment, at, providerName,
			res.Bindings, reach.Observations(results)); rerr != nil {
			say("  reachability observations could not be recorded: %v", rerr)
		}
	}
	for _, cr := range results {
		switch {
		case cr.Verdict == reach.Reachable:
			say("  reachable: %s GET %s — %s", cr.Capability, cr.URL, cr.Cause)
		case reach.IsAnonymousDenied(cr):
			say("  reachability unknown: %s GET %s — %s", cr.Capability, cr.URL, cr.Cause)
			say("    %s", reach.AnonymousRemediation)
			bannerState.rollup.Unknown = append(bannerState.rollup.Unknown,
				cr.Capability+" public edge not anonymously reachable")
		default: // unknown: transport failure or an unexpected status
			say("  reachability unknown (from here): %s GET %s — %s",
				cr.Capability, cr.URL, cr.Cause)
			bannerState.rollup.Unknown = append(bannerState.rollup.Unknown,
				cr.Capability+" public edge unreachable-from-here")
		}
	}
	if reach.Overall(results) == reach.Unknown {
		res.Reachability, res.Exit = "unknown", 2
	} else {
		res.Reachability = "reachable"
	}
}

// k8sDriver builds the Kubernetes driver from the kubeconfig flags/env. The path
// falls back GROUNDHOLD_KUBECONFIG -> KUBECONFIG -> ~/.kube/config; the context falls
// back to the kubeconfig's current-context when unset. Static auth only — exec
// plugins are refused inside NewFromKubeconfig.
// runLiveCrawl runs the gentle read-only crawl over the pairing registry through the
// pace scheduler — the shared engine behind both `groundhold crawl` and a live
// `groundhold posture`. Each paired provider's Discoverer is driven per scope; an
// Enumerator (when present) fans a scopeless pairing out to its scopes.
func runLiveCrawl(reg *pair.Registry, budgetArg int, at, kubeconfigPath, kubeContext string) (*crawl.Document, error) {
	pol := pace.DefaultPolicy()
	if budgetArg > 0 {
		pol.Budget = budgetArg
	}
	sched := pace.New(pol, pace.Clock{Now: time.Now, Sleep: time.Sleep, Jitter: rand.Float64})
	fetch := func(c pair.Connection, scope string) crawl.Fetched {
		prov := crawlProvider(c.Provider, scope, kubeconfigPath, kubeContext)
		if prov == nil {
			return crawl.Fetched{Pace: pace.Result{Outcome: pace.AuthError}}
		}
		res, derr := discover.Run(prov, scope, scope, at)
		if derr != nil {
			return crawl.Fetched{Pace: pace.Result{Outcome: pace.ServerError}}
		}
		return crawl.Fetched{Resources: res.Discovery.Resources, Pace: pace.Result{Outcome: pace.OK}}
	}
	enum := func(c pair.Connection) crawl.EnumResult {
		prov := crawlProvider(c.Provider, "", kubeconfigPath, kubeContext)
		if prov == nil {
			return crawl.EnumResult{Pace: pace.Result{Outcome: pace.AuthError}}
		}
		en, ok := prov.(provider.Enumerator)
		if !ok {
			return crawl.EnumResult{Scopes: []string{""}, Pace: pace.Result{Outcome: pace.OK}}
		}
		scopes, diags, eerr := en.Enumerate()
		if eerr != nil {
			return crawl.EnumResult{Pace: pace.Result{Outcome: pace.ServerError}}
		}
		return crawl.EnumResult{Scopes: scopes, Diags: diags, Pace: pace.Result{Outcome: pace.OK}}
	}
	return crawl.Run(reg, fetch, enum, sched, pol.Budget, at, time.Now)
}

// classifyPosture folds a crawl document + the ledger + audit into the posture
// document — shared by `groundhold posture` (full or live crawl) and `groundhold react`
// (a spliced crawl). Pure given its inputs.
func classifyPosture(led *ledger.Ledger, ledgerPath string, ctx *crawl.Document, contractPaths []string, at string) (*posture.Document, error) {
	in := posture.Input{At: at, Bindings: led.BoundProviderIDs(),
		Deposed: map[string]bool{}, Decayed: map[string]bool{}, Verdict: map[string]string{}}
	if ctx != nil {
		for _, p := range ctx.Providers {
			for _, s := range p.Scopes {
				complete := s.Status == "complete"
				for _, r := range s.Resources {
					in.Discovered = append(in.Discovered, posture.Discovered{
						ProviderID: r.ProviderID, Scope: s.Scope, ScopeComplete: complete})
				}
			}
		}
	}
	for _, d := range led.Deposed(false) {
		in.Deposed[d.ProviderID] = true
	}
	// D323: defence in depth. The N1 gate refuses a malformed --at before any verb
	// runs, so this cannot fire from the CLI — but this function decides FRESHNESS,
	// and a zero clock here silently marks every expired proof fresh. A safety
	// decision must not depend on a caller having validated its input.
	atSec, aerr := ledger.ParseTs(at)
	if aerr != nil {
		return nil, fmt.Errorf("posture needs a parseable --at (RFC3339): %v", aerr)
	}
	for capID := range in.Bindings {
		recs := led.Observations[capID]
		if len(recs) == 0 {
			in.Decayed[capID] = true
			continue
		}
		for _, r := range recs {
			obsSec, perr2 := ledger.ParseTs(r.ObservedAt)
			if perr2 != nil || obsSec+r.TTLSeconds <= atSec {
				in.Decayed[capID] = true
				break
			}
		}
	}
	type vacc struct{ violated, unverifiable, unknown, satisfied bool }
	accs := map[string]*vacc{}
	for _, cp := range contractPaths {
		c, cerr := contract.LoadContract(cp)
		if cerr != nil {
			return nil, fmt.Errorf("contract error: %v", cerr)
		}
		ar, aerr := audit.Run(c, led, ledgerPath, at, false)
		if aerr != nil {
			return nil, fmt.Errorf("audit error: %v", aerr)
		}
		for _, v := range ar.Verdicts {
			a := accs[v.Capability]
			if a == nil {
				a = &vacc{}
				accs[v.Capability] = a
			}
			switch v.Verdict {
			case "violated":
				a.violated = true
			case "unverifiable":
				a.unverifiable = true
			case "unknown":
				a.unknown = true
			case "satisfied":
				a.satisfied = true
			}
		}
	}
	for capID, a := range accs {
		switch {
		case a.violated:
			in.Verdict[capID] = "violated"
		case a.unverifiable:
			in.Verdict[capID] = "unverifiable"
		case a.unknown:
			// leave unset -> falls through to decayed/unknown
		case a.satisfied:
			in.Verdict[capID] = "satisfied"
		}
	}
	return posture.Classify(in), nil
}

// crawlProvider builds the read-only discoverer for a paired provider+scope. nil =
// the provider cannot be constructed here (surfaced as an auth outcome by the crawl).
func crawlProvider(name, scope, kubeconfigPath, kubeContext string) provider.Provider {
	switch name {
	case "gcp":
		return gcp.NewDriver(scope)
	case "aws":
		return aws.NewDriver("")
	case "azure":
		return azure.NewDriver(scope)
	case "k8s":
		kd, err := k8sDriver(kubeconfigPath, kubeContext)
		if err != nil {
			return nil
		}
		return kd
	case "upstash":
		return upstash.NewDriver()
	case "hetzner":
		return hetzner.NewDriver(scope)
	case "cloudflare":
		return cloudflare.NewDriver(scope)
	case "fake":
		return &provider.Fake{}
	}
	return nil
}

func k8sDriver(kubeconfigPath, kubeContext string) (provider.Provider, error) {
	path := kubeconfigPath
	if path == "" {
		if home, err := os.UserHomeDir(); err == nil {
			path = filepath.Join(home, ".kube", "config")
		}
	}
	return k8s.NewFromKubeconfig(path, kubeContext)
}

// classifyProvider picks the provider whose PURE ClassifyChange the
// compiler consults — by the candidate's declared provider name.
// parityCaps returns each cloud's proven token->capability map (the drivers'
// ServiceCapabilities). ServiceCapabilities is a static declaration, so the
// constructor arg is irrelevant.
func parityCaps() map[string]map[string]string {
	return map[string]map[string]string{
		"aws":   aws.NewDriver("").ServiceCapabilities(),
		"gcp":   gcp.NewDriver("").ServiceCapabilities(),
		"azure": azure.NewDriver("").ServiceCapabilities(),
	}
}

// checkParityBindings refuses a candidate whose declared (provider, service) does
// not fulfil the capability TYPE the contract gives that capability — the
// confused-capability hole the parity matrix closes (D173). Deterministic and
// network-free; providers with no ServiceCapabilities map (fake, read-only) skip.
func checkParityBindings(c *contract.Contract, cand *contract.Candidate) error {
	caps := parityCaps()
	for capID, extras := range cand.Extras {
		prov, _ := extras["provider"].(string)
		svc, _ := extras["service"].(string)
		typ := ""
		if capRaw, ok := c.Capabilities[capID]; ok {
			typ, _ = capRaw["type"].(string)
		}
		if err := parity.CheckBinding(caps, capID, prov, svc, typ); err != nil {
			return err
		}
	}
	return nil
}

// runParity is the `groundhold parity [capability.type] [--json]` query — the
// deterministic projection of the parity matrix the bake-off (D92) consumes:
// for each cloud, does it FULFIL a capability (with which services), STRUCTURALLY
// cannot (a gap + reason), or simply lacks a driver (unbuilt)?
func runParity(args []string, asJSON bool) int {
	caps := parityCaps()
	target := ""
	for _, a := range args {
		if !strings.HasPrefix(a, "-") {
			target = a
		}
	}
	types := parity.CapabilityTypes(caps)
	if target != "" {
		if !strings.HasPrefix(target, "capability.") {
			target = "capability." + target
		}
		types = []string{target}
	}

	if asJSON {
		out := map[string]map[string]parity.Fulfilment{}
		for _, typ := range types {
			row := map[string]parity.Fulfilment{}
			for _, cloud := range parity.Clouds() {
				row[cloud] = parity.CanFulfil(caps, cloud, typ)
			}
			out[typ] = row
		}
		b, _ := json.MarshalIndent(out, "", "  ")
		fmt.Println(string(b))
		return 0
	}

	for _, typ := range types {
		fmt.Println(typ)
		for _, cloud := range parity.Clouds() {
			f := parity.CanFulfil(caps, cloud, typ)
			switch f.State {
			case "fulfilled":
				fmt.Printf("  %-6s fulfilled: %s\n", cloud, strings.Join(f.Tokens, ", "))
			case "gap":
				fmt.Printf("  %-6s gap (%s): %s\n", cloud, f.Class, f.Reason)
			default:
				fmt.Printf("  %-6s unbuilt\n", cloud)
			}
		}
	}
	return 0
}

// classifyProviders builds the name->driver map the compiler dispatches
// ClassifyChange/claim-gating through, one entry per DISTINCT provider the
// candidate declares. A mixed candidate (e.g. aws podidentity + k8s witness)
// must classify each capability with its OWN driver — selecting a single
// driver by map-iteration order made the plan nondeterministic (D186).
// Pure ClassifyChange + claim-gating only; no server needed.
func classifyProviders(cand *contract.Candidate) map[string]provider.Provider {
	out := map[string]provider.Provider{}
	for _, extras := range cand.Extras {
		name, _ := extras["provider"].(string)
		if _, done := out[name]; done {
			continue
		}
		switch name {
		case "gcp":
			out[name] = gcp.NewDriver("")
		case "aws":
			out[name] = aws.NewDriver("")
		case "azure":
			out[name] = azure.NewDriver("")
		case "k8s":
			out[name] = k8s.NewDriver("", "")
		}
	}
	return out
}

func loadStringMap(path, what string) (map[string]string, error) {
	raw, err := docio.ReadDoc(path)
	if err != nil {
		return nil, err
	}
	var docAny any
	if err := yaml.Unmarshal(raw, &docAny); err != nil {
		return nil, err
	}
	doc, ok := docAny.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("%s: not a mapping", what)
	}
	out := map[string]string{}
	for k, v := range doc {
		s, _ := v.(string)
		out[k] = s
	}
	return out, nil
}

// loadObservations parses observe's own output format — the natural
// pipe: `groundhold observe ... > obs.json; groundhold forecast --observations obs.json`.
// loadObservations splits a supplied observation file into the SEMANTIC map
// (capability -> path -> record) and the WIRING map (capability -> output name
// -> record, D286). Same split the ledger replay performs, so a file-supplied
// observation set cannot smuggle a wiring record into semantic knowledge —
// which would re-open the fail-open the projection separation closed.
func loadObservations(path string) (map[string]map[string]ledger.ObsRecord,
	map[string]map[string]ledger.ObsRecord, error) {
	raw, err := docio.ReadDoc(path)
	if err != nil {
		return nil, nil, err
	}
	var doc struct {
		Observations []struct {
			Capability string `yaml:"capability" json:"capability"`
			Path       string `yaml:"path" json:"path"`
			Value      any    `yaml:"value" json:"value"`
			Source     string `yaml:"source" json:"source"`
			Derivation string `yaml:"derivation" json:"derivation"`
			ObservedAt string `yaml:"observedAt" json:"observedAt"`
			TTLSeconds int    `yaml:"ttlSeconds" json:"ttlSeconds"`
		} `yaml:"observations" json:"observations"`
	}
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		return nil, nil, err
	}
	out := map[string]map[string]ledger.ObsRecord{}
	wiring := map[string]map[string]ledger.ObsRecord{}
	for _, o := range doc.Observations {
		rec := ledger.ObsRecord{
			Value: o.Value, ObservedAt: o.ObservedAt,
			TTLSeconds: o.TTLSeconds, Derivation: o.Derivation,
			Source: o.Source,
		}
		if name, isWiring := strings.CutPrefix(o.Path, ledger.WiringPrefix); isWiring {
			if wiring[o.Capability] == nil {
				wiring[o.Capability] = map[string]ledger.ObsRecord{}
			}
			wiring[o.Capability][name] = rec
			continue
		}
		if out[o.Capability] == nil {
			out[o.Capability] = map[string]ledger.ObsRecord{}
		}
		out[o.Capability][o.Path] = rec
	}
	return out, wiring, nil
}

// runForecast: D40/D45 — deterministic forecast from declared inputs.
// The ledger supplies decision heads, bindings and observations at once;
// explicit files override each piece.
func runForecast(planPath, candPath, headsPath, ledgerPath,
	bindingsPath, observationsPath, evalTime string) int {
	planDoc, err := plan.LoadPlan(planPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "plan error: %v\n", err)
		return 1
	}
	cand, err := contract.LoadCandidate(candPath, nil, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "candidate error: %v\n", err)
		return 1
	}

	heads := map[string]string{}
	bindings := map[string]string{}
	generations := map[string]int{}
	observations := map[string]map[string]ledger.ObsRecord{}
	if ledgerPath != "" {
		led, err := ledger.ReplayFile(ledgerPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "ledger error: %v\n", err)
			return 5
		}
		heads = led.DecisionHeads // D41: plans pin decision heads
		bindings = led.BoundProviderIDs()
		generations = led.BoundGenerations()
		observations = led.Observations
	}
	if headsPath != "" {
		if heads, err = loadStringMap(headsPath, "heads"); err != nil {
			fmt.Fprintf(os.Stderr, "heads error: %v\n", err)
			return 1
		}
	}
	if bindingsPath != "" {
		if bindings, err = loadStringMap(bindingsPath, "bindings"); err != nil {
			fmt.Fprintf(os.Stderr, "bindings error: %v\n", err)
			return 1
		}
	}
	if observationsPath != "" {
		if observations, _, err = loadObservations(observationsPath); err != nil {
			fmt.Fprintf(os.Stderr, "observations error: %v\n", err)
			return 1
		}
	}

	fc, err := forecast.Forecast(planDoc, cand, heads, bindings,
		generations, observations, evalTime)
	if err != nil {
		fmt.Fprintf(os.Stderr, "forecast error: %v\n", err)
		return 1
	}
	out, err := json.MarshalIndent(fc, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "forecast error: %v\n", err)
		return 1
	}
	fmt.Println(string(out))
	return 0
}

// runObserve: D44 — observe only what we own; bindings are the input.
func runObserve(ledgerPath, bindingsPath, providerName, at string,
	ttl int, record bool, kubeconfigPath, kubeContext string) int {
	var led *ledger.Ledger
	bindings := map[string]string{}
	switch {
	case ledgerPath != "":
		l, err := ledger.ReplayFile(ledgerPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "ledger error: %v\n", err)
			return 5
		}
		led = l
		bindings = led.BoundProviderIDs()
	case bindingsPath != "":
		raw, err := docio.ReadDoc(bindingsPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "bindings error: %v\n", err)
			return 1
		}
		var docAny any
		if err := yaml.Unmarshal(raw, &docAny); err != nil {
			fmt.Fprintf(os.Stderr, "bindings error: %v\n", err)
			return 1
		}
		doc, ok := docAny.(map[string]any)
		if !ok {
			fmt.Fprintln(os.Stderr, "bindings error: not a mapping")
			return 1
		}
		for k, v := range doc {
			s, _ := v.(string)
			bindings[k] = s
		}
	default:
		fmt.Fprintln(os.Stderr, "observe requires --ledger or --bindings")
		return 1
	}

	var prov provider.Provider
	switch providerName {
	case "fake":
		prov = &provider.Fake{}
	case "gcp":
		// project rides in each providerId (project:region:name);
		// the driver parses it per call
		prov = gcp.NewDriver("")
	case "aws":
		prov = aws.NewDriver("")
	case "azure":
		// subscription rides in each providerId (sub:rg:name); with an empty
		// driver subscription the ownership guard defers to the providerId
		prov = azure.NewDriver("")
	default:
		fmt.Fprintf(os.Stderr, "unknown provider %q\n", providerName)
		return 1
	}

	res, err := observe.Run(bindings, prov, at, ttl, led, ledgerPath, record)
	if err != nil {
		fmt.Fprintf(os.Stderr, "observe error: %v\n", err)
		return 1
	}
	out, err := json.MarshalIndent(res, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "observe error: %v\n", err)
		return 1
	}
	fmt.Println(string(out))
	return 0
}

// runRepair: D69 — diagnose-first, quarantine on fingerprint consent.
func runRepair(ledgerPath string, quarantine bool, fp string,
	explain bool) int {
	if ledgerPath == "" {
		fmt.Fprintln(os.Stderr, "repair requires --ledger")
		return 1
	}
	if !quarantine {
		d, err := ledger.Diagnose(ledgerPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "repair error: %v\n", err)
			return 1
		}
		printResult(d, explain)
		if d.Status == "healthy" {
			return 0
		}
		return 5
	}
	if fp == "" {
		printResult(map[string]any{
			"status": "refused", "code": "confirmation-required",
			"reasons": []string{"--quarantine requires --fingerprint " +
				"from a diagnosis you have seen — repair is a two-step " +
				"decision, never a blind cut"}}, explain)
		return 2
	}
	res, _, err := ledger.Quarantine(ledgerPath, fp)
	if err != nil {
		fmt.Fprintf(os.Stderr, "repair error: %v\n", err)
		return 1
	}
	printResult(res, explain)
	if res.Status == "refused" {
		return 2
	}
	return 0
}

// runAnchor: D70 — emit or verify the tail anchor.
// runCapsule (D103): emit with a capability + --ledger; verify with
// --verify (+ optional --trust / --check). Refusals during verification
// are corruption-class evidence (exit 5); a capability with no events
// is an operator error (exit 1).
func runCapsule(capability, ledgerPath, verifyPath, checkPath string) int {
	if verifyPath != "" {
		raw, err := docio.ReadDoc(verifyPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "capsule error: %v\n", err)
			return 1
		}
		var c ledger.Capsule
		if err := json.Unmarshal(raw, &c); err != nil {
			fmt.Fprintf(os.Stderr, "capsule error: %v\n", err)
			return 1
		}
		var anchor *ledger.Anchor
		if checkPath != "" {
			a, err := ledger.LoadAnchorFile(checkPath)
			if err != nil {
				fmt.Fprintf(os.Stderr, "capsule error: %v\n", err)
				return 1
			}
			// D135: the anchor's policy arms this verification too
			if err := ledger.ApplyAnchorPolicy(a); err != nil {
				fmt.Fprintf(os.Stderr, "capsule error: %v\n", err)
				return 1
			}
			anchor = a
		}
		claimed, err := ledger.VerifyCapsule(&c, anchor)
		if err != nil {
			fmt.Fprintf(os.Stderr, "capsule error: %v\n", err)
			return 5
		}
		// claimedLedger proves the events were signed for ONE common
		// ledger — NOT membership in yours; that is what --check adds
		out, _ := json.MarshalIndent(map[string]any{
			"status": "verified", "capability": c.Capability,
			"events": len(c.Events), "head": c.Head, "asOf": c.AsOf,
			"anchorChecked": anchor != nil, "claimedLedger": claimed,
		}, "", "  ")
		fmt.Println(string(out))
		return 0
	}
	if capability == "" || ledgerPath == "" {
		fmt.Fprintln(os.Stderr,
			"capsule requires a capability and --ledger (or --verify)")
		return 1
	}
	c, err := ledger.EmitCapsule(ledgerPath, capability)
	if err != nil {
		fmt.Fprintf(os.Stderr, "capsule error: %v\n", err)
		if strings.Contains(err.Error(), "ledger line") ||
			strings.Contains(err.Error(), "torn final line") {
			return 5
		}
		return 1
	}
	out, _ := json.MarshalIndent(c, "", "  ")
	fmt.Println(string(out))
	return 0
}

func runAnchor(ledgerPath, checkPath string) int {
	if ledgerPath == "" {
		fmt.Fprintln(os.Stderr, "anchor requires --ledger")
		return 1
	}
	// D135: the checked anchor's trust policy arms BEFORE the replay it
	// is supposed to guard — a signature-stripped ledger then refuses
	// with no flags given at all.
	if checkPath != "" {
		a, err := ledger.LoadAnchorFile(checkPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "anchor error: %v\n", err)
			return 1
		}
		if err := ledger.ApplyAnchorPolicy(a); err != nil {
			fmt.Fprintf(os.Stderr, "anchor error: %v\n", err)
			return 1
		}
	}
	led, err := ledger.ReplayFile(ledgerPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ledger error: %v\n", err)
		return 5
	}
	if checkPath == "" {
		out, _ := json.MarshalIndent(ledger.BuildAnchor(led), "", "  ")
		fmt.Println(string(out))
		return 0
	}
	raw, err := docio.ReadDoc(checkPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "anchor error: %v\n", err)
		return 1
	}
	var a ledger.Anchor
	if err := yaml.Unmarshal(raw, &a); err != nil || a.Kind != "LedgerAnchor" {
		fmt.Fprintln(os.Stderr, "anchor error: not a LedgerAnchor document")
		return 1
	}
	res := ledger.CheckAnchor(led, &a)
	out, _ := json.MarshalIndent(res, "", "  ")
	fmt.Println(string(out))
	if res.Status != "verified" {
		return 5
	}
	return 0
}

// runScenario: D37 — deterministic concurrency scenario engine.
func atoiOr(s string, def int) int {
	n, err := strconv.Atoi(s)
	if err != nil {
		return def
	}
	return n
}

// detachRun forks a background run and returns its handle (D229,
// detach-after-admission). The child is this same binary re-run WITHOUT
// --detach; the parent then blocks up to 5s for the run's `*.started` event so a
// fast refusal (preflight, staleness, lease contention) is surfaced here rather
// than swallowed into a log the operator has not been told to read yet.
func detachRun(handle, kind, ledgerPath, at string, args []string, jsonMode bool) int {
	self, err := os.Executable()
	if err != nil {
		fmt.Fprintf(os.Stderr, "detach error: %v\n", err)
		return 1
	}
	childArgv := make([]string, 0, len(args))
	for _, a := range args {
		if a != "--detach" {
			childArgv = append(childArgv, a)
		}
	}
	e, lerr := detach.Launch(detach.OSRunner{Self: self},
		detach.Entry{Handle: handle, Kind: kind, LedgerPath: ledgerPath, LaunchedAt: at},
		childArgv)
	if lerr != nil {
		fmt.Fprintf(os.Stderr, "detach error: %v\n", lerr)
		return 1
	}
	// block for admission: watch the ledger for this run's start.
	admitted := false
	for i := 0; i < 25; i++ { // ~5s at 200ms
		if evs, rerr := runstatus.ReadEvents(ledgerPath); rerr == nil {
			if st := runstatus.DeriveRunStatus(evs, handle, 1<<62); st.State != runstatus.StateUnknown {
				admitted = true
				break
			}
		}
		time.Sleep(200 * time.Millisecond)
	}
	if jsonMode {
		out, _ := json.MarshalIndent(map[string]any{
			"handle": handle, "kind": kind, "pid": e.PID,
			"logPath": e.LogPath, "ledgerPath": ledgerPath, "admitted": admitted}, "", "  ")
		fmt.Println(string(out))
	} else {
		fmt.Printf("detached  %s  %s\n", kind, handle)
		fmt.Printf("log       %s\n", e.LogPath)
		fmt.Printf("watch     groundhold status %s --ledger %s --at <t>  |  groundhold wait %s --ledger %s\n",
			handle, ledgerPath, handle, ledgerPath)
	}
	if !admitted {
		fmt.Fprintf(os.Stderr, "warning: run did not start within 5s — check the log: %s\n", e.LogPath)
		return 1
	}
	return 0
}

// runRuns lists every run in the ledger with its derived state (D231). The
// ledger is the census; order is most-recent-first (never re-sorted by severity —
// that would be a covert ranking). Attention states are glyph-marked and a
// per-state count line lets "what needs me" read at a glance WITHOUT a composite
// health rollup (the four-valued discipline on run state).
func runRuns(ledgerPath, at string, jsonMode bool) int {
	evs, err := runstatus.ReadEvents(ledgerPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ledger error: %v\n", err)
		return 1
	}
	nowClock, _ := ledger.ParseTs(at)
	// D231: union in detach-registry handles so a run that was launched but never
	// admitted (no ledger events) surfaces as registry-only/unknown rather than
	// vanishing. Best-effort — a missing/unreadable registry is not an error (the
	// ledger is the truth; the registry only widens the question set).
	var regHandles []string
	if ents, rerr := detach.ListRegistry(ledgerPath); rerr == nil {
		for _, e := range ents {
			regHandles = append(regHandles, e.Handle)
		}
	}
	runs := runstatus.ListRuns(evs, nowClock, regHandles)

	if jsonMode {
		counts := map[string]int{}
		for _, r := range runs {
			counts[string(r.State)]++
		}
		out, _ := json.MarshalIndent(map[string]any{
			"runs": runs, "total": len(runs), "byState": counts}, "", "  ")
		fmt.Println(string(out))
		return 0
	}
	if len(runs) == 0 {
		fmt.Println("0 runs")
		return 0
	}
	counts := map[string]int{}
	for _, r := range runs {
		counts[string(r.State)]++
		age := "-"
		if nc, err := ledger.ParseTs(r.StartedAt); err == nil && r.StartedAt != "" {
			age = fmtAge(nowClock - nc)
		}
		note := runNote(r)
		if r.Source == "registry-only" {
			note = "  launched, no ledger events — check its log"
		}
		fmt.Printf("%s  %-8s  %-14s  %-8s  %s%s\n",
			r.Handle, orDash(r.Kind), r.State, age, orDash(r.StartedAt), note)
	}
	// per-state counts (a projection, not a rollup) — attention states first.
	fmt.Println("---")
	fmt.Print(stateCountLine(counts))
	return 0
}

func fmtAge(sec int) string {
	if sec < 0 {
		sec = 0
	}
	if sec < 3600 {
		return fmt.Sprintf("%dm", sec/60)
	}
	if sec < 86400 {
		return fmt.Sprintf("%dh%dm", sec/3600, (sec%3600)/60)
	}
	return fmt.Sprintf("%dd", sec/86400)
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// runNote is the state's evidence stub — lease/pending/phase — never invented.
func runNote(r runstatus.RunStatus) string {
	switch r.State {
	case runstatus.StateNeedsReconcile:
		return fmt.Sprintf("  (%d unsettled)", len(r.Pending))
	case runstatus.StateRunning:
		if r.Phase != "" {
			return "  phase " + r.Phase
		}
	case runstatus.StateStalled:
		return "  lease lapsed — run resume"
	}
	return ""
}

// stateCountLine renders per-state counts, attention states named first, in the
// closed enum order — a projection of the four-valued set, never a green/red score.
func stateCountLine(counts map[string]int) string {
	order := []runstatus.State{
		runstatus.StateFailed, runstatus.StateNeedsReconcile, runstatus.StateStalled,
		runstatus.StateUnknown, runstatus.StateRunning, runstatus.StateDone,
	}
	var parts []string
	for _, s := range order {
		if n := counts[string(s)]; n > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", n, s))
		}
	}
	return strings.Join(parts, ", ") + "\n"
}

// runStatus derives and prints a background run's state from the ledger (D229).
// Status itself always exits 0 when derivation succeeded — reporting a failed
// run is a successful status; relaying run exit codes is wait's job.
func runStatus(handle, ledgerPath, at string, jsonMode bool) int {
	evs, err := runstatus.ReadEvents(ledgerPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ledger error: %v\n", err)
		return 1
	}
	nowClock, _ := ledger.ParseTs(at)
	st := runstatus.DeriveRunStatus(evs, handle, nowClock)
	printRunStatus(st, jsonMode)
	return 0
}

// runWait polls the ledger until the run reaches a terminal state (D229),
// unblocking on done/failed AND stalled/needs-reconcile — waiting on a dead
// writer is a lie. It samples the wall clock each poll (wait IS the live clock).
func runWait(handle, ledgerPath string, pollS, timeoutS int, jsonMode bool, notifier notify.Notifier) int {
	if pollS < 1 {
		pollS = 1
	}
	start := time.Now()
	for {
		evs, err := runstatus.ReadEvents(ledgerPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "ledger error: %v\n", err)
			return 1
		}
		st := runstatus.DeriveRunStatus(evs, handle, int(time.Now().Unix()))
		if isTerminalRun(st.State) {
			exit := exitForRun(st)
			// D229: the doorbell fires AFTER the terminal state is derived and
			// the exit computed — it holds an immutable payload and no ledger
			// handle, so a slow/broken hook can only log, never corrupt the run.
			if notifier != nil {
				p := notify.Build(st.Handle, st.Kind, string(st.State),
					string(st.Code), exit, st.ConcludedAt, "")
				if err := notifier.Notify(p); err != nil {
					fmt.Fprintf(os.Stderr, "notify failed (ignored): %v\n", err)
				}
			}
			printRunStatus(st, jsonMode)
			return exit
		}
		if timeoutS > 0 && time.Since(start) >= time.Duration(timeoutS)*time.Second {
			bannerState.code = string(perr.WaitTimeout)
			printRunStatus(st, jsonMode)
			fmt.Fprintf(os.Stderr, "wait timed out after %ds; run is still %s\n", timeoutS, st.State)
			return 3
		}
		time.Sleep(time.Duration(pollS) * time.Second)
	}
}

// isTerminalRun: the states wait stops on. stalled/needs-reconcile are terminal
// FOR WAIT (a lapsed writer will not conclude itself) even though resume can
// still advance them.
func isTerminalRun(s runstatus.State) bool {
	switch s {
	case runstatus.StateDone, runstatus.StateFailed,
		runstatus.StateStalled, runstatus.StateNeedsReconcile:
		return true
	}
	return false
}

// exitForRun maps a terminal run state to wait's exit code (D22 codes reused):
// done=0, failed relays the run's exit code (default 4), stalled/needs-reconcile
// = 3 (reconcile-required — run resume).
func exitForRun(st runstatus.RunStatus) int {
	switch st.State {
	case runstatus.StateDone:
		return 0
	case runstatus.StateFailed:
		if st.ExitCode != 0 {
			return st.ExitCode
		}
		return 4
	default: // stalled / needs-reconcile
		return 3
	}
}

func printRunStatus(st runstatus.RunStatus, jsonMode bool) {
	if jsonMode {
		out, _ := json.MarshalIndent(st, "", "  ")
		fmt.Println(string(out))
		return
	}
	kind := st.Kind
	if kind == "" {
		kind = "run"
	}
	line := fmt.Sprintf("%s %s  %s", kind, st.Handle, st.State)
	if st.Phase != "" {
		line += "  phase " + st.Phase
	}
	if st.Lease.Live {
		line += "  lease live (expires " + st.Lease.ExpiresAt + ")"
	}
	fmt.Println(line)
	if len(st.Pending) > 0 {
		fmt.Printf("  %d unsettled receipt(s)\n", len(st.Pending))
	}
	if st.Remediation != "" {
		fmt.Println("  " + st.Remediation)
	}
}

func runScenario(path string) int {
	raw, err := docio.ReadDoc(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "scenario error: %v\n", err)
		return 1
	}
	var docAny any
	if err := yaml.Unmarshal(raw, &docAny); err != nil {
		fmt.Fprintf(os.Stderr, "scenario error: %v\n", err)
		return 1
	}
	results, err := scenario.Run(docAny)
	if err != nil {
		fmt.Fprintf(os.Stderr, "scenario error: %v\n", err)
		return 1
	}
	out, err := json.MarshalIndent(map[string]any{"results": results}, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "scenario error: %v\n", err)
		return 1
	}
	fmt.Println(string(out))
	return 0
}

// runHash: D34 — identity of the semantic model, kind-detected from the doc.
// runKeygen (D102): mint a signing seed. Refuses to overwrite — a key
// file is an identity, clobbering one silently would orphan every
// signature it ever made. stdout is the PUBLIC key: the half you hand
// to verifiers (--trust); the seed never leaves the file.
func runKeygen(path string) int {
	if _, err := os.Stat(path); err == nil {
		fmt.Fprintf(os.Stderr, "keygen error: %s already exists — "+
			"refusing to overwrite a signing identity\n", path)
		return 1
	}
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "keygen error: %v\n", err)
		return 1
	}
	seedHex := hex.EncodeToString(priv.Seed())
	if err := os.WriteFile(path, []byte(seedHex+"\n"), 0o600); err != nil {
		fmt.Fprintf(os.Stderr, "keygen error: %v\n", err)
		return 1
	}
	fmt.Println(hex.EncodeToString(pub))
	return 0
}

func runHash(path string) int {
	raw, err := docio.ReadDoc(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "document error: %v\n", err)
		return 1
	}
	var docAny any
	if err := yaml.Unmarshal(raw, &docAny); err != nil {
		fmt.Fprintf(os.Stderr, "document error: %v\n", err)
		return 1
	}
	doc, _ := docAny.(map[string]any)
	kind, _ := doc["kind"].(string)
	var h string
	switch kind {
	case "InfrastructureContract":
		c, err := contract.LoadContract(path)
		if err == nil {
			h, err = canonical.HashContract(c)
		}
		if err != nil {
			fmt.Fprintf(os.Stderr, "document error: %v\n", err)
			return 1
		}
	case "ImplementationCandidate":
		cand, err := contract.LoadCandidate(path, nil, nil)
		if err == nil {
			h, err = canonical.HashCandidate(cand)
		}
		if err != nil {
			fmt.Fprintf(os.Stderr, "document error: %v\n", err)
			return 1
		}
	case "LedgerEvent":
		ev, err := state.LoadEvent(path)
		if err == nil {
			h, err = canonical.HashEvent(ev)
		}
		if err != nil {
			fmt.Fprintf(os.Stderr, "document error: %v\n", err)
			return 1
		}
	case "SealedPlan":
		pl, err := plan.LoadPlan(path)
		if err == nil {
			h, err = canonical.HashPlan(pl)
		}
		if err != nil {
			fmt.Fprintf(os.Stderr, "document error: %v\n", err)
			return 1
		}
	case "DiscoveryDocument":
		h, err = canonical.HashDiscovery(doc)
		if err != nil {
			fmt.Fprintf(os.Stderr, "document error: %v\n", err)
			return 1
		}
	default:
		fmt.Fprintf(os.Stderr, "document error: unknown kind %q\n", kind)
		return 1
	}
	fmt.Println(h)
	return 0
}

// verdictRollup lifts the hard-constraint verdicts out of a verify
// report for banner selection (exit 2 alone cannot tell VIOLATED from
// BLOCKED).
func verdictRollup(r *verify.Report) render.Rollup {
	var out render.Rollup
	for _, v := range r.Verdicts {
		if v.Severity != "hard" {
			continue
		}
		switch v.Verdict {
		case "violated":
			out.Violated = append(out.Violated, v.Constraint)
		case "unknown":
			out.Unknown = append(out.Unknown, v.Constraint)
		case "unverifiable":
			out.Unverifiable = append(out.Unverifiable, v.Constraint)
		}
	}
	return out
}

// printText renders the human report per spec/presentation.md: shape-first
// glyphs, provenance as brightness, the vocabulary joined at friction only,
// and the banner — never alone — as the last line block.
// runExplain answers for any noun the system emits (D89): a machine
// error code (spec/errors.md) or a vocabulary path. One obvious place
// to ask; prose only, never a machine interface.
// loadVocabs resolves the vocabulary for a run. The base is the vocabulary
// COMPILED INTO the binary (go:embed) — a downloaded groundhold is ready with no
// external files. --vocab DIR EXTENDS that base (custom documents override the
// built-in per capability type); --no-vocab forces the empty vocabulary (D23:
// a vocabulary is an optional, strengthening input). The empty result is
// returned as nil so verification reports pathInVocabulary as absent, not false.
//
// GROUNDHOLD_NO_EMBEDDED_VOCAB is a TEST-HARNESS hook only (conformance /
// differential): it drops the embedded base so the suites drive the vocabulary
// explicitly and exercise the exact semantics their cases were written against.
// It is never set in production.
func loadVocabs(vocabDir string, noVocab bool) (map[string]vocab.Vocabulary, error) {
	if noVocab {
		return nil, nil
	}
	out := map[string]vocab.Vocabulary{}
	if os.Getenv("GROUNDHOLD_NO_EMBEDDED_VOCAB") == "" {
		emb, err := vocab.Embedded()
		if err != nil {
			return nil, fmt.Errorf("embedded vocabulary: %w", err)
		}
		for k, v := range emb {
			out[k] = v
		}
	}
	if vocabDir != "" {
		custom, err := vocab.LoadDir(vocabDir)
		if err != nil {
			return nil, err
		}
		for k, v := range custom {
			out[k] = v // custom extends/overrides the built-in per capability
		}
	}
	if len(out) == 0 {
		return nil, nil // "no vocabulary" — pathInVocabulary stays absent
	}
	return out, nil
}

// printMCPConfig emits the config an agent needs to run the MCP server —
// the one step a bare binary cannot do to a foreign agent's config, made
// copy-paste instead of reverse-engineered. self is the absolute binary path
// so it works regardless of the caller's PATH or cwd.
func printMCPConfig(self string) {
	fmt.Printf(`# Wire the groundhold MCP server into your agent.

# 1) Project-scoped: write this to .mcp.json at your repo root
{
  "mcpServers": {
    "groundhold": {
      "command": %q,
      "args": ["mcp"]
    }
  }
}

# 2) Or one command (Claude Code CLI):
#    claude mcp add groundhold -- %s mcp

# The read-only tools (verify/plan/forecast/...) are always available.
# To enable the two-step apply tool (it mutates infrastructure), start the
# server with:  GROUNDHOLD_MCP_ALLOW_APPLY=1 %s mcp
`, self, self, self)
}

// runExample prints a valid starter document so an agent never reverse-engineers
// the schema. "contract" / "candidate" print canonical annotated templates;
// "candidate <contract.yaml>" scaffolds a candidate matching that contract —
// one entry per capability, pre-filled with the capability's vocabulary
// attribute paths. This is the answer to "what shape is a candidate?": the
// binary shows you, keyed exactly as the loader expects.
func runExample(pos []string) int {
	sub := ""
	if len(pos) >= 2 {
		sub = pos[1]
	}
	switch sub {
	case "contract":
		fmt.Print(exampleContract)
		return 0
	case "candidate":
		if len(pos) >= 3 {
			return scaffoldCandidate(pos[2])
		}
		fmt.Print(exampleCandidate)
		return 0
	default:
		fmt.Fprintln(os.Stderr,
			"usage: groundhold example <contract|candidate> [<contract.yaml>]")
		return 1
	}
}

const exampleContract = `# A minimal Infrastructure Contract: WHAT must be true, not how.
apiVersion: contract/v0.1
kind: InfrastructureContract
meta: { id: my-service, environment: prod, version: 1 }
capabilities:
  - id: db
    type: capability.database.relational   # see 'groundhold parity' for types
constraints:
  hard:                                     # unknown/violated here BLOCKS apply
    - { id: eu,   subject: db, path: location.region,         op: equals, value: eu-central-1, verify: { method: static } }
    - { id: priv, subject: db, path: network.publicExposure,  op: equals, value: false,        verify: { method: static } }
`

const exampleCandidate = `# An Implementation Candidate: HOW a contract is fulfilled.
# NOTE: capabilities is a MAP keyed by the contract's capability ids (not a list).
apiVersion: candidate/v0.1
kind: ImplementationCandidate
contract: my-service          # must equal the contract's meta.id
capabilities:
  db:                         # the capability id from the contract
    provider: aws             # aws | gcp | azure | k8s | fake
    service: rds              # the provider's service token
    attributes:               # vocabulary attribute paths -> values
      location.region: eu-central-1
      network.publicExposure: false
    implementation:           # optional, provider-specific, free-form (D26)
      instance_class: db.t3.micro
`

// scaffoldCandidate loads a contract and prints a candidate skeleton with one
// entry per capability, each pre-filled with that capability type's vocabulary
// attribute paths (kind-appropriate sample values + the attribute's own doc).
func scaffoldCandidate(contractPath string) int {
	c, err := contract.LoadContract(contractPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "contract error: %v\n", err)
		return 1
	}
	vocabs, err := loadVocabs("", false)
	if err != nil {
		fmt.Fprintf(os.Stderr, "vocab error: %v\n", err)
		return 1
	}
	var b strings.Builder
	fmt.Fprintf(&b, "# Candidate scaffold for contract %q — fill in provider,\n"+
		"# service and the attribute values, then: groundhold verify <contract> <this>\n",
		c.ID)
	b.WriteString("apiVersion: candidate/v0.1\n")
	b.WriteString("kind: ImplementationCandidate\n")
	fmt.Fprintf(&b, "contract: %s\n", c.ID)
	b.WriteString("capabilities:\n")
	for _, capID := range sortedKeys(c.Capabilities) {
		capType, _ := c.Capabilities[capID]["type"].(string)
		if s, _ := c.Capabilities[capID]["state"].(string); s == "retired" {
			continue // a retired capability is not implemented (D47)
		}
		fmt.Fprintf(&b, "  %s:                     # type: %s\n", capID, capType)
		b.WriteString("    provider: aws           # aws | gcp | azure | k8s | fake\n")
		b.WriteString("    service: \"\"             # the provider's service token\n")
		voc, ok := vocabs[capType]
		if !ok || len(voc.Attributes) == 0 {
			b.WriteString("    attributes: {}          # no vocabulary attributes for this type\n")
			continue
		}
		b.WriteString("    attributes:\n")
		for _, path := range sortedKeys(voc.Attributes) {
			attr := voc.Attributes[path]
			kind, _ := attr["kind"].(string)
			desc, _ := attr["description"].(string)
			desc = strings.TrimSpace(strings.SplitN(desc, "\n", 2)[0])
			if len(desc) > 60 {
				desc = desc[:60] + "…"
			}
			fmt.Fprintf(&b, "      %s: %s  # %s%s\n",
				path, sampleForAttr(attr, kind), kind, descSuffix(desc))
		}
	}
	fmt.Print(b.String())
	return 0
}

func descSuffix(desc string) string {
	if desc == "" {
		return ""
	}
	return " — " + desc
}

// sampleForAttr picks a scaffold placeholder that will LOAD: an enum-bound
// attribute must use one of its members (empty string is not in the enum), so
// enums win over the kind default.
func sampleForAttr(attr map[string]any, kind string) string {
	if enum, ok := attr["enum"].([]any); ok && len(enum) > 0 {
		return fmt.Sprintf("%q", fmt.Sprintf("%v", enum[0]))
	}
	return sampleForKind(kind)
}

// sampleForKind gives a kind-valid placeholder so the scaffold parses and the
// expected scalar shape is unmistakable (D-battery kinds).
func sampleForKind(kind string) string {
	switch kind {
	case "bool":
		return "false"
	case "duration":
		return "24h"
	case "money":
		return "\"100 EUR\""
	case "number":
		return "1"
	case "percent":
		return "\"99.9%\""
	case "bytes":
		return "\"10GB\""
	case "protocol":
		return "\"postgresql/16\""
	default: // string and anything else
		return "\"\""
	}
}

// readDocMap reads a YAML document as a raw mapping (for structural composition).
func readDocMap(path string) (map[string]any, error) {
	raw, err := docio.ReadDoc(path)
	if err != nil {
		return nil, err
	}
	var m map[string]any
	if err := yaml.Unmarshal(raw, &m); err != nil {
		return nil, err
	}
	if m == nil {
		return nil, fmt.Errorf("%s: empty document", path)
	}
	return m, nil
}

// runCompose merges a base contract with ordered overlays into one flat contract
// (D199) — environment DRY without inheritance in the language. It refuses to
// emit an invalid result (the structural check a string-concat generator lacks).
func runCompose(pos []string) int {
	if len(pos) < 2 {
		fmt.Fprintln(os.Stderr,
			"usage: groundhold compose <base.yaml> [overlay.yaml ...]")
		return 1
	}
	base, err := readDocMap(pos[1])
	if err != nil {
		fmt.Fprintf(os.Stderr, "compose error: %v\n", err)
		return 1
	}
	var overlays []map[string]any
	for _, p := range pos[2:] {
		ov, err := readDocMap(p)
		if err != nil {
			fmt.Fprintf(os.Stderr, "compose error: %v\n", err)
			return 1
		}
		overlays = append(overlays, ov)
	}
	merged, err := compose.Merge(base, overlays...)
	if err != nil {
		fmt.Fprintf(os.Stderr, "compose error: %v\n", err)
		return 1
	}
	if _, err := contract.LoadContractDoc(merged); err != nil {
		fmt.Fprintf(os.Stderr,
			"compose error: merged contract is invalid: %v\n", err)
		return 1
	}
	out, err := yaml.Marshal(merged)
	if err != nil {
		fmt.Fprintf(os.Stderr, "compose error: %v\n", err)
		return 1
	}
	fmt.Print(string(out))
	return 0
}

// diffJSON is the self-describing envelope for `groundhold diff --json`: the
// DiffResult delta plus the identity the console needs to key it (mirrors
// `cost --json`). ContractB is emitted only when the two contracts carry
// different meta.id; environments are always emitted so a promotion diff is
// legible on its own.
type diffJSON struct {
	SpecVersion  string `json:"specVersion"`
	Contract     string `json:"contract"`
	ContractB    string `json:"contractB,omitempty"`
	EnvironmentA string `json:"environmentA"`
	EnvironmentB string `json:"environmentB"`
	compose.DiffResult
}

// metaString reads a string field from a contract document's meta block,
// returning "" when absent or mistyped.
func metaString(doc map[string]any, key string) string {
	m, _ := doc["meta"].(map[string]any)
	s, _ := m[key].(string)
	return s
}

// runDiff reports the constraint/capability delta between two contracts and
// whether the first's invariants are a subset of the second's — the
// deterministic promotion proof (dev ⊆ staging ⊆ prod).
func runDiff(pos []string, jsonMode bool) int {
	if len(pos) < 3 {
		fmt.Fprintln(os.Stderr, "usage: groundhold diff <a.yaml> <b.yaml>")
		return 1
	}
	a, err := readDocMap(pos[1])
	if err != nil {
		fmt.Fprintf(os.Stderr, "diff error: %v\n", err)
		return 1
	}
	b, err := readDocMap(pos[2])
	if err != nil {
		fmt.Fprintf(os.Stderr, "diff error: %v\n", err)
		return 1
	}
	d := compose.Diff(a, b)
	if jsonMode {
		// Self-describing wrapper so the console can ingest and key the diff
		// without re-deriving identity (mirrors `cost --json`). Output metadata
		// only — the DiffResult fields are unchanged and nothing here is hashed.
		idA, idB := metaString(a, "id"), metaString(b, "id")
		out := diffJSON{
			SpecVersion:  "contract/v0.1",
			Contract:     idA,
			EnvironmentA: metaString(a, "environment"),
			EnvironmentB: metaString(b, "environment"),
			DiffResult:   d,
		}
		if idB != idA {
			out.ContractB = idB
		}
		raw, _ := json.MarshalIndent(out, "", "  ")
		fmt.Println(string(raw))
		return 0
	}
	fmt.Printf("hard constraints only in %s: %s\n", pos[1], orNone(d.HardOnlyInA))
	fmt.Printf("hard constraints only in %s: %s\n", pos[2], orNone(d.HardOnlyInB))
	if len(d.CapsOnlyInA) > 0 || len(d.CapsOnlyInB) > 0 {
		fmt.Printf("capabilities only in %s: %s\n", pos[1], orNone(d.CapsOnlyInA))
		fmt.Printf("capabilities only in %s: %s\n", pos[2], orNone(d.CapsOnlyInB))
	}
	if d.ASubsetOfB {
		fmt.Printf("%s ⊆ %s: yes — every invariant in the first also holds in the second\n",
			pos[1], pos[2])
	} else {
		fmt.Printf("%s ⊆ %s: NO — the first carries invariants the second lacks: %s\n",
			pos[1], pos[2], orNone(d.HardOnlyInA))
	}
	return 0
}

func orNone(ss []string) string {
	if len(ss) == 0 {
		return "(none)"
	}
	return strings.Join(ss, ", ")
}

var currencyRE = regexp.MustCompile(`^[A-Z]{3}$`)

// resolveCurrency defaults the reporting currency to EUR and validates the code.
func resolveCurrency(c string) (string, error) {
	if c == "" {
		return "EUR", nil
	}
	if !currencyRE.MatchString(c) {
		return "", fmt.Errorf("currency %q must be a 3-letter ISO code (e.g. EUR)", c)
	}
	return c, nil
}

// costItemsFromPlan builds one cost item per DISTINCT capability the plan
// touches (cost is per resource, not per action — a replace is two actions),
// reading cost.monthly + its provenance from the candidate. Shared by the
// plan/converge stderr estimate and the `cost` verb so they never diverge.
func costItemsFromPlan(doc *compiler.Document, cand *contract.Candidate) []costproj.Item {
	seen := map[string]bool{}
	var items []costproj.Item
	for _, a := range doc.Plan.Actions {
		if seen[a.Capability] {
			continue
		}
		seen[a.Capability] = true
		it := costproj.Item{}
		if pv, ok := cand.Capabilities[a.Capability]["cost.monthly"]; ok &&
			pv.Scalar != nil && pv.Scalar.Kind == scalars.Money {
			mv := pv.Scalar.Value.(scalars.MoneyValue)
			it.Amount, it.Currency, it.Basis = mv.Amount, mv.Currency, pv.Status
		}
		items = append(items, it)
	}
	return items
}

// renderCostProjection prints the cost estimate to w (stderr) from a plan's
// per-capability cost.monthly claims (D202). It is display only — never part of
// the hashed plan on stdout, and never FX (foreign currencies stay uncoerced).
func renderCostProjection(w io.Writer, doc *compiler.Document,
	cand *contract.Candidate, ccy string) {
	items := costItemsFromPlan(doc, cand)
	if len(items) == 0 {
		return
	}
	costproj.Compute(items, ccy, len(items)).Render(w)
}

// runCost emits the AUTHORITATIVE cost projection for a plan (D202) — the same
// number plan/converge show on stderr, but machine-readable with --json so the
// console ingests it verbatim (no downstream re-computation, no divergence).
func runCost(planPath, candPath, currency string, jsonOut bool) int {
	ccy, err := resolveCurrency(currency)
	if err != nil {
		fmt.Fprintf(os.Stderr, "currency error: %v\n", err)
		return 1
	}
	raw, err := os.ReadFile(planPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "cost error: %v\n", err)
		return 1
	}
	var doc compiler.Document
	if err := json.Unmarshal(raw, &doc); err != nil {
		fmt.Fprintf(os.Stderr, "cost error: plan is not a valid sealed plan: %v\n", err)
		return 1
	}
	cand, err := contract.LoadCandidate(candPath, nil, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "candidate error: %v\n", err)
		return 1
	}
	items := costItemsFromPlan(&doc, cand)
	proj := costproj.Compute(items, ccy, len(items))
	if jsonOut {
		// Stamp specVersion + contract/environment so the console can accept and
		// key the report (it refuses a version-less output and needs the contract
		// name to associate) — the same self-describing shape as verify.
		out := struct {
			SpecVersion string `json:"specVersion"`
			Contract    string `json:"contract"`
			Environment string `json:"environment,omitempty"`
			costproj.Report
		}{
			SpecVersion: "contract/v0.1",
			Contract:    doc.Plan.Contract,
			Environment: doc.Plan.Environment,
			Report:      proj.Report(),
		}
		raw, _ := json.MarshalIndent(out, "", "  ")
		fmt.Println(string(raw))
		return 0
	}
	proj.Render(os.Stdout)
	return 0
}

// runSuggest is the deterministic, cited best-practice advisor (D203). It reads
// the vocabulary's `recommended` markers — which the verifier NEVER consults —
// and prints recommended-but-absent hardening constraints as ready-to-paste
// snippets. It is ADVISORY: the exit code never depends on how many suggestions
// were found (0 on success regardless), and it never blocks.
func runSuggest(contractPath, candPath, vocabDir string, noVocab bool, asMode string, jsonOut bool) int {
	if asMode != "hard" && asMode != "soft" {
		fmt.Fprintln(os.Stderr, "--as must be hard or soft")
		return 1
	}
	vocabs, verr := loadVocabs(vocabDir, noVocab)
	if verr != nil {
		fmt.Fprintf(os.Stderr, "vocab error: %v\n", verr)
		return 1
	}
	c, err := contract.LoadContract(contractPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "contract error: %v\n", err)
		return 1
	}
	var cand *contract.Candidate
	if candPath != "" {
		cand, err = contract.LoadCandidate(candPath, c, vocabs)
		if err != nil {
			fmt.Fprintf(os.Stderr, "candidate error: %v\n", err)
			return 1
		}
	}
	res := suggest.Compute(c, vocabs, cand)
	if jsonOut {
		// Self-describing, mirroring `cost --json`: specVersion + contract +
		// environment let the console accept and key the report verbatim.
		out := struct {
			SpecVersion     string               `json:"specVersion"`
			Contract        string               `json:"contract"`
			Environment     string               `json:"environment,omitempty"`
			Suggested       int                  `json:"suggested"`
			AlreadyEnforced int                  `json:"alreadyEnforced"`
			Suggestions     []suggest.Suggestion `json:"suggestions"`
		}{
			SpecVersion:     "contract/v0.1",
			Contract:        c.ID,
			Environment:     c.Environment,
			Suggested:       len(res.Suggestions),
			AlreadyEnforced: res.AlreadyEnforced,
			Suggestions:     res.Suggestions,
		}
		raw, _ := json.MarshalIndent(out, "", "  ")
		fmt.Println(string(raw))
		return 0
	}
	renderSuggestText(os.Stdout, c.ID, res, asMode)
	return 0
}

// renderSuggestText prints the human, ready-to-paste form: a header, then one
// constraint snippet per suggestion grouped by capability, each preceded by a
// `# rationale (source: …)` comment, under constraints.<hard|soft>.
func renderSuggestText(w io.Writer, contractID string, res suggest.Result, asMode string) {
	envSuffix := ""
	if res.Environment != "" {
		envSuffix = fmt.Sprintf(" (environment: %s)", res.Environment)
	}
	if len(res.Suggestions) == 0 {
		fmt.Fprintf(w, "# No hardening suggestions for contract %s%s.\n", contractID, envSuffix)
		fmt.Fprintf(w, "# %d already enforced. Advisory only — never gates.\n", res.AlreadyEnforced)
		return
	}
	fmt.Fprintf(w, "# %d hardening suggestion(s) for contract %s%s\n",
		len(res.Suggestions), contractID, envSuffix)
	fmt.Fprintf(w, "# %d already enforced. Advisory only — never gates; paste what you want to adopt.\n\n",
		res.AlreadyEnforced)
	fmt.Fprintln(w, "constraints:")
	fmt.Fprintf(w, "  %s:\n", asMode)
	lastCap := ""
	for _, sg := range res.Suggestions {
		if sg.Capability != lastCap {
			fmt.Fprintf(w, "    # --- %s (%s) ---\n", sg.Capability, sg.Type)
			lastCap = sg.Capability
		}
		src := sg.Source()
		if src != "" {
			fmt.Fprintf(w, "    # %s (source: %s)\n", sg.Rationale, src)
		} else {
			fmt.Fprintf(w, "    # %s\n", sg.Rationale)
		}
		for _, ln := range strings.Split(sg.Snippet, "\n") {
			fmt.Fprintf(w, "    %s\n", ln)
		}
	}
}

// renderSuggestHint prints the one-line advisory pointer at the end of plan/
// converge (stderr, like the cost line). Never gates; silent when there is
// nothing to suggest.
func renderSuggestHint(w io.Writer, c *contract.Contract, vocabs map[string]vocab.Vocabulary, cand *contract.Candidate) {
	res := suggest.Compute(c, vocabs, cand)
	if len(res.Suggestions) == 0 {
		return
	}
	fmt.Fprintf(w, "%d hardening suggestion(s) — run `groundhold suggest`\n", len(res.Suggestions))
}

// renderNoOp surfaces the compiled plan's converged no-op capabilities on stderr
// (the prose channel, D90) — one honest line each naming WHY a bound capability
// produced no action (Part B). Silent when there are none; the hashed plan on
// stdout already carries them in `plan.noop`.
func renderNoOp(w io.Writer, doc *compiler.Document) {
	if doc == nil {
		return
	}
	for _, n := range doc.Plan.NoOp {
		fmt.Fprintf(w, "%s: no-op (%s)\n", n.Capability, n.Reason)
	}
}

func runExplain(term, vocabDir string, jsonMode bool) int {
	// D233: `explain --json` (no term) dumps the whole error-code registry —
	// the machine-readable remediation glossary a consumer (the console) projects
	// verbatim so a blocked/refused figure also shows how to fix it. Single source
	// (perr.Registry), deterministic, sorted.
	if term == "" {
		if !jsonMode {
			fmt.Fprintln(os.Stderr, "explain <error-code | vocab-path> "+
				"(or --json alone for the machine error registry)")
			return 1
		}
		out, _ := json.MarshalIndent(map[string]any{
			"apiVersion": "errors/v0",
			"codes":      perr.Registry(),
		}, "", "  ")
		fmt.Println(string(out))
		return 0
	}
	if ex, ok := perr.Explain[perr.Code(term)]; ok {
		if jsonMode {
			out, _ := json.MarshalIndent(perr.RegistryEntry{
				Code: term, Summary: ex.Summary, Remediation: ex.Remediation}, "", "  ")
			fmt.Println(string(out))
			return 0
		}
		fmt.Printf("%s — machine error code (spec/errors.md)\n", term)
		fmt.Printf("  %s\n  next: %s\n", ex.Summary, ex.Remediation)
		return 0
	}
	vocabs, err := loadVocabs(vocabDir, false)
	if err != nil {
		fmt.Fprintf(os.Stderr, "vocab error: %v\n", err)
		return 1
	}
	// A capability TYPE lists its attributes — the middle rung of the
	// discovery ladder (parity -> explain <type> -> explain <path>): an agent
	// that knows a type can enumerate everything it may constrain, without a
	// contract to scaffold from.
	if voc, ok := vocabs[term]; ok {
		fmt.Printf("%s — capability type (%d attributes)\n", term,
			len(voc.Attributes))
		for _, path := range sortedKeys(voc.Attributes) {
			attr := voc.Attributes[path]
			kind, _ := attr["kind"].(string)
			line := "  " + path
			if kind != "" {
				line += "  (" + kind + enumSuffix(attr) + ")"
			}
			if d, _ := attr["description"].(string); d != "" {
				line += " — " + firstLine(d)
			}
			fmt.Println(line)
		}
		fmt.Printf("  next: groundhold explain <attribute> for one; " +
			"groundhold example candidate <contract.yaml> to scaffold\n")
		return 0
	}
	found := false
	for _, capName := range sortedKeys(vocabs) {
		attrs, ok := vocabs[capName].Attributes[term]
		if !ok {
			continue
		}
		found = true
		fmt.Printf("%s — vocabulary attribute of %s\n", term, capName)
		if kind, _ := attrs["kind"].(string); kind != "" {
			fmt.Printf("  kind: %s\n", kind)
		}
		// allowed values are the first thing an author needs and were
		// previously invisible (agents hunted the enum elsewhere).
		if vals := enumValues(attrs); len(vals) > 0 {
			fmt.Printf("  enum: [%s]\n", strings.Join(vals, ", "))
		}
		if d, _ := attrs["description"].(string); d != "" {
			fmt.Printf("  %s\n", strings.TrimSpace(d))
		}
		if n, _ := attrs["verification"].(string); n != "" {
			fmt.Printf("  verification: %s\n", strings.TrimSpace(n))
		}
		if maps, ok := attrs["mappings"].(map[string]any); ok {
			for _, k := range sortedKeys(maps) {
				fmt.Printf("  %s: %s\n", k,
					strings.TrimSpace(fmt.Sprintf("%v", maps[k])))
			}
		}
	}
	if !found {
		where := vocabDir
		if where == "" {
			where = "the built-in vocabulary"
		}
		fmt.Fprintf(os.Stderr, "%s: not an error code and not a "+
			"vocabulary attribute in %s\n"+
			"  next: groundhold parity for the capability map, then "+
			"groundhold explain <capability.type> for its attributes\n",
			term, where)
		return 1
	}
	return 0
}

// runAPIVer prints the API-version pin catalog (D236) and, given a
// canary-fetched --live snapshot, the per-pin drift verdicts. Offline it is a
// pure catalog: live drift state is cannot-verify by construction (no provider
// call ever runs here). It surfaces drift; it never bumps a pin. Exit 2 when a
// live snapshot shows actionable drift (newer-available or deprecated), so CI
// can gate; cannot-verify never fails (the honest unknown).
func runAPIVer(livePath string, jsonMode bool) int {
	pins := apiver.All()

	// catalog mode: no live snapshot.
	if livePath == "" {
		if jsonMode {
			out, _ := json.MarshalIndent(map[string]any{
				"apiVersion": "apiver/v0",
				"pins":       pins,
				"note": "live drift state is cannot-verify without a --live snapshot " +
					"(fetched by the canary); this is the offline catalog",
			}, "", "  ")
			fmt.Println(string(out))
			return 0
		}
		fmt.Println("API-version pins (offline catalog — drift state needs --live)")
		printPinTable(pins)
		return 0
	}

	// drift mode: compare against a fetched snapshot.
	raw, err := os.ReadFile(livePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "apiver: cannot read --live snapshot: %v\n", err)
		return 1
	}
	var snaps []apiver.LiveVersions
	if err := json.Unmarshal(raw, &snaps); err != nil {
		fmt.Fprintf(os.Stderr, "apiver: --live must be a JSON array of live-version snapshots: %v\n", err)
		return 1
	}
	byKey := map[string]*apiver.LiveVersions{}
	for i := range snaps {
		byKey[snaps[i].Provider+"/"+snaps[i].Service] = &snaps[i]
	}
	var results []apiver.Result
	actionable := 0
	for _, p := range pins {
		results = append(results, apiver.Compare(p, byKey[p.Provider+"/"+p.Service]))
	}
	for _, r := range results {
		if r.Verdict == apiver.NewerAvailable || r.Verdict == apiver.Deprecated {
			actionable++
		}
	}
	if jsonMode {
		out, _ := json.MarshalIndent(map[string]any{
			"apiVersion": "apiver/v0",
			"results":    results,
			"actionable": actionable,
		}, "", "  ")
		fmt.Println(string(out))
	} else {
		fmt.Printf("API-version drift (%d pin(s), %d actionable)\n", len(results), actionable)
		for _, r := range results {
			line := fmt.Sprintf("  %-6s %-32s %-16s -> %s", r.Provider, r.Service, r.Pinned, r.Verdict)
			if len(r.Newer) > 0 {
				line += " (newer: " + strings.Join(r.Newer, ", ") + ")"
			}
			fmt.Println(line)
		}
	}
	if actionable > 0 {
		return 2 // surface, do not follow: a human reviews and bumps the pin
	}
	return 0
}

func printPinTable(pins []apiver.Pin) {
	for _, p := range pins {
		fmt.Printf("  %-6s %-38s %-18s [%s]  %s\n", p.Provider, p.Service, p.Version, p.Embed, p.Source)
	}
}

// runAPIReq prints the API-requirement registry (D329) or, with the `classify`
// subcommand, turns an observed edge-canary outcome into the shared canary
// incident class. The registry is the DATA the functional canary iterates as its
// target list, and the source of the GuardID+SourceURL citation a drift verdict
// carries — so nothing about which operations matter is hardcoded in the shell.
func runAPIReq(pos []string, providerName string, providerProvided bool, jsonMode bool) int {
	if len(pos) >= 2 && pos[1] == "classify" {
		return runAPIReqClassify(pos[2:], providerName, jsonMode)
	}
	reqs := apireq.All()
	if providerProvided {
		reqs = apireq.For(providerName)
	}
	if jsonMode {
		out, _ := json.MarshalIndent(map[string]any{
			"apiVersion":   "apireq/v0",
			"requirements": reqs,
			"note": "the enumerated catalog of KNOWN provider API requirements (D329); " +
				"currency is proven by the live functional canary, this is the claim",
		}, "", "  ")
		fmt.Println(string(out))
		return 0
	}
	fmt.Printf("API-requirement registry (%d entr%s)\n", len(reqs), plural(len(reqs), "y", "ies"))
	for _, r := range reqs {
		fmt.Printf("  %-6s %-10s %s\n", r.Provider, r.Service, r.Operation)
		fmt.Printf("      %s\n", r.Requirement)
		fmt.Printf("      since %s  [%s]  %s\n", r.SinceDate, r.GuardID, strings.Join(r.SourceURL, ", "))
	}
	return 0
}

// runAPIReqClassify is the CLI face of edgecanary.ClassifyFor — the deterministic,
// unit-tested verdict core the shell canary delegates to (so the truth table
// lives in ONE tested place and the drift citation is data-driven from the
// registry). Flags mirror edgecanary.Outcome; --provider selects the cloud edge
// (default aws, so the AWS canary is unaffected); the exit code IS the class.
func runAPIReqClassify(args []string, providerName string, jsonMode bool) int {
	var o edgecanary.Outcome
	parseBool := func(v string) bool { return v == "true" || v == "1" || v == "yes" }
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--applied":
			if i+1 < len(args) {
				o.Applied = parseBool(args[i+1])
				i++
			}
		case "--deployed":
			if i+1 < len(args) {
				o.Deployed = parseBool(args[i+1])
				i++
			}
		case "--transport":
			o.Transport = true
		case "--http-status":
			if i+1 < len(args) {
				n, err := strconv.Atoi(args[i+1])
				if err != nil {
					fmt.Fprintf(os.Stderr, "apireq classify: --http-status must be an integer, got %q\n", args[i+1])
					return 30 // fail SAFE as a flake, never a false green
				}
				o.HTTPStatus = n
				i++
			}
		}
	}
	res := edgecanary.ClassifyFor(edgecanary.EdgeFor(providerName), o)
	if jsonMode {
		out, _ := json.MarshalIndent(res, "", "  ")
		fmt.Println(string(out))
	} else {
		fmt.Printf("%s (exit %d)\n%s\n", res.Class, res.Exit, res.Message)
	}
	return res.Exit
}

// plural picks a suffix for a count (a tiny local helper for the registry table).
func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

// enumValues returns an attribute's allowed values as strings (empty if none).
func enumValues(attr map[string]any) []string {
	raw, ok := attr["enum"].([]any)
	if !ok || len(raw) == 0 {
		return nil
	}
	out := make([]string, 0, len(raw))
	for _, v := range raw {
		out = append(out, fmt.Sprintf("%v", v))
	}
	return out
}

// enumSuffix renders " = a|b|c" for an enum-bound attribute, else "".
func enumSuffix(attr map[string]any) string {
	if vals := enumValues(attr); len(vals) > 0 {
		return " = " + strings.Join(vals, "|")
	}
	return ""
}

func firstLine(s string) string {
	s = strings.TrimSpace(strings.SplitN(s, "\n", 2)[0])
	if len(s) > 72 {
		s = s[:72] + "…"
	}
	return s
}

func sortedKeys[M ~map[string]V, V any](m M) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func printText(r *verify.Report, c *contract.Contract,
	vocabs map[string]vocab.Vocabulary, m render.Mode, exit int) {
	byID := map[string]contract.Constraint{}
	for _, cn := range c.Constraints {
		byID[cn.ID] = cn
	}
	capType := map[string]string{}
	for id, raw := range c.Capabilities {
		t, _ := raw["type"].(string)
		capType[id] = t
	}
	fmt.Printf("contract %s v%d\n", r.Contract, r.ContractVersion)
	var rollup render.Rollup
	for _, v := range r.Verdicts {
		glyph := m.Paint(render.VerdictColor(v.Verdict), m.Glyph(v.Verdict))
		basis := ""
		dim := false
		if v.Basis != nil && *v.Basis != "declared" {
			basis = fmt.Sprintf(" [%s]", *v.Basis)
			dim = true
		}
		line := fmt.Sprintf("%-28s %-12s%s  %s", v.Constraint, v.Verdict, basis, v.Reason)
		if dim {
			line = m.Dim(line)
		}
		fmt.Printf("  %s %s\n", glyph, line)
		cn := byID[v.Constraint]
		if v.Verdict != "satisfied" {
			if cn.Severity == "hard" {
				switch v.Verdict {
				case "violated":
					rollup.Violated = append(rollup.Violated, v.Constraint)
				case "unknown":
					rollup.Unknown = append(rollup.Unknown, v.Constraint)
				case "unverifiable":
					rollup.Unverifiable = append(rollup.Unverifiable, v.Constraint)
				}
			}
			if voc, ok := vocabs[capType[cn.Subject]]; ok {
				if f := render.Friction(cn.Path, voc.Attributes[cn.Path]); f != "" {
					fmt.Printf("      %s\n", m.Dim(f))
				}
			}
		}
	}
	s := r.Summary
	fmt.Printf("\n  %d satisfied, %d violated, %d unknown, %d unverifiable",
		s.Satisfied, s.Violated, s.Unknown, s.Unverifiable)
	if s.VerdictsOnAssumedValues > 0 {
		fmt.Printf(", %d verdict(s) rest on assumed/inferred values",
			s.VerdictsOnAssumedValues)
	}
	fmt.Println()
	word, color := render.Pick("verify", exit, r.Code, rollup)
	fmt.Printf("  %s%s\n", m.Paint(color, word), bannerCulprit(word, rollup, byID))
}

// bannerCulprit: a non-green banner always names its culprit — the bare
// word reads as procedural state (a queue, a lock), the culprit makes it
// semantic.
func bannerCulprit(word string, r render.Rollup,
	byID map[string]contract.Constraint) string {
	var ids []string
	var verdict string
	switch word {
	case "VIOLATED":
		ids, verdict = r.Violated, "violated"
	case "BLOCKED":
		ids = append(append([]string{}, r.Unknown...), r.Unverifiable...)
		verdict = "unknown"
		if len(r.Unknown) == 0 {
			verdict = "unverifiable"
		}
	default:
		return ""
	}
	if len(ids) == 0 {
		return ""
	}
	cn := byID[ids[0]]
	out := fmt.Sprintf(": %s %s — %s", ids[0], verdict, cn.Path)
	if verdict == "unknown" && cn.VerifyMethod == "probe" {
		out += " requires probe verification"
	}
	if len(ids) > 1 {
		out += fmt.Sprintf(" (+%d more)", len(ids)-1)
	}
	return out
}
