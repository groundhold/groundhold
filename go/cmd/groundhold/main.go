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
	"syscall"
	"time"

	"gopkg.in/yaml.v3"

	"slices"
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
                   [--ledger <f>] [--bindings <f>] [--observations <f>] --at <ts>
  groundhold preflight <contract.yaml> <candidate.yaml> --provider <aws|gcp|azure|k8s>
                   [--project <p>]  (every capability's missing implementation
                    operands + unsatisfiable attributes in ONE pass; exit 2 if any)
  groundhold forecast <plan.yaml> <candidate.yaml> [--ledger <file>]
                   [--heads <f>] [--bindings <f>] [--observations <f>] --at <ts>
  groundhold apply    <contract.yaml> <candidate.yaml> <plan.yaml>
                   --ledger <file> [--provider fake|gcp|aws|azure|k8s|cloudflare|hetzner|upstash] --at <ts>
                   [--vocab <dir>] [--require-preflight] [--no-reachability]
                   [--detach] [--fail-key <k>] [--unknown-key <k>]
  groundhold observe  (--ledger <file> | --bindings <file>)
                   [--provider fake|gcp|aws|azure|k8s|cloudflare|hetzner|upstash] --at <ts> [--ttl <s>] [--record]
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
                   [--provider fake|gcp|aws|azure|k8s|cloudflare|hetzner|upstash] [--vocab <dir>] [--project <p>]
                   --at <ts> [--yes] [--allow-data-loss] [--allow-exposure]
                   [--json] [--detach]
                   [--no-reachability]  (skip the post-apply public-edge probe)
  groundhold discover [--provider fake|gcp|aws|azure|k8s|cloudflare|hetzner|upstash] [--project <p>] [--region <r>]
                   (cloudflare, hetzner and upstash are READ-ONLY: they discover and
                    observe, and refuse to create, update or delete — D732/D734)
                   --at <ts>  (read-only; never writes the ledger)
                   (k8s: --region is the namespace, empty = cluster-wide)
  groundhold k8s-skeleton <group>/<version>/<Kind> --capability <cap>
                   [--kubeconfig <f>] [--context <c>]  (offline mapping
                   scaffolding: emits the machine half only, authors no
                   semantics; use "core" for the core group)
  groundhold pair <provider> --cred-ref <kind>:<value> [--scope <s>] [--verify-ref]
                   (register a credential REFERENCE for the gentle crawler,
                   never a secret; gcp|aws|azure|k8s only, OAuth deferred D141)
  groundhold connections   (list pairings; references only, never secrets)
  groundhold version       (which build this is; also --version, -v)
  groundhold unpair <provider> [--scope <s>]
  groundhold crawl --provider <p> --at <ts> [--budget <n>] [--out <dir>]
                   [--pairings <f>]
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
  groundhold react --event <file> --ledger <f> --provider <p> --at <ts>
                   [--crawl <base.json>]
                   [--contract <f>...] [--out <dir>]  (event-driven ingress:
                   map one cloud change or k8s watch event to a scope, re-list it,
                   splice, reclassify posture — the opt-in real-time path over polling)
  groundhold posture --ledger <f> --at <ts> [--crawl <crawl.json>]
                   [--contract <f>...] [--out <dir>]  (proactive classifier:
                   managed-ok/drifted/shadow/decayed/unknown with adopt/converge/
                   observe recipes; exit 2 on shadow or drift; writes nothing)
  groundhold adopt    <contract.yaml> <candidate.yaml> --ledger <file>
                   --map <cap=providerId> [--map ...] [--provider fake|gcp|aws|azure|k8s|cloudflare|hetzner|upstash]
                   [--project <p>] [--vocab <dir>] --at <ts>
                   [--discovery <file>]
                   (binds existing resources; mutates the ledger, never
                    the cloud; refuses when reality disagrees)
  groundhold unadopt  <contract.yaml> <capability> --ledger <file> --at <ts>
                   (removes the binding, never the resource)
  groundhold hints    <state-file> [--format auto|tfstate|pulumi]
                   (terraform/pulumi state -> adoption hints; pure
                    translation — hints, never a contract)
  groundhold export   --ledger <file> [--since <index>] [--type <t> ...]
                   [--from <ts>] [--to <ts>] [--format ndjson|cloudevents]
                   (deterministic ledger fold to stdout; --from/--to window the
                   emitted events by occurredAt — the 4D DR primitive; transport and
                    cursor belong to the operator)
  groundhold publish  <contract.yaml> --ledger <file> --actor <id> --at <ts>
                   (records contract authorship: appends
                    contract.published with the canonical hash and a
                    HUMAN actor — the ledger answers "who approved this")
  groundhold audit    <contract.yaml> --ledger <file> --at <ts> [--record]
                   (constraints vs recorded REALITY; --record appends
                    violation.detected; exit 2 when hard constraints
                    are violated or unknown)
  groundhold resume   <contract.yaml> --ledger <file> [--provider fake|gcp|aws|azure|k8s|cloudflare|hetzner|upstash]
                   [--project <p>] --at <ts> [--fail-key <k>]
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
  groundhold probe    <contract.yaml> --ledger <file> [--provider fake|gcp|aws|azure|k8s|cloudflare|hetzner|upstash]
                   [--project <p>] [--capability <id>] --at <ts>
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
        Time-sensitive verbs REQUIRE an explicit --at (RFC3339): a
        safety clock never defaults to a value that makes stale
        observations look fresh (N1). They are: adopt, apply, attest,
        audit, converge, crawl, discover, forecast, observe, plan,
        posture, probe, publish, react, refresh, resume, runs, status,
        unadopt. (wait is exempt: it IS the live clock.)
        Provider verbs (discover/apply/adopt/observe/converge/probe/
        resume/react/refresh/crawl/preflight) REQUIRE an
        explicit --provider (aws|gcp|azure|k8s|cloudflare|hetzner|upstash|fake): the fake driver
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
        --allow-exposure, --allow-intrusive, --require-preflight, --yes)
        — those must be
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
  (apireq classify carries its own verdict scheme: 0 green / 10 provider-drift /
   20 groundhold-regression / 30 infra-flake — route on it separately)
`

// buildVersion is stamped at release time via
// -ldflags "-X main.buildVersion=<tag>"; a plain `go build` reports "dev".
var buildVersion = "dev"

// intFlag parses a whole-number flag. D657: these four flags were read with
//
//	_, _ = fmt.Sscanf(args[i+1], "%d", &x)
//
// which discards BOTH return values. `--ttl 1e9` therefore recorded `ttlSeconds: 1`
// — Sscanf stops at the `e` and keeps the 1 — into an append-only ledger, so every
// later audit blocked on a one-second freshness window that nobody typed. `--ttl
// abc`, `--ttl -5` and `--ttl 99999999999999999999` were silently ignored, and
// `--window 1e9` made the unattended freshness agent report `exit 0, fresh=[…]`
// while refreshing nothing at all — a safety control switched off by a flag parse.
//
// A value the operator typed and the tool could not read is refused, named, and
// never guessed at.
func parseIntFlag(name, raw string) (int, error) {
	n, err := strconv.Atoi(strings.TrimSpace(raw))
	if err != nil {
		return 0, fmt.Errorf("%s %q is not a whole number — refusing rather than "+
			"reading a prefix of it (D657)", name, raw)
	}
	if n < 0 {
		return 0, fmt.Errorf("%s %q is negative", name, raw)
	}
	return n, nil
}

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
  groundhold version                       — which build this is (also --version, -v)
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
	// D631: `discover` stamps `--at` into the DiscoveryDocument and the document's
	// canonical hash, and `adopt --discovery` writes that hash into the ledger as the
	// adoption's provenance root. Outside this set it got neither the presence gate
	// nor D323's parse gate, so `discover` with no clock produced `at: 1970-…` and
	// `--at not-a-time` produced `at: "not-a-time"` — both at exit 0, both permanent.
	// `pair`, the other ungated clock consumer, handles this explicitly (D588: "a
	// record saying 1970 is worse than a record saying nothing"), which is how we
	// know the pattern was understood and this verb was simply missed.
	"discover": true,
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
	"converge": true, "probe": true, "resume": true, "react": true,
	"refresh": true, "crawl": true, "preflight": true,
	// D571: `anchor` and `repair` were here and belong to neither half of the
	// definition above — runAnchor and runRepair take no provider and their bodies
	// name no driver. They are PURE LEDGER operations, and both are recovery verbs:
	// demanding --provider to check a chain's integrity tells the operator the check
	// contacts a cloud, at the moment they are least able to spare the doubt.
	// Removing them is not the fail-open regression this comment warns about —
	// there is no provider path here to fall open onto.
}

// knownProviders is the closed set of provider names the CLI accepts (a typo must
// be an error, not a silent fake fallthrough).
var knownProviders = map[string]bool{
	"aws": true, "gcp": true, "azure": true, "k8s": true, "fake": true,
	"upstash": true, "hetzner": true, "cloudflare": true,
}

// knownProviderList renders the accepted provider names deterministically, so the errors
// that name them cannot drift from the set the CLI actually accepts. Three copies of
// "(aws|gcp|azure|k8s|fake)" had gone stale while 8 are accepted, so a user who mistyped
// `cloudfare` was told cloudflare was not a real provider (D1006).
func knownProviderList() string {
	ks := make([]string, 0, len(knownProviders))
	for k := range knownProviders {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	return strings.Join(ks, "|")
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
		strings.Contains(reason, "allow_replace_stateful") ||
		strings.Contains(reason, "allow_protection_lift"):
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
	allowExposure := false
	// D364: silences the plaintext-credential warning. A warning nobody can turn
	// off is a warning everybody learns to ignore.
	allowPlaintextSecret := false
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
	versionFlag := false
	signKeyPath := ""
	liveVersionsPath := "" // D236: apiver --live snapshot
	var trustArgs []string
	trustFromArg := ""
	verifyPath := ""
	endOfFlags := false
	for i := 0; i < len(args); i++ {
		// D590: POSIX `--` ends the flags; everything after it is positional. D567
		// made an unrecognised "-" token an error and refused this one too, which is
		// the same failure as --version: a rule that fails closed has to be checked
		// against the conventions it closes ON.
		if endOfFlags {
			pos = append(pos, args[i])
			continue
		}
		if args[i] == "--" {
			endOfFlags = true
			continue
		}
		switch args[i] {
		case "--help", "-h":
			helpFlag = true
		case "--version", "-v":
			// D589: these are FLAGS and belong in the flag switch. They used to fall
			// through to the positional list, where `cmd == "--version"` picked them
			// up — until D567 made an unrecognised token starting with "-" an error
			// and closed on them. A fail-closed rule must be checked against what it
			// closes ON, not only against what it is meant to stop.
			versionFlag = true
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
			if v, ferr := parseIntFlag("--since", args[i+1]); ferr != nil {
				fmt.Fprintln(os.Stderr, ferr)
				return 1
			} else {
				since = v
			}
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
			if v, ferr := parseIntFlag("--ttl", args[i+1]); ferr != nil {
				fmt.Fprintln(os.Stderr, ferr)
				return 1
			} else {
				ttl = v
			}
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
			if v, ferr := parseIntFlag("--budget", args[i+1]); ferr != nil {
				fmt.Fprintln(os.Stderr, ferr)
				return 1
			} else {
				budgetArg = v
			}
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
			if v, ferr := parseIntFlag("--window", args[i+1]); ferr != nil {
				fmt.Fprintln(os.Stderr, ferr)
				return 1
			} else {
				windowArg = v
			}
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
		case "--allow-exposure":
			// D630: consent for a plan that provably increases security exposure.
			allowExposure = true
		case "--allow-plaintext-secret":
			allowPlaintextSecret = true
		default:
			// D567: an unrecognised token starting with "-" is an operator error,
			// never a positional. Absorbing it silently made the run answer a
			// question nobody asked: `posture ... --discovery d.json` printed
			// "shadow": 0 and a postureHash over a cluster holding 169 unmanaged
			// objects, because posture takes no such flag and the value went the
			// same way. Same class as the candidate's silent operand (D530), one
			// layer out.
			//
			// A lone "-" stays a positional. D590 corrects what this comment used to
			// claim: no verb reads stdin, so calling that "stdin, by convention" was
			// a convention this tool does not implement — the exact kind of unearned
			// claim the day was spent removing.
			// D602: a verb may own PRIVATE flags that the global switch does not
			// know — `apireq classify` parses four of its own out of the positional
			// list, which is how they used to arrive. D567 closed that door on them
			// and made the whole sub-verb unreachable. The registry below is the
			// mechanism: a private flag passes through to its own verb and is still
			// refused for every other one, and a gate requires the registry to hold
			// exactly what the sub-parser reads.
			if verbOwnsFlag(firstPositional(pos), args[i]) {
				pos = append(pos, args[i])
				continue
			}
			if len(args[i]) > 1 && strings.HasPrefix(args[i], "-") { //nolint:gosec // G602: i is bounded by the enclosing for i := 0; i < len(args); i++
				fmt.Fprintf(os.Stderr, "unknown flag %q — refusing rather than "+
					"ignoring it: a run that drops an input answers a question you "+
					"did not ask. `groundhold %s --help` lists what this verb takes.\n",
					args[i], firstPositional(pos))
				return 1
			}
			pos = append(pos, args[i]) //nolint:gosec // G602: i is bounded by the enclosing for i := 0; i < len(args); i++
		}
	}
	// D589: --version answers before the "no command" branch, or a bare
	// `groundhold --version` prints the usage instead of the version.
	if versionFlag {
		fmt.Printf("groundhold %s\n", buildVersion)
		return 0
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
	if cmd == "version" {
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
		a, anchorState, aerr := ledger.AnchorStateOf(ledgerPath)
		if anchorState == ledger.AnchorUnreadable {
			// D709: an anchor beside the ledger is how a receiver's held artifact
			// arms verification (D135). This test was `err == nil && a != nil`, which
			// reads a CORRUPT anchor exactly like an absent one — so the policy was
			// silently not applied: no trusted keys, no trustFrom cutoff, and events
			// the policy required to be signed accepted unsigned. Running under a
			// policy we cannot read is the downgrade D135 exists to prevent.
			fmt.Fprintf(os.Stderr, "trust error: an anchor exists beside %s and could "+
				"not be read (%v) — it carries the trust policy this run would verify "+
				"under, so proceeding would silently verify under NO policy. Repair or "+
				"remove the anchor deliberately.\n", ledgerPath, aerr)
			return 1
		}
		if anchorState == ledger.AnchorPresent {
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
				"(%s): fake fabricates reality, so it must be chosen "+
				"deliberately (--provider fake) rather than defaulted\n", cmd, knownProviderList())
			return 1
		}
		if !knownProviders[providerName] {
			fmt.Fprintf(os.Stderr, "unknown provider %q (want %s)\n", providerName, knownProviderList())
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
			// D647: the anchor beside the ledger detects accidents; only a copy the
			// attacker cannot reach detects an attacker. Say so at the moment the
			// file is written, which is the only moment the operator is looking.
			"anchorFile": ledger.AnchorPath(ledgerPath),
			"next": "copy " + ledger.AnchorPath(ledgerPath) + " OFF-HOST — a " +
				"snapshot family proves the sidecar, archive and tail agree with " +
				"each other; authenticity needs a witness stored somewhere this " +
				"directory's writer cannot reach (or an armed --sign-key)",
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
			return refuseCorruptLedger(err)
		}
		out, _ := json.MarshalIndent(rep, "", "  ")
		fmt.Println(string(out))
		// D1020: attest is the UNION integrity reporter (chain + anchor + snapshot +
		// archive + signatures) and it ALREADY gates the chain — missing ledger exits 1,
		// a broken chain exits 5. But an anchor/snapshot/archive integrity FAILURE was
		// written into a report FIELD and the exit code stayed 0, so a cron/CI running
		// `attest` as its one-pass integrity check read ALL-CLEAR over a foreign/rewritten
		// anchor, a truncated tail, a neutralized witness, or a swapped snapshot/archive —
		// while `anchor --check` exits 5 on the same input. D613 corrected the report WORD
		// (verified→unverifiable), not the code. Gate on what attest reports: a corrupted
		// off-host witness is corruption-class (5), exactly as certify-capsule/anchor exit.
		if !attestIntegrityHealthy(rep) {
			return 5
		}
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
		convCand := ""
		if len(pos) > 2 {
			convCand = pos[2]
		}
		crunID, cenv, ccaps, cerr := converge.RunID(pos[1], convCand, evalTime, project)
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
			Yes: yes, AllowDataLoss: allowDataLoss, AllowExposure: allowExposure,
			JSON:           jsonMode,
			NoReachability: noReachability,
			// D612: the run's security policy travels to the children, which are
			// separate PROCESSES and inherit no in-process trust set.
			Trust: trustArgs, TrustFrom: trustFromArg, SignKey: signKeyPath,
			// D638: and WHICH cluster. A child process inherits neither.
			Kubeconfig: kubeconfigPath, KubeContext: kubeContext,
			// D638: and everything else a child needs to see the same world.
			Region: region, Bindings: bindingsPath, Observations: observationsPath,
			TTL: intFlag(ttl), RequirePreflight: requirePreflight,
			FailKey: oneKey(failKeys), UnknownKey: oneKey(unknownKeys),
			RetryableKey: oneKey(retryableKeys),
			In:           os.Stdin, Out: os.Stdout,
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
		dp, derr := driverFor(providerName, project, region, kubeconfigPath, kubeContext)
		if derr != nil {
			fmt.Fprintln(os.Stderr, derr.Error())
			return 1
		}
		prov = dp
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
		conn := pair.Connection{Provider: pos[1], Scope: scopeArg, Credential: ref}
		// D588: through StampPairedAt, which records nothing when there is no clock.
		// `pair` takes no --at, so evalTime here is the epoch default unless the
		// operator supplied one, and a record saying 1970 is worse than a record
		// saying nothing.
		conn.StampPairedAt(evalTime)
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
			row := map[string]string{
				"provider": c.Provider, "scope": c.Scope,
				"credentialRef": c.Credential.String(),
			}
			// D588/D230: a clock nobody supplied is OMITTED, not published empty.
			// An absent key says "not recorded"; "" says the field exists and is
			// blank, which is a third thing nobody meant.
			if c.PairedAt != "" {
				row["pairedAt"] = c.PairedAt
			}
			rows = append(rows, row)
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
		led, lerr := ledger.ReplayExisting(ledgerPath)
		if lerr != nil {
			return refuseCorruptLedger(lerr)
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
		// D649: refresh runs unattended on a schedule, so the exit code is the only
		// alert. A capability whose re-observation failed left the proof untouched
		// and still decaying — the run did not do its job, and saying 0 is how a
		// cron never notices a provider it has not read for a month.
		if len(rep.Unreadable) > 0 {
			return perr.ExitFor(perr.ObservationRequired)
		}
		return 0
	}
	if cmd == "posture" {
		// the proactive classifier (candidate D142): fold a crawl (--context) + the
		// ledger + audit (--contract) into managed-ok/drifted/shadow/decayed/unknown
		// with on-a-plate remediation. Pure + deterministic; N1 --at. Writes nothing.
		// D567: posture takes its swept resources from a CRAWL, never from a
		// `discover` output, and the difference is load-bearing rather than
		// cosmetic: a crawl records per-scope COMPLETENESS, which is what
		// shadowLowerBound is a claim about. Folding a discovery document would
		// let posture report a shadow count it has not earned. The flag was
		// silently ignored — and posture's own remediation tells the operator to
		// run `discover`, so the tool set this trap for itself.
		if discoveryPath != "" {
			fmt.Fprintln(os.Stderr, "posture does not take --discovery: it classifies "+
				"what a CRAWL swept, because a crawl records whether each scope was "+
				"listed COMPLETELY and `discover` does not — without that, a shadow "+
				"count would be a number with no claim behind it. Use --crawl <doc>, "+
				"or run posture with a paired provider so it crawls first.")
			return 1
		}
		if ledgerPath == "" {
			fmt.Fprintln(os.Stderr, "posture requires --ledger")
			return 1
		}
		led, lerr := ledger.ReplayExisting(ledgerPath)
		if lerr != nil {
			return refuseCorruptLedger(lerr)
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
			// D615: every field of crawl.Document is optional to the JSON decoder, so
			// a `discover` output decodes CLEANLY into an empty crawl — no providers,
			// no scopes — and posture then reports "shadow": 0 with
			// shadowLowerBound:false, an affirmative claim that the sweep was
			// complete, at exit 0. Measured on one ledger and one resource: a real
			// crawl gave shadow 1 and exit 2; the discovery document gave shadow 0
			// and OK.
			//
			// This is the trap D567 closed on --discovery and left open next to it,
			// which is worse than never having closed it: the refusal on one flag
			// reads as diligence covering both. Posture's own shadow recipe tells the
			// operator to run `discover`, so the wrong file is the one they have.
			if kind, _ := docKind(raw); kind == "DiscoveryDocument" {
				fmt.Fprintf(os.Stderr, "posture --crawl was given a DISCOVERY "+
					"document. It classifies what a CRAWL swept, because a crawl "+
					"records whether each scope was listed COMPLETELY and `discover` "+
					"does not — folding it would report a shadow count posture has "+
					"not earned. Run `groundhold crawl --provider <p> %s` "+
					"(or pair the provider and let posture crawl) and pass that file.\n",
					perr.AtNow)
				return 1
			}
			if len(loaded.Providers) == 0 {
				fmt.Fprintln(os.Stderr, "posture --crawl: the document names no "+
					"providers, so it swept nothing. A posture over an empty sweep "+
					"would report zero shadow resources and mean nothing by it.")
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
		fmt.Println(string(out))
		if crawlOut != "" {
			if err := writeReport(crawlOut, "posture.json", doc); err != nil {
				fmt.Fprintln(os.Stderr, "posture: --out was given and the document "+
					"could not be written:", err)
				return 1
			}
		}
		// exit 2 on findings that demand action or an estate that could not be fully
		// judged (D958): shadow/drift/unknown/incomplete-scope. decayed alone does not
		// fail (renew). The decision lives in posture.Summary.ExitCode so it is testable.
		return doc.Summary.ExitCode()
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
			// D591: a routine frame and an event we could not understand are
			// different outcomes and must not share an exit code. A stream consumer
			// routes on this: 0 means "handled, nothing to do", and telling it that
			// for a dropped event hides the real-time path losing changes.
			if errors.Is(perr2, react.ErrNothingToReactTo) {
				fmt.Fprintln(os.Stderr, "react: nothing to react to —", perr2)
				return 0
			}
			// Still never a crash loop: a malformed envelope is a structural error in
			// the INPUT document, which is what exit 1 means here (spec/errors.md).
			fmt.Fprintln(os.Stderr, "react: event NOT understood and dropped —", perr2)
			return 1
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
		// D592: the re-listed scope is stamped NOW; every scope the splice carries
		// over keeps its own listing time, so the document stops re-dating what it
		// did not read.
		fresh := crawl.ScopeContext{Scope: ev.Scope, Status: "complete", ListedAt: evalTime, Resources: []crawl.Resource{}}
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
		out, _ := json.MarshalIndent(doc, "", "  ")
		fmt.Println(string(out))
		if crawlOut != "" {
			for _, w := range []struct {
				name string
				doc  any
			}{{"context.json", spliced}, {"posture.json", doc}} {
				if err := writeReport(crawlOut, w.name, w.doc); err != nil {
					fmt.Fprintln(os.Stderr, "react: --out was given and the document "+
						"could not be written:", err)
					return 1
				}
			}
		}
		// D966: the exit decision lives in posture.Summary.ExitCode (the same source
		// the `posture` verb returns), so react cannot silently drop the Unknown and
		// ShadowLowerBound arms. react is the unattended stream-consumer path — exit 0
		// is its "handled, nothing to do", and reading it over an incomplete sweep or
		// an unknown hard constraint is the incomplete-as-complete / unverifiable-as-
		// success inversion posture and audit both refuse (invariant #1, D650, D958).
		return doc.Summary.ExitCode()
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
			// D616: the RESTORED ledger is the authority on which documents this
			// history pins — the manifest beside the blobs is not.
			vrep, vcode := backup.VerifyDocumentsAgainst(documentsPath, crawlOut)
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
		led, err := ledger.ReplayExisting(ledgerPath)
		if err != nil {
			return refuseCorruptLedger(err)
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
		warnPlaintextSecrets(os.Stderr, cand, allowPlaintextSecret)
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
		// D697: a run that measured nothing (or only some of it) is MISSING KNOWLEDGE,
		// not a refusal — the probe ran. The banner vocabulary already distinguishes
		// the two (spec/presentation.md); it needs the rollup to say so.
		for _, f := range res.Failures {
			bannerState.rollup.Unknown = append(bannerState.rollup.Unknown,
				f.Capability+"."+f.Path+" not measured")
		}
		if res.Status == "unmeasured" && len(res.Failures) == 0 {
			bannerState.rollup.Unknown = append(bannerState.rollup.Unknown,
				"the driver returned no measurements and named no failure")
		}
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
		res, err := audit.Run(c, led, ledgerPath, evalTime, record, vocabs)
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
		warnPlaintextSecrets(os.Stderr, cand, allowPlaintextSecret)
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
			// D734: never the fake by fall-through.
			dp, derr := driverFor(providerName, project, region, kubeconfigPath, kubeContext)
			if derr != nil {
				fmt.Fprintln(os.Stderr, derr.Error())
				return 1
			}
			prov = dp
		}
		res, code := adopt.Run(c, cand, report, adoptMap, prov, led,
			ledgerPath, evalTime, discoveryHash)
		// D322: an adoption can succeed and still have something to SAY — an
		// assumed declaration the live reading contradicts. JSON alone would bury
		// it, so it also goes to the human channel (stderr, never stdout: the
		// result document stays machine-clean).
		sayNotes(res.Notes)
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
		sayNotes(res.Notes)
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
		warnPlaintextSecrets(os.Stderr, cand, allowPlaintextSecret)
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
		renderSuggestHint(os.Stderr, c, vocabs, cand, pos[1])
		// Part B: name every converged no-op on stderr (the prose channel), so a
		// plan that changes some capabilities and leaves others alone says WHY it
		// left them alone. The hashed plan on stdout already carries plan.noop.
		renderNoOp(os.Stderr, doc)
		// D721, from the field: a capability the compiler could not plan at all was
		// carried in plan.blocked and NEVER SPOKEN. This channel named the no-ops —
		// capabilities deliberately left alone, the harmless case — and said nothing
		// about the capabilities that fell out of the deployment, which is the
		// dangerous one. A pilot read a plan of 24 actions for a 27-capability
		// contract, applied it, and learned what was missing from converge afterwards.
		unaccounted := renderBlocked(os.Stderr, doc, c)
		if len(unaccounted) > 0 {
			// converge already refuses the clean "converged" verdict while a capability
			// is blocked; plan called the same state a success. One state, two verbs,
			// two answers — and the verb people read first was the one that said fine.
			return 2
		}
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
		warnPlaintextSecrets(os.Stderr, cand, allowPlaintextSecret)
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
		warnPlaintextSecrets(os.Stderr, cand, allowPlaintextSecret)
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
		res.Reachability = string(reach.Skipped)
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
		case cr.Verdict == reach.Failing:
			say("  reachability FAILING: %s GET %s — %s", cr.Capability, cr.URL, cr.Cause)
		case reach.IsAnonymousDenied(cr):
			say("  reachability unknown: %s GET %s — %s", cr.Capability, cr.URL, cr.Cause)
			say("    %s", reach.AnonymousRemediation)
		default: // unknown: transport failure or an unexpected status
			say("  reachability unknown (from here): %s GET %s — %s",
				cr.Capability, cr.URL, cr.Cause)
		}
	}
	if len(results) > 0 {
		say("  checked: %s", reach.Checked)
	}
	// One classification for both renderers (D696) — the prose differs per verb, what
	// a verdict MEANS does not.
	violated, unknown, verdict := reach.Fold(results)
	bannerState.rollup.Violated = append(bannerState.rollup.Violated, violated...)
	bannerState.rollup.Unknown = append(bannerState.rollup.Unknown, unknown...)
	switch verdict {
	case reach.Failing:
		res.Reachability, res.Exit = string(reach.Failing), 2
	case reach.Unknown:
		res.Reachability, res.Exit = string(reach.Unknown), 2
	default:
		res.Reachability = string(reach.Reachable)
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
		// D803: the sweep succeeded — and the provider may have said there was more.
		// A driver that can answer is asked; one that cannot is not assumed complete by
		// this code, it simply says nothing and the scope keeps whatever the sweep said.
		f := crawl.Fetched{Resources: res.Discovery.Resources, Pace: pace.Result{Outcome: pace.OK}}
		if lc, ok := prov.(provider.ListingCompleteness); ok {
			if notes := lc.TruncatedListings(); len(notes) > 0 {
				calls := make([]string, 0, len(notes))
				for _, n := range notes {
					calls = append(calls, n.Call)
				}
				sort.Strings(calls)
				f.Incomplete = true
				f.Reason = "the scope is incomplete — a listing did not finish (a page went " +
					"unread, or a discovery sweep failed): " + strings.Join(calls, ", ") +
					" — the resources found are real, the count is a lower bound (D803/D873)"
			}
		}
		return f
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

// writeReport writes a JSON document into a --out directory and says so when it
// cannot. D653: two call sites did
//
//	if err := os.MkdirAll(dir, 0o755); err == nil { _ = os.WriteFile(...) }
//
// so a read-only directory, a full disk, or a plain file sitting where the
// directory should be produced NOTHING — no error, no message, and the verb's own
// exit code unchanged. A cron reading `$OUT/posture.json` then consumes a stale
// document indefinitely while every run reports success. The output IS the
// deliverable when --out is given; failing to produce it is not a detail.
func writeReport(dir, name string, doc any) error {
	raw, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return fmt.Errorf("%s: %v", name, err)
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, name), append(raw, '\n'), 0o600)
}

// classifyPosture folds a crawl document + the ledger + audit into the posture
// document — shared by `groundhold posture` (full or live crawl) and `groundhold react`
// (a spliced crawl). Pure given its inputs.
func classifyPosture(led *ledger.Ledger, ledgerPath string, ctx *crawl.Document, contractPaths []string, at string) (*posture.Document, error) {
	in := posture.Input{At: at, Bindings: led.BoundProviderIDs(),
		Deposed: map[string]bool{}, Decayed: map[string]bool{},
		Verdict: map[string]string{}, Absent: map[string]bool{}}
	if ctx != nil {
		for _, p := range ctx.Providers {
			for _, s := range p.Scopes {
				complete := s.Status == "complete"
				// D650: the SCOPE carries its own completeness. It used to travel
				// only on the resources, so a scope that listed nothing — an auth
				// error, a throttle, an exhausted budget — was invisible and
				// posture called its shadow count exact.
				in.Scopes = append(in.Scopes, posture.Scope{Provider: p.Provider,
					Scope: s.Scope, Complete: complete, Reason: s.Reason})
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
		// D652: the reserved absence marker, judged for freshness the same way the
		// compiler judges it — a STALE "it was gone last year" says nothing about
		// now, and the decayed branch below already covers that case.
		if r, ok := recs[provider.ResourceAbsentPath]; ok {
			gone, _ := r.Value.(bool)
			obsSec, oerr := ledger.ParseTs(r.ObservedAt)
			// D666: the absence marker is judged by the SAME predicate the compiler
			// applies (D652 claimed it already was; it was off by one second, so
			// posture went green on a resource it was simultaneously planning to
			// re-create). A FUTURE-dated marker is still refused separately — the
			// compiler refuses it too, and "measured after the moment we are asking
			// about" is a different fact from "too old".
			if gone && oerr == nil && atSec >= obsSec &&
				!ledger.ObservationExpired(r.ObservedAt, r.TTLSeconds, atSec) {
				in.Absent[capID] = true
			}
		}
		for _, r := range recs {
			// D666: `<=` here called a proof decayed one second before audit,
			// plan, apply and forecast did — and posture's own remediation chains
			// those verbs. One predicate now.
			if ledger.ObservationExpired(r.ObservedAt, r.TTLSeconds, atSec) {
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
		// D660: audit needs the vocabulary to canonicalize SET attributes; the
		// embedded set is the source of truth (D23) and posture is a read-only
		// classification, so overrides do not apply here.
		postureVocabs, _ := vocab.Embedded()
		ar, aerr := audit.Run(c, led, ledgerPath, at, false, postureVocabs)
		if aerr != nil {
			return nil, fmt.Errorf("audit error: %v", aerr)
		}
		// D755: soft is ADVISORY. Folding it in made an advisory violation render as
		// drift ("a hard constraint is violated") with a converge recipe, and an
		// advisory pass render as managed-ok — green with nothing hard proven, past
		// the very arm that refuses to "claim ok without a proof".
		for _, v := range audit.HardOnly(ar.Verdicts) {
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
			// D965: a HARD constraint whose audit verdict is unknown (its proof is
			// stale or unprovable) must BLOCK — invariant #1, and audit exits 2 on the
			// identical evidence. Set it so capRow ranks it ABOVE decayed, exactly as
			// violated/unverifiable already do. Leaving it unset let a coincident
			// decayed proof mask a stale hard constraint as exit 0 (posture's own
			// audit-parity claim, broken for the staleness subclass).
			in.Verdict[capID] = "unknown"
		case a.satisfied:
			in.Verdict[capID] = "satisfied"
		}
	}
	return posture.Classify(in), nil
}

// driverFor is the ONE place a provider NAME becomes a driver (D734). It returns nil
// for a name this binary cannot construct, and every caller must refuse on nil rather
// than substituting the fake.
//
// Four copies of this mapping existed. Three ended in `else { prov = &provider.Fake{} }`,
// so a name that passed `knownProviders` but was missing from that particular chain —
// cloudflare, upstash, hetzner — silently became the FAKE. `discover --provider
// cloudflare` returned `fake:existing-db`, a fabricated relational database, as the
// result of a DNS sweep. A pilot was one `adopt` away from writing that into their
// ledger as a real binding, and caught it only because they read the output first.
//
// It broke the rule printed a few lines above the validator, in this binary's own
// words: "fake fabricates reality, so it must be chosen deliberately (--provider fake)
// rather than defaulted". A set with two homes has no home; this one had four.
func driverFor(name, project, region, kubeconfigPath, kubeContext string) (provider.Provider, error) {
	switch name {
	case "fake":
		return &provider.Fake{}, nil
	case "gcp":
		return gcp.NewDriver(project), nil
	case "aws":
		return aws.NewDriver(region), nil
	case "azure":
		return azure.NewDriver(project), nil
	case "k8s":
		return k8sDriver(kubeconfigPath, kubeContext)
	case "upstash":
		return upstash.NewDriver(), nil
	case "hetzner":
		return hetzner.NewDriver(project), nil
	case "cloudflare":
		return cloudflare.NewDriver(project), nil
	}
	return nil, fmt.Errorf("provider %q has no driver in this binary — refusing rather "+
		"than substituting the fake, which fabricates reality and must be chosen "+
		"deliberately with --provider fake", name)
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
// k8sCapabilityMappings is the k8s driver's service -> capability map, in the shape
// parity.OutsideTheClouds takes (D622).
func k8sCapabilityMappings() map[string]string {
	out := map[string]string{}
	for svc, m := range k8s.NewDriver("http://unused", "").Mappings {
		if m != nil && m.Capability != "" {
			out[svc] = m.Capability
		}
	}
	return out
}

// providerHintFor writes the candidate's provider line for a capability type, naming
// the clouds that actually fulfil it (D622). With no type, or a type nobody fulfils, it
// says so rather than picking one — a scaffold is advice, and advice is a claim (D585).
func providerHintFor(capType string) string {
	if capType == "" {
		return "    provider: \"\"              # aws | gcp | azure | k8s | fake\n"
	}
	caps := parityCaps()
	var able []string
	for _, cloud := range parity.Clouds() {
		if parity.CanFulfil(caps, cloud, capType).State == "fulfilled" {
			able = append(able, cloud)
		}
	}
	if outside := parity.OutsideTheClouds(k8sCapabilityMappings())[capType]; len(outside) > 0 {
		// Fulfilled outside the clouds (k8s). Naming it here is the difference between
		// "groundhold cannot do this" and "not with a cloud driver" (D622).
		able = append(able, "k8s")
	}
	switch len(able) {
	case 0:
		return "    provider: \"\"              # no driver fulfils this type yet — " +
			"see `groundhold parity " + capType + "`\n"
	case 1:
		return fmt.Sprintf("    provider: %-15s # the only driver that fulfils this type\n",
			able[0])
	default:
		return fmt.Sprintf("    provider: %-15s # or %s — `groundhold parity %s`\n",
			able[0], strings.Join(able[1:], ", "), capType)
	}
}

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
	// D622: the list is the union of what the CLOUD drivers know and what is
	// fulfilled outside them. Derived from the cloud maps alone it published 51 of
	// the 57 types the generated matrix carries, and the six it dropped are exactly
	// the ones only k8s fulfils — so the verb was silent about them rather than
	// wrong, which is harder to notice.
	types := parity.CapabilityTypes(caps)
	// The VOCABULARY is the full set of types this project publishes. Derived from
	// the drivers alone the verb listed 51 of 57, and the six it dropped were the
	// ones no cloud driver implements — precisely the answers a reader runs `parity`
	// to get. A type nobody builds is three `unbuilt` rows, which is the truth.
	if voc, verr := vocab.Embedded(); verr == nil {
		for typ := range voc {
			types = append(types, typ)
		}
	}
	for typ := range parity.OutsideTheClouds(k8sCapabilityMappings()) {
		known := false
		for _, t := range types {
			if t == typ {
				known = true
				break
			}
		}
		if !known {
			types = append(types, typ)
		}
	}
	sort.Strings(types)
	types = slices.Compact(types)
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

	outside := parity.OutsideTheClouds(k8sCapabilityMappings())
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
		// D622: the generated matrix has carried `fulfilledOutsideTheClouds` since
		// D502, and this verb — the one the help text sends a reader to — did not,
		// so eight capabilities the k8s driver ships read as three `unbuilt` rows.
		// spec/parity.yaml's own header names that misreading as the reason the
		// marker exists.
		if o := outside[typ]; len(o) > 0 {
			fmt.Printf("  %-6s fulfilled outside the clouds: %s\n", "k8s",
				strings.Join(o, ", "))
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
	case "k8s":
		// D505: observe was the ONE verb the k8s driver could not be reached
		// through. apply, converge, adopt, resume and probe all resolve it; this
		// switch did not, so a capability could be created and retired on a
		// cluster and never read back — the exact gap TestObserveCompleteness
		// forbids INSIDE a driver, present at the CLI seam between them.
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
	led, err := ledger.ReplayExisting(ledgerPath)
	if err != nil {
		return refuseCorruptLedger(err)
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
	// D613: `anchor --check` uses the anchor AS PROOF, which is exactly where D312
	// put this rule — and it was wired into restore and capsule --verify and not
	// here. An anchor that names no ledgerId cannot say which ledger it manifests,
	// so the identity checks that key on it pass vacuously.
	if err := a.RequireIdentity(); err != nil {
		fmt.Fprintf(os.Stderr, "anchor error: %v\n", err)
		return 5
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
		// D679: "did not start" is a claim about a PROCESS, and nothing looked at
		// the process. Measured: with the ledger lock held by another writer, the
		// child was alive and blocked; this printed "run did not start within 5s",
		// exited 1 — and the run later woke up and created the infrastructure. The
		// tool said it had not started; the run then acted.
		//
		// The registry stores a pid and nothing ever read it. Signal 0 is the
		// question "does this process exist", which is exactly what is being
		// asserted, so it is asked before asserting.
		code, msg := detachVerdict(handle, ledgerPath, e, processAlive(e.PID))
		fmt.Fprintln(os.Stderr, msg)
		return code
	}
	return 0
}

// processAlive answers the question the launcher's verdict ASSERTS: does this
// process exist? Signal 0 is exactly that question. Injectable so the verdict can
// be driven both ways without forking anything.
var processAlive = func(pid int) bool {
	return pid > 0 && syscall.Kill(pid, 0) == nil
}

// detachVerdict decides what to say about a detached run that has not reached
// admission within the wait. D679: this used to be one sentence and exit 1 for both
// cases — measured, a child alive and blocked on the ledger lock was declared not
// started, and it woke up 27 seconds later and created the infrastructure.
//
// It is a pure function so the two answers can be tested; the launcher supplies the
// aliveness. A slow start is not a failure and must not exit non-zero, or a caller
// routing on the code tears down a run that is about to do its work.
func detachVerdict(handle, ledgerPath string, e detach.Entry, alive bool) (int, string) {
	if alive {
		return 0, fmt.Sprintf(
			"warning: run %s has not reached admission after 5s and is STILL "+
				"RUNNING (pid %d) — it is most likely waiting for the ledger lock; "+
				"it will proceed on its own. Watch it: groundhold status %s "+
				"--ledger %s --at <t>. Log: %s",
			handle, e.PID, handle, ledgerPath, e.LogPath)
	}
	return 1, fmt.Sprintf(
		"warning: run %s did not start within 5s and its process is gone (pid %d) "+
			"— check the log: %s", handle, e.PID, e.LogPath)
}

// runRuns lists every run in the ledger with its derived state (D231). The
// ledger is the census; order is most-recent-first (never re-sorted by severity —
// that would be a covert ranking). Attention states are glyph-marked and a
// per-state count line lets "what needs me" read at a glance WITHOUT a composite
// health rollup (the four-valued discipline on run state).
// refuseCorruptLedger is the one exit for `runs`, `status` and `wait` when the ledger
// does not read as a ledger. D611: they used to print the error and return 1, while
// every other verb refused the same file with ledger-corrupted (5) — and before that
// they did not notice at all, because the reader accepted any JSON object as an event.
// The spec's rule is "nothing proceeds over corruption"; these verbs' own rule is
// "reporting is not judging", and both hold: a file that is not a ledger is not a run
// that failed.
// attestIntegrityHealthy reports whether every integrity fact `attest` re-checked
// passed (D1020). A nil sub-report (no anchor sidecar / no snapshot) is nothing to
// gate. The anchor is healthy only when it VERIFIED against the live ledger or was
// genuinely ABSENT; a present snapshot must self-verify, bind THIS ledger, and its
// archive still match. Anything else — a diverged/truncated/unreadable/unverifiable
// anchor, a snapshot that does not self-verify or names another ledger, a
// mismatched/missing/misnamed/unreadable archive — is a corrupted off-host witness the
// exit code must not read as all-clear.
func attestIntegrityHealthy(rep *ledger.IntegrityReport) bool {
	if a := rep.Anchor; a != nil && a.Status != "verified" && a.Status != "absent" {
		return false
	}
	if s := rep.Snapshot; s != nil {
		if s.Unreadable || !s.SignatureSelfVerifies || !s.LedgerIdMatches {
			return false
		}
		if st := s.Archive.Status; st != "matched" && st != "not-claimed" {
			return false
		}
	}
	// D1081: the signatures arm of the union D1020 named (chain+anchor+snapshot+
	// archive+SIGNATURES). A tail event whose detached envelope is PRESENT but does not
	// self-verify is tamper evidence (attest.go) — the same corruption class the
	// snapshot-signature check above already gates on, and pure self-consistency (no
	// trust policy). It was reported in a field and exited 0; a cron reading exit 0
	// over an invalidated signature downgrades signed evidence to unsigned in silence.
	// Unsigned (D102) and self-verified events do not increment this, so a legitimately
	// unsigned or fully-signed ledger stays healthy.
	if rep.Signatures.EnvelopePresentButInvalid > 0 {
		return false
	}
	return true
}

func refuseCorruptLedger(err error) int {
	// D617: a path that is WRONG and bytes that do not REPLAY are different operator
	// problems. Between them they had four exit codes across sixteen verbs; a caller
	// branching on the status could not tell "fix your path" from "your history is
	// damaged" — and the published remediation for 5 is `groundhold repair`, which
	// used to answer "healthy" for a file that is not there.
	if errors.Is(err, ledger.ErrNoLedger) {
		fmt.Fprintf(os.Stderr, "ledger error: %v\n", err)
		return 1
	}
	bannerState.code = string(perr.LedgerCorrupted)
	fmt.Fprintf(os.Stderr, "ledger error: %v\n", err)
	return 5
}

func runRuns(ledgerPath, at string, jsonMode bool) int {
	evs, incomplete, err := runstatus.ReadEventsFull(ledgerPath)
	if err != nil {
		return refuseCorruptLedger(err)
	}
	// D672: an incomplete history is stated, never implied. A pruned archive is the
	// operator's own decision (spec §10), so this is a note rather than a refusal —
	// but a list that cannot see part of the history must not read as a full one.
	if incomplete != "" {
		fmt.Fprintln(os.Stderr, "note:", incomplete)
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
			if e.Unreadable != "" { // D678
				fmt.Fprintf(os.Stderr, "note: registry pointer %s: %s\n",
					e.Handle, e.Unreadable)
			}
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
	evs, incomplete, err := runstatus.ReadEventsFull(ledgerPath)
	if err != nil {
		return refuseCorruptLedger(err)
	}
	if incomplete != "" { // D672
		fmt.Fprintln(os.Stderr, "note:", incomplete)
	}
	nowClock, _ := ledger.ParseTs(at)
	st := runstatus.DeriveRunStatus(evs, handle, nowClock)
	// D678: `runs` consults the detach registry and `status` did not, so one handle
	// got two answers from two verbs at one instant — `runs` saying
	// `registry-only` with "launched but no ledger events; check its log", and
	// `status` a bare `unknown` with no source and no remediation. The per-run verb
	// was the blind one.
	if st.State == runstatus.StateUnknown {
		if ents, rerr := detach.ListRegistry(ledgerPath); rerr == nil {
			for _, e := range ents {
				if e.Handle != handle {
					continue
				}
				st.Source = "registry-only"
				st.Remediation = "launched but no ledger events — it may have died " +
					"before admission; check its log"
				if e.Unreadable != "" {
					st.Remediation = "the registry pointer for this handle is " +
						"unusable (" + e.Unreadable + ") — check its log directly"
				}
			}
		}
	}
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
		evs, incomplete, err := runstatus.ReadEventsFull(ledgerPath)
		if err != nil {
			return refuseCorruptLedger(err)
		}
		_ = incomplete // D672: wait polls; the note would repeat every tick
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
	// Generate BEFORE opening: a path that already holds a key is refused below with
	// nothing written, and a create that fails leaves no half-file behind.
	pub, priv, err := ed25519.GenerateKey(nil) // nil rand -> crypto/rand
	if err != nil {
		fmt.Fprintf(os.Stderr, "keygen error: %v\n", err)
		return 1
	}
	// O_EXCL makes "create a NEW file, never overwrite" the kernel's ATOMIC guarantee,
	// not a Stat-then-write check with a TOCTOU window a concurrent create could slip a
	// truncate into. A signing key is the root of every signature's trust — losing one
	// to a race is losing the ability to prove any history it signed.
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0o600)
	if err != nil {
		if os.IsExist(err) {
			fmt.Fprintf(os.Stderr, "keygen error: %s already exists — "+
				"refusing to overwrite a signing identity\n", path)
		} else {
			fmt.Fprintf(os.Stderr, "keygen error: %v\n", err)
		}
		return 1
	}
	if _, err := f.WriteString(hex.EncodeToString(priv.Seed()) + "\n"); err != nil {
		f.Close()
		fmt.Fprintf(os.Stderr, "keygen error: %v\n", err)
		return 1
	}
	if err := f.Close(); err != nil {
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
  # HARD means the world must be WITNESSED to satisfy it: an attribute the provider
  # cannot read back is unknown, and unknown BLOCKS. So a hard constraint is only
  # useful where the provider you run against can observe it.
  hard:
    - { id: managed, subject: db, path: service.managed, op: equals, value: true, verify: { method: static } }
  # SOFT is verified and reported, never blocking. Region and public exposure belong
  # under hard on a real cloud — they are soft here because the built-in fake provider,
  # which is what a first run uses, witnesses neither. Move them up when you point this
  # at aws/gcp/azure.
  soft:
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
	// D1063: which attributes the CONTRACT asks about. A candidate ANSWERS a
	// contract; declaring an attribute asserts the implementation has that
	// property, so scaffolding every attribute in the vocabulary manufactures
	// assertions the author never made. The curated example is the proof of the
	// intended shape: its contract constrains one path and its candidate declares
	// exactly that one.
	asked := map[string]map[string]bool{}
	// D1087: where the contract PINS a literal (`op: equals`), the scaffold proposes
	// that literal. Without this the placeholder came from the attribute's KIND, and a
	// bool's kind default is `false` — so a contract requiring `service.managed: true`
	// was answered by a scaffold declaring `false`, and the tool's own two documents
	// refused each other on the reader's first run.
	pinned := map[string]map[string]any{}
	for _, con := range c.Constraints {
		if asked[con.Subject] == nil {
			asked[con.Subject] = map[string]bool{}
			pinned[con.Subject] = map[string]any{}
		}
		asked[con.Subject][con.Path] = true
		if con.Op == "equals" && con.Value != nil {
			pinned[con.Subject][con.Path] = con.Value
		}
	}

	var b strings.Builder
	fmt.Fprintf(&b, "# Candidate scaffold for contract %q — fill in provider, service\n"+
		"# and the attribute values, then ask BOTH questions:\n"+
		"#   groundhold verify <contract> <this>                 — do the documents agree?\n"+
		"#   groundhold preflight <contract> <this> --provider <p> — can it actually be built?\n"+
		"# They answer different things: verify is a document check and can say PROVEN\n"+
		"# about a pair no provider can honour (D622, D1063).\n",
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
		// D622: the scaffold used to write `provider: aws` for every capability,
		// whatever its type — including types this tool's OWN parity verb calls a
		// structural gap on aws. The scaffold's next-step line then sends the reader
		// to `verify`, which is a pure document check and says PROVEN, while `plan`
		// refuses the same pair as impossible. A default that reads as a
		// recommendation must not name a cloud that cannot do the job.
		b.WriteString(providerHintFor(capType))
		b.WriteString("    service: \"\"             # the provider's service token\n")
		voc, ok := vocabs[capType]
		if !ok || len(voc.Attributes) == 0 {
			b.WriteString("    attributes: {}          # no vocabulary attributes for this type\n")
			continue
		}
		// D1063: the attributes the contract asks about are LIVE; the rest of the
		// vocabulary is offered COMMENTED OUT, so the reader still sees the whole
		// palette (that is the scaffold's teaching value) without the document
		// asserting properties nobody chose. The walk that found this: the dumped
		// form wrote `service.managed: false` — the kind default for a bool, and
		// the one value no managed service can honour — one line under a
		// `provider: aws` the scaffold itself recommends, so `converge` applied
		// once and then REFUSED every later pass. Same argument as the D622
		// comment above, applied to the values rather than the provider: a
		// placeholder that reads as a declaration must not assert what the
		// recommended cloud cannot do.
		live, offered := 0, 0
		for _, path := range sortedKeys(voc.Attributes) {
			if asked[capID][path] {
				live++
			} else {
				offered++
			}
		}
		if live == 0 {
			b.WriteString("    attributes: {}          # the contract constrains none of this type's attributes\n")
		} else {
			b.WriteString("    attributes:\n")
		}
		for _, path := range sortedKeys(voc.Attributes) {
			attr := voc.Attributes[path]
			kind, _ := attr["kind"].(string)
			desc, _ := attr["description"].(string)
			desc = strings.TrimSpace(strings.SplitN(desc, "\n", 2)[0])
			if len(desc) > 60 {
				desc = desc[:60] + "…"
			}
			prefix := "      "
			if !asked[capID][path] {
				prefix = "      # " // offered, not asserted
			}
			value := sampleForAttr(attr, kind)
			if v, ok := pinned[capID][path]; ok {
				value = pinnedLiteral(v, kind)
			}
			fmt.Fprintf(&b, "%s%s: %s  # %s%s\n",
				prefix, path, value, kind, descSuffix(desc))
		}
		if offered > 0 {
			fmt.Fprintf(&b, "      # ^ %d more attribute(s) this type supports, commented out: the\n"+
				"      #   contract does not ask about them. Uncomment one only to ASSERT it.\n", offered)
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

// pinnedLiteral renders a value the CONTRACT already fixed, so the scaffold answers
// the question instead of guessing at it. Strings are quoted; everything else is
// printed as the contract stated it (bools, numbers, durations already carry their
// own syntax). A value the contract pinned is not a placeholder and is deliberately
// not left blank — the reader has nothing to decide about it.
func pinnedLiteral(v any, kind string) string {
	if kind == "string" || kind == "money" || kind == "protocol" {
		return fmt.Sprintf("%q", fmt.Sprintf("%v", v))
	}
	return fmt.Sprintf("%v", v)
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
	fmt.Fprintf(w, "# %d already enforced. Advisory only — never gates; paste what you want to adopt.\n",
		res.AlreadyEnforced)
	// D594: "never gates" is true of the SUGGESTION and misleading about the PASTE.
	// A hard constraint over an attribute the candidate does not declare verifies
	// UNKNOWN, and unknown blocks — measured: a PROVEN contract went to BLOCKED the
	// moment these three were pasted. Say the cost where the paste happens, not one
	// verb later where it reads as a failure. Only in hard mode: the caveat cannot
	// apply in soft, and a caveat where it cannot apply is noise (D537).
	if asMode == "hard" {
		fmt.Fprintln(w, "# NOTE: a hard constraint whose attribute the candidate does not declare")
		fmt.Fprintln(w, "# verifies UNKNOWN, and unknown blocks. Declare it in the candidate too, or")
		fmt.Fprintln(w, "# take these with `--as soft` to adopt the intent without blocking.")
	}
	fmt.Fprintln(w)
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
// warnPlaintextSecrets reports values whose SHAPE says they should not be in a
// stored document (D364). It is a WARNING, never a refusal: groundhold records
// what it is told to record, and a heuristic must not block a run it cannot prove
// anything about. What it must do is say what the operator can do instead — the
// reporter's point was that "this is dangerous" alone leaves you where you were.
//
// Silenced with --allow-plaintext-secret, because a warning nobody can turn off
// is a warning everybody learns to ignore.
func warnPlaintextSecrets(w io.Writer, cand *contract.Candidate, allowed bool) {
	if allowed {
		return
	}
	findings := contract.ScanForPlaintextSecrets(cand)
	if len(findings) == 0 {
		return
	}
	for _, f := range findings {
		fmt.Fprintf(w, "WARNING  %s\n", f.Pointer)
		fmt.Fprintf(w, "  looks like %s. groundhold will apply and PERSIST this value in the\n", f.Kind)
		fmt.Fprintf(w, "  ledger verbatim — the ledger then holds material as sensitive as this value.\n")
		fmt.Fprintf(w, "  Instead: %s.\n", f.Advice)
	}
	fmt.Fprintf(w, "  Deliberate? re-run with --allow-plaintext-secret to silence this.\n")
}

// contractPath: the document the reader just passed. D693 — the hint used to name
// a bare `groundhold suggest`, which exits 1 with a usage line: the verb takes the
// contract positionally. Advice printed at the moment a reader is most likely to
// follow it must be the command they can paste, and this caller already knows it.
func renderSuggestHint(w io.Writer, c *contract.Contract, vocabs map[string]vocab.Vocabulary, cand *contract.Candidate, contractPath string) {
	res := suggest.Compute(c, vocabs, cand)
	if len(res.Suggestions) == 0 {
		return
	}
	if contractPath == "" {
		contractPath = "<contract.yaml>"
	}
	fmt.Fprintf(w, "%d hardening suggestion(s) — run `groundhold suggest %s`\n",
		len(res.Suggestions), contractPath)
}

// renderNoOp surfaces the compiled plan's converged no-op capabilities on stderr
// (the prose channel, D90) — one honest line each naming WHY a bound capability
// produced no action (Part B). Silent when there are none; the hashed plan on
// stdout already carries them in `plan.noop`.
func renderNoOp(w io.Writer, doc *compiler.Document) {
	if doc == nil {
		return
	}
	// D531, from the field: this printed the no-ops and nothing else, so a plan
	// that CREATED a resource summarised as twenty-one lines of "nothing to do".
	// A bound, converged capability is harmless by definition; an unbound one is a
	// new resource, a new cost and a new surface — and only the second was
	// missing. Attention was distributed inversely to risk.
	//
	// The actions lead, and the no-ops follow as the answer to "why was nothing
	// done to the rest". A plan with no actions prints exactly what it printed
	// before: inventing a line for the steady state would be noise on the path
	// every deployment runs.
	if len(doc.Plan.Actions) > 0 {
		byOp := map[string][]string{}
		var ops []string
		for _, a := range doc.Plan.Actions {
			if _, seen := byOp[a.Operation]; !seen {
				ops = append(ops, a.Operation)
			}
			byOp[a.Operation] = append(byOp[a.Operation], a.Capability)
		}
		sort.Strings(ops)
		for _, op := range ops {
			caps := byOp[op]
			sort.Strings(caps)
			fmt.Fprintf(w, "%s: %d capability(ies) — %s\n",
				strings.ToUpper(op), len(caps), strings.Join(caps, ", "))
		}
	}
	for _, n := range doc.Plan.NoOp {
		fmt.Fprintf(w, "%s: no-op (%s)\n", n.Capability, n.Reason)
	}
}

// anyMappingCanAuthor reports whether any `<provider>.<service>` key in an
// attribute's mappings names a driver service that can AUTHOR its capability
// (D687). A mapping to a discovery-only driver — or to a provider with no driver at
// all — documents where the concept comes from, not that a candidate can carry it.
func anyMappingCanAuthor(maps map[string]any) bool {
	// `provider.CanAuthor` answers a narrower question — is this service WITNESS-only
	// within a driver that has one — and defaults to true for a provider it has never
	// heard of. `cloudflare` is such a provider: its driver is read-only discovery and
	// has no create path at all, so CanAuthor said yes and this said "authorable".
	// The provider must be one whose driver AUTHORS, and the service must not be a
	// witness within it.
	authoring := map[string]bool{"aws": true, "gcp": true, "azure": true, "k8s": true}
	for k := range maps {
		prov, svc, ok := strings.Cut(k, ".")
		if !ok {
			continue
		}
		if authoring[prov] && provider.CanAuthor(prov, svc) {
			return true
		}
	}
	return false
}

// servingServices returns the "<provider>.<service>" tokens whose driver claims to
// realise this capability type, asked of the drivers themselves (D691). Empty means
// nothing ships that can build it.
func servingServices(capType string) []string {
	var out []string
	for prov, m := range map[string]map[string]string{
		"aws":   aws.NewDriver("eu-central-1").ServiceCapabilities(),
		"gcp":   gcp.NewDriver("p").ServiceCapabilities(),
		"azure": azure.NewDriver("00000000-0000-0000-0000-000000000001").ServiceCapabilities(),
		"k8s":   k8s.NewDriver("https://example.invalid", "t").ServiceCapabilities(),
	} {
		for svc, ct := range m {
			if ct == capType && provider.CanAuthor(prov, svc) {
				out = append(out, prov+"."+svc)
			}
		}
	}
	sort.Strings(out)
	return out
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
	// D623: markers (per-capability verdicts, compiler advisories) are nouns the
	// runtime emits too, and `explain` is published as the single place to ask.
	if ex, ok := perr.Markers[perr.Code(term)]; ok {
		if jsonMode {
			out, _ := json.MarshalIndent(perr.RegistryEntry{
				Code: term, Summary: ex.Summary, Remediation: ex.Remediation}, "", "  ")
			fmt.Println(string(out))
			return 0
		}
		fmt.Printf("%s — a marker the runtime emits (not a process exit code)\n", term)
		fmt.Printf("  %s\n  next: %s\n", ex.Summary, ex.Remediation)
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
		// D691: three capability types are declared and served by no driver at all —
		// capability.ai.speech, capability.identity.sso and
		// capability.identity.oauth-client (which carries no `mappings:` anywhere).
		// A contract can declare one and nothing can ever implement it: `verify`
		// reports it unimplemented and `plan` blocks, so the author learns at the
		// bottom of the ladder what the top could have said. `parity` knows — it
		// prints `unbuilt` for exactly these — and `explain`, the rung an author
		// reads BEFORE writing, did not.
		if svcs := servingServices(term); len(svcs) == 0 {
			fmt.Printf("  UNBUILT: no shipped driver realises this capability — a "+
				"contract declaring it cannot be implemented by any candidate "+
				"(groundhold parity %s reports the same, per cloud)\n", term)
		}
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
		// D701: `note:` carried the sharpest prose in the vocabulary — what STATIC
		// verification proves versus what an outcome probe proves — on twelve
		// attributes, and no reader ever saw a word of it. The key loaded and nothing
		// consumed it, which is indistinguishable, to its author, from working.
		if n, _ := attrs["note"].(string); strings.TrimSpace(n) != "" {
			fmt.Printf("  note: %s\n", strings.TrimSpace(n))
		}
		if maps, ok := attrs["mappings"].(map[string]any); ok {
			for _, k := range sortedKeys(maps) {
				fmt.Printf("  %s: %s\n", k,
					strings.TrimSpace(fmt.Sprintf("%v", maps[k])))
			}
			// D687: a mapping names a provider, and a reader takes that as support.
			// `dns.proxied` lists exactly one — `cloudflare.dnsrecord` — and the
			// cloudflare driver is read-only discovery, so no candidate can ever
			// carry the attribute and a contract requiring it cannot be satisfied.
			// The vocabulary says as much in a COMMENT; `explain` printed the
			// mapping and not the comment.
			if !anyMappingCanAuthor(maps) {
				fmt.Printf("  NOT AUTHORABLE: no driver that can CREATE this " +
					"capability implements this attribute — a contract requiring " +
					"it cannot be satisfied by any candidate, and the drivers " +
					"refuse it rather than defaulting\n")
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
	// D620: a usage error must not become a VERDICT. `--applied yeees` and a missing
	// `--applied` both silently produced false, and false is a fact about the world:
	// with no flags at all the verb announced "converge did not stand up the
	// known-good edge — a groundhold-regression", exit 20, from inputs nobody
	// supplied. Two daily canaries consume that code, so a broken invocation reported
	// a regression that had not happened. The unknown-flag refusal (D567) states the
	// rule this broke, in its own message: a run that drops an input answers a
	// question you did not ask.
	seen := map[string]bool{}
	parseBool := func(flag, v string) (bool, bool) {
		switch v {
		case "true", "1", "yes":
			return true, true
		case "false", "0", "no":
			return false, true
		}
		fmt.Fprintf(os.Stderr, "apireq classify: %s must be true or false, got %q — "+
			"refusing rather than reading it as false, which is a claim about the "+
			"edge and not about your command line\n", flag, v)
		return false, false
	}
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--applied":
			if i+1 < len(args) {
				v, ok := parseBool("--applied", args[i+1])
				if !ok {
					return 30 // fail SAFE as a flake, never a false verdict
				}
				o.Applied = v
				seen["--applied"] = true
				i++
			}
		case "--deployed":
			if i+1 < len(args) {
				v, ok := parseBool("--deployed", args[i+1])
				if !ok {
					return 30
				}
				o.Deployed = v
				seen["--deployed"] = true
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
	// D620: the two facts the truth table turns on must have been SUPPLIED. Absent,
	// they defaulted to false — which reads as "converge did not stand up the edge"
	// and is a verdict about infrastructure, not about a missing argument. A
	// transport failure is its own input and needs no pair.
	if !o.Transport {
		for _, need := range []string{"--applied", "--deployed"} {
			if !seen[need] {
				fmt.Fprintf(os.Stderr, "apireq classify: %s was not given. Its absence "+
					"used to read as false, which is a claim about the edge; the "+
					"canaries branch on the exit code, so a missing input became a "+
					"reported regression.\n", need)
				return 30 // a flake: nothing was measured
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

// firstPositional names the verb for an error message, or "help" before one is seen.
// verbPrivateFlags lists, per verb, the flags parsed by that verb's OWN sub-parser
// rather than by the global switch. Anything here is passed through as a positional
// for that verb only; every other verb still refuses it (D567). Keep it exact: a flag
// listed but not read would be silently swallowed, which is the failure D567 fixed.
var verbPrivateFlags = map[string][]string{
	"apireq": {"--applied", "--deployed", "--transport", "--http-status"},
}

func verbOwnsFlag(verb, flag string) bool {
	for _, f := range verbPrivateFlags[verb] {
		if f == flag {
			return true
		}
	}
	return false
}

// docKind reads apiVersion/kind out of a document without committing to its schema —
// enough to refuse the wrong KIND of file with a message about that file (D615).
func docKind(raw []byte) (string, string) {
	var head struct {
		APIVersion string `json:"apiVersion"`
		Kind       string `json:"kind"`
	}
	_ = json.Unmarshal(raw, &head)
	return head.Kind, head.APIVersion
}

// intFlag renders a numeric flag back onto a child's argv, empty when unset (D638).
func intFlag(v int) string {
	if v == 0 {
		return ""
	}
	return strconv.Itoa(v)
}

// oneKey renders an injection-key set back onto a child's argv (D638). The sets are
// built from repeatable flags; converge forwards each key it was given.
func oneKey(m map[string]bool) string {
	for k := range m {
		return k
	}
	return ""
}

func firstPositional(pos []string) string {
	if len(pos) > 0 {
		return pos[0]
	}
	return "help"
}

// sayNotes renders a result's notes to the HUMAN channel (stderr, never stdout:
// the result document stays machine-clean). D573: this was inline in the adopt
// branch, so `unadopt` computed a note about the ownership marker it leaves behind
// and printed it nowhere — while D322's own comment says notes go here because
// "JSON alone would bury it". One renderer, so a verb that starts producing notes
// cannot bury them by omission.
func sayNotes(notes []string) {
	for _, n := range notes {
		fmt.Fprintf(os.Stderr, "note: %s\n", n)
	}
}
