# CLI reference

Every verb the binary accepts, grouped below. `groundhold --help` prints the same
set with full flags and is the authority; this page is the same set with what each
verb is FOR. A gate holds the two lists equal, because a reference that quietly omits
a verb is how a capability stops existing for its reader. Exit codes: `0` ok · `1` structural error · `2` refused ·
`3` stale/lease conflict · `4` failed mid-flight · `5` corrupted
ledger. JSON refusals carry a machine `code`
([registry](errors.md)); `--explain` attaches remediation. Human
output ends with a one-word state banner and shape-first glyphs —
see [Reading the output](presentation.md); `--color auto|never|always`
and `--ascii` control rendering, and none of it is a machine
interface.

## Authoring and verification

| verb | what it does |
|---|---|
| `validate <contract>` | structural check of a contract |
| `verify <contract> <candidate>` | four-valued verdicts; exit 2 when not executable |
| `hash <document>` | canonical identity of any document |
| `explain <noun>` | one place to ask about any noun the system emits — an error code, a vocabulary path, or a capability type; a type lists its attributes (kind, enum) — the discovery ladder |
| `example contract` · `example candidate <contract.yaml>` | print a valid starter document; the candidate form scaffolds one entry per capability with its vocab attributes |
| `suggest <contract> [<candidate>]` | advisory hardening: recommended-but-absent constraints as ready-to-paste snippets, cited by control ID (FSBP/CIS/GDPR); never gates (D203) |
| `compose <base> [overlay ...]` | merge a base contract with per-environment overlays into ONE flat contract — dev/staging/prod DRY without inheritance (D199) |
| `diff <a> <b>` | constraint/capability delta + whether a's invariants are a subset of b's — the dev ⊆ staging ⊆ prod promotion proof (D199) |
| `survey <contract> --survey <s.json> ...` | code-survey coverage vs the contract; uncovered required deps are drift (`survey-drift`); orphans harden only under `--complete` |

## Deciding and executing

| verb | what it does |
|---|---|
| `plan` | compile a Sealed Plan; refuses non-executable input, staleness, missing consent |
| `forecast <plan> <candidate>` | predicted effects + attribute predictions vs observations |
| `apply <contract> <candidate> <plan>` | execute under lease; write-ahead receipts |
| `converge <contract> <candidate>` | the porcelain: whole loop, confirm gates, converged-is-success |
| `cost <plan> <candidate>` | cost.monthly rollup over week/month/year for a plan; reporting currency `--currency` (default EUR), foreign currencies shown uncoerced — never FX (D202) |
| `preflight` | every capability's missing implementation operands and unsatisfiable attributes in ONE read-only pass, before anything mutates; exit 2 if any |
| `status <handle>` | a background run's state from the ledger — reporting is not judging, so it exits 0 either way |
| `wait <handle>` | block until a run is terminal, then relay its exit code; `--notify-url`/`--notify-cmd` for hooks |
| `runs` | every run in the ledger with its derived state, most-recent-first; counts per state, no health rollup |

## Knowing the world

| verb | what it does |
|---|---|
| `observe` | read bound resources; record derivation-tagged observations |
| `probe` | outcome measurements (restore test, connection attempt); never implicit; intrusive needs double consent |
| `audit <contract>` | judge RECORDED reality; `violation.detected/resolved` on transitions; exit 2 on violations |
| `parity [capability.type]` | cross-cloud capability matrix: for each cloud, does it FULFIL a capability, STRUCTURALLY cannot (gap), or lack a driver (unbuilt) |
| `export` | fold the ledger to ndjson/CloudEvents; hash-as-id; operator owns cursor |
| `posture` | proactive classifier: `managed-ok`/`drifted`/`shadow`/`decayed`/`unknown`, each with the remediation it implies |
| `horizon` | posture's future tense: WHEN a verdict changes as evidence and leases expire, and what to run before each deadline |
| `refresh` | gentle sweep: re-observe bound resources whose proof is stale or decaying inside `--window` |
| `crawl` | gentle read-only context crawl over the paired providers, under a budget |
| `react` | event-driven ingress: map one cloud change to a scope, re-list it, reclassify — the opt-in real-time path over polling |
| `apiver` | the API-version pin each driver targets; `--live` surfaces drift verdicts, never follows them |
| `apireq` | the known provider API-requirement registry the functional canary iterates as data |

## Brownfield and recovery

| verb | what it does |
|---|---|
| `discover` | enumerate existing resources (read-only) |
| `hints <state-file>` | terraform/pulumi state → adoption hints (never a contract) |
| `adopt` / `unadopt` | bind existing resources (must not lie) / release the binding, never the resource |
| `publish <contract>` | record contract authorship: append contract.published with the hash + a named human actor (D74) |
| `resume <contract>` | conclude pending receipts read-only; never guesses (creates, updates, deletes — D72) |
| `deposed` | orphans of failed replacements; `plan --deposed` compiles their pinned deletes (D71) |
| `repair` | diagnose a corrupt ledger (read-only); `--quarantine --fingerprint <fp>` cuts to the valid prefix under two-step consent (D69) |
| `anchor` | emit the tail anchor for external storage; `--check` verifies the ledger still extends it (D70) |
| `keygen <keyfile>` | mint an ed25519 signing seed (0600, refuses overwrite); prints the public key for verifiers (D102) |
| `backup` | bundle the anchor, one capsule per capability and the pinned contract blobs into one directory |
| `restore` | rebuild a ledger from a verified capsule set plus its off-host anchor; refuses a set that does not hold |
| `snapshot` | compact: replay-verify, write the snapshot, ARCHIVE the old file (never deleted), start fresh |
| `certify-capsule` | witness-side self-cert and import check: structure and signatures PLUS the honesty shape |
| `capsule <capability>` | emit a self-contained evidence capsule: the capability's event subchain verbatim + tip hash (D103) |
| `capsule --verify <f>` | verify a capsule standalone — no ledger needed; `--trust` checks authorship, `--check` pins it against an anchor |
| `attest <--ledger f>` | deterministic integrity/provenance report (D139): identity, compaction, signature self-verification counts, anchor position — facts of PRESENCE and math, never a trust verdict; the console projects it |

## Integration

| verb | what it does |
|---|---|
| `mcp` | MCP server over stdio; apply exists only under `GROUNDHOLD_MCP_ALLOW_APPLY=1`, two-step with single-use token |
| `scenario <file>` | deterministic concurrency scenarios (conformance) |
| `pair` / `unpair` | register or drop a credential REFERENCE for the gentle crawler — references only, never secrets |
| `connections` | list the pairings, references only |
| `version` | which build this is (also `--version`, `-v`) |

Cross-cutting flags: `--sign-key <keyfile>` signs every event the
process appends (detached ed25519, D102); `--trust <hex-pub>`
(repeatable — rotation is receiver policy, trust both keys during the
overlap, D133) makes every ledger-reading verb require a signature by
any trusted key on every event; `--trust-from <event-hash>` pins where
signing became mandatory for pre-signing history. Unsigned or foreign
lines refuse like a broken chain. Signing is opt-in; unsigned history
stays valid forever.

Full flag listing: `groundhold --help` (the usage text is the authority).
