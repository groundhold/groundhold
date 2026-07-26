# Presentation: the state vocabulary (D89)

How Groundhold's states are RENDERED for humans — CLI output and any
downstream console. This layer sits strictly downstream of semantics:
verdicts, exit codes and machine codes (spec/errors.md) are the truth;
this spec only defines how they look. Machine consumers keep routing
on exit codes and `code` fields; nothing defined here is parseable by
contract.

## The prime rule

The presentation layer must never collapse the four-valued verdict
model back to a binary. Concretely:

- `unknown` and `unverifiable` never render in the success color or
  the failure color. They are the absence of knowledge, not a verdict.
- A refusal (exit 2) never renders as a failure. The gate holding is
  the system working; if refusal looks like an error, operators learn
  to resent and bypass the gate.
- Meaning must survive with color stripped (CI logs, pipes, NO_COLOR,
  color-blind operators): SHAPE carries the meaning, color only
  reinforces it.

## Banner vocabulary

Every verb ends its human output with exactly one banner word from
this closed set, always in the same position (last line block).
Registry rules mirror spec/errors.md: additive-only; a published word
never changes meaning; a misleading word is superseded, not redefined.

| banner | color | source | action hint |
|---|---|---|---|
| `PROVEN` | green | verify: executable — every hard constraint satisfied under accepted evidence | — |
| `CONVERGED` | green | converge: fixed point proven (including `nothing-to-change`) — ONLY when the convergence check verified (D136) | — |
| `APPLIED` | green | apply; converge whose convergence check was inconclusive/unverified (D136) | re-observe, converge again |
| `VIOLATED` | red | verdict rollup contains `violated` on a hard constraint | fix the world or the contract |
| `INVALID` | red | exit 1 (`structural-error`) | fix the input document |
| `BLOCKED` | yellow | hard constraint `unknown` / `unverifiable`, nothing violated | collect evidence: `probe`, `observe` |
| `STALE` | yellow | exit 3 (`stale-decision`, `lease-conflict`, ...) | refresh knowledge, re-plan |
| `REFUSED <code>` | blue | exit 2, any code not claimed above | per the machine code |
| `DIED` | red | exit 4 | `groundhold resume` |
| `CORRUPTED` | red inverse | exit 5 | `groundhold repair`; nothing proceeds over corruption |
| `SEALED` | green | plan: a hash-pinned Sealed Plan exists and is executable | `apply` it |
| `OK` | green | a procedural verb completed (publish, adopt, unadopt, resume, repair, anchor) — the record says what | — |

`SEALED` and `OK` used to live only in the per-verb table below, while this
one already called itself "this closed set" (D329). A registry that is
complete only if you read a later section is not a registry — the console
implements against THIS table from another repository. Which verb earns
which green word still belongs below; the closed set is here, whole.

`PROVEN` vs `CONVERGED` is a deliberate epistemic distinction, not a
synonym pair: PROVEN says every hard constraint is satisfied under
accepted evidence (verify's claim); CONVERGED says a reconciliation
reached its proven fixed point (converge's claim). Neither word is
ever used for the other verb's success.

### Green words per verb (D90)

A green banner appears only where success is a crisp human-facing
claim; the green vocabulary stays smaller than the failure vocabulary,
or success banners become a second API:

| verbs | green word | the claim |
|---|---|---|
| `verify`, `audit` | `PROVEN` | hard constraints satisfied under accepted evidence |
| `converge` | `CONVERGED` | reconciliation reached its proven fixed point — the check verified it (D136); an inconclusive or unverified check earns `APPLIED`, true and exactly as much as was checked |
| `apply` | `APPLIED` | the sealed plan's mutations committed |
| `plan` | `SEALED` | a hash-pinned Sealed Plan exists and is executable |
| `publish`, `adopt`, `unadopt`, `resume`, `repair`, `anchor` | `OK` | the procedural verb completed; the record says what |
| `validate`, `hash`, `explain`, `export`, `hints`, `scenario`, `discover`, `forecast`, `deposed`, `observe`, `probe` | — silent | see below |

Product verbs print NO green banner: their stdout is the deliverable
and `OK` is noise that reads as part of the product. Two of them are
silent for a sharper reason: a green word after `probe` or `observe`
would claim the world is HEALTHY, when the verb only claims the
measurement was recorded — the verdict belongs to `verify`/`audit`.
Success silence beats generic reassurance. Failure banners (INVALID,
STALE, DIED, CORRUPTED, REFUSED, and VIOLATED/BLOCKED where the verb
has verdicts) apply to every verb, product or not.

### The channel rule (D90)

- A verb whose stdout is the human surface (text-mode `verify`,
  `converge`) renders the banner as the LAST stdout line.
- A verb whose stdout is machine output (JSON, ndjson) or a product
  (hash, plan document, export stream) emits the banner on stderr —
  the prose channel, already documented as unparseable. One final
  line, never interleaved into stream progress.
- Machines still route on exit codes and `code` fields only. A zero
  exit with a banner on stderr is normal, not a warning.

### Banner selection is (exit, code, rollup) — with precedence

Exit codes alone cannot pick the banner: verify with a violation and
verify with an unknown both exit 2 with `code: not-executable`. The
verdict rollup refines the code. Precedence, first match wins:

1. exit 5 → `CORRUPTED`
2. exit 4 → `DIED`
3. exit 3 → `STALE`
4. exit 1 → `INVALID`
5. rollup has `violated` on a hard constraint → `VIOLATED`
   (a proven falsehood outranks missing knowledge)
6. rollup has `unknown`/`unverifiable` on a hard constraint → `BLOCKED`
7. exit 2 → `REFUSED <code>` (the machine code rendered adjacent —
   exit 2 is heterogeneous and the one word must not hide which gate
   held: `REFUSED consent-required` ≠ `REFUSED unsupported-operation`)
8. success → `PROVEN` or `CONVERGED` per the verb

### The banner is never alone

A non-green banner always names its culprit on the same line block:

```
BLOCKED: c-rto unknown — recovery.rto requires probe verification
```

Never the bare word. `BLOCKED` without a culprit reads as procedural
state (a queue, a lock); the culprit row makes it semantic.

## Constraint rows

One glyph per verdict, shape-first. Pinned, including the ASCII
fallback set (used when the terminal cannot render the glyph, or under
`--ascii`):

| verdict | glyph | ascii | color | meaning of the shape |
|---|---|---|---|---|
| satisfied | `✓` | `OK` | green | proven true |
| violated | `✗` | `X` | red | proven false |
| unknown | `?` | `?` | yellow | not known yet — go look (probe/observe) |
| unverifiable | `∅` | `NA` | magenta | not knowable this way — change the contract or the method |

`?` and `∅` are distinct because their next actions are distinct:
unknown is fixed by gathering evidence, unverifiable only by changing
the question. `NA` (not `-`) is the pinned ASCII fallback: `-` reads
as skipped/neutral/absent.

Objectives (soft constraints) keep their verdict glyph and carry the
existing "(scored, not gated)" suffix; they never influence the banner.

## Provenance renders as brightness, not color

Color says WHAT we know; brightness says HOW FIRMLY. A verdict resting
on `inferred`/`assumed` values keeps its glyph and color but renders
dim, with the existing `[inferred]`/`[assumed]` marker retained (the
marker is the NO_COLOR carrier). Green-but-dim is precisely the
message: satisfied, standing on sand.

## Color discipline

- Palette is closed: green, red, yellow, blue, magenta, dim, inverse.
  Nothing else, no shades.
- Color only on a TTY; honor `NO_COLOR`; `--color=auto|never|always`
  with auto the default.
- Every rendering must remain unambiguous in monochrome — guaranteed
  by shape-first glyphs and the banner words, never by color alone.

## Teaching in passing

The vocabulary (`spec/vocab/`) already carries a human description and
a verification note for every path. The presentation layer joins to it
at the moment of friction — and only then:

- Rows in a friction state (`violated`, `unknown`, `unverifiable`, or
  any row named by a blocking reason / refusal) append one indented
  line from the vocabulary:

  ```
  ? c-rto   unknown   recovery.rto lte '30m': requires probe verification
                      recovery.rto — time to restore service after failure;
                      a value here is a claim until a restore test measures it
  ```

- Satisfied rows stay terse. Never explain the happy path: the reader
  is not reading, and the noise teaches them to skim.
- The banner's culprit gets the same join (see above).
- `explain` extends from error codes (D64) to vocabulary terms:
  `groundhold explain recovery.rto` prints the vocab entry — kind,
  description, verification note, per-provider mapping notes. Every
  noun the system emits has one obvious place to ask about it.
- Consoles surface the same descriptions (tooltips, detail panes) from
  the same files. The vocabulary is the single glossary; there is no
  second source to drift.

Constraint ids (`c-rto`) are author-chosen and opaque; the system
teaches PATHS, not ids. No mechanism can rescue `c-x17` — and none
tries.

## Freshness

"Converged" is always "converged as of T". Human renderings of
convergence or audit status carry the age of the newest evidence they
rest on ("converged — proof from 2026-07-14T09:12Z"). Consoles MUST
show the age; a green badge with no age claims an eternal truth the
ledger does not contain.

## Normative status

Normative for any human-facing renderer (the CLI, the console): the
banner words and their selection precedence, the glyph set and ASCII
fallbacks, the prime rule, the friction-only vocabulary join. The
exact prose around them stays free. The machine interface is
unchanged and remains exit codes + JSON `code` fields; banners and
glyphs MUST NOT be parsed for control flow.

## Converge phase checklist (D232)

`converge` renders a live PHASE CHECKLIST on stderr — the loop's roadmap with
per-phase marks. It pre-lists the full canonical loop (verify, plan, observe
(refresh), forecast, confirm, apply, observe (evidence), convergence-check); every
row reaches exactly one terminal state before the region freezes. Closed
phase-state glyph set (shape-first, ASCII fallback):

| state | glyph | ASCII | meaning |
|---|---|---|---|
| pending | `·` | `.` | unknown — listed, not yet reached (never "will run") |
| active | `~` | `~` | running now (the only motion state) |
| done | `✓` | `OK` | the sub-step ran and its exit code said proceed |
| refused | `⊘` | `REF` | the sub-verb refused — did its job (refusal-is-not-failure) |
| failed | `✗` | `X` | an unexpected failure (crash / bad exit) |
| skipped | `»` | `SKIP` | did not run — carries a mandatory why |

`refused` is deliberately distinct from `failed`. `done` carries NO verdict — a
fully-done checklist is not a converged claim. The banner is the sole carrier of
the loop verdict (converged/refused/failed); the checklist freezes into
subordinate scrollback before the banner is emitted, once, last. Conditional
phases resolve to `skipped(why)`; an early exit resolves the remaining rows to
`skipped(loop ended: <phase> refused)` — never dangling `pending`, never `failed`.
The two observe phases are two rows named by role; the ledger phase name stays
`observe` for both.
