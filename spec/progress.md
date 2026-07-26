# Progress stream (D227)

Honest liveness for the execution loop. `apply`/`converge` run a sealed DAG of
N actions, some long provider LROs. This spec defines the **ephemeral progress
stream** that reports position and per-action state during the wait — and the
closed vocabulary that keeps it from ever lying.

Governing rule: **progress is a projection of the executor's action state
machine, never a second source of truth.** The durable truth is the ledger
(receipts, D42/D57); the stream carries only what is missing from it —
liveness — and is free to be absent without changing apply semantics.

## Channel

- The stream is versioned NDJSON, `stream: "groundhold/progress/v1"`, emitted
  in-process to **stderr**. Stdout stays the machine result (unchanged in every
  progress mode).
- It is **not** in the sealed plan, **not** in the plan hash, **not** a ledger
  event. It carries no durable fact — the ledger's receipts are the durable
  record (a durable WALL-duration source for ETA is a separate store, see the
  boundary section).
- `--progress=<mode>`: `auto` (default; `tty` when stderr is a terminal, else
  `none` — CI/pipes stay clean, clig.dev's christmas-tree rule), `tty` (sticky
  region), `plain` (transition + tick lines, no ANSI), `ndjson` (pure machine
  stream; the human banner is suppressed so the channel stays parseable), `none`.

## Event shape

Per-action **deltas** keyed by `actionId`; a consumer folds them by key into a
snapshot. The run opens with a `run-start` manifest (the whole world for a
consumer attaching at t=0); a consumer attaching late reads the ledger instead.

```
ProgressEvent {
  stream:   "groundhold/progress/v1"
  seq:      uint64        // monotonic per run; a gap means lost events, resync from the ledger
  kind:     run-start | transition | tick | run-end | banner
  runId:    string        // planHash + attempt ordinal (resume increments the attempt)
  planHash: string

  manifest?: { totalActions, actions:[{actionId, index, operation, capability, target, dependsOn}] }  // run-start only

  actionId?: string       // transition / tick
  state?:    ActionState  // closed enum below
  prev?:     ActionState  // transitions only; the edge MUST be in the pinned table
  k:         int          // count of TERMINAL actions; moves ONLY on transitions
  n:         int

  startedAt?: string      // coordination clock (D56) — same source as receipts
  elapsedMs:  int64       // monotonic runtime clock; a DURATION, never a freshness claim

  providerPercent?: number   // present ONLY if the provider literally supplied it (basis: declared)
  providerPhase?:   string   // provider's own phase, verbatim (e.g. Cloud SQL "CREATING")
  retryAfterMs?:    int64

  eta?: ETABand           // nil unless receipt history justifies it (below)

  outcome?: satisfied|violated|unknown|unverifiable  // terminal transitions only — the ACTION claim, not contract constraints
  skipWhy?: cached | dep-failed
  reason?:  string        // blocked/stalled: what exactly, incl. age of last evidence
  code?:    string        // spec/errors.md code on failed/indeterminate
}
```

**Two kinds, two honesty contracts.** A `transition` = the state machine moved;
it is the ONLY kind that advances `k`, changes `state`, or moves an indicator.
A `tick` = liveness heartbeat carrying `elapsedMs` and (if the provider supplied
one) a fresh `providerPercent`; it can NEVER change `state` or `k`. Enforced by
type, pinned by a case.

## Closed action-state enum

The transition table is itself conformance data — the enum is closed twice, in
code and in the suite. Any new state or edge arrives through a new case first.

| state | action claim (four-valued) | render | advancing |
|---|---|---|---|
| `pending` | unknown | stillness (dim) | no |
| `ready` | unknown | stillness — no false "about to move" | no |
| `running` | unknown | MOTION | yes |
| `provider-wait` | unknown | MOTION **only while evidence is fresh** | yes* |
| `stalled` | unknown | stillness + alarm glyph + evidence age | no |
| `blocked-consent` | unknown | stillness + friction glyph + what is awaited | no |
| `done` | satisfied | terminal, k++ | no |
| `failed` | violated | terminal, k++ | no |
| `skipped` | satisfied (cached) / unknown (dep-failed) | terminal, k++ | no |
| `indeterminate` | unverifiable | terminal, k++, prints the `resume` command | no |

- **Motion is a pure function of state.** The only motion states are `running`
  and `provider-wait`; `provider-wait` requires fresh evidence to remain itself.
  Miss the poll-freshness budget → the machine transitions to `stalled`, the
  glyph freezes, and `reason` names the silence.
- **Elapsed increments in stillness too** — time passing is honest. Slow-but-fine
  reads as motion with elapsed within band; wedged reads as stillness with
  evidence age growing.
- `blocked-input` is deliberately absent: a sealed plan takes no mid-flight input
  (else the seal is a lie). Only consent friction is a legitimate human gate.
- `k` counts **terminal** actions ("k of N resolved" — the honest determinate
  signal). The terminal banner reports resolved AND succeeded separately.

## Three clocks (N1 untouched)

1. **evaluation clock** (`--at`, fail-closed, N1) — observation freshness in
   verdict logic. The progress subsystem has no import path to it.
2. **coordination clock** (D56) — stamps receipts and `startedAt`; same source as
   the durable record, so progress adds no new time authority.
3. **monotonic runtime clock** — `elapsedMs` durations only.

Import-graph enforced (vet, like the post-D62 `time.Now` bans): progress cannot
read the evaluation clock; the verifier/ledger cannot read the runtime clock.

## Honest time

- **elapsed** is measured, therefore always emitted, always honest.
- **provider percent** is passthrough or absent — never computed from
  elapsed/typical. GCP LROs (AIP-151) supply none; Azure sometimes supplies
  `percentComplete`, then shown attributed to the provider.
- **ETA band** is a forecast, therefore basis-tagged and often absent:

```
ETABand { atLeast, typical, worst, basis: inferred, samples }
```

`atLeast` = fastest observed success, `typical` = EWMA of successes, `worst` =
p95 of successes; keyed by (capability type, operation, provider, region), with
success and failure populations kept separate. **No band** when `samples < 3`,
or the history spans a provider/region change, or `elapsed` has exceeded
`worst` — then the band is WITHDRAWN for prose ("beyond seen worst p95 9m2s,
still waiting"): a band already beaten is a lie, and out-of-distribution is
information. No history → no number. Never `{basis: unknown, typical: 123}`.
Rendered as "typically ~7m (seen 12x)", never a bare countdown.

## Render folds

One stream, one fold library (`go/internal/render`, beside the D89 glyph table
— one glossary; the console's `statusOf` mirrors it). TTY sticky bottom region,
one line per non-terminal action (collapse beyond ~8):

```
[ 3/9] ~ create  database.relational  demo-db   provider-wait  4m12s   typ ~7m (n=12)
[ 3/9] . create  private-network      demo-net  pending (after demo-db)
[ 3/9] ! update  container-workload   api       STALLED 1m34s — no poll answer for 94s
```

Shape-first (D89): state is carried by the leading glyph SHAPE and the state
word, never color alone. `~` animates only in motion states; `!` is frozen.
Terminal actions leave the live region and scroll into history as plain lines.

**Coexistence with D89 banners** (terminal one-shots) on the same stderr:
banners scroll, progress repaints. Emitting a banner = clear the sticky region,
print the banner as a permanent line, redraw beneath. In `plain` mode there is
no region — banners and transition lines interleave chronologically. In `ndjson`
mode banners become `kind: banner` events. Refusal remains refusal, not failure.

## Testability

Progress is non-deterministic only in its timings. Split the surface:

1. **Golden layer** — the D37 scenario engine scripts each action's provider
   timeline as data and binds the runtime clock to a VIRTUAL clock; every field
   becomes a pure function of the script and the case asserts the byte-exact
   golden NDJSON sequence (stall transitions, tick cadence, band presence via
   seeded receipt histories, percent passthrough).
2. **Clock-free invariants** — over a real-clock stream: every transition edge is
   in the pinned table; `k` monotone, increments only on terminal transitions,
   ends at N; a tick never changes state/k; every action reaches exactly one
   terminal; band absent with empty history; percent absent unless scripted.
3. **Purity cases** — stdout under `--progress=ndjson` is byte-identical to
   `--progress=none`; the ledger hash-matches across progress modes for the same
   scenario (invariant #6 as an executable assertion).

Rule: anything byte-pinned runs under the virtual clock; anything real-clock is
covered by clock-free invariants; nothing is exempt from both.

## Non-goal, forever

No global percent. `[k/N]` resolved, per-action state with reason, honest
elapsed, and a basis-tagged band when history earned it — that is the whole
vocabulary, and it is enough.

## What ships live vs. what is gated (honest boundary)

**Live now** (pinned by Go tests + a conformance purity case): the stream
(`run-start` manifest → transitions → `run-end`), position (`k/N`), the closed
action states, measured `elapsed`, the `plain`/`ndjson`/`tty` renders, and the
purity guarantee (stdout + ledger byte-identical across `--progress` modes).

**Gated — machinery built, emits nothing until the real source exists** (D227
addendum; the never-fabricate rule forbids faking either):

- **ETA band.** `Band()` is complete and tested, but the deterministic ledger
  carries no wall-durations (the coordination clock is logical and does not
  advance within a run; recording measured time would break ledger determinism).
  A band needs a durable timing store outside the hash-chained ledger. Until it
  exists: no band.
- **provider-wait / tick / stalled.** Fully supported by the enum, `Fold`, frame
  and emitter, but today's drivers conclude synchronously, so the executor emits
  `running → terminal` and nothing enters `provider-wait`. It becomes live when a
  driver exposes incremental LRO polling — additive, per-driver, no vocabulary
  change.
