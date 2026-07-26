---
name: dr-forensics
description: Correlate what happened across contracts in a time window during an incident or disaster-recovery review — read the ledger's 4D fold (groundhold export --from/--to), narrate likely cause-and-effect across capabilities, and hand back a hypothesis that cites event hashes. Use after an incident, a restore, or when asked "what changed between T1 and T2 and how are the changes related".
---

# 4D disaster-recovery forensics (outside the verifier)

The ledger is the only source of truth. Your job is the fourth dimension —
**time** — the one the verifier deliberately does not reason about. groundhold's
core stays deterministic and heuristic-free (invariant #6): it will tell you
WHAT each event was and WHEN it was declared, never which change *caused*
another. Causation across capabilities is an interpretation, and interpretation
lives here, in an agent, never in the runtime.

So the contract of this skill is strict: **you produce a hypothesis, not a
verdict.** Every claim is labelled interpreted-not-proven and every sentence
cites the event hash it rests on. A reader must be able to discard your story
and keep the facts.

## What the runtime gives you (facts)

- `groundhold export --ledger <f> --from <T1> --to <T2>` — the deterministic
  fold-window: every event whose `occurredAt` is in `[T1, T2]`, verbatim, each
  carrying its canonical `id` (event hash) and `capabilities`. This is a
  PROJECTION — every line was still trust-checked in the fold; the window only
  chose what to show. Use `--type` to narrow, `cloudevents` for a portable envelope.
- `groundhold audit`, `groundhold capsule --verify`, `groundhold restore` — the sound,
  per-capability facts you must not contradict.

## What you add (interpretation)

Ordering, adjacency and cause. The axes are provider × service × capability
(space) and the hash-chain (time). You look across capabilities — which the
per-capability chains never do — and propose how a change in one relates to a
change or violation in another.

## Procedure

1. **Bound the window.** Get T1/T2 from the incident (a violation.detected, an
   alert, a restore's asOf). Run `export --from T1 --to T2`. If the window is
   open-ended, say so — an unbounded story is weaker.
2. **Lay the lanes.** Group events by capability into parallel time-lanes.
   Within a lane the order is proven (the chain). ACROSS lanes it is only
   `occurredAt` — a DECLARED time, not a total order. Never assert cross-lane
   ordering more precisely than `occurredAt` supports; ties and near-ties are
   "concurrent (cannot order)", not a guess.
3. **Propose links, do not assert them.** "binding.updated on A (hash abc…) at
   08:02 precedes violation.detected on B (hash def…) at 08:05 — PLAUSIBLY the
   trigger; interpreted, not proven." A link needs a mechanism you can name, or
   it is coincidence you must call coincidence.
4. **Cite or delete.** Any sentence without an event hash is speculation and
   comes out. If you cannot cite it, you cannot claim it.
5. **Hand back a hypothesis.** A short causal narrative + an explicit
   "what would confirm this" list (a probe to run, an observation to refresh, a
   capsule to verify) — the reader decides, the runtime proves.

## Hard lines

- **Never write to the ledger.** Forensics is read-only. You narrate history;
  you do not append to it.
- **occurredAt is declared, not measured.** A backdated or clock-skewed event is
  possible; if the story depends on a tight ordering, flag the assumption.
- **No secrets.** The ledger excludes them by construction (D53); do not infer or
  reconstruct any.
- **Hypothesis, not verdict.** If the user needs proof, the answer is a caveat
  command (`audit`, `probe`, `capsule --verify`), not your prose.

The console's "4D" view renders the same fold-window over `?at=` — lanes, fold
diffs, incident grouping — with the identical discipline: every grouping is
labelled interpreted-not-proven and links back to the event hash. Your narrative
and that view are two projections of one set of facts; neither is allowed to add
a fact.
