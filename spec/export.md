# Ledger export and audit (D54)

The ledger is the event source. Two verbs prove it.

## export

`export --ledger <file> [--since <index>] [--type <t> ...]
[--format ndjson|cloudevents]` — a DETERMINISTIC, STATELESS fold of the
ledger to stdout: same ledger + same cursor = byte-identical output.
Transport belongs to the operator (pipe to vector, fluentbit, curl);
the runtime never talks to third-party tools (D39). The cursor is a
plain line index — the ledger is append-only, so indexes are stable;
the operator persists the cursor (`index + 1` of the last consumed
record). A torn final line is corruption (exit 5), never silently
skipped.

Every record carries the canonical event hash as its id
(`groundhold/canon/v1:event`): globally unique AND content-derived, so
at-least-once delivery dedupes on the consumer side.

CloudEvents 1.0 mapping:
- `id`: the canonical event hash;
- `source`: `groundhold://<environment>/ledger` — the authority, never a
  file path (paths differ per machine, sources must not);
- `type`: `io.groundhold.<ledger event type>`;
- `subject`: affected capabilities, comma-joined;
- `time`: `occurredAt` VERBATIM — decision time, never export time
  (re-exporting must not re-date history);
- `groundholdindex` (extension): the record's cursor index;
- `data`: the raw ledger event — nothing summarized away; consumers
  filter, the exporter does not editorialize.

## audit

`audit <contract> --ledger <file> [--at <ts>] [--record]` — evaluates
the contract's subject constraints against RECORDED REALITY: the
latest ledger observations. Verify asks "does the proposal satisfy the
contract"; audit asks "does the world still".

Verdicts keep the four-valued semantics (D2): no observation or a
stale one (past TTL at `--at`) is `unknown`; an unparseable or
incomparable observation is `unverifiable`; never a silent false, and
a stale observation is NEVER collapsed into satisfied.

The alerting bar: HARD constraints with verdict `violated` or
`unknown` count as violations — exit 2, and with `--record` each
appends one `violation.detected` knowledge event (audit-chained,
decision-neutral) whose body is alert-complete without re-reading the
ledger: constraint id, capability, path, severity, verdict, reason,
required `{op, value}`, observed `{value, observedAt, derivation}`,
and the contract id+version it was judged against.

Ledger writes happen on TRANSITIONS only: violation.detected appends
when a constraint's verdict newly fails or CHANGES between violated and
unknown; violation.resolved appends when a previously recorded failure
returns to satisfied. Re-running audit against an unchanged failing
world emits NOTHING — otherwise polling frequency would become ledger
semantics and identical unresolved violations would pile up as
duplicate facts in an append-only log. The heartbeat lives in the
command itself: exit 2 and the full verdicts on stdout, every run. The
recorded alarm state is a ledger projection keyed by
(capability, constraint).

The loop this closes: `observe --record` writes facts, `audit --record`
judges them, `export --type violation.detected` streams the judgments —
drift becomes an alert without Groundhold knowing what alerting system
exists.
