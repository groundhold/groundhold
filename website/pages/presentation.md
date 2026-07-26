# Reading the output

Terraform can be red/green because its semantics are binary. Groundhold's
are not — the whole system refuses to collapse "I don't know" into a
boolean — so the output speaks a slightly richer, **closed** visual
vocabulary. You can read it at a glance without understanding the
system; this page is the whole glossary.

## The banner: one word, always last

Every verb ends its human output with one word. It answers the only
question you have at a glance: *can I walk away?*

| banner | color | it means | do |
|---|---|---|---|
| `PROVEN` | green | every hard constraint satisfied under accepted evidence | — |
| `CONVERGED` | green | reconciliation reached its proven fixed point | — |
| `APPLIED` | green | the sealed plan's mutations committed | — |
| `SEALED` | green | a hash-pinned plan exists and is executable | — |
| `OK` | green | the procedural verb completed | — |
| `VIOLATED` | red | something is proven false | fix the world or the contract |
| `INVALID` | red | the input document does not parse/validate | fix the document |
| `BLOCKED` | yellow | missing knowledge on a hard constraint — **not a failure** | gather evidence: `probe`, `observe` |
| `STALE` | yellow | the world moved since the decision was made | re-observe, re-plan |
| `REFUSED <code>` | blue | a gate held, deliberately | follow the code (`groundhold explain <code>`) |
| `DIED` | red | apply failed mid-flight | `groundhold resume` |
| `CORRUPTED` | red inverse | the ledger is damaged | `groundhold repair`; nothing proceeds |

Two deliberate oddities, both load-bearing:

- **A refusal is blue, never red.** The gate holding is the system
  working. If refusals looked like errors, you would learn to resent
  and bypass the gate — so they look like a guard, not an accident.
- **A non-green banner always names its culprit**:
  `BLOCKED: c-rto unknown — recovery.rto requires probe verification`,
  never the bare word.

Machine consumers ignore banners entirely and route on exit codes and
the JSON `code` field — banners are explicitly not a machine
interface. Verbs whose stdout is machine output (JSON, ndjson, plans)
print the banner on stderr instead, one final line.

## Verdict rows: shape first, color second

Everything stays readable with color stripped (CI logs, `NO_COLOR`,
`--color=never`, color-blindness) because the SHAPE carries the
meaning:

| glyph | ascii | verdict | next action |
|---|---|---|---|
| `✓` | `OK` | satisfied — proven true | — |
| `✗` | `X` | violated — proven false | fix the world or the contract |
| `?` | `?` | unknown — not known **yet** | go look: `probe`, `observe` |
| `∅` | `NA` | unverifiable — not knowable **this way** | change the contract or the method |

`?` and `∅` are different shapes because their remedies differ:
unknown is fixed by gathering evidence, unverifiable only by changing
the question. The ASCII set appears automatically under non-UTF-8
locales or `--ascii`.

**Provenance renders as brightness.** A verdict resting on
`inferred`/`assumed` values keeps its glyph and color but renders dim,
with the `[inferred]` marker: green-but-dim means *satisfied, standing
on sand*.

## The output teaches as it blocks

When a constraint is in a friction state (violated, unknown,
unverifiable), the row gains one indented line straight from the
vocabulary — what the attribute means and why configuration alone may
not prove it:

```
? c-rto   unknown   requires probe verification; not evaluable from the candidate alone
    recovery.rto — time to restore service after failure; probe-only —
    a value here is a claim until a restore test measures it
```

Satisfied rows stay terse — the happy path never lectures. And every
noun the system emits has one place to ask about it:

```
groundhold explain recovery.rto        # vocabulary attribute
groundhold explain consent-required    # machine error code
```

## Freshness is part of the claim

"Converged" is always "converged **as of** some observation". Human
renderings carry the age of the evidence they rest on, and the
a downstream management console shows it on every green badge — a green state is
only as fresh as its stalest proof.
