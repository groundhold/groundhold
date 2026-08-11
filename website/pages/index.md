# What is Groundhold

**AI should not write Terraform.** The problem is not Terraform; it is
that a probabilistic author needs a medium built for verification
rather than for authoring implementations. An agent should emit
verifiable contracts, and a deterministic runtime should validate,
gate, execute and prove them.

Groundhold splits infrastructure into three layers with three authors:

| Layer | Author | What it says |
|---|---|---|
| **InfrastructureContract** | a human (reviewed) | what must be TRUE — constraints, never resources |
| **ImplementationCandidate** | an agent (proposed) | how to make it true |
| runtime artifacts | the deterministic runtime | sealed plans, receipts, observations, proofs |

A contract says things like:

```yaml
- id: c-rto
  subject: orders-db
  path: recovery.rto
  op: lte
  value: 30m
  verify: { method: probe }   # provable ONLY by an actual restore test
```

and the verifier renders **four-valued verdicts** — `satisfied`,
`violated`, `unknown`, `unverifiable`:

```
? c-rto   unknown   requires probe verification
BLOCKED: c-rto unknown — recovery.rto requires probe verification
```

`unknown` on a hard constraint means the runtime **refuses to
execute** — exit 2, machine code, no flag to bypass it. A claim nobody
proved never deploys.

Everything downstream keeps that discipline:

- **Plans are sealed**: the compiler pins the exact document hashes,
  decision heads and provider identities it read; if any of them
  changed between seal and apply, apply refuses (exit 3, re-plan).
- **The ledger is append-only**: hash-chained events, leases with
  fencing tokens, write-ahead receipts. An unknown outcome is
  *pending*, never guessed — `resume` asks the provider what actually
  happened.
- **Reality is measured**: `observe` reads configuration, `probe` runs
  outcome tests (a restore test, a connection attempt), `audit` judges
  recorded reality against the contract and emits
  `violation.detected/resolved` on transitions.
- **Destruction takes consent**: stateful deletes and replacements
  need explicit contract autonomy entries, checked at compile AND
  apply. `--yes` never supplies consent.
- **Zero telemetry**: the runtime makes no network calls beyond the
  provider you configure. The ledger is the observability surface;
  `export` streams it as CloudEvents to whatever you already run.

The whole lifecycle is one verb when you want it (`groundhold converge`),
and a couple of dozen plumbing verbs when you need them. Each promise
above is a mechanism with a gate behind it, which
[the honesty rules](honesty.md) set out one at a time.

## The thesis, as a conformance case

`probe-closes-the-thesis-loop`: a contract demands RTO under an hour
as a **hard constraint** with `verify.method: probe`. Nothing can
*deploy* that claim — a hard constraint may not ship unproven. The capability is adopted, the audit
alarms (`unknown`), a doubly-consented restore test measures 35
minutes, and the next audit rules `satisfied` and resolves the alarm.
**A claim became a measurement.**
