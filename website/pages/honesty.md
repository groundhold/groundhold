# The honesty rules

Groundhold asks you to let software — proposed by an AI — touch
production. That only works if the system never earns your trust with
adjectives. So every promise below is enforced by a mechanism, and
every mechanism is pinned by conformance cases that both
implementations must pass. Not one of them is a policy or a habit;
they are the shape of the system.

**1. It never pretends to have checked something.**
Every verdict is `satisfied`, `violated`, `unknown` or `unverifiable`
— and *I don't know* on a hard constraint stops execution. There is no
flag to bypass it, deliberately: a bypass flag would become a habit.

**2. Every value says where it came from.**
`declared` by a human, `inferred` or `assumed` by an agent, or
`unknown` — and that label survives into the verdict. When a green
check rests on an assumption, it renders dim: satisfied, standing on
sand. You always know which.

**3. Configuration is a claim; only measurement is proof.**
A constraint declares HOW it can be proven (`static`, `provider-api`,
`probe`). An RTO is not satisfied by settings that *should* work — only
by a restore test that did. Until then it is honestly `unknown`, and it
blocks.

**4. A refusal is an answer, not an error.**
When a gate holds — missing consent, stale knowledge, unproven claim —
you get a blue `REFUSED` with a machine code, and `groundhold explain
<code>` tells you the exact next action. Refusals are the system
working; they are never dressed as failures, so you never learn to
route around them.

**5. Green always carries its age.**
"Converged" means "converged as of an observation". The console shows
the age of the stalest proof behind every green badge; a timeless green
light would be a claim the ledger cannot back.

**6. If a cloud cannot honor or measure something, it says so loudly.**
When a provider cannot enforce an attribute in the same operation it
already makes, the driver refuses that cloud — it never half-applies
or quietly creates extra resources. An attribute one cloud honors and
another refuses is the comparison, not a bug.

**7. Nothing mutates before it is proven safe to try.**
Plans are sealed against the exact documents and identities they read;
permissions are preflighted before the lease; delete targets are
pinned; destroying stateful things needs explicit consent at compile
AND apply — `--yes` never supplies it.

**8. History cannot be quietly rewritten.**
The ledger is append-only and hash-chained; replay verifies the chain;
anchors detect truncation from outside the file. Repairing a corrupt
ledger is a two-step, consented operation — nothing proceeds over
corruption.

**9. When it dies, it says so — and resumes honestly.**
A crash mid-apply leaves write-ahead receipts, not guesses. `resume`
asks the provider what actually happened; an outcome stays *pending*
until the provider answers. `DIED` is a state, not an apology.

**10. Your data does not leave.**
Zero telemetry. The runtime talks to the cloud provider you configured
and to nothing else. The ledger is the observability surface — stream
it wherever you already look, with `export`.

**11. Proof travels without asking for trust.**
An evidence capsule (`groundhold capsule`) carries one capability's
history verbatim and verifies anywhere — linkage, hashes, signatures
(`--trust`, D102) — with no ledger and no faith in the sender's
filesystem. And it states its own limit: it proves what was said as of
its tip, never that nothing newer exists; that check belongs to an
anchor you hold (`--check`). A verifier that proves less says so.

---

## Don't believe this page — run it

Every rule above is pinned by named conformance cases that BOTH
implementations (Go runtime, Python reference) must pass through
their own binaries. A sample, verbatim from `conformance/cases/`:

| rule | case |
|---|---|
| unknown blocks (1, 3) | `probe-gated-hard-constraint-blocks-execution` |
| provenance survives (2) | `assumed-value-satisfies-but-carries-basis` |
| no type coercion (1) | `unit-mismatch-is-unverifiable-not-false` |
| measurement closes claims (3) | `probe-closes-the-thesis-loop` |
| sealed plans (7) | `apply-refuses-stale-plan` |
| consent for destruction (7) | `plan-refuses-delete-stateful-under-autonomy` |
| tamper-evident history (8) | `repair-quarantines-a-chain-break` |
| honest death (9) | `apply-unknown-outcome-is-not-failure` |

```sh
make check          # every gate: all suites, both implementations
make differential   # seeded random documents through both CLIs — byte-identical
```

The suite is the definition of the semantics; the prose you just read
is only its shadow.

---

The same rules bind everything downstream: a downstream management console
renders these words and never invents its own, agents get the same
read-only API as the browser, and the [output you read](presentation.md)
is designed so that the honest answer — including *I don't know* — is
always the easiest one to see.
