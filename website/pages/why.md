# Why Groundhold

AI can now propose infrastructure faster than any human can read it, and an agent is
a probabilistic author: fluent, confident, and wrong often enough that "looks right"
is not a safe basis for touching a cloud account. Terraform and its kin are authoring
media built for careful humans, so handing them to a probabilistic author
industrializes the mistake.

Groundhold is a machine-first medium where agents declare what must be TRUE about
infrastructure, and a deterministic runtime verifies, gates, executes and proves it.
A claim nobody proved never deploys, and a refusal is the system working rather than
an error to route around.

## The problem we kept hitting

Give an LLM a cloud and a Terraform file and it will produce something that
applies cleanly and is subtly, expensively wrong: a database one flag short of
private, a region that quietly routes data outside the EU, a backup policy that
never actually runs. It is plausible. It passes review by a tired human. It ships.

The reflex is "add a linter" or "make the human review harder." Both miss the
shape of the problem. The medium itself — HCL, YAML templates, imperative SDK
code — is built for **authoring implementations**. It has no first-class notion
of a *claim* that must be *proven* before it runs. When the author was a careful
engineer, the medium's optimism was fine. When the author is a model that
hallucinates, the medium has no place to stand and say *"prove that."*

So the question is not "how do we make the AI write better Terraform." It is
**"what medium does a probabilistic author actually need?"**

## The thesis

Split infrastructure into three layers, each with a different author and a
different job:

| Layer | Author | Its job |
|---|---|---|
| **InfrastructureContract** | a human, reviewed | say what must be TRUE — constraints, never resources |
| **ImplementationCandidate** | an agent, proposed | say how to make it true |
| runtime artifacts | the deterministic runtime | sealed plans, receipts, observations, proofs |

The agent's fluency is spent where it is safe — *proposing* how. The claims that
matter — residency, encryption, recovery, exposure, cost — are a human-owned,
reviewed contract. And a deterministic runtime, with **no model and no network
in its core**, decides whether the proposal actually satisfies the contract, and
refuses to execute anything it cannot prove.

The probabilistic part proposes and the deterministic part verifies, and neither is
allowed to stand in for the other. That separation is the whole design.

## The rules we will not break

These are load-bearing rather than features. Break one and the guarantee collapses.

- **Four-valued verdicts.** Every check is `satisfied`, `violated`, `unknown`,
  or `unverifiable` — never a boolean. `unknown` on a hard constraint **blocks
  execution**: exit code, machine reason, no flag to bypass it. Collapsing
  "I couldn't prove this" into "false" (or worse, "true") is the lie we refuse.
- **A refusal is not a failure.** When Groundhold stops because a claim is unproven,
  that is the product doing its job, loudly, before it touches your cloud — not
  an error to route around.
- **Reality is measured, not assumed.** A successful `apply` is not proof the
  world is correct. `observe` reads it, `probe` tests it (an actual restore, an
  actual connection), `audit` judges recorded reality against the contract. A
  claim only becomes true when something measured it.
- **No coercion.** Comparing a duration to a size, or euros to dollars, is
  `unverifiable` — never a silent conversion. The system would rather admit it
  cannot compare than guess.
- **Provenance survives.** Whether a value was `declared`, `inferred`, `assumed`,
  or is `unknown` rides all the way into the verdict. Green built on assumptions
  is visibly green-on-sand, not indistinguishable from proven.
- **A closed operator set.** No expression language, no interpolation, no
  logical gymnastics inside constraints. More hardening means *more constraints*,
  not a cleverer DSL. Complexity that cannot be verified is complexity we do not
  add.
- **The verifier is deterministic.** No LLM calls, no network, no heuristics in
  the core. Given the same inputs it returns the same verdicts, forever, in two
  independent implementations checked against one conformance suite. The
  probabilistic components live strictly outside.
- **Honesty over convenience.** The tool tells you what it cannot prove, cites
  the standard behind advice rather than inventing it, and never claims a
  guarantee it did not earn. It even grades its own maturity with the same
  four-valued honesty it applies to your infrastructure.
- **Zero telemetry.** The runtime makes no network call beyond the provider you
  configured. The append-only ledger is the observability surface; you export it
  to whatever you already run.

## What Groundhold is not

- **Not a Terraform generator.** The runtime is standalone: it compiles to a
  Sealed Plan and speaks provider APIs directly. `.tf.json` is at most an
  optional export, never on the execution path.
- **Not policy-as-code bolted on after.** Verification is not a scan that runs
  beside the authoring tool; it is the medium. The contract *is* the policy, and
  nothing executes that the contract has not proven.
- **Not an autonomous optimizer.** It will estimate cost and suggest cited
  best-practice hardenings — advisory only, never gating. It proposes and proves;
  a human decides.
- **Not, yet, a product with an SLA.** It is `v0.x`, experimental — an RFC you
  can run. Real execution has run against all three clouds and Kubernetes —
  mostly on our own accounts, each run cited in the coverage matrix; what it
  lacks is an external operator beyond the one AWS pilot. We say so plainly
  rather than imply more.

## The whole thing in one example

A contract demands recovery time under an hour as a **hard** constraint, provable
only by `verify.method: probe` — an actual restore test. Nothing can *deploy*
that claim: a hard constraint may not ship unproven, so the plan refuses. The
resource is adopted; the audit alarms `unknown`; a doubly-consented restore test
measures 35 minutes; the next audit rules `satisfied` and resolves the alarm.

**A claim became a measurement.** It is a conformance case
(`probe-closes-the-thesis-loop`), which is why it can be repeated rather than
believed.

## Where to go next

- [What is Groundhold](index.md) — the layers and mechanisms, a little deeper.
- [The honesty rules](honesty.md) — the promises above, as mechanisms.
- [Quickstart](quickstart.md) — first `verify` on your laptop, no cloud needed.
- `MATURITY.md` in the repo — groundhold judged by its own discipline: what is
  proven, what is golden-tested, and the gaps we are not hiding.
