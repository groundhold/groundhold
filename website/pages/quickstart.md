# Quickstart

## Build

```sh
git clone git@github.com:groundhold/groundhold.git && cd groundhold
make check        # vet + tests + the full conformance suite (494 cases), both implementations
cd go && go build -o ../bin/groundhold-go ./cmd/groundhold && cd ..   # the CLI binary
```

Requirements: Go ≥ 1.25, Python ≥ 3.12 (reference implementation),
PyYAML. Nothing else — the runtime is stdlib + yaml only.

The full attribute vocabulary is compiled into the binary, so it works
with no external files — `--vocab <dir>` is optional and only EXTENDS
the built-in set with your own types; `--no-vocab` forces the empty set.

## Your first contract

`db.contract.yaml` — what must be TRUE (constraints, not resources):

```yaml
apiVersion: contract/v0.1
kind: InfrastructureContract
meta: { id: orders, environment: production, version: 1 }
capabilities:
  - id: db
    type: capability.database.relational
constraints:
  hard:
    - id: c-region
      subject: db
      path: location.region
      op: equals
      value: europe-central2
      verify: { method: static }
    - id: c-private
      subject: db
      path: network.publicExposure
      op: equals
      value: false
      verify: { method: static }
autonomy:
  forbidden:
    - delete_stateful: true
```

`db.candidate.yaml` — an agent's proposal (tiers and flags live in the
free-form `implementation:` block; the verifier judges semantics only):

```yaml
apiVersion: candidate/v0.1
kind: ImplementationCandidate
contract: orders
capabilities:
  db:
    attributes:
      location.region: europe-central2
      network.publicExposure: false
      engine.protocol: postgresql/16
      service.managed: true
    provider: gcp
    service: cloudsql
    implementation:
      tier: db-custom-2-8192
```

## Verify

```sh
bin/groundhold-go verify db.contract.yaml db.candidate.yaml
```

```
contract orders v1
  ✓ c-region                     satisfied     location.region equals europe-central2: observed europe-central2
  ✓ c-private                    satisfied     network.publicExposure equals false: observed false

  2 satisfied, 0 violated, 0 unknown, 0 unverifiable
  PROVEN
```

## Converge on your laptop — no cloud, no credentials

The full loop (verify → plan → forecast → confirm → apply → observe →
convergence check) runs end to end against the built-in `fake`
provider. It can only observe one attribute honestly
(`service.managed`), so the laptop demo uses a minimal pair — shipped in
the repository as `examples/laptop/`, so you can run it without pasting
anything:

```yaml
# lap.contract.yaml
apiVersion: contract/v0.1
kind: InfrastructureContract
meta: { id: orders, environment: production, version: 1 }
capabilities:
  - id: db
    type: capability.database.relational
constraints:
  hard:
    - id: c-managed
      subject: db
      path: service.managed
      op: equals
      value: true
      verify: { method: static }
```

```yaml
# lap.candidate.yaml
apiVersion: candidate/v0.1
kind: ImplementationCandidate
contract: orders
capabilities:
  db:
    attributes:
      service.managed: true
    provider: fake
    service: sql
```

```sh
bin/groundhold-go converge \
  examples/laptop/laptop.contract.yaml examples/laptop/laptop.candidate.yaml \
  --ledger state/prod.jsonl --provider fake --at "$(date -u +%FT%TZ)" --yes
# ... apply, observe ...
#   ✓ converged — verified against observed reality
# CONVERGED

bin/groundhold-go converge \
  examples/laptop/laptop.contract.yaml examples/laptop/laptop.candidate.yaml \
  --ledger state/prod.jsonl --provider fake --at "$(date -u +%FT%TZ)" --yes
#   ✓ converged — the world already matches the candidate
# CONVERGED
```

The second run touching nothing IS the product: convergence is proven
against recorded reality, not assumed from a successful apply.

Without `--yes`, converge stops at the plan and asks you to type
`apply` — in CI or a pipe that refuses (exit 2,
`code: confirmation-required`), deliberately. `--ledger` names a fresh
path; the directory is created for you.

One honest limit, on purpose: if a candidate declares attributes the
provider's `observe` cannot witness (on `fake`: anything beyond
`service.managed`), the first converge banners `APPLIED` — not
`CONVERGED` — because the convergence check came back inconclusive,
and a SECOND converge refuses with `observation-required`: drift
cannot be judged against observations that do not exist. Both are the
observation gate working, not bugs; on a real provider `observe`
covers the real attribute surface and `CONVERGED` is earned.

## Real cloud

The same rich pair from [Your first contract](#your-first-contract),
with a real driver (GCP shown; credentials come from Application
Default Credentials — `gcloud auth application-default login`):

```sh
bin/groundhold-go converge db.contract.yaml db.candidate.yaml \
  --ledger state/prod.jsonl --provider gcp --project my-project \
  --at "$(date -u +%FT%TZ)"
```

A plan with `dataLoss: certain` refuses under plain `--yes` and demands
`--allow-data-loss`. Refusals arrive verbatim with a machine `code`
(see [Errors](errors.md)); add `--explain` for remediation.

## Already have infrastructure?

```sh
bin/groundhold-go discover --provider gcp --project my-project
bin/groundhold-go hints terraform.tfstate       # tf/pulumi state -> adoption hints
bin/groundhold-go adopt ... --map db=project:region:name
bin/groundhold-go converge ...                  # must report "converged" — the proof
```

Adoption refuses when the candidate disagrees with live observation:
**adoption must not lie**.

## Keep the code and the contract agreeing

If an agent crawled your application repo (the `code-to-contract`
skill persists its evidence table as a commit-pinned survey), CI can
hold the two sides of the mirror together:

```sh
bin/groundhold-go survey db.contract.yaml --survey .groundhold/survey/9f3c1a7.json
```

Exit `2` with `code: survey-drift` means the code and the contract
disagree about reality — a dependency the code now requires with no
capability behind it, or (under `--complete`) a capability no repo
witnesses anymore. `audit` watches the cloud side of the contract;
`survey` watches the code side.
