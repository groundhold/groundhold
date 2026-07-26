# Lifecycle — create, change, delete

The three stages the README walks through, as files you can run. Everything here
uses the `fake` provider, so there is no cloud account involved, and every stage
is asserted by [`../check.sh`](../check.sh) on each commit.

## 1. Create

```sh
groundhold converge 1-create.contract.yaml 1-create.candidate.yaml \
  --ledger state/orders.jsonl --provider fake --at "$(date -u +%FT%TZ)" --yes
```

Two capabilities — a relational database and an object store. The contract names
no vendor; the candidate proposes how each is implemented.

## 2. Change the intent, and get refused

`2-refused.*` is the same database under a contract that now requires EU
residency, proposed in `us-east-1`:

```sh
groundhold verify 2-refused.contract.yaml 2-refused.candidate.yaml
```

```
  ✗ c-eu-only  violated  location.region in [eu-central-1 eu-west-1]: observed us-east-1
```

Exit 2, before a plan exists. This example is expected to keep failing forever —
`check.sh` asserts the refusal, because a residency constraint that quietly
stopped biting is the worst regression this project could ship.

## 3. Delete

```sh
groundhold converge 3-retire.contract.yaml 3-retire.candidate.yaml \
  --ledger state/orders.jsonl --provider fake --at "$(date -u +%FT%TZ)" --yes
```

Refused: `--yes` covers changes, not destruction. Add `--allow-data-loss` and it
proceeds.

Three things are deliberate here:

- **Retirement is explicit.** `state: retired` in the contract, never mere
  absence — otherwise "I forgot to write it" and "destroy it" would be the same
  edit.
- **A retired capability carries no constraints and no implementation.** Both are
  refused as contradictions rather than ignored.
- **The delete target is pinned from the ledger**, not inferred from the file you
  just edited. The plan names the exact recorded resource
  (`target=fake:assets-…`), so an edit cannot redirect a destroy at something
  else.

Run stage 3 against the same `--ledger` you used for stage 1; the binding
recorded there is what makes the delete target knowable.
