# The laptop example — the full loop, no cloud

Two files and one command run the entire loop: verify → plan → forecast →
confirm → apply → observe → convergence-check. The provider is `fake`, an
in-process stand-in, so there is no account to create, nothing to pay for and
nothing to clean up afterwards.

```sh
cd go && go build -o ../bin/groundhold-go ./cmd/groundhold && cd ..

bin/groundhold-go converge \
  examples/laptop/laptop.contract.yaml \
  examples/laptop/laptop.candidate.yaml \
  --ledger state/try.jsonl --provider fake \
  --at "$(date -u +%FT%TZ)" --yes
```

Ends in `CONVERGED`. Run the exact same command again and it ends in
`CONVERGED` having touched nothing:

```
  ✓ converged — the world already matches the candidate
```

That second run is the point. Convergence is proven against what was observed
back from the world, not assumed from an apply that exited zero.

## What the pieces are

`laptop.contract.yaml` states what must be true — one capability, one hard
constraint, no implementation detail. `laptop.candidate.yaml` proposes how to
satisfy it. An agent writes the candidate; the verifier decides whether it may
execute. Nothing in the contract names a vendor, and swapping
`provider: fake` for `aws`, `gcp` or `azure` is the only edit that stands
between this and real infrastructure.

## Why it is this small

`fake` can honestly observe exactly one attribute, `service.managed`. A
constraint it cannot witness comes back inconclusive rather than assumed-true,
which is the observation gate doing its job. That case is spelled out in
`website/pages/quickstart.md`; the example stays minimal so the first run
succeeds for the right reason.

## Where to go next

- `--yes` is what skips the confirmation. Drop it and converge stops at the
  plan and waits for you to type `apply`; in a pipe it refuses outright with
  `confirmation-required`, deliberately.
- `state/try.jsonl` is the ledger — an append-only record of what happened.
  Read it with `groundhold export`, or audit it against the contract with
  `groundhold audit`.
- `examples/acme/` is the same idea at real-platform size: network, cluster,
  database, mail, AI, keys, audit trail, with EU-residency constraints the
  verifier enforces deterministically.
