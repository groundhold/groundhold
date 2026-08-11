# Azure live canary (D290)

The smallest honest proof that groundhold's loop closes against **real Azure**.
Azure is the one cloud that has never met reality (`docs/MATURITY.md` names it
the weakest claim in the system); this is the slice that changes that — or
proves it does not, which is equally useful.

## Why a virtual network

A VNet costs **nothing** in Azure. This canary therefore proves the whole
spine — bearer auth, the ARM PUT, the async provisioning poll, ownership tags,
the observe reverse-map, the convergence check, retirement — **without a bill**.
It does not prove the expensive surfaces (AKS, Flexible PostgreSQL); saying so
here is cheaper than discovering later that a green canary meant less than it
looked.

## What you must supply (and why groundhold will not)

| Input | Why it is yours |
|---|---|
| `GROUNDHOLD_AZURE_ACCESS_TOKEN` | An AAD bearer. `az account get-access-token` mints it; logging in is interactive, so it is yours to run. |
| a subscription id | groundhold does not create subscriptions. |
| a **pre-existing resource group** | groundhold does not own resource groups — there is no such service in the Azure driver, deliberately: an RG is an account-shaped container, like the subscription. Substitute yours in the candidate. |

```bash
az login                                            # interactive — yours
export GROUNDHOLD_AZURE_ACCESS_TOKEN="$(az account get-access-token \
  --resource https://management.azure.com --query accessToken -o tsv)"
export SUB=<subscription-guid>
az group create -n groundhold-canary -l westeurope  # the container, not ours
```

## The loop

```bash
AT=$(date -u +%Y-%m-%dT%H:%M:%SZ)
bin/groundhold-go converge examples/canary-azure/canary.contract.yaml \
  examples/canary-azure/canary.candidate.yaml \
  --ledger .canary-azure.ledger --provider azure --project "$SUB" --at "$AT" --yes
```

Expect: `verify ✓ plan ✓ forecast ✓ confirm ✓ apply ✓ observe ✓
convergence-check ✓` then **CONVERGED**. A second run with a fresh `--at` must
report `converged` and touch nothing — that no-op is the actual proof, because
it says observed reality matched the sealed intent.

## Teardown (run it — an unowned canary is how bills start)

```bash
# retire through the contract, so the ledger records a tombstone rather than
# a resource that merely stopped being mentioned. The retirement pair SHIPS —
# D692: this used to be a `sed -i` on the tracked contract above, which mutated
# a repo file and produced a document the loader refuses ("constraint targets
# retired capability"), i.e. a teardown that could not run for a canary that
# spends real money.
bin/groundhold-go publish examples/canary-azure/canary-retired.contract.yaml \
  --ledger state/canary.jsonl --actor you@org --at "$(date -u +%FT%TZ)"
bin/groundhold-go converge examples/canary-azure/canary-retired.contract.yaml \
  examples/canary-azure/canary-retired.candidate.yaml \
  --ledger state/canary.jsonl --provider azure --at "$(date -u +%FT%TZ)" \
  --allow-data-loss --yes
az group delete -n groundhold-canary --yes            # the container you made
```

## Honest expectations

This is the driver family's **first** contact with real ARM. Golden tests pin
the request shapes; they cannot pin what Azure actually answers. Treat a
failure here as the canary earning its keep — the AWS pilot found a poll on a
nonexistent path and a transport regression that every hermetic gate passed
(D273, D269/D271). File what breaks; that is the point of running it.

## What the first real run found (2026-07-24, D292)

It worked — and it immediately paid for itself. The first converge APPLIED but
the convergence check came back inconclusive with an empty observation set:
**every Azure read returned "unreadable"**. The driver built its request URLs
from a subscription pin that `observe` deliberately does not set (the ledger
may span subscriptions; the identity already carries it). The entire Azure
observe family had never worked outside a test that set the field by hand.
Fixed at the dispatcher (D294) and re-verified against the live resource.

Treat that as the expected shape of a first live run, not an anomaly.

## Retiring: three refusals, each one correct

Tearing the canary down through the contract teaches the D47 rules in order:

1. `constraint targets retired capability` — drop the constraints too.
2. `candidate declares attributes for retired capability` — an empty attribute
   map is still a declaration.
3. It converges once the capability is gone from the CANDIDATE entirely while
   the CONTRACT marks it `state: retired`. The delete acts on the pinned
   providerId from the binding, so the candidate has nothing left to say.

The retirement pair used here SHIPS beside this README (D692):
retirement is contract-shaped, not a fixture.
