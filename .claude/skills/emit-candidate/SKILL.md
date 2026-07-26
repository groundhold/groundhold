---
name: emit-candidate
description: Emit an ImplementationCandidate for a given InfrastructureContract — the agent proposes, the verifier gates, the human publishes. Use when the user has a contract and wants the implementation proposal, or says "wygeneruj kandydata" / "emit a candidate".
---

# Emit a candidate (D49)

You are the probabilistic author Groundhold was designed around. Your
output is a PROPOSAL — the deterministic verifier gates it, so you need
no trust, but you owe honesty: provenance on every value you did not
take verbatim from an authoritative source.

## Procedure

1. **Read the contract** the user points at. Note every capability, its
   type, every constraint (hard/soft/budget/requirements) and the
   autonomy block.
2. **Read the vocabulary** for each capability type
   (`spec/vocab/capability.*.yaml`). The vocabulary IS the type system:
   only emit attribute paths it defines (plus what constraints
   explicitly reference); respect each path's `kind`.
3. **Read the provider spec** (`spec/providers/gcp.md`) for the target
   provider's mapping table and refusals — do not emit what the driver
   will refuse (e.g. `network.publicExposure: false` without a prepared
   `implementation.network.privateNetwork`; `availability.class:
   multi-regional` on Cloud SQL).
4. **Emit the candidate** into the generated-artifacts directory
   (`.groundhold/` by convention), NEVER over the human's contract file:
   - satisfy every hard constraint and requirement by construction
   - carry provenance (D5): values you computed from a catalog or doc
     are `{value, status: inferred, source: "...", confidence: 0.x}`;
     values you could not ground are `{status: unknown}` — an unknown
     on a hard constraint will block, and that is CORRECT behavior,
     not a failure to route around
   - the `implementation:` block carries provider detail (tier, disks,
     flags); pick the cheapest tier satisfying the constraints unless
     the contract's budget or the user says otherwise, and SAY what you
     picked and why
5. **Self-verify in a loop**: run
   `bin/groundhold-go verify <contract> <candidate> --vocab spec/vocab`
   and iterate until `executable: true` — or until the blocker is one
   only reality can lift (probe-gated constraints stay `unknown`; say
   so instead of faking).
6. **Present**: the candidate path, the verify report, every `inferred`
   or `assumed` value with its source, and anything you left `unknown`.
   The human publishes; you never apply.

## Never (D49)

- Never generate Terraform/HCL.
- Never weaken, remove or reinterpret a constraint to make verification
  pass — if the contract is unsatisfiable, REPORT the contradiction.
- Never add autonomy consents (`allow_replace_stateful`,
  deletion-protection opt-outs) on the user's behalf; flag when one
  would be needed and ask.
- Never convert `unknown` into an assumed satisfied value.
- Never silently choose weaker security, weaker residency, weaker
  recovery or higher cost than an alternative you rejected — surface
  the trade-off.
- Never mutate the human's contract while regenerating a candidate.
- Never auto-bind existing resources; adoption is a human decision.
