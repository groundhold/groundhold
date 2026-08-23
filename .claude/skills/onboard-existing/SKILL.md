---
name: onboard-existing
description: Onboard existing (brownfield) infrastructure into Groundhold — discover real resources, draft a contract whose reality-derived constraints carry observed-not-intent markers, adopt bindings, claim authorship, prove the takeover with a converged no-op run after the claim. Use when the user has infrastructure Groundhold did not create (including terraform/pulumi-managed).
---

# Onboard existing infrastructure (D52)

Reality is the first author, never the authority. Discovery tells you
what IS; only a human can say what OUGHT to be. Your job is to keep
those two voices from blurring.

## Procedure

1. **Discover, read-only**: `bin/groundhold-go discover --provider gcp
   --project P --region R --at <now>` — save the output; note its
   `discoveryHash`. Discovery never writes the ledger and never mutates
   the cloud.
2. **Draft the contract from the discovery** (follow [draft-contract]
   for shape and severity rules), with one addition: EVERY constraint
   whose value came from reality carries an assumption
   `{status: observed, source: "discovery <hash-prefix> at <ts>"}`.
   These markers say "reality claimed this, nobody has confirmed it is
   intent". Then walk the human through them: tier/disk/flags are
   accidents (drop or move to the candidate), residency/exposure/
   recovery are usually intent (keep, marker removed on confirmation).
3. **Emit the candidate** from the discovery's `candidateSkeleton`
   (follow [emit-candidate]) — declare only attributes the provider can
   observe; adoption will verify every one of them against reality.
4. **Adopt**: `bin/groundhold-go adopt <contract> <candidate> --ledger L
   --map <cap>=<providerId> --discovery <saved-discovery-file>
   --provider <cloud> --at <now>` —
   deterministic gate; refusals are verdicts, not obstacles:
   - "declared X but reality says Y" — the candidate lies; fix the
     candidate (or the resource), never argue with the gate;
   - "declared but not observable" — remove the attribute or add
     observation support to the driver; unknown never passes as a match;
   - "already bound" — no double adoption, in either direction.
5. **Stamp the takeover, then prove it.** `adopt` binds the ledger and
   touches nothing in the cloud, so the first converge after it plans a
   **claim** — the operation that stamps authorship on an adopted
   resource. That is the takeover proceeding, not a bad draft. Run
   `bin/groundhold-go converge <contract> <candidate> --ledger L
   --provider <cloud> --at <now> --yes`; it executes the claim and
   reports **converged**. Run it once more: it must now report
   **converged** having planned nothing.
   If a converge plans an ATTRIBUTE change — anything other than that one
   claim — the draft does not match reality: go back to 2, and do NOT
   apply your way out of it. The claim is the exception, and it is the
   only one: no amount of redrafting removes a missing authorship stamp.
6. **Mistaken adoption**: `bin/groundhold-go unadopt <contract> <cap>
   --ledger L --at <now>` releases the binding and never touches the resource.
   Retirement (D47) is the destructive verb; unadopt is the eraser.

## Terraform / pulumi migration

State files are ADOPTION HINTS, never a contract:

1. `bin/groundhold-go hints terraform.tfstate` (auto-detects pulumi
   checkpoints too) — per resource: suggested capability type,
   providerId for `--map`, and `expected` attributes.
2. Run `discover` live and COMPARE expected vs observed. Every
   disagreement is state drift found during migration — surface it to
   the human ("tfstate says private, reality says exposed") before
   drafting; never quietly prefer either value. The live observation is
   the authority; the hint is the claim being audited.
3. Read the hint `notes` aloud to the human — e.g. deletion_protection
   OFF in state (Groundhold defaults protection on) changes behavior after
   migration and must be a conscious choice.
4. Proceed with the normal path: draft → adopt (cite the DISCOVERY, not
   the hints — hints are untrusted throwaway input) → `converge --yes`
   to execute the claim → converged no-op proof. Composite children
   (sql users, databases) ride along with their instance; they are not
   separately adopted.

## Never

- Never adopt with attributes you weakened until the gate passed —
  deleting a mismatched attribute to force adoption converts a lie into
  a blind spot; surface the mismatch to the human instead.
- Never leave an observed-not-intent marker unresolved in a contract
  you present as final — every marker is either confirmed intent
  (marker removed) or an accident (constraint removed).
- Never skip the converged no-op proof; an adoption without it is a
  binding, not a takeover. It comes AFTER the claim — a first converge
  that plans one is the takeover working, not a draft to fix.
- Never parse `-gN` suffixes out of adopted resource names — foreign
  names are opaque; Groundhold derives replacement names from
  (project, environment, capability, generation), never from them.
