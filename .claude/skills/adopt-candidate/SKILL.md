---
name: adopt-candidate
description: Adopt a single discovered cloud resource under a Groundhold contract from the command line, in one shot. Use when you have `groundhold discover` output and want to bring one of its resources under contract without hand-writing the contract/candidate YAML. This is the CLI counterpart of the console's read-only "how to adopt" recipe — the console shows candidates, this adopts them.
---

# Adopt a discovered candidate (CLI)

The console (groundhold-console) shows discovered resources as `adopted` or
`candidate` and hands you a recipe, but it is read-only and runs nothing.
This skill runs the recipe from the command line. It invents nothing: the
contract and candidate are built from the discovery's own observations, so
adoption confirms every declared attribute against the same reality groundhold
measured — no "declared but not observable" refusal from a hand-authored
mismatch.

## Procedure

1. **Have a discovery document.** From a read-only sweep:
   `groundhold discover --provider <cloud> --region <r> > discover.json`.
   Its `resources[].providerId` is the menu of what you can adopt.

2. **Pick the resource and name the obligation.** The `--contract` is your
   word for what must be true (e.g. `tfstate`, `backups`). The
   `--capability` is a label used identically in the contract, the
   candidate, and the `--map` (e.g. `state-store`).

3. **Run the script:**
   ```
   scripts/adopt-candidate.sh \
     --discovery discover.json \
     --resource  s3:eu-central-1:my-bucket \
     --contract  backups --capability backup-store \
     --ledger    ledger.ndjson \
     --env aws-eu --owner you@org \
     --seed <console-seed-dir>   # optional
   ```
   It generates `contract.yaml` (type prefilled from the discovered
   `resourceType`, hard constraints from the observations), a matching
   `candidate.yaml`, then runs `groundhold publish` and `groundhold adopt`
   (`adopt` binds the LEDGER, never the cloud; it reads the resource to
   confirm). With `--seed`, it exports + verifies into the console seed dir
   so the panel flips the row from `candidate` to `adopted`.

4. **Trim the contract, then re-publish.** The generated constraints mirror
   everything groundhold observed. Reality is the first author, not the
   authority (see [onboard-existing]): drop the constraints that are
   accidents (tier, disk), keep the ones that are intent (residency,
   exposure, encryption, recovery), and re-publish a v2 when you have.

`GROUNDHOLD=<path>` overrides the binary; default is `groundhold` on PATH.
Cloud credentials come from the environment the same way every groundhold
verb reads them (e.g. `AWS_ACCESS_KEY_ID`/`AWS_SECRET_ACCESS_KEY`).
