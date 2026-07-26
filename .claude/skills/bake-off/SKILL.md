---
name: bake-off
description: Compare cloud vendors for one InfrastructureContract by emitting one ImplementationCandidate per vendor, running verify + forecast on each, and assembling a deterministic comparison report. The runtime gates eligibility, the agent summarizes trade-offs, the HUMAN picks the winner. Use when the user asks which cloud fits a contract ("aws czy gcp?", "porównaj vendorów", "bake-off").
---

# Vendor bake-off (D92)

The choice of cloud is not an LLM opinion — it is a comparison of
deterministic verdicts on real candidates. The agent's only creative
act is emitting honest candidates; everything that ranks them comes
out of `verify` and `forecast`, and the human chooses.

## Procedure

0. **Parity precheck (the deterministic feasibility map)** — before
   emitting anything, ask the runtime which vendors can even fulfil the
   contract's capabilities: `groundhold parity <capability.type> --json`
   for each capability TYPE the contract declares. Each cloud answers
   `fulfilled` (with the service tokens), `gap` (STRUCTURAL — the cloud
   has no such service; a fact about the cloud, with a reason), or
   `unbuilt` (no groundhold driver yet — a fact about groundhold, not a
   verdict on the cloud). This is the D173 machine-verified matrix, so
   the answer cannot drift or be guessed. A vendor with a `gap` on any
   REQUIRED capability is ineligible up front, cited with the gap reason
   (e.g. "gcp cannot fulfil email.sending: no first-party transactional
   email"); an `unbuilt` cell is a roadmap note ("no azure driver yet"),
   NOT a structural exclusion — surface it honestly as such.
1. **One candidate per vendor with a driver family** — `aws`, `gcp` and
   `azure` all have full families (see spec/parity.yaml). A vendor whose
   required capability shows `gap` in the parity precheck is reported
   `ineligible: <gap reason>`, never mocked up. Candidates go to
   `.groundhold/bakeoff/<contract-id>/<vendor>.candidate.yaml`, each
   emitted per the emit-candidate skill (agent proposes, marks
   inferred/assumed). A confused binding (a service that does not fulfil
   the declared capability) is refused deterministically at `plan`.
2. **Judge each candidate deterministically**:
   `verify --json --vocab spec/vocab`, then `plan`/`forecast` where a
   ledger context exists. Store the raw outputs next to the candidates
   — the report cites them, it never restates them from memory.
3. **Classify eligibility from the verdicts** (deterministic reasons,
   never taste): `eligible` (executable, budget constraint satisfied),
   `ineligible` (hard constraint violated, an attribute the vendor's
   driver refuses, forecast breaches a hard budget), `blocked`
   (unknowns — name the probes that would close them). Eliminated
   candidates STAY IN THE REPORT with their reasons; the human sees
   what was excluded and why, and may change the contract instead.
4. **Assemble the report** in four sections, in this order:
   - **Hard gates** — eligibility per vendor with the citing verdict.
   - **Decision drivers** — only dimensions where vendors MATERIALLY
     differ: predicted cost vs budget, honest refusals (a vendor
     refusing retention.locked or encryption.inTransit is a signal,
     not a bug — D88), forecast confidence (which numbers are priced
     vs assumed), declared-only factors (org vendor commitments, team
     skills — if the human declared them; ask once, never infer).
   - **Non-differentiators** — checked and equal; one line each.
   - **Unknowns / probes** — what must be measured before publish
     (rto restore tests, etc.).
5. **Write both renderings**: `report.md` for the human,
   `report.json` for machines (the console and MCP agents project it
   later; keep the shape stable):
   `{contract, contractHash, generatedAt, candidates: [{vendor,
   candidatePath, eligibility, reasons[], verify: <raw report>,
   forecast: <raw doc|null>}]}`.
6. **Stop.** Present the report; the human picks among eligible
   candidates or amends the contract. Converge happens on their say.

## Banned from the report (noise, per review)

Feature counts, market share, "mature ecosystem"-grade adjectives,
benchmarks not tied to this workload's shape, console/UI preference,
kubernetes/serverless ideology, cost deltas smaller than the forecast's
own uncertainty, and any dimension where the vendors are equal
(that is what Non-differentiators is for — one line, no table).

## Never

- Never auto-pick the winner; never hide an eliminated candidate.
- Never rank on inferred team-fit or inferred org preferences —
  declared or absent.
- Never fabricate a candidate for a vendor without a driver family.
