---
name: draft-contract
description: Draft an InfrastructureContract from prose intent ("potrzebuję bazy MySQL w Warszawie, prywatnej, RPO 5 minut"). The draft is a PROPOSAL for human review — the agent proposes, the human publishes. Use when the user describes infrastructure needs in natural language.
---

# Draft a contract from intent (D49)

A contract is not sacred because a human typed it; it is sacred because
it is the reviewed authority. You may draft it — the human publishes.

## Procedure

1. **Listen for constraints, not resources.** "Baza MySQL w Warszawie,
   prywatna, RPO 5 minut" is four constraints (engine.protocol
   compatible-with mysql/8.x; location.region equals europe-central2;
   network.publicExposure equals false; recovery.rpo lte 5m) — not a
   resource spec. Tiers, disks and flags are implementation noise: they
   belong in the future candidate, never in the contract.
2. **Every requirement becomes a constraint** with the right severity:
   compliance/security/data-loss → hard; preferences/cost objectives →
   soft or budget. When the speaker is vague ("szybka baza"), draft the
   closest measurable constraint and MARK the leap: put it in
   `assumptions:` with a `statement:` saying WHAT is assumed ("the
   database must serve reads under 50ms"), `status: assumed`, a
   `source:` saying where that came from ("user said 'fast'"), a
   confidence, and `affects:` pointing at the constraints resting on it.
   `statement` and `source` are different fields and both are needed:
   the schema requires the statement, and a citation with no proposition
   travels into a verdict's basis as evidence for a claim nobody wrote
   down (D1157).
3. **Contradictions and gaps are findings, not fill-ins.** If intent
   conflicts (private + "accessible from the office WiFi") or omits
   something material (no environment, no region), ASK — do not guess
   silently. If the speaker changed their mind mid-stream, the LAST
   statement wins; note the supersession in the assumption's source.
4. **Autonomy is the user's voice**: propose `forbidden:
   [{delete_stateful: true}]` as a safe default for stateful
   capabilities; never propose replacement consents unprompted.
5. **Validate the draft**: `bin/groundhold-go validate <draft>` must pass;
   then present the draft with every assumption highlighted and ask for
   review. The published contract goes at the top of the repo, owned by
   the human; drafts live in `.groundhold/` until accepted.

## Never

- Never publish (move/rename the draft into the human's space) without
  explicit approval.
- Never encode implementation detail (tiers, instance names, disk types)
  into the contract.
- Never omit an assumption you made — unstated leaps are how contracts
  lie.
