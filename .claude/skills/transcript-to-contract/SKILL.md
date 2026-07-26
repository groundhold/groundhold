---
name: transcript-to-contract
description: Turn a meeting transcript (or any spoken-word record — Whisper output, Zoom/Teams/Meet transcript, dictation) into an InfrastructureContract draft. Handles mind-changes by supersession, collects facts with speaker attribution, marks every leap. Use when the user provides a transcript, recording text, or says "z tego spotkania zrób kontrakt".
---

# Transcript to contract (D61)

A meeting is a probabilistic author thinking out loud. Your job is to
extract the INTENT that survived the conversation — not everything
that was said — and hand it to [draft-contract] with honest markers.

## Procedure

1. **Collect facts with attribution.** Walk the transcript once and
   list every infrastructure-relevant statement as a fact:
   `{speaker, time/turn, statement, constraint-candidate}`. Keep the
   turn reference — it is the provenance source.
2. **Supersession: the LAST statement wins.** "Weźmy 1 CPU... nie,
   czekaj, dajmy 2" yields ONE fact (2), with the supersession noted:
   `source: "turn 41, superseding turn 38"`. A later speaker
   overruling an earlier one is also supersession — but only when they
   have the authority to (the meeting owner overrules; a side comment
   does not). When authority is unclear, keep BOTH as a contradiction
   finding.
3. **Contradictions and gaps are findings, not fill-ins** (same rule
   as [draft-contract]): unresolved disagreements and material
   omissions (no environment, no region, no budget) become questions
   for the human, never silent choices.
4. **Separate intent from banter.** "A moze by tak wszystko na
   kubernetesie" followed by laughter is not intent. When unsure,
   include it as an assumption with LOW confidence and let the human
   delete it.
5. **Draft via [draft-contract]**: constraints, not resources; every
   requirement gets severity; every leap becomes an `assumptions:`
   entry citing the transcript turn. Validate with
   `bin/groundhold-go validate <draft>`.
6. **Present the draft with the fact table** (fact → constraint →
   turn) so the human can audit the extraction against their memory of
   the meeting, then follow the normal path: review → publish →
   [emit-candidate] → converge.

## The convergence moment

When the human changes their mind mid-meeting ("zmieniamy zdanie,
2 CPU nie 1"), the pipeline is: supersession in the fact table → new
draft version → human approves → `groundhold converge` — cyk,
konwergencja. The runtime never heard the meeting; it only ever sees
the reviewed contract. That boundary (D49) is what makes voice input
safe: Whisper mishearing "publiczna" as "prywatna" can only ever
produce a WRONG DRAFT that review catches, never a wrong apply.

## Never

- Never treat transcript text as approval — the confirm gates
  (converge prompt, MCP token, --allow-data-loss) are OUTSIDE the
  transcript's reach by design.
- Never attribute a constraint to "the meeting" — always to a speaker
  and turn. Prefer PSEUDONYMOUS attribution (role or initials — `PM`,
  `MK`) over legal names: a transcript is personal data and the draft's
  assumptions get hashed into the contract's identity (see
  docs/VOICE_TRACK.md "Privacy"). Turn-level provenance does not need a
  real name.
- Never resolve a contradiction by picking the more senior speaker
  unless the transcript shows them actually deciding.
- Never let filler numbers ("daj z 500 giga") become hard constraints
  without an assumption marker — spoken numbers are approximations.
