# Voice track (D61): spoken intent → verified infrastructure

## The pipeline

```
audio (meeting / dictation)
  → STT (Whisper — local whisper.cpp or provider transcript API)
  → transcript with speaker turns
  → transcript-to-contract skill (agent): facts, supersession,
    assumptions with turn-level provenance
  → contract DRAFT (.groundhold/drafts/)
  → HUMAN REVIEW — the authoring boundary (D49)
  → published contract → emit-candidate → verify → converge
```

The runtime never hears the meeting. Everything left of "human review"
is probabilistic and disposable; everything right of it is the
deterministic machine this repo builds. A misheard word can only ever
produce a wrong draft that review catches — never a wrong apply. The
confirm gates (converge prompt, MCP two-step token, --allow-data-loss)
are structurally outside the transcript's reach.

## Meeting-platform integrations (planned)

Zoom / Teams / Google Meet / Slack huddles all reduce to the same
adapter shape: **get the transcript out**, everything downstream is
identical.

| Platform | Transcript source |
|----------|------------------|
| Zoom | cloud recording transcript API, or bot (recall.ai-style) |
| Teams | Graph API callTranscript |
| Google Meet | Meet API conferenceRecords.transcripts |
| Slack | huddle transcripts / thread text (already text) |
| anything | local capture → whisper.cpp |

The adapter's ONLY job: produce `{turns: [{speaker, at, text}]}` and
hand it to the skill. No platform logic touches contracts. Outbound
integration is already solved generically: `groundhold export`
(CloudEvents) feeds whatever notifier a team uses — a Slack webhook
consumer is an operator script, not a Groundhold feature.

## Privacy: transcripts carry personal data

A meeting transcript is personal data: speaker names, timestamps, and
verbatim quotes. The skill deliberately attributes every extracted fact
to a speaker and turn (contradictions are findings, not noise), so those
identifiers can flow into a drafted contract's `assumptions` — and a
contract is canonically hashed (D34), with sealed plans pinning its
hash. That makes redaction-after-publication operationally costly:
changing a name changes the contract's identity and voids plans pinned
to the old hash. Guidance, so adopters inherit no hidden obligation:

- **Minimise at the boundary.** Pseudonymous attribution satisfies the
  skill's provenance requirement — a role or initials (`PM`, `MK`) is
  enough to say "who claimed this"; legal names are not required and
  should be kept out of published contracts.
- **Keep the raw transcript out of the ledger.** The transcript is
  authoring input, not runtime state; it is never appended to the
  ledger. Drafts live under `.groundhold/drafts/` (0600) and are the
  operator's to retain or delete under their own retention policy.
- **The adopter is the controller.** Groundhold hosts nothing and has zero
  telemetry (SECURITY.md); lawful basis, retention, and erasure for
  ingested speech are the adopting organisation's responsibility. This
  note exists so that responsibility is explicit, not transferred by
  silence.

## Why this is the demo

"Potrzebuję bazy MySQL w Warszawie, prywatnej, RPO 5 minut… nie,
czekaj, RPO minuta." — thirty seconds of speech; the skill extracts
four constraints with one supersession; the human glances at the fact
table and publishes; converge builds it and proves it converged. The
missing piece was never speech recognition — it is that everything
after the transcript is VERIFIED: four-valued verdicts, sealed plans,
gated destruction, measured probes. Voice is just the cheapest way to
author intent; Groundhold is what makes authored intent safe to execute.
