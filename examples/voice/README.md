# Transcript → contract: the worked example

`meeting.transcript.md` is seven turns of a planning sync, including
one mid-meeting mind-change. `drafted.contract.yaml` is what the
`transcript-to-contract` skill produces from it.

What to notice:

1. **Supersession**: "five minutes RPO" (00:04:31) was revised to "one
   minute" (00:06:44). One constraint came out (`c-rpo: lte 1m`), with
   the supersession recorded in the assumption's source — auditable
   against anyone's memory of the meeting.
2. **Filler numbers stay out**: "give it, like, 500 gigs" did not
   become a constraint. Spoken capacity estimates are approximations;
   the draft flags it for the human instead of encoding it.
3. **Implementation talk stays out**: "PITR, not snapshots" is how,
   not what — the meeting owner said so herself.
4. **The unprovable is marked probe**: RTO "an hour is fine" drafts as
   `verify.method: probe` — nothing can deploy that claim until a
   restore test measures it (`groundhold probe`, double consent).
5. **The runtime never heard the meeting.** The draft is a proposal;
   review publishes it; only then does the verified path begin:

```sh
bin/groundhold-go validate examples/voice/drafted.contract.yaml
# review, publish, then: emit a candidate and converge
```

Platform adapters (Zoom/Teams/Meet transcripts) are deliberately out
of the core — see docs/VOICE_TRACK.md for the ingestion interface and
the source-per-platform map.
