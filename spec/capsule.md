# Evidence Capsule v0.1 (D103)

A capsule is a **self-contained, portable proof** for one capability:
its full event subchain, verbatim, genesis to tip, plus the tip hash.
It is what you hand across a boundary — to an auditor, a customer, a
central console — when "trust our filesystem" is not an answer.

```json
{
  "apiVersion": "capsule/v0.1",
  "kind": "EvidenceCapsule",
  "eventHashAlg": "sha256",              // D132: self-description, exact-match pins
  "canonicalization": "groundhold/canon/v1",
  "capability": "billing-db",
  "head": "sha256:…",          // tip event hash for this capability
  "asOf": "2026-07-15T08:06:00Z", // the tip event's occurredAt — recomputed at verify
  "events": [ /* verbatim ledger line documents, sig envelopes included */ ]
}
```

## Emission

`groundhold capsule <capability> --ledger <file>` replays the ledger first
(enforcing `--trust` when armed) and only then cuts the subchain: a
capsule from a corrupt ledger would launder corruption into a portable
document. Every event listing the capability is carried verbatim; a
capability with no events refuses (exit 1) — an empty proof is a lie
shaped like a document.

## Verification

`groundhold capsule --verify <capsule.json> [--trust <hex-pub>]
[--check <anchor.json>]` needs **no ledger, no groundhold deployment, no
filesystem trust**. Deterministic replay of the structure:

1. the capsule declares `eventHashAlg`/`canonicalization` and they are
   exactly what this verifier implements — an unknown algebra is refused
   loudly instead of guessed (D132: no silent interpretation drift);
2. every event validates as a `LedgerEvent` and lists the capability;
3. linkage: the first event's `prev[capability]` is `genesis`, each
   next one pins the recomputed hash of its predecessor;
4. the recomputed tip equals `head`, and the tip's `occurredAt` equals
   `asOf` — a proof must not claim a different time than its evidence;
5. under `--trust`: every event carries a verifying signature by
   exactly that key (D102 rules, all-or-nothing);
6. under `--check`: the receiver-held anchor pins `heads[capability]`
   equal to the capsule's head.

Any refusal is corruption-class evidence: exit 5.

**Limitation — capsules and a `--trust-from` boundary (D135).** A capsule
is ONE capability's subchain. A `--trust-from` boundary names one global
event, belonging to whichever capability authored it; a capsule for any
other capability does not carry it. A capsule that lacks the boundary
cannot locally prove which of its events are post-boundary (and so must be
signed), so verifying it under an anchor that embeds a `--trust-from`
policy REFUSES rather than accept it blind — accepting would be fail-open
on the signing obligation. Verify such capsules against an anchor without a
trust boundary, or sign the ledger from genesis (no unsigned era) if
per-capability capsules must carry the trust claim. This is a deliberate
fail-closed limit, not a bug: the refusal names it explicitly.

## What a verified capsule proves — and what it does not

Proves: *this capability's history, in this order, said exactly this*
— and, under `--trust`, *was authored by the holder of this key* as of
`asOf`. The reported `claimedLedger` (D134) proves ONLY that the events
were signed for one common ledger — **never membership in yours**: a
capsule without `--check` can be a different ledger's truth under a
shared key. Membership is exactly what `--check` adds (the anchor pins
`ledgerId` and the capability head). Multi-capability events are integrity-bound in full (the hash
covers their other-capability `prev` entries), even though only this
capability's chain is replayable from the capsule.

Does **not** prove: that nothing newer exists. A signer can withhold a
fresh suffix and emit a truthful-but-stale capsule. The countermeasure
is the anchor (D70): receivers keep anchors off-host and pass them to
`--check`; a stale capsule then fails loudly because the anchored head
has moved past the capsule's. Without `--check` the verifier still
verifies — it just proves less, and says so (`"anchorChecked": false`).
