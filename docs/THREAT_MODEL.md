# Threat model

What groundhold defends, what it deliberately does not, and how each guarantee is
earned. Read `SECURITY.md` first for the reporting process and the trust
boundary in prose; this document is the structured version. Honesty is the
whole thesis, so the accepted risks below are stated as plainly as the defenses.

## Scope and assumptions

groundhold is a **local CLI/library**. There is no hosted service, no in-process
authentication, and no network egress except to the cloud provider the operator
explicitly configures (and zero telemetry). Its integrity guarantees are scoped
to that shape; overstepping them is not a vulnerability.

## Assets

- **The ledger** — the append-only, content-addressed decision history. Every
  binding, verdict-of-record, lease and receipt projects from it.
- **Sealed plans** — the hash-pinned IR the executor runs; the only thing that
  may mutate cloud state.
- **Evidence capsules + signatures** — portable proofs a receiver verifies with
  no ledger and no groundhold deployment.
- **The observation stream** — measured/observed reality feeding the verifier.
- **Provider credentials** — read from the environment / the operator's
  configured auth; never stored by groundhold.

## Trust boundaries

- **OS file permissions** are the ledger's authenticity base. groundhold writes
  `0600`/`0700` and re-verifies the hash chain on replay, but anyone who can
  write the file can forge an internally consistent history (see accepted risks).
- **The provider API** — groundhold trusts the provider's responses to reverse-map
  into observations; a lying provider is out of scope, but the drivers refuse
  rather than fabricate when a response is absent/ambiguous (D181).
- **Untrusted inputs** — candidate documents, meeting transcripts, and provider
  responses are attacker-influenceable. They may propose anything; they may
  never *supply consent* (the injection boundary, below).

## Threats and mitigations

| Threat | Mitigation | Where |
|---|---|---|
| Ledger tamper: reorder/drop/rewrite events | per-capability hash chain + a positional/manifest tail **anchor** (external tamper-evidence) | D70, D182–D185 |
| Forged/altered evidence capsule | verify recomputes every hash from raw bytes + walks the linkage; a claimed head that isn't the recomputed tip refuses | D103, D187 |
| Signature transplant / foreign-key acceptance | Ed25519 verify is fail-closed; the signed message binds `scheme:ledgerId:eventHash`; foreign key / unsigned-under-`--trust` refuse | D102, D187 |
| Unconsented destruction (delete/replace of stateful) | layered consent: contract `autonomy` + runtime `--allow-data-loss` + two-step apply; converge fail-closes the destructive detection | D47/D48, D193 |
| False verdict from a fabricated/weak observation | four-valued verdicts (no silent false); driver honesty (no measurement from config-intent); the evidence-bar gate (`verify.method` enforced by source) | D181, D189–D191, D190 |
| Stale evidence read as fresh / time-travel | N1 requires explicit `--at`; a future-dated observation is invalid, not fresh; freshness is part of the type | N1, D188 |
| Prompt injection via candidate/transcript/provider response | the author-vs-witness boundary: an untrusted input can propose a contract/candidate but the runtime re-verifies and **never** supplies a human's consent; a misheard word yields a wrong draft, never a wrong apply | D61, D177 |
| Secrets leaking from **tf/pulumi state** into adoption hints | values cross into hints only through an explicit per-path mapping — nothing is copied from state wholesale | D53 |
| Secrets leaking into the **ledger/exports/capsules** via a failed mutation | two defences: no driver diagnostic carries a response body (only the provider's own error code + a bounded message), and the driver scrubs the credential values the candidate handed it out of the Reason at the Create/Update boundary — the Reason is persisted, exported and signed | D309 |
| Secrets leaking into **observations** | structural, not a scan: an observation is a typed vocabulary attribute, and no vocabulary declares a credential-valued attribute — a driver has nowhere to put one | D60, vocab discipline |
| Lease/fencing bypass, resurrected tokens, backdated writes | decision-heads CAS, fencing tokens, the coordination clock refuses regression | D41, D56 |
| Path/symlink escape (MCP, providerId) | workspace confinement + providerId validation | D73, MCP hardening |

The adversarial-hardening series (D182–D195) is, in effect, this table's test
suite: each round hunted one threat class and pinned the fix with a
fails-without-fix case.

## Accepted risks (NOT defended — by design, in v0.x)

- **Actor identity is self-asserted.** `publish --actor` and `actor.id` record
  who *claims* to have acted; they are not authenticated. The ledger evidences
  sequence and content per writer trust, never identity.
- **Tamper-evidence, not tamper-prevention.** A party who can write the ledger
  file can forge a consistent history; the anchor detects it only when the
  operator stores the anchor off-host. Event signatures are optional in v0.
- **No in-process separation of duties.** One operator can author, publish,
  consent and apply. SoD must come from surrounding infrastructure (repo
  permissions, CI approvals).
- **The authoring boundary is trust, not proof.** A compromised authoring model
  can propose a *valid but wrong* contract; groundhold catches only what the
  constraints + gates catch, plus human review at publish. This is the open
  question the design log tracks, surfaced here rather than left implicit.
- **No external security audit yet** (see `docs/MATURITY.md`); all adversarial
  review to date is internal.

## Reporting

Vulnerabilities go through GitHub private advisories, never public issues —
see `SECURITY.md` for the process (72h acknowledgment) and the researcher scope.
