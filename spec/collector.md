# The groundhold collector standard (witness-side extensibility)

A **collector** is how a third party extends groundhold's reach into reality that the
first-party drivers do not cover — an exotic control plane, a private endpoint, a
device behind a management network — **without entering groundhold's trusted,
credentialed core**. It runs out-of-band at the vantage, gathers state with its
OWN scoped credentials, and emits a signed **evidence capsule** (`spec/capsule.md`,
D103) that the core imports and RE-VERIFIES.

This is groundhold's deliberate answer to "community drivers", and the boundary is the
whole point.

## 1. Why a collector, not an out-of-process driver

A live, out-of-process community driver was considered and **rejected**. Two
reasons, both fatal:

- **It would move untrusted code inside the credentialed blast radius.** A driver is
  handed the operator's paired cloud credentials (D141) and a mutating executor
  pointed at production. Go cannot meaningfully sandbox a subprocess, so a community
  driver becomes a credential-exfiltration and prod-mutation vector — the malicious-
  plugin attack, verbatim.
- **It would make the deterministic verifier credulous.** `Observe` is the INPUT to
  groundhold's deterministic verifier (invariant #6). A driver that returns
  `encryption.atRest = true` when it is false produces a deterministic `satisfied`
  over a fabrication. A conformance kit can certify a binary on fixtures once; it
  cannot bind that binary's PRODUCTION behavior against a real cloud. "Honesty
  enforced by a kit" over live output is a category error.

A collector keeps both boundaries intact. It holds ITS OWN scoped credentials —
never groundhold's — so the credential blast radius does not grow. Its evidence is
**signed** (D102) and the core **re-verifies** it (recomputing `asOf`, never
believing the collector's clock), so the verifier stays deterministic over evidence
whose signatures the operator CHOSE to trust (`--trust`). The trust boundary moves
to a signature the operator controls, not to a binary groundhold runs.

## 2. What a collector produces

One **evidence capsule per capability** (`capsule/v0.1`): the capability's event
subchain, genesis to tip, each event signed, plus the tip hash and `asOf`. The
events are `observation.recorded` documents whose bodies carry the capability's
observations. A collector authors these the way an in-tree driver's `Observe` does,
honoring the same honesty rules — but because a collector is NOT trusted the way an
in-tree driver is, the rules are also **checked at the boundary** (§4).

## 3. The honesty rules (what a collector MUST do)

- **Four-valued, never collapsed.** An observation is `measured` (read from live
  state), `config-intent` (a value the resource stores but does not itself
  enforce), or `platform-invariant` (D759: true of EVERY instance of the service
  by the provider's own guarantee, read from nothing on this resource — e.g.
  "an ElastiCache Serverless cache encrypts at rest"). Nothing else is a valid
  derivation. A platform guarantee is not a measurement and it is not the
  resource's configuration: it is a claim about the SERVICE, and it carries the
  evidence weight of a claim (the `static` bar), never that of a reading. Absence of a fact is an omission
  (leave it out, note it in diagnostics), never a fabricated value.
- **Secrets are structurally excluded (D53).** A collector NEVER puts a password,
  token, key, or credential into an observation value, path, diagnostic, or any
  field. It gathers reality with its credentials; it emits only the GOVERNED
  semantics (residency, exposure, encryption posture, protocol), never the secret
  itself.
- **The core owns the clock (N1).** Every observation carries an `observedAt`; the
  capsule's `asOf` is its tip's time. A collector may not date anything past its own
  `asOf`, and the core recomputes `asOf` at verify — a collector cannot forge
  freshness.
- **Map to a capability vocabulary.** Observations land on `spec/vocab/` capability
  paths (`encryption.atRest`, `network.publicExposure`, …), never a
  collector-invented schema and never a secret-named path.
- **Sign what you emit (D102).** The capsule's events carry detached ed25519
  signatures; the operator adds the collector's key to their trust set (`--trust`)
  to accept it. An unsigned capsule is accepted only by an operator who explicitly
  runs without trust — the honest, weaker posture.

## 4. Certification (`groundhold certify-capsule`)

`groundhold certify-capsule <capsule.json>` is BOTH the collector author's
self-certification gate and the core's import-time check. It composes
`VerifyCapsule`'s structural proof with the honesty-shape checks a third party is
not trusted to have satisfied on its own:

- **Structure / signatures / linkage** (existing, D103): the algebra self-matches,
  every event validates, the chain links genesis→tip, the recomputed head and
  `asOf` match, signatures verify against the trust policy, the ledger identity is
  consistent (D134). A tampered or reordered capsule refuses HERE.
- **D53 secrets scan** (new, the boundary enforcement): every byte crossing into the
  core is scanned — a secret-NAMED field or observation path, and any string VALUE
  carrying an unambiguous secret signature (a PEM private key, an AWS access-key id,
  a bearer token, a JWT) — is rejected.
- **Derivation vocabulary**: every observation's derivation is `measured` or
  `config-intent` or `platform-invariant`; an unlabeled or invented basis is rejected.
- **Freshness discipline**: every observation carries an `observedAt`; nothing is
  dated past the capsule's `asOf`.

Rejected is corruption-class (exit 5): the core imports nothing it cannot certify,
and invariant #1 then makes every downstream query answer `unknown` for the missing
capability rather than believe an uncertified fact.

**The honest boundary.** The secrets scan catches SIGNATURE-bearing and
secret-NAMED payloads; it cannot catch an arbitrary plaintext secret with no
signature emitted at a benign-looking path. So the scan is a SAFETY NET, not a
guarantee — the collector is still contractually required to exclude secrets
structurally (§3). Certification is EVIDENCE that a capsule is well-formed and
honest-shaped, not PROOF that its measurements are true — the same honest stance as
every groundhold gate (a passing preflight is evidence, not proof, D75). Truth of the
measurement rests on the operator's decision to trust the collector's signature.

## 5. Onboarding a collector — the checklist

A third-party collector is ready when ALL hold:

1. Gathers state with its OWN scoped credentials — never groundhold's paired creds.
2. Emits one `capsule/v0.1` per capability, events signed (D102).
3. Every observation is `measured`, `config-intent` or `platform-invariant`, on a `spec/vocab/` path.
4. No secret in any field — value, path, diagnostic (D53).
5. Every observation carries `observedAt`; nothing dated past `asOf`.
6. `groundhold certify-capsule` returns `certified` on its output.
7. The operator adds the collector's key to their trust set to import it.

When these hold, the collector extends groundhold's reality-gathering at witness-side
distance — no untrusted code in the core, no growth of the credential blast radius,
and the deterministic verifier still runs only over evidence the operator trusts.
