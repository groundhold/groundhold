# Authoring a vocabulary (a capability type)

A vocabulary file IS the type system. It defines a **capability type** — which
attribute paths exist, their scalar kind, and how each maps to real provider
implementations. Contracts constrain these paths; candidates declare them; the
compiler maps them to provider resources. The sibling guide
[`../providers/AUTHORING.md`](../providers/AUTHORING.md) is for the *execution*
side (a driver); this is for the *meaning* side (what a capability IS).

The payoff of getting a vocabulary right: the verifier, compiler, forecast,
audit and every other verb pick up a new capability type with **zero engine
changes** (D23, D55) — the semantics live entirely in the declarative file,
loaded identically by the Go runtime and the Python reference.

## 1. The one judgment: capability SEMANTICS vs implementation NOISE

An attribute earns a place ONLY if it is capability meaning, not provider
plumbing. This is the whole discipline:

- **Semantics (belongs):** data residency, public exposure, RPO/RTO, cost,
  wire protocol, encryption posture, retention, availability class, identity
  federation — the *what must be true* a contract author reasons about.
- **Noise (does not belong):** instance tiers, disk types, node counts, SKU
  names, feature flags, region-specific machine shapes — the *how* a provider
  happens to deliver it.

When unsure, LEAVE IT OUT and note why. A vocabulary that leaks provider knobs
becomes un-portable and turns the contract into a config file. The test to
apply to every candidate attribute: *would an author on a different cloud still
mean this?* If not, it is implementation detail — it lives in the candidate's
free-form `implementation:` block, never as a capability path.

## 2. The file shape

```yaml
# spec/vocab/capability.<domain>.<name>.yaml
capability: capability.<domain>.<name>   # the type id; matches the filename
version: 0.1
stateful: true            # D47: retiring a stateful capability is DATA LOSS,
                          # gated by autonomy.forbidden delete_stateful. Set
                          # honestly — a database is stateful, a load balancer
                          # is not; the wrong answer weakens a safety gate.

attributes:
  encryption.atRest:
    kind: bool
    description: One line an author (and a reviewer) can act on.
    mappings:
      gcp.cloudsql: always true (CMEK optional via disk_encryption)
      aws.rds: storage_encrypted
      azure.flexpostgres: always true (=false refused rather than pretended)
    note: >
      Optional. Say the honest edge: what a provider CANNOT express, and that
      the driver refuses rather than pretends.
```

## 3. Scalar kinds (the closed set)

Every attribute declares a `kind`. Comparison is kind-checked — a value of one
kind compared against a constraint of another is `unverifiable`, never a silent
false (invariant #2). Kinds in use:

| kind | for | notes |
|---|---|---|
| `bool` | on/off posture | the most common; `publicExposure`, `encryption.atRest` |
| `string` | opaque identifiers | `location.region`; add `enum:` to make it a closed set |
| `number` | counts, unitless | e.g. `replicas.minimum` |
| `money` | cost | `{amount, currency}` — currency mismatch is `unverifiable`, not converted |
| `duration` | RPO/RTO, retention | `5m`, `24h` — cross-unit equal (`300s` == `5m`) via canonical value |
| `protocol` | wire compatibility | e.g. `postgresql/16` |
| `list` | sets | element-wise, kind-checked |

For a CLOSED set of allowed values, add an `enum:` allowlist to a `string`
attribute — the loader rejects a candidate value outside it, and a contract can
only constrain within it:

```yaml
  security.podStandard:
    kind: string
    enum: [restricted, baseline, privileged]
    description: The Pod Security Standard the namespace enforces.
```

## 4. Mappings — honest, per provider

Each attribute's `mappings` block records how the SEMANTIC attribute maps to
each provider that implements it. Two rules:

- **Say what a provider cannot honor, and that the driver REFUSES it** — never
  a mapping that silently pretends (e.g. "azure.flexpostgres: always true;
  `=false` refused rather than pretended"). A dishonest mapping is a false
  verdict waiting to happen (the D181 fabrication class).
- **The mapping is documentation for the driver author**, not executable here.
  The driver (`../providers/AUTHORING.md`) turns it into golden-tested code;
  this file is the contract between the two.

## 5. Wire it + test it

A vocabulary is declarative, so "implementing" it is mostly proving it loads
and verifies identically in both implementations:

1. **Both loaders read it** — Go (`go/internal/vocab/`) and Python
   (`ref/groundholdlib/vocab.py`) parse the same file; nothing else changes if the
   attribute is a plain scalar. This is the D23 promise.
2. **A conformance case pins the type** (case-first, per `CONTRIBUTING.md`):
   a `verify` case in `conformance/cases/` with a contract constraining a new
   path and a candidate declaring it — dual (both impls), plus a load-error
   case for an out-of-enum or ill-typed value.
3. `make check` → both suites green. `make differential` after scalar-adjacent
   changes.
4. Add a one-line `docs/DESIGN.md` note if the type introduces a new judgment
   (a new stateful class, a new kind usage).

## 6. Checklist (a vocabulary is not done until)

- [ ] every attribute is capability semantics, not a provider knob (§1);
- [ ] `stateful` is set honestly (§2 — it gates a real safety path);
- [ ] each `kind` is from the closed set, `enum:` used for closed value sets;
- [ ] mappings name what each provider CANNOT honor + that the driver refuses;
- [ ] a dual conformance case pins verify, plus a load-error case for a bad value;
- [ ] any attribute that is NOT resource state declares its `evidence:` class (§7);
- [ ] `make check` green in BOTH implementations, `make differential` clean.

## 7. Evidence class — how an attribute's value becomes true

Most attributes are **resource state**: the driver sets them and `observe` reads
them back. Some are not, and the vocabulary must say so, because the engine
decides real behaviour from it:

```yaml
  cost.monthly:
    kind: money
    evidence: projection    # a forecast/derivation — never resource state
  recovery.rto:
    kind: duration
    evidence: probe         # a claim until an outcome probe measures it
```

The closed set is `resource` (the default, omit it) | `projection` | `probe`.
An unrecognised value is refused by `TestEveryDeclaredEvidenceClassIsInTheClosedSet`
— a typo here would silently restore the default and make a reconcile block
forever on an observation that can never arrive.

What the declaration buys you (D311): an attribute that is not resource state is
skipped by the reconcile change-set and is **never handed to a driver at all**.
Before this was declarative, every one of ~50 driver builders needed a no-op
`case "cost.monthly":` arm — a builder refuses any attribute it cannot map — so
adding one attribute of this class meant editing ~50 Go files. Now it is one
line here and zero engine changes, which is the property a declarative
vocabulary exists to provide (D23/D55).

Do NOT re-decide the class inside a driver: `TestNoDriverHardcodesAnEvidenceClass`
fails on any `case` arm naming such a path. Producing one is fine and expected —
a probe EMITS `recovery.rto`, and the compiler READS `cost.monthly` for the risk
projection.
