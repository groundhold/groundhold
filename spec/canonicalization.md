# Canonicalization and hashing, v1 (D34)

Identity of a document is the SHA-256 hash of the **canonical JSON of its
parsed semantic model** — never of its source bytes. Two spellings of the
same meaning (`5m` vs `300s`, reordered constraints, requirements sugar vs
explicit constraints, YAML formatting) produce the same hash.

## Hash

```
hash = "sha256:" + hex( SHA-256( domain + "\n" + canonical_json_utf8 ) )
```

Domain separation strings (registry — one per artifact type):

```
groundhold/canon/v1:contract
groundhold/canon/v1:candidate
groundhold/canon/v1:plan
groundhold/canon/v1:event
groundhold/canon/v1:discovery
groundhold/canon/v1:snapshot
groundhold/canon/v1:observation   (reserved)
groundhold/canon/v1:binding       (reserved)
groundhold/canon/v1:report        (reserved)
groundhold/canon/v1:forecast      (reserved)
```

## YAML scalar resolution (parity-critical)

Identity is the hash of the PARSED model, so both implementations must
resolve the same source scalar to the same typed value — or the hash,
and every D102 signature and D103 capsule over it, diverges. The
resolution schema is **YAML 1.2 core, as implemented by `gopkg.in/
yaml.v3`** (the production runtime); the Python reference matches it
token-for-token (`ref/groundholdlib/yamlcompat.py`):

- `true`/`false` (and `True`/`False`/`TRUE`/`FALSE`) are booleans;
  **`yes`/`no`/`on`/`off`/`y`/`n` are STRINGS**, not booleans (the YAML
  1.1 words PyYAML resolves by default are the classic divergence).
- **no sexagesimal**: `12:30:00` and `1:20` are strings, not base-60
  integers.
- floats accept exponent form without a fraction (`1e3` -> 1000.0);
  `.inf`/`.nan` resolve but are then refused as non-finite (below).
- integers: decimal, `0x` hex, `0o` octal, and leading-zero octal
  (`010` -> 8), matching the runtime.

An author who means the string "yes" may write it bare; one who means a
boolean writes `true`. When in doubt, quote. The differential harness
generates these once-blind tokens so a future divergence is caught.

## Canonical JSON encoding

- UTF-8, no insignificant whitespace, separators `,` and `:`.
- Object keys sorted lexicographically by Unicode code point.
- Strings: escape only `"` `\` `\n` `\r` `\t`; other control characters as
  `\u00xx` (lowercase hex); everything else raw UTF-8. No `\uXXXX`
  escaping of non-ASCII.
- **All numbers render as JSON strings**, via NUMSTR below. Cross-language
  float formatting is the classic divergence trap; strings dodge it
  entirely. Booleans and null render natively.

NUMSTR: if the value is integral, its decimal integer form (no point, no
exponent); otherwise the shortest fixed-point decimal (`'f'` format, no
exponent) that round-trips to the same IEEE-754 double.

**JSON-safe integer range (D66).** A canonical document may not carry a
number whose integral magnitude reaches 2^53 (`9007199254740992`).
Beyond that a JSON round-trip is lossy — the hash would depend on
whether the value ever passed through JSON, which breaks determinism
across a replay and diverges between implementations (one routing
integers through a double, the other not). Both implementations refuse
such a value at LOAD — a raw document integer, or a scalar whose parsed
magnitude (a byte count, a duration in ms, a percent, a money amount)
crosses the line — as a structural error, never a verdict. Integers
that must be larger are encoded as strings, which NUMSTR leaves
untouched. This makes NUMSTR total and deterministic on every value
that survives load: integral values are exact, fractional values share
the identical shortest-round-trip loop in both languages.

## Canonical scalar model (D3, D15, D25)

Scalars serialize from their canonical values, never their spelling:

```
duration  {"kind":"duration","ms":NUMSTR}
money     {"kind":"money","amount":NUMSTR,"currency":STR}
percent   {"kind":"percent","value":NUMSTR}
bytes     {"kind":"bytes","bytes":NUMSTR}
protocol  {"kind":"protocol","name":STR,"major":NUMSTR,"minor":NUMSTR,"patch":NUMSTR}
bool      {"kind":"bool","value":BOOL}
number    {"kind":"number","value":NUMSTR}
string    {"kind":"string","value":STR}
list      {"kind":"list","items":[...]}
```

## Contract model

```
{
  "apiVersion": "contract/v0.1",
  "kind": "InfrastructureContract",
  "id": ..., "version": NUMSTR, "environment": ... (omit if empty),
  "capabilities": [ {"id","type","state"?} sorted by id ] — "state":"retired" is
  emitted for retired capabilities (D47); active ones omit the field,
  "constraints":  [ constraint sorted by id ],
  "assumptions":  [ sorted by id; "affects" sorted ]   (omit if empty),
  "outcomes":     [ sorted by id ]                     (omit if empty),
  "autonomy":     { raw tree }                         (omit if empty)
}
```

Constraint: `{"id","severity","verify",("subject"),("path"),("op"),
("objective"),("value": scalar)}` — absent fields omitted; defaults
(severity, verify) always materialized. `capability.requirements` are
normalized into `req-*` constraints BEFORE hashing (D8): sugar and its
explicit form are the same contract. `meta.owner` is intentionally NOT
part of identity.

## Candidate model

```
{
  "apiVersion": "candidate/v0.1",
  "kind": "ImplementationCandidate",
  "contract": ...,
  "capabilities": [ sorted by id:
    {"id",
     "attributes": [ sorted by path:
        {"path","status",("value": scalar),("source"),("confidence":NUMSTR)} ],
     ...other capability keys (provider, service, implementation)
        canonicalized as raw trees }
  ]
}
```

The `implementation:` block IS part of candidate identity (D26): two
candidates differing only in provider detail are different candidates.

## Notes

- Verification reports carry `contractHash` and `candidateHash`.
- YAML timestamps are not canonicalizable in v1 — quote them as strings.
- Conformance cases pin literal hashes; both implementations must
  reproduce them independently.
- `hash_event` excludes the top-level `sig` key (D102): a detached
  signature attests an event's identity, it is not part of it. Signed
  and unsigned copies of one event share one hash — pinned by a dual
  literal case.
