# Versioning and licenses

## What is frozen

- **Registries are additive-only with reserved semantics**: event
  types, canonical domains, capability types, error codes. Nothing is
  reused, nothing changes meaning, nothing leaves conformance.
- **Ledger history is append-only**; the decision log
  (`docs/DESIGN.md`) is append-only; conformance expectations are
  never weakened.
- **CLI exit codes and the JSON output shapes** are stable; outputs
  may GROW fields (consumers must tolerate unknown fields —
  `spec/outputs.schema.json`).

## Licenses

| tree | license | why |
|---|---|---|
| `spec/`, `conformance/`, `ref/` | Apache 2.0 | the trust interface: anyone may implement and measure against it |
| `go/` (runtime) | MPL 2.0 | file-level copyleft — forks return file fixes; embedding apps stay unencumbered |

The split is carried by the tree, not only by this table: the repository root holds
the Apache text and `go/LICENSE` holds the MPL text beside the code it covers, so a
tool that walks directories resolves the runtime correctly.

**GitHub's repository badge says Apache-2.0**, because that is the licence at the root
and GitHub reports exactly one. It is a lossy summary of a dual-licensed tree, not a
statement about `go/`. Anyone embedding the runtime is under MPL 2.0 — file-level
copyleft — and should read `go/LICENSE` rather than the badge. Saying so here because
a dependency scanner reading the repository API sees only the badge.

The GOVERNANCE.md promise: this open core will never be relicensed.
No BSL, no SSPL. "Groundhold Conformant" is intended to mean passing the unmodified suite; "Groundhold" is a working name, with a formal trademark and usage policy to follow the name decision.

## Telemetry

None. The runtime makes no network calls beyond the provider you
configure. The ledger is the observability surface; `export` streams
it wherever you want. Any traffic beyond that is a bug — report it
via SECURITY.md.
