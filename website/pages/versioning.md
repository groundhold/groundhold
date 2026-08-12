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

The GOVERNANCE.md promise: this open core will never be relicensed.
No BSL, no SSPL. "Groundhold Conformant" is intended to mean passing the unmodified suite; "Groundhold" is a working name, with a formal trademark and usage policy to follow the name decision.

## Telemetry

None. The runtime makes no network calls beyond the provider you
configure. The ledger is the observability surface; `export` streams
it wherever you want. Any traffic beyond that is a bug — report it
via SECURITY.md.
