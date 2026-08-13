# Security policy

## Reporting

Report vulnerabilities privately through GitHub's private vulnerability
reporting ("Report a vulnerability" under the repository's Security tab,
which opens a private advisory visible only to maintainers). Do not open
public issues for exploitable problems. You will get an acknowledgment
within 72 hours.

(Private vulnerability reporting is enabled on this repository.)

A structured threat model — assets, trust boundaries, threats/mitigations,
and the accepted risks — is in [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md).

## Disclosure process

1. **Acknowledge** — within 72 hours.
2. **Triage** — we confirm, scope impact, and reduce the report to a
   failing conformance case where applicable (a fix is not done until the
   case is pinned and both implementations agree).
3. **Fix + coordinate** — we agree a disclosure date with you. Default
   **coordinated-disclosure window: 90 days** from acknowledgment, or when
   a fix ships — whichever is first. We can move faster for actively
   exploited issues.
4. **Publish** — a GitHub Security Advisory with the fix and, unless you
   decline, credit to you.

Please do not publicly disclose before the coordinated date.

## Verifying a release

Release binaries ship with a CycloneDX SBOM, `SHA256SUMS`, and `BUILDINFO.txt`.
Before running a downloaded binary, verify the checksums:

```sh
sha256sum -c SHA256SUMS
```

A keyless SLSA build-provenance attestation is produced **only once this repository
is public** — GitHub does not make one retrievable for a private repository on a free
plan, so `gh attestation verify` returns 404 until the flip and the release notes claim
it only after the workflow confirms it exists (D354). Once public:

```sh
gh attestation verify groundhold_<ver>_<os>_<arch> --repo groundhold/groundhold
```

**Reproducible builds.** Binaries are built deterministically (`-trimpath`,
`-buildvcs=false`, `CGO_ENABLED=0`, pinned `-ldflags`), so **within the same
toolchain** you can rebuild a bit-identical binary from the tagged source (use the
exact toolchain/command in `BUILDINFO.txt`) and confirm it matches `SHA256SUMS`.
Cross-host / cross-toolchain reproducibility is NOT yet verified — see
`docs/THREAT_MODEL.md` (accepted risks).

## Supported versions

The project is experimental (`v0.x`). Only the latest tagged
release and `main` receive security fixes; there is no back-porting or LTS
during v0.x.

## Trust boundary (read this first)

Groundhold is a local CLI/library with no hosted service and no in-process
authentication. Its integrity guarantees are scoped accordingly, and
overstepping them is not a vulnerability:

- **The ledger's authenticity rests on OS file permissions plus a
  recomputable SHA-256 hash chain.** The chain is tamper-EVIDENCE, not
  prevention: anyone who can write the ledger file can forge an
  internally consistent history. Optional detached Ed25519 event signatures
  (D102) close that gap when armed, but are OFF by default in v0 — the
  default ledger rests on the hash chain alone. The optional `anchor` gives the tail external
  tamper-evidence, but only when the operator stores the anchor
  off-host; arm it and enforcement runs on the apply/resume path.
- **Actor identity is self-asserted.** `publish --actor` and event
  `actor.id` record who *claims* to have acted; they are not
  authenticated. The ledger evidences sequence and content, per writer
  trust — not identity.
- **There is no in-process separation of duties.** One operator can
  author, publish, consent, and apply. SoD must come from the
  surrounding infrastructure (repo permissions, CI approvals).

## Scope notes for researchers

- The runtime makes NO network calls except to the cloud provider the
  operator explicitly configures, and has ZERO telemetry. Any network
  traffic beyond the configured provider is a vulnerability — report it.
- The ledger is append-only with hash chains and fencing tokens;
  anything that lets a writer rewind time, forge a head, bypass a
  lease, resurrect an expired fencing token, or mutate cloud state
  without a sealed plan is a vulnerability.
- Confirmation gates (converge prompts, MCP two-step tokens,
  --allow-data-loss, contract consents) are security boundaries:
  any path that supplies consent on a human's behalf is a
  vulnerability — including prompt-injection paths through candidate
  documents, transcripts, or provider responses.
- Secrets crossing from terraform/pulumi state into hints documents
  (the allowlist boundary in the importer) is a vulnerability.
